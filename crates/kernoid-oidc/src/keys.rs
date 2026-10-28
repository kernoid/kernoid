// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing keys of an instance, with a life cycle as in ZITADEL's web keys (RFC 0001, section 6):
//! **initial** (published in the JWKS, not yet signing) → **active** (signs ID tokens; one per instance) →
//! **inactive** (still published, so tokens it signed stay verifiable until they expire) → **removed**.
//!
//! All keys of an instance form one aggregate (`signing_keys`, owned by the instance), so that activating one key and
//! deactivating the previous one is a single event. The private key (RSA 2048, PKCS#8) is sealed with the main key and
//! bound to instance and key id; it is never in an event. An instance without a key gets one at its first login.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair, KeySize},
    signature::KeyPair as _,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use kernoid_events::{
    Error, Event, InlineFuture,
    aggregate::{Aggregate, CommandError, DomainEvent},
    inline,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Oidc, OidcError, Result, internal, lifetime};

pub const ALGORITHM: &str = "RS256";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    Initial,
    Active,
    Inactive,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Initial => "initial",
            KeyState::Active => "active",
            KeyState::Inactive => "inactive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SigningKeyEvent {
    #[serde(rename = "signing_key.added")]
    Added { kid: String, algorithm: String },
    /// The key signs from now on; the key that was active becomes inactive.
    #[serde(rename = "signing_key.activated")]
    Activated { kid: String },
    #[serde(rename = "signing_key.removed")]
    Removed { kid: String },
}

impl DomainEvent for SigningKeyEvent {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SigningKeys {
    pub keys: BTreeMap<String, KeyState>,
}

impl SigningKeys {
    pub fn active(&self) -> Option<&str> {
        self.keys.iter().find(|(_, state)| **state == KeyState::Active).map(|(kid, _)| kid.as_str())
    }
}

impl Aggregate for SigningKeys {
    const TYPE: &'static str = "signing_keys";
    type Event = SigningKeyEvent;

    fn apply(&mut self, event: SigningKeyEvent) {
        match event {
            SigningKeyEvent::Added { kid, .. } => {
                self.keys.insert(kid, KeyState::Initial);
            }
            SigningKeyEvent::Activated { kid } => {
                for state in self.keys.values_mut() {
                    if *state == KeyState::Active {
                        *state = KeyState::Inactive;
                    }
                }
                self.keys.insert(kid, KeyState::Active);
            }
            SigningKeyEvent::Removed { kid } => {
                self.keys.remove(&kid);
            }
        }
    }
}

/// Activation and removal; adding is written by [`Oidc::add_signing_key`], which holds the private key.
async fn project(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        let instance = event.owner;
        match SigningKeyEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            SigningKeyEvent::Added { .. } => {}
            SigningKeyEvent::Activated { kid } => {
                sqlx::query!(
                    "UPDATE signing_keys SET state = 'inactive', state_since = now()
                     WHERE instance_id = $1 AND state = 'active'",
                    instance,
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query!(
                    "UPDATE signing_keys SET state = 'active', state_since = now() WHERE instance_id = $1 AND kid = $2",
                    instance,
                    kid,
                )
                .execute(&mut *connection)
                .await?;
            }
            SigningKeyEvent::Removed { kid } => {
                sqlx::query!("DELETE FROM signing_keys WHERE instance_id = $1 AND kid = $2", instance, kid)
                    .execute(&mut *connection)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Unsealed private keys, by key id.
#[derive(Debug, Clone, Default)]
pub(crate) struct KeyCache(Arc<Mutex<HashMap<String, Arc<KeyPair>>>>);

fn context(instance: Uuid, kid: &str) -> Vec<u8> {
    format!("kernoid/signing-key/v1/{instance}/{kid}").into_bytes()
}

/// Who rotates keys, in the audit log.
const ROTATION: &str = "system:key-rotation";

/// What one round of [`Oidc::rotate_signing_keys`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rotated {
    pub added: u64,
    pub activated: u64,
    pub removed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub kid: String,
    pub algorithm: String,
    pub state: KeyState,
    pub created_at: DateTime<Utc>,
    pub state_since: DateTime<Utc>,
}

fn command_error(error: CommandError<OidcError>) -> OidcError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => internal(error),
    }
}

impl Oidc {
    async fn key_command(
        &self,
        instance: Uuid,
        creator: &str,
        decide: impl Fn(&SigningKeys) -> Result<Vec<SigningKeyEvent>>,
    ) -> Result<()> {
        self.events
            .execute_with(instance, instance, &instance.to_string(), creator, decide, |c, e| Box::pin(project(c, e)))
            .await
            .map(drop)
            .map_err(command_error)
    }

    /// Creates a key (initial: published, not yet signing); returns its id.
    pub async fn add_signing_key(&self, instance: Uuid, creator: &str) -> Result<String> {
        let kid = Uuid::now_v7().simple().to_string();
        let key = tokio::task::spawn_blocking(|| KeyPair::generate(KeySize::Rsa2048))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        let pkcs8 = zeroize::Zeroizing::new(key.as_der().map_err(internal)?.as_ref().to_vec());
        let sealed = self.main.seal_secret(&context(instance, &kid), &pkcs8).map_err(internal)?;
        let public = key.public_key();
        let jwk = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": ALGORITHM,
            "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
            "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
        });
        let stored_kid = kid.clone();
        let store = inline(move |connection, _| {
            let (kid, jwk, sealed) = (stored_kid.clone(), jwk.clone(), sealed.clone());
            Box::pin(async move {
                sqlx::query!(
                    "INSERT INTO signing_keys (kid, instance_id, algorithm, state, public_jwk, private_sealed)
                     VALUES ($1, $2, $3, 'initial', $4, $5)",
                    kid,
                    instance,
                    ALGORITHM,
                    jwk,
                    sealed,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                instance,
                &instance.to_string(),
                creator,
                |_: &SigningKeys| Ok(vec![SigningKeyEvent::Added { kid: kid.clone(), algorithm: ALGORITHM.into() }]),
                store,
            )
            .await
            .map_err(command_error)?;
        Ok(kid)
    }

    /// Makes a key the one that signs; the key active so far becomes inactive. Publish a key (initial) for a while
    /// before activating it, so that clients that cache the JWKS already know it.
    pub async fn activate_signing_key(&self, instance: Uuid, kid: &str, creator: &str) -> Result<()> {
        self.key_command(instance, creator, |keys| match keys.keys.get(kid) {
            None => Err(OidcError::InvalidRequest(format!("no key {kid}"))),
            Some(KeyState::Active) => Ok(Vec::new()),
            Some(_) => Ok(vec![SigningKeyEvent::Activated { kid: kid.to_owned() }]),
        })
        .await
    }

    /// Removes an inactive key – only once ID tokens it signed can no longer be valid.
    pub async fn remove_signing_key(&self, instance: Uuid, kid: &str, creator: &str) -> Result<()> {
        let info = self.signing_keys(instance).await?.into_iter().find(|key| key.kid == kid);
        let earliest = info.as_ref().map(|key| key.state_since + lifetime::ID_TOKEN);
        self.key_command(instance, creator, |keys| match keys.keys.get(kid) {
            None => Err(OidcError::InvalidRequest(format!("no key {kid}"))),
            Some(KeyState::Inactive) if earliest.is_some_and(|earliest| earliest <= Utc::now()) => {
                Ok(vec![SigningKeyEvent::Removed { kid: kid.to_owned() }])
            }
            Some(KeyState::Inactive) => {
                Err(OidcError::InvalidRequest("tokens signed with this key may still be valid; remove it later".into()))
            }
            Some(_) => Err(OidcError::InvalidRequest("only an inactive key can be removed".into())),
        })
        .await
    }

    pub async fn signing_keys(&self, instance: Uuid) -> Result<Vec<KeyInfo>> {
        let rows = sqlx::query!(
            "SELECT kid, algorithm, state, created_at, state_since FROM signing_keys
             WHERE instance_id = $1 ORDER BY created_at",
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|row| KeyInfo {
                kid: row.kid,
                algorithm: row.algorithm,
                state: match row.state.as_str() {
                    "active" => KeyState::Active,
                    "inactive" => KeyState::Inactive,
                    _ => KeyState::Initial,
                },
                created_at: row.created_at,
                state_since: row.state_since,
            })
            .collect())
    }

    /// Rotates the signing keys of every instance (the worker, by `oidc.key_rotation_days`): a key active for
    /// `rotation` gets a successor, published (initial) for `publish` before it signs, so that clients caching the
    /// JWKS know it in time; a key inactive for `keep` is removed. Instances without an active key are left to
    /// [`Oidc::signer`], which makes one when it is needed.
    pub async fn rotate_signing_keys(&self, rotation: Duration, publish: Duration, keep: Duration) -> Result<Rotated> {
        let mut done = Rotated::default();
        let now = Utc::now();
        // Never before ID tokens it signed have expired (`remove_signing_key` refuses that anyway).
        let keep = keep.max(lifetime::ID_TOKEN);
        for instance in self.identity.instances().await? {
            let keys = self.signing_keys(instance.id).await?;
            let Some(active) = keys.iter().find(|key| key.state == KeyState::Active) else { continue };
            let newest_initial =
                keys.iter().filter(|key| key.state == KeyState::Initial).max_by_key(|key| key.created_at);
            if active.state_since + rotation <= now {
                match newest_initial {
                    None => {
                        self.add_signing_key(instance.id, ROTATION).await?;
                        done.added += 1;
                    }
                    Some(next) if next.created_at + publish <= now => {
                        self.activate_signing_key(instance.id, &next.kid, ROTATION).await?;
                        done.activated += 1;
                    }
                    Some(_) => {}
                }
            }
            for old in keys.iter().filter(|key| key.state == KeyState::Inactive && key.state_since + keep <= now) {
                self.remove_signing_key(instance.id, &old.kid, ROTATION).await?;
                done.removed += 1;
            }
        }
        Ok(done)
    }

    /// The published keys of an instance, as a JWK set.
    pub async fn jwks(&self, instance: Uuid) -> Result<Value> {
        let keys = sqlx::query_scalar!(
            "SELECT public_jwk FROM signing_keys WHERE instance_id = $1 ORDER BY created_at",
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        Ok(json!({ "keys": keys }))
    }

    /// The key that signs for `instance` – created and activated if there is none.
    pub(crate) async fn signer(&self, instance: Uuid) -> Result<(String, Arc<KeyPair>)> {
        for _ in 0..2 {
            let row = sqlx::query!(
                "SELECT kid, private_sealed FROM signing_keys WHERE instance_id = $1 AND state = 'active'",
                instance,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(internal)?;
            let Some(row) = row else {
                // Another process may do the same; activating twice is refused, then both read the winner's key.
                let kid = self.add_signing_key(instance, "system").await?;
                if let Err(error) = self.activate_signing_key(instance, &kid, "system").await {
                    tracing::debug!(%error, "another process activated a key first");
                }
                continue;
            };
            if let Some(key) = self.keys.0.lock().expect("lock").get(&row.kid) {
                return Ok((row.kid, key.clone()));
            }
            let (pkcs8, _) =
                self.main.open_secret(&context(instance, &row.kid), &row.private_sealed).map_err(internal)?;
            let key = Arc::new(KeyPair::from_pkcs8(&pkcs8).map_err(internal)?);
            self.keys.0.lock().expect("lock").insert(row.kid.clone(), key.clone());
            return Ok((row.kid, key));
        }
        Err(OidcError::Internal("no signing key could be made active".into()))
    }

    /// Seals every signing key that is sealed with a previous main key again with the current one (after changing
    /// the main key, with `kernoid keys rewrap`); returns how many.
    pub async fn rewrap_signing_keys(&self) -> Result<u64> {
        let rows = sqlx::query!("SELECT kid, instance_id, private_sealed FROM signing_keys")
            .fetch_all(self.pool())
            .await
            .map_err(internal)?;
        let mut count = 0;
        for row in rows {
            let context = context(row.instance_id, &row.kid);
            let (private, previous) = self.main.open_secret(&context, &row.private_sealed).map_err(internal)?;
            if !previous {
                continue;
            }
            let sealed = self.main.seal_secret(&context, &private).map_err(internal)?;
            count += sqlx::query!(
                "UPDATE signing_keys SET private_sealed = $2 WHERE kid = $1 AND private_sealed = $3",
                row.kid,
                sealed,
                row.private_sealed,
            )
            .execute(self.pool())
            .await
            .map_err(internal)?
            .rows_affected();
        }
        Ok(count)
    }
}
