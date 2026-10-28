// SPDX-License-Identifier: AGPL-3.0-or-later
//! Passkeys (WebAuthn), verified with webauthn-rs (the Kanidm project's library, MPL-2.0) – kernoid parses no WebAuthn
//! structures itself.
//!
//! - **Registering** needs a recent session. The challenge and its state stay on the server (`webauthn_challenges`,
//!   five minutes); the passkey's public key and counter go to `account_passkeys`, the event `account.passkey_added`
//!   only names it.
//! - **A further check** of a session: the account's passkeys are offered, user verification is required.
//! - **Logging in without a password**: a discoverable passkey; the browser offers the person's passkeys, no address is
//!   typed, so the answer tells nothing about which accounts exist. Failed attempts count against the client address.
//! - The **relying party** is the instance: its primary domain as RP ID, `<public scheme>://<primary domain>` as origin
//!   – a passkey works only there.

use std::time::Duration;

use chrono::{DateTime, Utc};
use kernoid_events::{InlineFuture, aggregate::CommandError, inline};
use serde_json::Value;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

use crate::{
    Identity, IdentityError, Result,
    account::{Account, AccountEvent, AccountInfo, project},
    session::{CHECK_PASSKEY, ClientMeta, FAILURES_PER_ADDRESS, NewSession, SessionInfo},
};

const CHALLENGE_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Who the passkeys are for: the instance.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// The RP ID: the instance's `passkey_rp_id` – its first domain unless set otherwise.
    pub id: String,
    /// Where passkeys may be used: the instance's domains, and its own login UI. Origins the RP ID does not cover
    /// need the RP ID's `/.well-known/webauthn` to list them (WebAuthn Level 3, related origins).
    pub origins: Vec<url::Url>,
    pub name: String,
}

/// A WebAuthn challenge for the browser: `options` go to `navigator.credentials.create()` or `.get()`, the answer
/// comes back with `id`.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: String,
    pub options: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

fn webauthn(rp: &RelyingParty) -> Result<Webauthn> {
    let unavailable =
        |error: &dyn std::fmt::Display| IdentityError::Refused(format!("passkeys are not available here: {error}"));
    // The builder wants a first origin under the RP ID; the others are added as they are.
    let covered = |origin: &&url::Url| {
        origin.host_str().is_some_and(|host| host == rp.id || host.ends_with(&format!(".{}", rp.id)))
    };
    let first = rp.origins.iter().find(covered).ok_or_else(|| unavailable(&"no origin under the RP ID"))?;
    let mut builder = WebauthnBuilder::new(&rp.id, first).map_err(|error| unavailable(&error))?;
    for origin in rp.origins.iter().filter(|origin| *origin != first) {
        builder = builder.append_allowed_origin(origin);
    }
    builder.rp_name(&rp.name).build().map_err(|error| unavailable(&error))
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn command_error(error: CommandError<IdentityError>) -> IdentityError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| IdentityError::Refused(error.to_string()))
}

/// Every failure of a ceremony is the same answer.
fn invalid<E>(_: E) -> IdentityError {
    IdentityError::PasskeyRejected
}

impl Identity {
    async fn store_challenge(
        &self,
        instance: Uuid,
        purpose: &str,
        account: Option<Uuid>,
        session: Option<Uuid>,
        state: Value,
        options: Value,
    ) -> Result<Challenge> {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
        let id = format!("wac1.{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        sqlx::query!(
            "INSERT INTO webauthn_challenges (id, instance_id, purpose, account_id, session_id, state, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
            id,
            instance,
            purpose,
            account,
            session,
            state,
            CHALLENGE_LIFETIME.as_secs() as f64,
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?;
        Ok(Challenge { id, options })
    }

    /// Takes a challenge for one use: whatever happens next, it is gone.
    async fn take_challenge(&self, instance: Uuid, id: &str, purpose: &str, session: Option<Uuid>) -> Result<Value> {
        sqlx::query_scalar!(
            "DELETE FROM webauthn_challenges
             WHERE id = $1 AND instance_id = $2 AND purpose = $3 AND session_id IS NOT DISTINCT FROM $4
               AND expires_at > now()
             RETURNING state",
            id,
            instance,
            purpose,
            session,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::PasskeyRejected)
    }

    async fn stored_passkeys(&self, account: Uuid) -> Result<Vec<(Uuid, Passkey)>> {
        let rows = sqlx::query!("SELECT id, credential FROM account_passkeys WHERE account_id = $1", account)
            .fetch_all(self.pool())
            .await
            .map_err(store_error)?;
        rows.into_iter()
            .map(|row| {
                Ok((row.id, serde_json::from_value(row.credential).map_err(|e| IdentityError::Refused(e.to_string()))?))
            })
            .collect()
    }

    /// Keeps the counter and backup state current after a use (a counter going backwards is refused by webauthn-rs
    /// as a sign of a cloned key).
    async fn note_use(
        &self,
        id: Uuid,
        mut passkey: Passkey,
        result: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Result<()> {
        if passkey.update_credential(result) == Some(true) {
            sqlx::query!("UPDATE account_passkeys SET credential = $2 WHERE id = $1", id, json(&passkey)?)
                .execute(self.pool())
                .await
                .map_err(store_error)?;
        }
        sqlx::query!("UPDATE account_passkeys SET last_used_at = now() WHERE id = $1", id)
            .execute(self.pool())
            .await
            .map_err(store_error)?;
        Ok(())
    }

    /// Starts registering a passkey for the session's account.
    pub async fn start_passkey_registration(
        &self,
        rp: &RelyingParty,
        instance: Uuid,
        token: &str,
    ) -> Result<Challenge> {
        let session = self.recent_session(instance, token).await?;
        let account = &session.account;
        let existing: Vec<_> =
            self.stored_passkeys(account.id).await?.into_iter().map(|(_, passkey)| passkey.cred_id().clone()).collect();
        let (options, state) = webauthn(rp)?
            .start_passkey_registration(account.id, &account.address, &account.display_name, Some(existing))
            .map_err(|error| IdentityError::Refused(error.to_string()))?;
        self.store_challenge(
            instance,
            "registration",
            Some(account.id),
            Some(session.id),
            json(&state)?,
            json(&options)?,
        )
        .await
    }

    /// Finishes registering: checks the browser's answer and stores the passkey under `name`; returns its id.
    pub async fn finish_passkey_registration(
        &self,
        rp: &RelyingParty,
        instance: Uuid,
        token: &str,
        challenge: &str,
        name: &str,
        credential: &Value,
    ) -> Result<Uuid> {
        let session = self.recent_session(instance, token).await?;
        let name = crate::valid_name(name)?;
        let state: PasskeyRegistration =
            serde_json::from_value(self.take_challenge(instance, challenge, "registration", Some(session.id)).await?)
                .map_err(invalid)?;
        let credential: RegisterPublicKeyCredential = serde_json::from_value(credential.clone()).map_err(invalid)?;
        let passkey = webauthn(rp)?.finish_passkey_registration(&credential, &state).map_err(invalid)?;
        let (id, account) = (Uuid::now_v7(), session.account.id);
        let (credential_id, stored, stored_name) = (passkey.cred_id().to_vec(), json(&passkey)?, name.clone());
        let store = inline(move |connection, events| {
            let (credential_id, stored, name) = (credential_id.clone(), stored.clone(), stored_name.clone());
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO account_passkeys (id, account_id, name, credential_id, credential)
                     VALUES ($1, $2, $3, $4, $5)",
                    id,
                    account,
                    name,
                    credential_id,
                    stored,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                session.account.tenant,
                &account.to_string(),
                &format!("account:{account}"),
                |_: &Account| Ok(vec![AccountEvent::PasskeyAdded { id, name: name.clone() }]),
                store,
            )
            .await
            .map_err(|error| match error {
                CommandError::Store(kernoid_events::Error::Database(sqlx::Error::Database(database)))
                    if database.is_unique_violation() =>
                {
                    IdentityError::Exists("the passkey")
                }
                other => command_error(other),
            })?;
        Ok(id)
    }

    /// The passkeys of the session's account.
    pub async fn passkeys(&self, instance: Uuid, token: &str) -> Result<Vec<PasskeyInfo>> {
        let session = self.session(instance, token).await?;
        let rows = sqlx::query!(
            "SELECT id, name, created_at, last_used_at FROM account_passkeys WHERE account_id = $1 ORDER BY created_at",
            session.account.id,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| PasskeyInfo {
                id: row.id,
                name: row.name,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    /// Removes one of the session's account's passkeys.
    pub async fn remove_passkey(&self, instance: Uuid, token: &str, passkey: Uuid) -> Result<()> {
        let session = self.recent_session(instance, token).await?;
        self.events
            .execute_with(
                instance,
                session.account.tenant,
                &session.account.id.to_string(),
                &format!("account:{}", session.account.id),
                |state: &Account| {
                    if !state.passkeys.contains(&passkey) {
                        return Err(IdentityError::NotFound("the passkey"));
                    }
                    Ok(vec![AccountEvent::PasskeyRemoved { id: passkey }])
                },
                |c, e| Box::pin(project(c, e)),
            )
            .await
            .map(drop)
            .map_err(command_error)
    }

    /// Starts a passkey check of an existing session.
    pub async fn start_passkey_check(&self, rp: &RelyingParty, instance: Uuid, token: &str) -> Result<Challenge> {
        let session = self.session(instance, token).await?;
        let passkeys: Vec<Passkey> =
            self.stored_passkeys(session.account.id).await?.into_iter().map(|(_, passkey)| passkey).collect();
        if passkeys.is_empty() {
            return Err(IdentityError::Refused("the account has no passkey".into()));
        }
        let (options, state) = webauthn(rp)?
            .start_passkey_authentication(&passkeys)
            .map_err(|error| IdentityError::Refused(error.to_string()))?;
        self.store_challenge(
            instance,
            "authentication",
            Some(session.account.id),
            Some(session.id),
            json(&state)?,
            json(&options)?,
        )
        .await
    }

    /// Finishes a passkey check: the session has passed `passkey`.
    pub async fn finish_passkey_check(
        &self,
        rp: &RelyingParty,
        instance: Uuid,
        token: &str,
        challenge: &str,
        credential: &Value,
    ) -> Result<SessionInfo> {
        let session = self.session(instance, token).await?;
        let state: PasskeyAuthentication =
            serde_json::from_value(self.take_challenge(instance, challenge, "authentication", Some(session.id)).await?)
                .map_err(invalid)?;
        let credential: PublicKeyCredential = serde_json::from_value(credential.clone()).map_err(invalid)?;
        let result = webauthn(rp)?.finish_passkey_authentication(&credential, &state).map_err(invalid)?;
        if !result.user_verified() {
            return Err(IdentityError::PasskeyRejected);
        }
        let used = self
            .stored_passkeys(session.account.id)
            .await?
            .into_iter()
            .find(|(_, passkey)| passkey.cred_id() == result.cred_id())
            .ok_or(IdentityError::PasskeyRejected)?;
        self.note_use(used.0, used.1, &result).await?;
        self.add_session_check(instance, &session, CHECK_PASSKEY).await?;
        self.session(instance, token).await
    }

    /// Starts a login with a discoverable passkey: no address, no session yet.
    pub async fn start_passkey_login(
        &self,
        rp: &RelyingParty,
        instance: Uuid,
        client: &ClientMeta,
    ) -> Result<Challenge> {
        if let Some(address) = client.address {
            self.refuse_if_throttled(instance, &format!("address:{address}"), FAILURES_PER_ADDRESS).await?;
        }
        let (options, state) = webauthn(rp)?
            .start_discoverable_authentication()
            .map_err(|error| IdentityError::Refused(error.to_string()))?;
        self.store_challenge(instance, "login", None, None, json(&state)?, json(&options)?).await
    }

    /// Finishes a passkey login and creates a session with the check `passkey`.
    pub async fn finish_passkey_login(
        &self,
        rp: &RelyingParty,
        instance: Uuid,
        challenge: &str,
        credential: &Value,
        lifetime: Option<Duration>,
        client: &ClientMeta,
    ) -> Result<NewSession> {
        let attempt = self.passkey_login(rp, instance, challenge, credential).await;
        let (id, passkey, result, account) = match attempt {
            Ok(found) => found,
            Err(error) => {
                if let Some(address) = client.address {
                    self.count_failure(instance, &format!("address:{address}")).await?;
                }
                return Err(error);
            }
        };
        self.note_use(id, passkey, &result).await?;
        if !account.active {
            return Err(IdentityError::AccountDeactivated);
        }
        let lifetime = lifetime.unwrap_or(crate::session::DEFAULT_LIFETIME);
        if lifetime.is_zero() || lifetime > crate::session::MAX_LIFETIME {
            return Err(IdentityError::Refused("a session lives at most 30 days".into()));
        }
        self.open_session(instance, account, vec![CHECK_PASSKEY.to_owned()], lifetime, client).await
    }

    async fn passkey_login(
        &self,
        rp: &RelyingParty,
        instance: Uuid,
        challenge: &str,
        credential: &Value,
    ) -> Result<(Uuid, Passkey, webauthn_rs::prelude::AuthenticationResult, AccountInfo)> {
        let state: DiscoverableAuthentication =
            serde_json::from_value(self.take_challenge(instance, challenge, "login", None).await?).map_err(invalid)?;
        let credential: PublicKeyCredential = serde_json::from_value(credential.clone()).map_err(invalid)?;
        let webauthn = webauthn(rp)?;
        let (user, credential_id) = webauthn.identify_discoverable_authentication(&credential).map_err(invalid)?;
        let row = sqlx::query!(
            r#"SELECT p.id, p.credential, t.instance_id, a.tenant_id, a.display_name, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!", a.primary_address IS NOT NULL AS "native!",
                      (a.active AND t.active) AS "active!"
               FROM account_passkeys p JOIN accounts a ON a.id = p.account_id JOIN tenants t ON t.id = a.tenant_id
               WHERE p.credential_id = $1 AND p.account_id = $2"#,
            credential_id,
            user,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .filter(|row| row.instance_id == instance)
        .ok_or(IdentityError::PasskeyRejected)?;
        let passkey: Passkey = serde_json::from_value(row.credential).map_err(invalid)?;
        let result = webauthn
            .finish_discoverable_authentication(&credential, state, &[DiscoverableKey::from(&passkey)])
            .map_err(invalid)?;
        if !result.user_verified() {
            return Err(IdentityError::PasskeyRejected);
        }
        let account = AccountInfo {
            instance,
            tenant: row.tenant_id,
            id: user,
            display_name: row.display_name,
            address: row.primary_address,
            native: row.native,
            active: row.active,
            shared: false,
            drive: false,
        };
        Ok((row.id, passkey, result, account))
    }

    /// Removes every TOTP secret, passkey, recovery code and app password of an account – for operators, when someone
    /// has lost their devices.
    pub async fn reset_second_factors(&self, account: Uuid, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.remove_totp_of(instance, tenant, account, creator).await?;
        self.remove_recovery_codes_of(instance, tenant, account, creator).await?;
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                // The devices are lost: their app passwords go with the passkeys.
                |state: &Account| {
                    Ok(state
                        .passkeys
                        .iter()
                        .map(|id| AccountEvent::PasskeyRemoved { id: *id })
                        .chain(state.app_passwords.iter().map(|id| AccountEvent::AppPasswordRemoved { id: *id }))
                        .collect::<Vec<_>>())
                },
                |c, e| Box::pin(project(c, e)),
            )
            .await
            .map(drop)
            .map_err(command_error)
    }
}
