// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sessions: what a login produces (RFC 0001, section 7).
//!
//! - A session is created **only after a successful check** – for now the password – so that requests without
//!   credentials never write events. Its events (`session.created`, `session.terminated`) are owned by the account's
//!   tenant: a tenant's audit log shows its logins.
//! - The **token** (`ks1.<session id>.<secret>`) is shown once. Only its SHA-256 is kept, in `sessions`, never in an
//!   event; the secret has 256 bits, so a plain hash is enough.
//! - Every session **expires** (default 8 hours, at most 30 days). A session also stops working when its account or
//!   tenant is deactivated.
//! - **Failed attempts** are counted per login name (as typed – whether it exists or not, so the count tells nothing)
//!   and per client address, in windows of 15 minutes; above the limit, attempts are refused before the password is
//!   checked. The counts are kept in a table, not as events.

use std::{net::IpAddr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use kernoid_events::{
    InlineFuture,
    aggregate::{Aggregate, DomainEvent},
    inline,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Identity, IdentityError, Result, account::AccountInfo};

pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
pub const MAX_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Failed attempts counted in one window.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failed attempts per login name in a window before further attempts are refused.
pub const FAILURES_PER_NAME: i32 = 5;
/// Failed attempts per client address in a window before further attempts are refused.
pub const FAILURES_PER_ADDRESS: i32 = 50;
const TOKEN_PREFIX: &str = "ks1";
/// Device tokens: `kdt1.` and 256 random bits.
const DEVICE_PREFIX: &str = "kdt1.";
/// A known device stays known this long after its last login.
pub const DEVICE_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Longest user agent kept with a session.
const USER_AGENT_CHARS: usize = 256;

pub const CHECK_PASSWORD: &str = "password";
pub const CHECK_TOTP: &str = "totp";
pub const CHECK_PASSKEY: &str = "passkey";
pub const CHECK_RECOVERY: &str = "recovery";
/// A login at an external identity provider.
pub const CHECK_IDP: &str = "idp";
/// The external identity provider said its login had more than one factor (`amr` contains `mfa`).
pub const CHECK_IDP_MFA: &str = "idp_mfa";

/// Whether checks prove more than one factor: two different checks, or a passkey (possession, and user verification
/// by PIN or biometrics).
pub fn is_multi_factor(checks: &[String]) -> bool {
    checks.len() > 1 || checks.iter().any(|check| check == CHECK_PASSKEY)
}
/// How fresh a session must be to change how its account logs in (add or remove TOTP and passkeys).
pub const RECENT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SessionEvent {
    #[serde(rename = "session.created")]
    Created { account: Uuid, checks: Vec<String>, expires_at: DateTime<Utc> },
    /// Logged out, or ended by an administrator.
    #[serde(rename = "session.terminated")]
    Terminated,
    /// A further check passed, e.g. `totp` or `passkey`.
    #[serde(rename = "session.checked")]
    Checked { check: String },
}

impl DomainEvent for SessionEvent {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Session {
    pub exists: bool,
    pub account: Uuid,
    pub terminated: bool,
}

impl Aggregate for Session {
    const TYPE: &'static str = "session";
    type Event = SessionEvent;

    fn apply(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Created { account, .. } => *self = Self { exists: true, account, terminated: false },
            SessionEvent::Terminated => self.terminated = true,
            SessionEvent::Checked { .. } => {}
        }
    }
}

/// Where a login comes from; kept with the session.
#[derive(Debug, Clone, Default)]
pub struct ClientMeta {
    pub address: Option<IpAddr>,
    pub user_agent: Option<String>,
}

/// A session just created, with the token – shown this once.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub account: AccountInfo,
    /// After a password login: the token that makes this device known for the login name (see
    /// [`Identity::create_session_on_device`]).
    pub device_token: Option<String>,
}

/// A valid session, found by its token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: Uuid,
    pub account: AccountInfo,
    pub checks: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A session as its account and administrators see it – never with its token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: Uuid,
    pub account: Uuid,
    pub checks: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_address: Option<String>,
    pub user_agent: Option<String>,
}

/// What [`Identity::clean_up`] removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cleaned {
    pub sessions: u64,
    pub failure_counts: u64,
    pub devices: u64,
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// The session id in a token of the right form.
fn token_session(token: &str) -> Option<Uuid> {
    let mut parts = token.split('.');
    let (Some(TOKEN_PREFIX), Some(id), Some(secret), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    (secret.len() == 43).then_some(())?;
    Uuid::parse_str(id).ok()
}

fn new_token(id: Uuid) -> Result<String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
    Ok(format!("{TOKEN_PREFIX}.{id}.{}", URL_SAFE_NO_PAD.encode(secret)))
}

/// Equal in time whatever the contents.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

/// The counting key of a login name: as typed, trimmed and lower case, cut to a sane length.
pub(crate) fn name_key(login: &str) -> String {
    let name: String = login.trim().to_lowercase().chars().take(320).collect();
    format!("name:{name}")
}

pub(crate) fn address_key(address: IpAddr) -> String {
    format!("address:{address}")
}

/// The counting key of a known device: failures with its token count against the device, not the login name.
fn device_key(hash: &[u8; 32]) -> String {
    let hex: String = hash[..16].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("device:{hex}")
}

fn new_device_token() -> Result<String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
    Ok(format!("{DEVICE_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret)))
}

impl Identity {
    /// Checks `login` and `password` at `instance` and creates a session; `lifetime` defaults to 8 hours and is
    /// capped at 30 days.
    pub async fn create_session(
        &self,
        instance: Uuid,
        login: &str,
        password: &str,
        lifetime: Option<Duration>,
        client: &ClientMeta,
    ) -> Result<NewSession> {
        self.create_session_on_device(instance, login, password, lifetime, client, None).await
    }

    /// Like [`Identity::create_session`], from a device that may be known. Failed logins are limited per login name –
    /// which would let anyone hold off an account's logins by failing on purpose. A device that logged in with this
    /// login name before shows its device token instead: its failures count against the device, not the name, so its
    /// person still gets in while the name is throttled (OWASP, Blocking Brute Force Attacks: device cookies). A
    /// successful login answers with the device's token – a new one for a device not known yet.
    pub async fn create_session_on_device(
        &self,
        instance: Uuid,
        login: &str,
        password: &str,
        lifetime: Option<Duration>,
        client: &ClientMeta,
        device_token: Option<&str>,
    ) -> Result<NewSession> {
        let lifetime = lifetime.unwrap_or(DEFAULT_LIFETIME);
        if lifetime.is_zero() || lifetime > MAX_LIFETIME {
            return Err(IdentityError::Refused(format!(
                "a session lives at most {} days",
                MAX_LIFETIME.as_secs() / 86_400
            )));
        }
        let name = name_key(login);
        let known = match device_token {
            Some(token) => self.known_device(instance, token, &name).await?,
            None => None,
        };
        let first = match &known {
            Some(hash) => device_key(hash),
            None => name.clone(),
        };
        let mut keys = vec![(first, FAILURES_PER_NAME)];
        if let Some(address) = client.address {
            keys.push((address_key(address), FAILURES_PER_ADDRESS));
        }
        for (key, limit) in &keys {
            self.refuse_if_throttled(instance, key, *limit).await?;
        }

        let account = match self.authenticate(instance, login, password).await {
            Ok(account) => account,
            Err(IdentityError::InvalidCredentials) => {
                for (key, _) in &keys {
                    self.count_failure(instance, key).await?;
                }
                return Err(IdentityError::InvalidCredentials);
            }
            Err(error) => return Err(error),
        };
        sqlx::query!("DELETE FROM login_failures WHERE instance_id = $1 AND key = $2", instance, keys[0].0)
            .execute(self.pool())
            .await
            .map_err(store_error)?;

        let device_token = match (known, device_token) {
            (Some(hash), Some(token)) => {
                sqlx::query!(
                    "UPDATE known_devices SET last_used_at = now(), expires_at = now() + make_interval(secs => $2)
                     WHERE token_hash = $1",
                    &hash[..],
                    DEVICE_LIFETIME.as_secs() as f64,
                )
                .execute(self.pool())
                .await
                .map_err(store_error)?;
                token.to_owned()
            }
            _ => {
                let token = new_device_token()?;
                sqlx::query!(
                    "INSERT INTO known_devices (token_hash, instance_id, account_id, name_key, expires_at)
                     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
                    &hash_token(&token)[..],
                    instance,
                    account.id,
                    name,
                    DEVICE_LIFETIME.as_secs() as f64,
                )
                .execute(self.pool())
                .await
                .map_err(store_error)?;
                token
            }
        };
        let mut session =
            self.open_session(instance, account, vec![CHECK_PASSWORD.to_owned()], lifetime, client).await?;
        session.device_token = Some(device_token);
        Ok(session)
    }

    /// The hash of a device token, if it is a known device of this login name at `instance`.
    async fn known_device(&self, instance: Uuid, token: &str, name: &str) -> Result<Option<[u8; 32]>> {
        if !token.starts_with(DEVICE_PREFIX) || token.len() > 64 {
            return Ok(None);
        }
        let hash = hash_token(token);
        let known = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM known_devices
                   WHERE token_hash = $1 AND instance_id = $2 AND name_key = $3 AND expires_at > now()) AS "known!""#,
            &hash[..],
            instance,
            name,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        Ok(known.then_some(hash))
    }

    /// Creates a session for an account whose first check (`checks`) has just passed.
    pub(crate) async fn open_session(
        &self,
        instance: Uuid,
        account: AccountInfo,
        checks: Vec<String>,
        lifetime: Duration,
        client: &ClientMeta,
    ) -> Result<NewSession> {
        let id = Uuid::now_v7();
        let token = new_token(id)?;
        let token_hash = hash_token(&token);
        let expires_at = Utc::now() + chrono::Duration::from_std(lifetime).expect("at most 30 days");
        let user_agent =
            client.user_agent.as_deref().map(|agent| agent.chars().take(USER_AGENT_CHARS).collect::<String>());
        let client_address = client.address.map(|address| address.to_string());
        let (tenant, account_id) = (account.tenant, account.id);
        let stored_checks = checks.clone();
        let store_session = inline(move |connection, _| {
            let (checks, client_address, user_agent) =
                (stored_checks.clone(), client_address.clone(), user_agent.clone());
            Box::pin(async move {
                sqlx::query!(
                "INSERT INTO sessions
                     (id, instance_id, tenant_id, account_id, token_hash, checks, expires_at, client_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::inet, $9)",
                id,
                instance,
                tenant,
                account_id,
                &token_hash[..],
                &checks,
                expires_at,
                client_address,
                user_agent,
            )
            .execute(&mut *connection)
            .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                tenant,
                &id.to_string(),
                &format!("account:{account_id}"),
                |session: &Session| {
                    if session.exists {
                        return Err(IdentityError::Exists("the session"));
                    }
                    Ok(vec![SessionEvent::Created { account: account_id, checks: checks.clone(), expires_at }])
                },
                store_session,
            )
            .await
            .map_err(|error| match error {
                kernoid_events::aggregate::CommandError::Refused(error) => error,
                kernoid_events::aggregate::CommandError::Store(error) => IdentityError::Store(error),
            })?;
        Ok(NewSession { id, token, expires_at, account, device_token: None })
    }

    /// The session a token belongs to, if it is valid at `instance`: not expired, not ended, its account and tenant
    /// active. Every other case is the same `InvalidSession`.
    pub async fn session(&self, instance: Uuid, token: &str) -> Result<SessionInfo> {
        let id = token_session(token).ok_or(IdentityError::InvalidSession)?;
        let row = sqlx::query!(
            r#"SELECT s.id, s.token_hash, s.checks, s.created_at, s.expires_at, s.instance_id, s.tenant_id,
                      a.id AS account_id, a.display_name, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!", a.primary_address IS NOT NULL AS "native!", a.active AS account_active,
                      t.active AS tenant_active
               FROM sessions s
               JOIN accounts a ON a.id = s.account_id
               JOIN tenants t ON t.id = s.tenant_id
               WHERE s.id = $1 AND s.instance_id = $2 AND s.terminated_at IS NULL AND s.expires_at > now()"#,
            id,
            instance,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::InvalidSession)?;
        if !constant_time_eq(&row.token_hash, &hash_token(token)) || !row.account_active || !row.tenant_active {
            return Err(IdentityError::InvalidSession);
        }
        Ok(SessionInfo {
            id: row.id,
            account: AccountInfo {
                instance: row.instance_id,
                tenant: row.tenant_id,
                id: row.account_id,
                display_name: row.display_name,
                address: row.primary_address,
                native: row.native,
                active: row.account_active,
                shared: false,
                drive: false,
            },
            checks: row.checks,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }

    /// Ends the session of a valid token (logout).
    pub async fn terminate_session(&self, instance: Uuid, token: &str) -> Result<()> {
        let session = self.session(instance, token).await?;
        self.end_session(instance, session.id, session.account.tenant, &format!("account:{}", session.account.id)).await
    }

    /// Ends a session by its id – for a logout the application asks for (OpenID Connect RP-Initiated Logout), where
    /// the session is known from an ID token, not from its token. Ending a session that has ended or expired changes
    /// nothing. `creator` names who asked, e.g. `application:<id>`.
    pub async fn terminate_session_by_id(&self, instance: Uuid, id: Uuid, creator: &str) -> Result<()> {
        let tenant = sqlx::query_scalar!(
            "SELECT tenant_id FROM sessions WHERE id = $1 AND instance_id = $2 AND terminated_at IS NULL",
            id,
            instance,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        match tenant {
            Some(tenant) => self.end_session(instance, id, tenant, creator).await,
            None => Ok(()),
        }
    }

    async fn end_session(&self, instance: Uuid, id: Uuid, tenant: Uuid, creator: &str) -> Result<()> {
        let end = inline(move |connection, _| {
            Box::pin(async move {
                sqlx::query!("UPDATE sessions SET terminated_at = now() WHERE id = $1", id)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                tenant,
                &id.to_string(),
                creator,
                |state: &Session| {
                    Ok::<_, IdentityError>(if state.terminated { Vec::new() } else { vec![SessionEvent::Terminated] })
                },
                end,
            )
            .await
            .map(drop)
            .map_err(|error| match error {
                kernoid_events::aggregate::CommandError::Refused(error) => error,
                kernoid_events::aggregate::CommandError::Store(error) => IdentityError::Store(error),
            })
    }

    /// The sessions of an account that are still valid, newest first.
    pub async fn account_sessions(&self, account: Uuid) -> Result<Vec<SessionSummary>> {
        let rows = sqlx::query!(
            r#"SELECT id, account_id, checks, created_at, expires_at, host(client_address) AS "client_address?",
                      user_agent
               FROM sessions
               WHERE account_id = $1 AND terminated_at IS NULL AND expires_at > now()
               ORDER BY created_at DESC"#,
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| SessionSummary {
                id: row.id,
                account: row.account_id,
                checks: row.checks,
                created_at: row.created_at,
                expires_at: row.expires_at,
                client_address: row.client_address,
                user_agent: row.user_agent,
            })
            .collect())
    }

    /// Ends one session of an account; a session of another account is unknown.
    pub async fn terminate_account_session(&self, account: Uuid, session: Uuid, creator: &str) -> Result<()> {
        let row = sqlx::query!(
            "SELECT instance_id, tenant_id FROM sessions WHERE id = $1 AND account_id = $2 AND terminated_at IS NULL",
            session,
            account,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the session"))?;
        self.end_session(row.instance_id, session, row.tenant_id, creator).await
    }

    /// Ends every session of an account – after its password was reset, or when it is deactivated.
    pub async fn terminate_account_sessions(&self, account: Uuid, creator: &str) -> Result<usize> {
        let sessions = self.account_sessions(account).await?;
        for session in &sessions {
            self.terminate_account_session(account, session.id, creator).await?;
        }
        Ok(sessions.len())
    }

    /// The sessions of the token's own account.
    pub async fn own_sessions(&self, instance: Uuid, token: &str) -> Result<Vec<SessionSummary>> {
        let session = self.session(instance, token).await?;
        self.account_sessions(session.account.id).await
    }

    /// Ends another session of the token's own account (or this one).
    pub async fn terminate_own_session(&self, instance: Uuid, token: &str, id: Uuid) -> Result<()> {
        let session = self.session(instance, token).await?;
        let creator = format!("account:{}", session.account.id);
        self.terminate_account_session(session.account.id, id, &creator).await
    }

    /// Changes the display name of the token's own account.
    pub async fn rename_own_account(&self, instance: Uuid, token: &str, display_name: &str) -> Result<()> {
        let session = self.session(instance, token).await?;
        self.rename_account(session.account.id, display_name, &format!("account:{}", session.account.id)).await
    }

    /// Changes the password of the token's own account: needs a recent session and the current password, which is
    /// checked – and limited – like a login. Every other session of the account ends.
    pub async fn change_own_password(&self, instance: Uuid, token: &str, current: &str, new: &str) -> Result<()> {
        let session = self.recent_session(instance, token).await?;
        let key = name_key(&session.account.address);
        self.refuse_if_throttled(instance, &key, FAILURES_PER_NAME).await?;
        match self.authenticate(instance, &session.account.address, current).await {
            Ok(_) => {}
            Err(IdentityError::InvalidCredentials) => {
                self.count_failure(instance, &key).await?;
                return Err(IdentityError::InvalidCredentials);
            }
            Err(error) => return Err(error),
        }
        let creator = format!("account:{}", session.account.id);
        self.set_password(session.account.id, new, &creator).await?;
        for other in self.account_sessions(session.account.id).await? {
            if other.id != session.id {
                self.terminate_account_session(session.account.id, other.id, &creator).await?;
            }
        }
        Ok(())
    }

    /// Records that `session` passed a further check; checking the same twice changes nothing.
    pub(crate) async fn add_session_check(&self, instance: Uuid, session: &SessionInfo, check: &str) -> Result<()> {
        if session.checks.iter().any(|known| known == check) {
            return Ok(());
        }
        let (id, owned_check) = (session.id, check.to_owned());
        let store = inline(move |connection, _| {
            let check = owned_check.clone();
            Box::pin(async move {
                sqlx::query!(
                    "UPDATE sessions SET checks = array_append(checks, $2) WHERE id = $1 AND NOT ($2 = ANY(checks))",
                    id,
                    check,
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
                &id.to_string(),
                &format!("account:{}", session.account.id),
                |_: &Session| Ok::<_, IdentityError>(vec![SessionEvent::Checked { check: check.to_owned() }]),
                store,
            )
            .await
            .map(drop)
            .map_err(|error| match error {
                kernoid_events::aggregate::CommandError::Refused(error) => error,
                kernoid_events::aggregate::CommandError::Store(error) => IdentityError::Store(error),
            })
    }

    /// The session of `token`, if it is recent enough to change how its account logs in.
    /// The token's session, if it began a short while ago – for changes to how one logs in.
    pub async fn recent_session(&self, instance: Uuid, token: &str) -> Result<SessionInfo> {
        let session = self.session(instance, token).await?;
        let recent = chrono::Duration::from_std(RECENT).expect("small");
        if Utc::now() - session.created_at > recent {
            return Err(IdentityError::RecentLoginRequired);
        }
        Ok(session)
    }

    pub(crate) async fn refuse_if_throttled(&self, instance: Uuid, key: &str, limit: i32) -> Result<()> {
        let window = FAILURE_WINDOW.as_secs() as f64;
        let row = sqlx::query!(
            r#"SELECT failures, extract(epoch FROM window_start + make_interval(secs => $3) - now())::float8 AS "left!"
               FROM login_failures
               WHERE instance_id = $1 AND key = $2 AND window_start > now() - make_interval(secs => $3)"#,
            instance,
            key,
            window,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        match row {
            Some(row) if row.failures >= limit => Err(IdentityError::TooManyAttempts {
                retry_after: Duration::from_secs(row.left.ceil().max(1.0) as u64),
            }),
            _ => Ok(()),
        }
    }

    pub(crate) async fn count_failure(&self, instance: Uuid, key: &str) -> Result<()> {
        let window = FAILURE_WINDOW.as_secs() as f64;
        sqlx::query!(
            "INSERT INTO login_failures (instance_id, key, failures, window_start) VALUES ($1, $2, 1, now())
             ON CONFLICT (instance_id, key) DO UPDATE SET
                 failures = CASE WHEN login_failures.window_start <= now() - make_interval(secs => $3)
                                 THEN 1 ELSE login_failures.failures + 1 END,
                 window_start = CASE WHEN login_failures.window_start <= now() - make_interval(secs => $3)
                                     THEN now() ELSE login_failures.window_start END",
            instance,
            key,
            window,
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?;
        Ok(())
    }

    /// Removes sessions that ended or expired more than a day ago and failure counts of past windows. Run
    /// regularly by the worker role.
    pub async fn clean_up(&self) -> Result<Cleaned> {
        let sessions = sqlx::query!(
            "DELETE FROM sessions
             WHERE expires_at < now() - interval '1 day' OR terminated_at < now() - interval '1 day'"
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?
        .rows_affected();
        let window = FAILURE_WINDOW.as_secs() as f64;
        let failure_counts =
            sqlx::query!("DELETE FROM login_failures WHERE window_start <= now() - make_interval(secs => $1)", window,)
                .execute(self.pool())
                .await
                .map_err(store_error)?
                .rows_affected();
        sqlx::query!("DELETE FROM webauthn_challenges WHERE expires_at < now()")
            .execute(self.pool())
            .await
            .map_err(store_error)?;
        let devices = sqlx::query!("DELETE FROM known_devices WHERE expires_at < now()")
            .execute(self.pool())
            .await
            .map_err(store_error)?
            .rows_affected();
        Ok(Cleaned { sessions, failure_counts, devices })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let id = Uuid::now_v7();
        let token = new_token(id).unwrap();
        assert!(token.starts_with(&format!("ks1.{id}.")));
        assert_eq!(token_session(&token), Some(id));
        assert_ne!(new_token(id).unwrap(), token);
        for bad in [
            "",
            "ks1",
            &format!("ks1.{id}"),
            &format!("ks2.{id}.{}", "a".repeat(43)),
            &format!("{token}.x"),
            &format!("ks1.not-a-uuid.{}", "a".repeat(43)),
            &format!("ks1.{id}.short"),
        ] {
            assert_eq!(token_session(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn comparison() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"sane"));
        assert!(!constant_time_eq(b"same", b"same!"));
    }

    #[test]
    fn keys() {
        assert_eq!(name_key("  Alice@Firma.DE "), "name:alice@firma.de");
        assert_eq!(name_key(&"x".repeat(1000)).len(), 5 + 320);
        assert_eq!(address_key("2001:db8::1".parse().unwrap()), "address:2001:db8::1");
    }
}
