// SPDX-License-Identifier: AGPL-3.0-or-later
//! The program's own sessions after a login: who is behind a session id (the cookie of its web app), until when, and
//! which login at the provider it came from – so that the provider's back-channel logout ends it. Kept behind a
//! trait, so that a program keeps them in its own database; [`MemorySessions`] keeps them in the process.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::relying::{Login, Principal};

/// How long a session of the program lasts by default.
pub const SESSION_LIFETIME: SignedDuration = SignedDuration::from_hours(8);

/// A session of the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub principal: Principal,
    /// For logging out at the provider (`id_token_hint`).
    pub id_token: String,
    pub expires_at: Timestamp,
}

impl Session {
    pub fn new(login: Login, lifetime: SignedDuration) -> Self {
        Self { principal: login.principal, id_token: login.id_token, expires_at: Timestamp::now() + lifetime }
    }

    pub fn expired(&self) -> bool {
        self.expires_at <= Timestamp::now()
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where a program keeps its sessions. Ids are random and secret; implementations should keep only their hash.
pub trait Sessions: Send + Sync + std::fmt::Debug + 'static {
    fn put<'a>(&'a self, id: &'a str, session: Session) -> BoxFuture<'a, ()>;
    /// The session, unless it has expired.
    fn get<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>>;
    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()>;
    /// Ends the sessions a back-channel logout names: those of the provider's login `session`, or all of `subject`.
    fn remove_logins<'a>(&'a self, subject: Option<&'a str>, session: Option<&'a str>) -> BoxFuture<'a, usize>;
}

/// Sessions in the process: lost on restart, not shared between processes – for one process, and for tests.
#[derive(Debug, Clone, Default)]
pub struct MemorySessions {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl MemorySessions {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Sessions for MemorySessions {
    fn put<'a>(&'a self, id: &'a str, session: Session) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut sessions = self.sessions.lock().await;
            sessions.retain(|_, session| !session.expired());
            sessions.insert(id.to_owned(), session);
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>> {
        Box::pin(async move { self.sessions.lock().await.get(id).filter(|session| !session.expired()).cloned() })
    }

    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.sessions.lock().await.remove(id);
        })
    }

    fn remove_logins<'a>(&'a self, subject: Option<&'a str>, session: Option<&'a str>) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let mut sessions = self.sessions.lock().await;
            let before = sessions.len();
            sessions.retain(|_, kept| {
                let principal = &kept.principal;
                let named = match (subject, session) {
                    (_, Some(sid)) => principal.session.as_deref() == Some(sid),
                    (Some(sub), None) => principal.subject == sub,
                    (None, None) => false,
                };
                !named
            });
            before - sessions.len()
        })
    }
}

/// Sessions in PostgreSQL – in the program's database, in a table of their own (`kernoid_auth_sessions`, with a history
/// of migrations apart from the program's: `_kernoid_auth_migrations`). Only the hash of a session's id is stored.
#[cfg(feature = "postgres")]
#[derive(Debug, Clone)]
pub struct PgSessions {
    pool: sqlx::PgPool,
}

/// The migrations of [`PgSessions`].
#[cfg(feature = "postgres")]
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[cfg(feature = "postgres")]
impl PgSessions {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Brings the table up to date – once at start, by a role that may create tables.
    pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(pool).await
    }

    /// Removes expired sessions; how many.
    pub async fn clean_up(&self) -> Result<u64, sqlx::Error> {
        let done =
            sqlx::query!("DELETE FROM kernoid_auth_sessions WHERE expires_at <= now()").execute(&self.pool).await?;
        Ok(done.rows_affected())
    }
}

#[cfg(feature = "postgres")]
fn id_hash(id: &str) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(id.as_bytes()).to_vec()
}

#[cfg(feature = "postgres")]
fn logged(result: Result<impl Sized, sqlx::Error>, what: &str) {
    if let Err(error) = result {
        tracing::error!(%error, "kernoid-auth sessions: {what}");
    }
}

#[cfg(feature = "postgres")]
impl Sessions for PgSessions {
    fn put<'a>(&'a self, id: &'a str, session: Session) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            use jiff_sqlx::ToSqlx;
            let principal = serde_json::to_value(&session.principal).unwrap_or_default();
            let result = sqlx::query!(
                "INSERT INTO kernoid_auth_sessions (id_hash, principal, id_token, subject, provider_session, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (id_hash) DO UPDATE SET principal = EXCLUDED.principal, id_token = EXCLUDED.id_token,
                   subject = EXCLUDED.subject, provider_session = EXCLUDED.provider_session, expires_at = EXCLUDED.expires_at",
                id_hash(id),
                principal,
                session.id_token,
                session.principal.subject,
                session.principal.session,
                session.expires_at.to_sqlx(),
            )
            .execute(&self.pool)
            .await;
            logged(result, "storing a session");
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>> {
        Box::pin(async move {
            let row = sqlx::query!(
                "SELECT principal, id_token, expires_at FROM kernoid_auth_sessions WHERE id_hash = $1 AND expires_at > now()",
                id_hash(id),
            )
            .fetch_optional(&self.pool)
            .await;
            let row = match row {
                Ok(row) => row?,
                Err(error) => {
                    tracing::error!(%error, "kernoid-auth sessions: reading a session");
                    return None;
                }
            };
            Some(Session {
                principal: serde_json::from_value(row.principal).ok()?,
                id_token: row.id_token,
                expires_at: row.expires_at.to_jiff(),
            })
        })
    }

    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let result = sqlx::query!("DELETE FROM kernoid_auth_sessions WHERE id_hash = $1", id_hash(id))
                .execute(&self.pool)
                .await;
            logged(result, "removing a session");
        })
    }

    fn remove_logins<'a>(&'a self, subject: Option<&'a str>, session: Option<&'a str>) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let result = match (subject, session) {
                (_, Some(sid)) => {
                    sqlx::query!("DELETE FROM kernoid_auth_sessions WHERE provider_session = $1", sid)
                        .execute(&self.pool)
                        .await
                }
                (Some(sub), None) => {
                    sqlx::query!("DELETE FROM kernoid_auth_sessions WHERE subject = $1", sub).execute(&self.pool).await
                }
                (None, None) => return 0,
            };
            match result {
                Ok(done) => done.rows_affected() as usize,
                Err(error) => {
                    tracing::error!(%error, "kernoid-auth sessions: back-channel logout");
                    0
                }
            }
        })
    }
}
