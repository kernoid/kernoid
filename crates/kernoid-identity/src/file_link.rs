// SPDX-License-Identifier: AGPL-3.0-or-later
//! Links to files for people without an account (RFC 0005, 11.3): one file, or one directory with all below it, to
//! read – or a directory to add files to, or both –, with an expiry and a password if wanted. Adding and removing a link are events on the owning account; the
//! token (SHA-256) and the password (Argon2id) are written to `file_links` in the transaction of the event. Who may
//! link what is the caller's to decide (JMAP checks `mayShare`). Opening a link causes no events: wrong passwords are
//! counted in `file_link_failures`, a link opened with its password gets an access token for a while.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use kernoid_events::{InlineFuture, inline};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Identity, IdentityError, Result, account::AccountEvent};

/// How long a link opened with its password stays open.
pub const ACCESS_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Wrong passwords a link takes in a window before it refuses for the rest of it.
const MAX_FAILURES: i32 = 10;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);

/// What a link lets people do – at least one of them. Adding is for directories only: it puts new files in, never
/// replaces one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRights {
    pub read: bool,
    pub add: bool,
}

impl Default for LinkRights {
    fn default() -> Self {
        Self { read: true, add: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLinkInfo {
    pub id: Uuid,
    pub owner: Uuid,
    pub node: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub password: bool,
    pub rights: LinkRights,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// What came in through one link since its last notice, for whoever is told: the link's maker, or the store's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkArrivals {
    pub link: Uuid,
    pub owner: Uuid,
    /// The account that made the link (`account:<id>`); none if an operator did.
    pub maker: Option<Uuid>,
    /// The name of the directory the link names.
    pub folder: String,
    /// Names and sizes, in the order they came.
    pub files: Vec<(String, u64)>,
}

/// A link that is valid now: where it leads, and whether it needs its password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenLink {
    pub id: Uuid,
    pub owner: Uuid,
    pub node: Uuid,
    pub needs_password: bool,
    pub rights: LinkRights,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_token() -> Result<String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

impl Identity {
    /// A link to `node` of `owner`'s files; returns its id and its token – shown once.
    pub async fn add_file_link(
        &self,
        owner: Uuid,
        node: Uuid,
        rights: LinkRights,
        expires_at: Option<DateTime<Utc>>,
        password: Option<&str>,
        creator: &str,
    ) -> Result<(Uuid, String)> {
        if expires_at.is_some_and(|expires| expires <= Utc::now()) {
            return Err(IdentityError::Refused("the link would have expired already".into()));
        }
        if !rights.read && !rights.add {
            return Err(IdentityError::Refused("a link lets people read, add or both".into()));
        }
        let node_type =
            sqlx::query_scalar!("SELECT node_type FROM file_nodes WHERE id = $1 AND account_id = $2", node, owner)
                .fetch_optional(self.pool())
                .await
                .map_err(store_error)?
                .ok_or(IdentityError::NotFound("the file"))?;
        if rights.add && node_type != "directory" {
            return Err(IdentityError::Refused("files can be added through a link to a directory only".into()));
        }
        let password_hash = match password {
            Some(password) => {
                let password = zeroize::Zeroizing::new(password.to_owned());
                Some(
                    tokio::task::spawn_blocking(move || crate::password::hash(&password))
                        .await
                        .map_err(|error| IdentityError::Refused(error.to_string()))??,
                )
            }
            None => None,
        };
        let (instance, tenant) = self.account_owner(owner).await?;
        let id = Uuid::now_v7();
        let token = random_token()?;
        let token_hash = hash(&token);
        let who = creator.to_owned();
        let store = inline(move |connection, events| {
            let (password_hash, who) = (password_hash.clone(), who.clone());
            Box::pin(async move {
                crate::account::project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO file_links (id, owner_id, node_id, token_hash, password_hash, expires_at, created_by,
                                             created_at, may_read, may_add)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9)",
                    id,
                    owner,
                    node,
                    &token_hash[..],
                    password_hash,
                    expires_at,
                    who,
                    rights.read,
                    rights.add,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        let has_password = password.is_some();
        self.events
            .execute_with(
                instance,
                tenant,
                &owner.to_string(),
                creator,
                |state: &crate::account::Account| {
                    if !state.exists {
                        return Err(IdentityError::NotFound("the account"));
                    }
                    Ok(vec![AccountEvent::FileLinkAdded {
                        id,
                        node,
                        expires_at,
                        password: has_password,
                        read: rights.read,
                        add: rights.add,
                    }])
                },
                store,
            )
            .await
            .map_err(|error| match error {
                kernoid_events::aggregate::CommandError::Refused(error) => error,
                kernoid_events::aggregate::CommandError::Store(error) => IdentityError::Store(error),
            })?;
        Ok((id, token))
    }

    pub async fn remove_file_link(&self, owner: Uuid, id: Uuid, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(owner).await?;
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.file_links.contains(&id) {
                return Err(IdentityError::NotFound("the link"));
            }
            Ok(vec![AccountEvent::FileLinkRemoved { id }])
        })
        .await
    }

    /// The links to `owner`'s files – to one node, or all.
    pub async fn file_links(&self, owner: Uuid, node: Option<Uuid>) -> Result<Vec<FileLinkInfo>> {
        let rows = sqlx::query!(
            "SELECT id, node_id, expires_at, password_hash IS NOT NULL AS \"password!\", created_by, created_at,
                    may_read, may_add
             FROM file_links WHERE owner_id = $1 AND ($2::uuid IS NULL OR node_id = $2) ORDER BY created_at",
            owner,
            node,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| FileLinkInfo {
                id: row.id,
                owner,
                node: row.node_id,
                expires_at: row.expires_at,
                password: row.password,
                rights: LinkRights { read: row.may_read, add: row.may_add },
                created_by: row.created_by,
                created_at: row.created_at,
            })
            .collect())
    }

    /// The link of `token` at `instance`, if it has not expired and its owner and tenant are active.
    pub async fn open_file_link(&self, instance: Uuid, token: &str) -> Result<Option<OpenLink>> {
        let row = sqlx::query!(
            "SELECT l.id, l.owner_id, l.node_id, l.password_hash IS NOT NULL AS \"needs_password!\", l.may_read, l.may_add
             FROM file_links l
             JOIN accounts a ON a.id = l.owner_id
             JOIN tenants t ON t.id = a.tenant_id
             WHERE l.token_hash = $1 AND t.instance_id = $2 AND a.active AND t.active
               AND (l.expires_at IS NULL OR l.expires_at > now())",
            &hash(token)[..],
            instance,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        Ok(row.map(|row| OpenLink {
            id: row.id,
            owner: row.owner_id,
            node: row.node_id,
            needs_password: row.needs_password,
            rights: LinkRights { read: row.may_read, add: row.may_add },
        }))
    }

    /// Opens a link with its password: an access token, valid for [`ACCESS_LIFETIME`]. Wrong passwords are
    /// `InvalidCredentials`; too many in a while, `TooManyAttempts`.
    pub async fn unlock_file_link(&self, link: Uuid, password: &str) -> Result<String> {
        let row = sqlx::query!(
            "SELECT l.password_hash, f.failures AS \"failures?\", f.window_start AS \"window_start?\"
             FROM file_links l LEFT JOIN file_link_failures f ON f.link_id = l.id WHERE l.id = $1",
            link,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::InvalidCredentials)?;
        let window = chrono::Duration::from_std(FAILURE_WINDOW).unwrap_or_default();
        if let (Some(failures), Some(start)) = (row.failures, row.window_start)
            && failures >= MAX_FAILURES
            && start + window > Utc::now()
        {
            let left = (start + window - Utc::now()).to_std().unwrap_or_default();
            return Err(IdentityError::TooManyAttempts { retry_after: left });
        }
        let stored = row.password_hash.clone();
        let given = zeroize::Zeroizing::new(password.to_owned());
        let matches = tokio::task::spawn_blocking(move || crate::password::verify(stored.as_deref(), &given))
            .await
            .map_err(|error| IdentityError::Refused(error.to_string()))?;
        if !matches || row.password_hash.is_none() {
            sqlx::query!(
                "INSERT INTO file_link_failures (link_id, failures, window_start) VALUES ($1, 1, now())
                 ON CONFLICT (link_id) DO UPDATE SET
                     failures = CASE WHEN file_link_failures.window_start + make_interval(secs => $2) > now()
                                     THEN file_link_failures.failures + 1 ELSE 1 END,
                     window_start = CASE WHEN file_link_failures.window_start + make_interval(secs => $2) > now()
                                         THEN file_link_failures.window_start ELSE now() END",
                link,
                FAILURE_WINDOW.as_secs() as f64,
            )
            .execute(self.pool())
            .await
            .map_err(store_error)?;
            return Err(IdentityError::InvalidCredentials);
        }
        let token = random_token()?;
        sqlx::query!(
            "INSERT INTO file_link_access (token_hash, link_id, expires_at)
             VALUES ($1, $2, now() + make_interval(secs => $3))",
            &hash(&token)[..],
            link,
            ACCESS_LIFETIME.as_secs() as f64,
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?;
        sqlx::query!("DELETE FROM file_link_failures WHERE link_id = $1", link)
            .execute(self.pool())
            .await
            .map_err(store_error)?;
        Ok(token)
    }

    /// Whether `access` – from [`Identity::unlock_file_link`] – opens `link` now.
    pub async fn file_link_unlocked(&self, link: Uuid, access: &str) -> Result<bool> {
        let found = sqlx::query_scalar!(
            "SELECT link_id FROM file_link_access WHERE token_hash = $1 AND link_id = $2 AND expires_at > now()",
            &hash(access)[..],
            link,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        Ok(found.is_some())
    }

    /// Notes a file added through `link`, for the notice to its maker.
    pub async fn record_file_link_arrival(&self, link: Uuid, name: &str, size: u64) -> Result<()> {
        sqlx::query!(
            "INSERT INTO file_link_arrivals (id, link_id, name, size) VALUES ($1, $2, $3, $4)",
            Uuid::now_v7(),
            link,
            name,
            i64::try_from(size).unwrap_or(i64::MAX),
        )
        .execute(self.pool())
        .await
        .map_err(store_error)?;
        Ok(())
    }

    /// Takes what came in through links nothing has come in through for `quiet` – one notice for a batch of files,
    /// not one each. What is taken is gone: a notice that cannot be delivered is not tried again.
    pub async fn take_file_link_arrivals(&self, quiet: Duration) -> Result<Vec<LinkArrivals>> {
        let mut rows = sqlx::query!(
            "DELETE FROM file_link_arrivals
             WHERE link_id IN (SELECT link_id FROM file_link_arrivals GROUP BY link_id
                               HAVING max(added_at) <= now() - make_interval(secs => $1))
             RETURNING link_id, name, size, added_at",
            quiet.as_secs_f64(),
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        rows.sort_by_key(|row| row.added_at);
        let links: Vec<Uuid> = rows.iter().map(|row| row.link_id).collect();
        let found = sqlx::query!(
            "SELECT l.id, l.owner_id, l.created_by, n.name FROM file_links l JOIN file_nodes n ON n.id = l.node_id
             WHERE l.id = ANY($1)",
            &links,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let mut out: Vec<LinkArrivals> = found
            .into_iter()
            .map(|link| LinkArrivals {
                link: link.id,
                owner: link.owner_id,
                maker: link.created_by.strip_prefix("account:").and_then(|id| Uuid::parse_str(id).ok()),
                folder: link.name,
                files: Vec::new(),
            })
            .collect();
        for row in rows {
            if let Some(arrivals) = out.iter_mut().find(|arrivals| arrivals.link == row.link_id) {
                arrivals.files.push((row.name, u64::try_from(row.size).unwrap_or_default()));
            }
        }
        out.sort_by_key(|arrivals| arrivals.link);
        Ok(out)
    }

    /// Removes expired access tokens of links; returns how many.
    pub async fn clean_up_file_link_access(&self) -> Result<u64> {
        let done = sqlx::query!("DELETE FROM file_link_access WHERE expires_at <= now()")
            .execute(self.pool())
            .await
            .map_err(store_error)?;
        Ok(done.rows_affected())
    }
}
