// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebDAV locks (RFC 4918, 6 and 9.10; RFC 0005, 9): write locks on nodes, exclusive or shared, on one node or a
//! directory with all below it, that expire. File managers of operating systems take them before they write. Only
//! WebDAV honours them; JMAP does not know locks (OPEN).

use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{FileAccess, Files, FilesError, Result, Rights};

/// The longest a lock lasts before it is refreshed.
const MAX_TIMEOUT: Duration = Duration::hours(1);

/// A lock to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRequest {
    pub exclusive: bool,
    /// On a directory and all below it (`Depth: infinity`).
    pub deep: bool,
    /// The client's `owner` element, as it sent it.
    pub owner_info: Option<String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// `urn:uuid:…`, the lock token.
    pub token: String,
    pub node: Uuid,
    pub holder: Uuid,
    pub exclusive: bool,
    pub deep: bool,
    pub owner_info: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// The locks in force on `node`: its own, and the deep ones of its ancestors – and, if `below`, those of the nodes
/// below it.
async fn in_force(connection: &mut PgConnection, node: Uuid, below: bool) -> Result<Vec<Lock>> {
    let rows = sqlx::query!(
        r#"WITH RECURSIVE up AS (
               SELECT id, parent_id, 0 AS depth FROM file_nodes WHERE id = $1
               UNION ALL
               SELECT n.id, n.parent_id, up.depth + 1 FROM file_nodes n JOIN up ON n.id = up.parent_id
               WHERE up.depth < 64),
           down AS (
               SELECT id FROM file_nodes WHERE id = $1 AND $2
               UNION ALL
               SELECT n.id FROM file_nodes n JOIN down ON n.parent_id = down.id)
           SELECT l.token, l.node_id, l.holder_id, l.exclusive, l.deep, l.owner_info, l.expires_at
           FROM file_locks l
           WHERE l.expires_at > now()
             AND (l.node_id = $1
                  OR (l.deep AND l.node_id IN (SELECT id FROM up))
                  OR l.node_id IN (SELECT id FROM down))"#,
        node,
        below,
    )
    .fetch_all(connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| Lock {
            token: row.token,
            node: row.node_id,
            holder: row.holder_id,
            exclusive: row.exclusive,
            deep: row.deep,
            owner_info: row.owner_info,
            expires_at: row.expires_at,
        })
        .collect())
}

impl Files {
    /// The locks that hold `node`.
    pub async fn locks(&self, node: Uuid) -> Result<Vec<Lock>> {
        let mut connection = self.pool.acquire().await?;
        in_force(&mut connection, node, false).await
    }

    /// Fails with [`FilesError::Locked`] unless every lock in force on `node` (and below it, if `below`) is one the
    /// client named in `tokens` (WebDAV's `If` header) and holds.
    pub async fn check_unlocked(&self, access: &FileAccess, node: Uuid, below: bool, tokens: &[String]) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        let held = in_force(&mut connection, node, below).await?;
        if held.iter().all(|lock| lock.holder == access.user && tokens.contains(&lock.token)) {
            Ok(())
        } else {
            Err(FilesError::Locked)
        }
    }

    /// Takes a lock on a node `access` may change.
    pub async fn lock(&self, access: &FileAccess, node: Uuid, request: LockRequest) -> Result<Lock> {
        let rights = self.rights(access, node).await?;
        if !rights.contains(Rights::WRITE) {
            return Err(FilesError::Forbidden("not allowed".into()));
        }
        let mut tx = self.pool.begin().await?;
        self.lock_store(&mut tx, access.owner).await?;
        let held = in_force(&mut tx, node, request.deep).await?;
        if held.iter().any(|lock| lock.exclusive || request.exclusive) {
            return Err(FilesError::Locked);
        }
        let lock = Lock {
            token: format!("urn:uuid:{}", Uuid::new_v4()),
            node,
            holder: access.user,
            exclusive: request.exclusive,
            deep: request.deep,
            owner_info: request.owner_info,
            expires_at: Utc::now() + request.timeout.clamp(Duration::seconds(1), MAX_TIMEOUT),
        };
        sqlx::query!("DELETE FROM file_locks WHERE expires_at <= now() AND account_id = $1", access.owner)
            .execute(&mut *tx)
            .await?;
        sqlx::query!(
            "INSERT INTO file_locks (token, account_id, node_id, holder_id, exclusive, deep, owner_info, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            lock.token,
            access.owner,
            node,
            lock.holder,
            lock.exclusive,
            lock.deep,
            lock.owner_info,
            lock.expires_at,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(lock)
    }

    /// Extends a lock the caller holds.
    pub async fn refresh_lock(&self, access: &FileAccess, token: &str, timeout: Duration) -> Result<Lock> {
        let row = sqlx::query!(
            "UPDATE file_locks SET expires_at = now() + make_interval(secs => $3)
             WHERE token = $1 AND holder_id = $2 AND expires_at > now()
             RETURNING node_id, exclusive, deep, owner_info, expires_at",
            token,
            access.user,
            timeout.clamp(Duration::seconds(1), MAX_TIMEOUT).num_seconds() as f64,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FilesError::NotFound("the lock"))?;
        Ok(Lock {
            token: token.to_owned(),
            node: row.node_id,
            holder: access.user,
            exclusive: row.exclusive,
            deep: row.deep,
            owner_info: row.owner_info,
            expires_at: row.expires_at,
        })
    }

    /// Gives up a lock: the holder, or whoever may share the node (to clear a lock left behind).
    pub async fn unlock(&self, access: &FileAccess, token: &str) -> Result<()> {
        let node = sqlx::query_scalar!(
            "SELECT node_id FROM file_locks WHERE token = $1 AND account_id = $2",
            token,
            access.owner
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FilesError::NotFound("the lock"))?;
        let held = sqlx::query_scalar!(
            r#"SELECT holder_id = $2 AS "own!" FROM file_locks WHERE token = $1"#,
            token,
            access.user
        )
        .fetch_one(&self.pool)
        .await?;
        if !held && !self.rights(access, node).await?.contains(Rights::SHARE) {
            return Err(FilesError::Forbidden("someone else's lock".into()));
        }
        sqlx::query!("DELETE FROM file_locks WHERE token = $1", token).execute(&self.pool).await?;
        Ok(())
    }
}
