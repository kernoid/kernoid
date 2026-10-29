// SPDX-License-Identifier: AGPL-3.0-or-later
//! The contents of files (RFC 0005, 5 and 6): stored in parts in object storage before the change that needs them,
//! given to a file in that change, kept as versions when the file gets new content, and handed to the garbage with
//! the last content that names their parts.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::Stream;
use kernoid_store::{
    BlobError, garbage,
    parts::{self, PartsError, Stored},
};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{Files, FilesError, Locked, Result};

/// Content stored in object storage, not yet given to a file: below `prefix` in `tenant`'s space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub tenant: Uuid,
    pub prefix: String,
    pub stored: Stored,
}

/// A content of a file – the current one or a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentInfo {
    pub id: Uuid,
    pub node: Uuid,
    pub size: u64,
    pub media_type: String,
    pub sha256: Vec<u8>,
    /// The file's modification time while this was its content.
    pub modified: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub current: bool,
}

/// Where a content is, for reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readable {
    pub info: ContentInfo,
    pub content: Content,
}

impl From<PartsError> for FilesError {
    fn from(error: PartsError) -> Self {
        match error {
            PartsError::TooLarge { limit } => Self::TooLarge { limit },
            PartsError::Source(detail) => Self::Invalid(format!("the content could not be read: {detail}")),
            PartsError::Blob(error) => Self::Blob(error),
            PartsError::Database(error) => Self::Store(error),
            PartsError::Refused(refused) => Self::Refused(refused),
        }
    }
}

impl Files {
    /// Stores content for a file of `owner`'s store, before the change that gives it to the file.
    pub async fn store<S, E>(&self, owner: Uuid, content: S) -> Result<Content>
    where
        S: Stream<Item = std::result::Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let tenant = self.tenant_of(owner).await?;
        let prefix = format!("files/{owner}/{}", Uuid::now_v7());
        let due = Utc::now() + garbage::PENDING;
        let stored =
            parts::put(&self.blobs, &self.pool, tenant, &prefix, content, self.limits.max_file_size, due).await?;
        Ok(Content { tenant, prefix, stored })
    }

    /// Stores content that is in memory already.
    pub async fn store_bytes(&self, owner: Uuid, content: Bytes) -> Result<Content> {
        self.store(owner, futures_util::stream::iter([Ok::<_, std::convert::Infallible>(content)])).await
    }

    /// An existing content of the tenant – of any file – as content for another file (a copy shares the parts).
    pub async fn existing(&self, content: Uuid) -> Result<Content> {
        let row = sqlx::query!(
            "SELECT f.tenant_id, c.prefix, c.parts, c.size, c.sha256
             FROM file_contents c JOIN file_accounts f ON f.account_id = c.account_id WHERE c.id = $1",
            content,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FilesError::NotFound("the content"))?;
        Ok(Content {
            tenant: row.tenant_id,
            prefix: row.prefix,
            stored: Stored { parts: row.parts as u32, size: row.size as u64, sha256: sha(&row.sha256) },
        })
    }

    /// Reads a content from byte `start` to `end` (exclusive).
    pub fn read(
        &self,
        content: &Content,
        start: u64,
        end: u64,
    ) -> impl Stream<Item = std::result::Result<Bytes, BlobError>> + Send + 'static {
        parts::read(
            &self.blobs,
            content.tenant,
            &content.prefix,
            content.stored.parts,
            start,
            end.min(content.stored.size),
        )
    }

    /// The whole of a content in memory, if it is at most `limit` bytes.
    pub async fn read_all(&self, content: &Content, limit: u64) -> Result<Bytes> {
        if content.stored.size > limit {
            return Err(FilesError::TooLarge { limit });
        }
        Ok(parts::read_all(&self.blobs, content.tenant, &content.prefix, content.stored.parts, content.stored.size)
            .await?)
    }
}

fn sha(value: &[u8]) -> [u8; 32] {
    value.try_into().unwrap_or([0; 32])
}

/// Gives stored content to a file of the locked store, as a new content row; counts it against the quota.
pub(crate) async fn attach(
    tx: &mut Transaction<'static, Postgres>,
    locked: &mut Locked,
    max_size: u64,
    node: Uuid,
    content: &Content,
    media_type: &str,
    modified: DateTime<Utc>,
) -> Result<Uuid> {
    if content.tenant != locked.tenant {
        return Err(FilesError::Invalid("the content belongs to another tenant".into()));
    }
    if content.stored.size > max_size {
        return Err(FilesError::TooLarge { limit: max_size });
    }
    locked.charge(tx, content.stored.size as i64).await?;
    // Parts another content names already are kept; new ones are taken back from the garbage.
    let shared = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM file_contents WHERE prefix = $1) AS "shared!""#,
        content.prefix
    )
    .fetch_one(&mut **tx)
    .await?;
    if !shared && !parts::keep(tx, locked.tenant, &content.prefix, content.stored.parts).await? {
        return Err(FilesError::Invalid("storing the content took too long".into()));
    }
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO file_contents (id, account_id, node_id, prefix, parts, size, sha256, media_type, modified)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        id,
        locked.account,
        node,
        content.prefix,
        content.stored.parts as i32,
        content.stored.size as i64,
        &content.stored.sha256[..],
        media_type,
        modified,
    )
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

/// A content row that goes.
pub(crate) struct Released {
    pub prefix: String,
    pub parts: i32,
    pub size: i64,
}

/// After contents went: frees their space and hands parts no content names any more to the garbage.
pub(crate) async fn released(tx: &mut PgConnection, locked: &mut Locked, gone: Vec<Released>) -> Result<()> {
    let freed: i64 = gone.iter().map(|content| content.size).sum();
    locked.charge(tx, -freed).await?;
    for content in gone {
        let named = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM file_contents WHERE prefix = $1) AS "named!""#,
            content.prefix
        )
        .fetch_one(&mut *tx)
        .await?;
        if !named {
            parts::mark_now(tx, locked.tenant, &content.prefix, content.parts as u32).await?;
        }
    }
    Ok(())
}

/// Removes the versions of a file beyond the newest `kept` (the current content is no version).
pub(crate) async fn prune_versions(
    tx: &mut Transaction<'static, Postgres>,
    locked: &mut Locked,
    node: Uuid,
    kept: u32,
) -> Result<()> {
    let gone = sqlx::query_as!(
        Released,
        "DELETE FROM file_contents WHERE id IN (
             SELECT c.id FROM file_contents c JOIN file_nodes n ON n.id = c.node_id
             WHERE c.node_id = $1 AND c.id <> n.content_id
             ORDER BY c.created_at DESC OFFSET $2)
         RETURNING prefix, parts, size",
        node,
        i64::from(kept),
    )
    .fetch_all(&mut **tx)
    .await?;
    released(tx, locked, gone).await
}

/// The contents of a node: the current one first, then the versions, newest first.
pub(crate) async fn contents(connection: &mut PgConnection, node: Uuid) -> Result<Vec<ContentInfo>> {
    let rows = sqlx::query!(
        r#"SELECT c.id, c.node_id, c.size, c.media_type, c.sha256, c.modified, c.created_at,
                  c.id = n.content_id AS "current!"
           FROM file_contents c JOIN file_nodes n ON n.id = c.node_id
           WHERE c.node_id = $1 ORDER BY c.id = n.content_id DESC, c.created_at DESC"#,
        node,
    )
    .fetch_all(connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ContentInfo {
            id: row.id,
            node: row.node_id,
            size: row.size as u64,
            media_type: row.media_type,
            sha256: row.sha256,
            modified: row.modified,
            created_at: row.created_at,
            current: row.current,
        })
        .collect())
}
