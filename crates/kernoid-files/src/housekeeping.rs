// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the worker does for files (RFC 0005, 4 and 8): emptying trashes after the days their tenant keeps them, and
//! indexing the text of textual contents for searching inside files – PostgreSQL's full-text search with the
//! `simple` configuration, as for mail (RFC 0002, 13.1).

use std::collections::HashSet;

use uuid::Uuid;

use crate::{FileAccess, Files, FilesError, Result};

/// Contents larger than this are not indexed: their text would not fit PostgreSQL's limit of a `tsvector`.
pub const MAX_INDEXED: u64 = 1024 * 1024;

/// Whether a content of this media type is text to index.
pub fn textual(media_type: &str) -> bool {
    let media_type = media_type.to_ascii_lowercase();
    media_type.starts_with("text/")
        || [
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-sh",
            "application/x-yaml",
            "application/yaml",
            "application/toml",
            "application/sql",
            "application/ld+json",
            "message/rfc822",
        ]
        .contains(&media_type.as_str())
}

impl Files {
    /// Destroys what has been at the top of a trash longer than its tenant keeps it – each with all it holds –, up
    /// to `limit` nodes; returns how many. A node's last change is when it went into the trash. For one worker at
    /// a time.
    pub async fn apply_trash_retention(&self, limit: i64) -> Result<u64> {
        let due = sqlx::query!(
            "SELECT n.id, n.account_id FROM file_nodes n
             JOIN file_nodes trash ON trash.id = n.parent_id AND trash.role = 'trash'
             JOIN accounts a ON a.id = n.account_id
             JOIN tenants t ON t.id = a.tenant_id
             WHERE n.changed < now() - make_interval(days => t.files_trash_retention_days)
             ORDER BY n.changed LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut destroyed = 0;
        for node in due {
            match self.destroy(&FileAccess::own(node.account_id), node.id, true).await {
                Ok(_) => destroyed += 1,
                // Gone meanwhile; or too large to destroy at once – it stays until someone removes it in parts.
                Err(FilesError::NotFound(_)) => {}
                Err(error) => tracing::warn!(%error, node = %node.id, "emptying a trash"),
            }
        }
        Ok(destroyed)
    }

    /// Indexes up to `limit` contents not looked at yet; returns how many it looked at. Contents that are not text,
    /// or too large, get an empty index.
    pub async fn index_pending(&self, limit: i64) -> Result<u64> {
        let pending = sqlx::query!(
            "SELECT id, media_type, size FROM file_contents WHERE body_search IS NULL ORDER BY id LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut done = 0;
        for content in pending {
            let mut text = String::new();
            if textual(&content.media_type) && (content.size as u64) <= MAX_INDEXED {
                match self.existing(content.id).await {
                    Ok(stored) => match self.read_all(&stored, MAX_INDEXED).await {
                        Ok(bytes) => text = String::from_utf8_lossy(&bytes).replace('\0', " "),
                        Err(error) => tracing::warn!(%error, content = %content.id, "indexing a file"),
                    },
                    Err(error) => tracing::warn!(%error, content = %content.id, "indexing a file"),
                }
            }
            let indexed = sqlx::query!(
                "UPDATE file_contents SET body_search = to_tsvector('simple', $2) WHERE id = $1 AND body_search IS NULL",
                content.id,
                text,
            )
            .execute(&self.pool)
            .await;
            if let Err(error) = indexed {
                // Text PostgreSQL cannot index (too many words): nothing to search.
                tracing::warn!(%error, content = %content.id, "indexing a file");
                sqlx::query!("UPDATE file_contents SET body_search = ''::tsvector WHERE id = $1", content.id)
                    .execute(&self.pool)
                    .await?;
            }
            done += 1;
        }
        Ok(done)
    }

    /// The files of `owner`'s store whose current content holds `text` (as words, in the `simple` configuration).
    pub async fn body_matches(&self, owner: Uuid, text: &str) -> Result<HashSet<Uuid>> {
        let rows = sqlx::query_scalar!(
            "SELECT n.id FROM file_nodes n JOIN file_contents c ON c.id = n.content_id
             WHERE n.account_id = $1 AND c.body_search @@ websearch_to_tsquery('simple', $2)",
            owner,
            text,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }
}
