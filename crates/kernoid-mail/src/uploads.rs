// SPDX-License-Identifier: AGPL-3.0-or-later
//! Blobs uploaded for an account (JMAP, RFC 0002 11.1), kept a day: streamed into parts below
//! `upload/<account>/<id>` (RFC 0005, 5), each part marked as garbage due when the upload expires, so nothing has
//! to remember to remove them. They belong to the account, not to its mail store: files take them as well, without
//! copying – a file that takes an upload takes its parts back from the garbage. Uploads from before parts are one
//! object at the prefix itself.

use bytes::Bytes;
use chrono::{Duration, Utc};
use futures_util::Stream;
use kernoid_store::{BlobError, parts};
use uuid::Uuid;

use crate::{Mail, MailError, Result};

/// How long an upload is kept.
pub const UPLOAD_LIFETIME: Duration = Duration::days(1);

fn key(account: Uuid, id: Uuid) -> String {
    format!("upload/{account}/{id}")
}

/// Where an upload lies, for reading it or handing it to a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    pub id: Uuid,
    pub account: Uuid,
    pub tenant: Uuid,
    pub content_type: String,
    pub size: u64,
    /// The prefix of its parts and their number, and the SHA-256 of the whole; `None` for an upload of one object.
    pub parts: Option<(String, parts::Stored)>,
}

impl From<parts::PartsError> for MailError {
    fn from(error: parts::PartsError) -> Self {
        match error {
            parts::PartsError::TooLarge { limit } => Self::TooLarge { limit },
            parts::PartsError::Source(detail) => Self::Invalid(format!("the upload could not be read: {detail}")),
            parts::PartsError::Blob(error) => Self::Blob(error),
            parts::PartsError::Database(error) => Self::Store(error),
        }
    }
}

impl Mail {
    /// Stores an upload of at most `max_size` bytes as it arrives; returns its id and size.
    pub async fn put_upload<S, E>(
        &self,
        account: Uuid,
        content_type: &str,
        content: S,
        max_size: u64,
    ) -> Result<(Uuid, u64)>
    where
        S: Stream<Item = std::result::Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let tenant = sqlx::query_scalar!("SELECT tenant_id FROM accounts WHERE id = $1", account)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(MailError::NotFound("the account"))?;
        let id = Uuid::now_v7();
        let expires = Utc::now() + UPLOAD_LIFETIME;
        let stored = parts::put(&self.blobs, &self.pool, tenant, &key(account, id), content, max_size, expires).await?;
        sqlx::query!(
            "INSERT INTO jmap_uploads (id, account_id, tenant_id, content_type, size, expires_at, parts, sha256)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            id,
            account,
            tenant,
            content_type,
            stored.size as i64,
            expires,
            stored.parts as i32,
            &stored.sha256[..],
        )
        .execute(&self.pool)
        .await?;
        Ok((id, stored.size))
    }

    /// An upload of the account that has not expired.
    pub async fn upload_info(&self, account: Uuid, id: Uuid) -> Result<Upload> {
        let row = sqlx::query!(
            "SELECT tenant_id, content_type, size, parts, sha256 FROM jmap_uploads
             WHERE id = $1 AND account_id = $2 AND expires_at > now()",
            id,
            account,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MailError::NotFound("the upload"))?;
        let parts = match (row.parts, row.sha256) {
            (Some(count), Some(sha256)) => Some((
                key(account, id),
                parts::Stored {
                    parts: count as u32,
                    size: row.size as u64,
                    sha256: sha256.as_slice().try_into().unwrap_or([0; 32]),
                },
            )),
            _ => None,
        };
        Ok(Upload { id, account, tenant: row.tenant_id, content_type: row.content_type, size: row.size as u64, parts })
    }

    /// An upload's content in memory, and its type – for uploads no larger than a message may be.
    pub async fn upload(&self, account: Uuid, id: Uuid) -> Result<(Bytes, String)> {
        let upload = self.upload_info(account, id).await?;
        if upload.size > self.limits.max_message_size {
            return Err(MailError::TooLarge { limit: self.limits.max_message_size });
        }
        let content = match &upload.parts {
            Some((prefix, stored)) => {
                parts::read_all(&self.blobs, upload.tenant, prefix, stored.parts, stored.size).await?
            }
            None => self.blobs.get(upload.tenant, &key(account, id)).await?,
        };
        Ok((content, upload.content_type))
    }

    /// An upload's content from byte `start` to `end` (exclusive), as it is read.
    pub fn read_upload(
        &self,
        upload: &Upload,
        start: u64,
        end: u64,
    ) -> std::pin::Pin<Box<dyn Stream<Item = std::result::Result<Bytes, BlobError>> + Send>> {
        match &upload.parts {
            Some((prefix, stored)) => {
                Box::pin(parts::read(&self.blobs, upload.tenant, prefix, stored.parts, start, end.min(stored.size)))
            }
            None => {
                let blobs = self.blobs.clone();
                let (tenant, key) = (upload.tenant, key(upload.account, upload.id));
                Box::pin(futures_util::stream::once(async move {
                    let content = blobs.get(tenant, &key).await?;
                    let end = (end as usize).min(content.len());
                    Ok(content.slice((start as usize).min(end)..end))
                }))
            }
        }
    }

    /// Removes the rows of expired uploads (their objects are garbage already); for the worker.
    pub async fn prune_uploads(&self) -> Result<u64> {
        Ok(sqlx::query!("DELETE FROM jmap_uploads WHERE expires_at < now()").execute(&self.pool).await?.rows_affected())
    }

    /// The ids of all emails of the account, newest first.
    pub async fn email_ids(&self, account: Uuid) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar!(
            "SELECT id FROM emails WHERE account_id = $1 ORDER BY received_at DESC, id DESC",
            account
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// The account's display name and addresses, its login name first.
    pub async fn account_addresses(&self, account: Uuid) -> Result<(String, Vec<String>)> {
        let display_name = sqlx::query_scalar!("SELECT display_name FROM accounts WHERE id = $1", account)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(MailError::NotFound("the account"))?;
        let addresses = sqlx::query_scalar!(
            "SELECT address FROM addresses WHERE account_id = $1 ORDER BY is_primary DESC, address",
            account,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok((display_name, addresses))
    }

    /// The addresses of groups whose members may send as the group (RFC 0002, 9.2) and that have `account` as a
    /// member: the group's name and an address of it.
    pub async fn group_sender_addresses(&self, account: Uuid) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query!(
            "SELECT g.name, ad.address FROM group_members m
             JOIN groups g ON g.id = m.group_id JOIN addresses ad ON ad.group_id = g.id
             WHERE m.account_id = $1 AND g.members_send_as ORDER BY ad.address",
            account,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|row| (row.name, row.address)).collect())
    }

    /// Whether `account` may send from the addresses of `group`: it is a member, and the group lets its members.
    pub async fn may_send_as_group(&self, account: Uuid, group: Uuid) -> Result<bool> {
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM group_members m JOIN groups g ON g.id = m.group_id
                              WHERE m.group_id = $1 AND m.account_id = $2 AND g.members_send_as) AS "may!""#,
            group,
            account,
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// The tenant of the account's mail store.
    pub async fn account_tenant(&self, account: Uuid) -> Result<Uuid> {
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        tx.commit().await?;
        Ok(locked.tenant)
    }
}
