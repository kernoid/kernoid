// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sending a submitted email (RFC 0002, 10.1): to accounts of this installation at once – delivered like mail from
//! outside –, to everyone else through the queue. A submission held for later (RFC 8621, 7, `HOLDFOR`) waits in object
//! storage until its time, when the worker sends it ([`Mail::release_held`]) – unless it is taken back first
//! ([`Mail::cancel_held`]).

use bytes::Bytes;
use chrono::Duration;
use uuid::Uuid;

use crate::{Delivered, Delivery, Mail, MailError, Outgoing, Recipient, Result};

/// Why an email cannot go out.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("{0} takes no mail")]
    InvalidRecipient(String),
    #[error(transparent)]
    Mail(#[from] MailError),
}

fn held_key(submission: Uuid) -> String {
    format!("submissions/{submission}")
}

impl Mail {
    /// Checks that every recipient can be sent to, before anything is sent or held.
    pub async fn check_recipients(&self, recipients: &[String]) -> std::result::Result<(), SendError> {
        for recipient in recipients {
            match self.resolve_recipient(recipient).await? {
                Recipient::Account { .. } | Recipient::Group { .. } | Recipient::NotLocal => {}
                // An SRS address takes bounces from other servers only.
                Recipient::Disabled | Recipient::Unknown | Recipient::Forwarded { .. } => {
                    return Err(SendError::InvalidRecipient(recipient.clone()));
                }
            }
        }
        Ok(())
    }

    /// Sends an email from `account` now: delivers it to local recipients, queues it for the others.
    pub async fn send_now(
        &self,
        account: Uuid,
        from: &str,
        recipients: &[String],
        raw: Bytes,
        lifetime: Duration,
    ) -> std::result::Result<(), SendError> {
        let mut local = std::collections::BTreeSet::new();
        let mut remote = Vec::new();
        for recipient in recipients {
            match self.resolve_recipient(recipient).await? {
                Recipient::Account { account: target, .. } => {
                    local.insert((target, recipient.clone()));
                }
                Recipient::Group { members, .. } => {
                    local.extend(members.into_iter().map(|member| (member, recipient.clone())))
                }
                Recipient::NotLocal => remote.push(recipient.clone()),
                Recipient::Disabled | Recipient::Unknown | Recipient::Forwarded { .. } => {
                    return Err(SendError::InvalidRecipient(recipient.clone()));
                }
            }
        }
        let mut delivered = std::collections::BTreeSet::new();
        for (target, to) in &local {
            if !delivered.insert(*target) {
                continue;
            }
            match self.deliver(*target, raw.clone(), Delivery { from, to, junk: false }).await? {
                Delivered::Stored(_) | Delivered::Duplicate | Delivered::Discarded => {}
            }
        }
        if !remote.is_empty() {
            let tenant = self.account_tenant(account).await?;
            self.enqueue(Outgoing { tenant, account: Some(account), from, recipients: &remote, raw, lifetime }).await?;
        }
        Ok(())
    }

    /// Keeps a submission's message until it is sent or taken back.
    pub async fn hold(&self, account: Uuid, submission: Uuid, raw: Bytes) -> Result<()> {
        let tenant = self.account_tenant(account).await?;
        Ok(self.blobs.put(tenant, &held_key(submission), raw).await?)
    }

    /// Takes back a held submission that is not due yet; whether it was.
    pub async fn cancel_held(&self, account: Uuid, submission: Uuid) -> Result<bool> {
        let canceled = sqlx::query_scalar!(
            "UPDATE email_submissions SET undo_status = 'canceled'
             WHERE id = $1 AND account_id = $2 AND undo_status = 'pending' AND send_at > now()
             RETURNING id",
            submission,
            account,
        )
        .fetch_optional(&self.pool)
        .await?
        .is_some();
        if canceled {
            let tenant = self.account_tenant(account).await?;
            if let Err(error) = self.blobs.delete(tenant, &held_key(submission)).await {
                tracing::warn!(%error, %submission, "removing a held message taken back");
            }
        }
        Ok(canceled)
    }

    /// Sends the held submissions whose time has come, up to `limit`; returns how many went out. Each is taken under a
    /// row lock, so several workers never send one twice; one that fails stays held and is tried again.
    pub async fn release_held(&self, limit: i64) -> Result<usize> {
        let lifetime = self.limits.queue_lifetime;
        let mut released = 0;
        for _ in 0..limit {
            let mut tx = self.pool.begin().await?;
            let Some(row) = sqlx::query!(
                "SELECT id, account_id, envelope_from, recipients FROM email_submissions
                 WHERE undo_status = 'pending' AND send_at <= now()
                 ORDER BY send_at LIMIT 1 FOR UPDATE SKIP LOCKED",
            )
            .fetch_optional(&mut *tx)
            .await?
            else {
                break;
            };
            let tenant = self.account_tenant(row.account_id).await?;
            let key = held_key(row.id);
            match self.blobs.get(tenant, &key).await {
                Ok(raw) => {
                    match self.send_now(row.account_id, &row.envelope_from, &row.recipients, raw, lifetime).await {
                        Ok(()) => {}
                        Err(SendError::Mail(error)) => return Err(error),
                        // A recipient that went away meanwhile: what could be sent was; the rest is not tried again.
                        Err(SendError::InvalidRecipient(recipient)) => {
                            tracing::warn!(submission = %row.id, %recipient, "a held email's recipient takes no mail any more");
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(%error, submission = %row.id, "a held email's message cannot be read; it is not sent");
                }
            }
            sqlx::query!("UPDATE email_submissions SET undo_status = 'final' WHERE id = $1", row.id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            if let Err(error) = self.blobs.delete(tenant, &key).await {
                tracing::warn!(%error, submission = %row.id, "removing a sent held message");
            }
            released += 1;
        }
        Ok(released)
    }
}
