// SPDX-License-Identifier: AGPL-3.0-or-later
//! The queue of outgoing mail (RFC 0002, 10.2): messages sealed in object storage, each recipient's state in
//! PostgreSQL. Workers lease the due recipients of one domain at a time, so that several can deliver side by side
//! without sending anything twice.

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use kernoid_store::garbage;
use uuid::Uuid;

use crate::{Mail, MailError, Result};

/// A message for the queue.
#[derive(Debug, Clone)]
pub struct Outgoing<'a> {
    pub tenant: Uuid,
    /// The account that sends it, if any.
    pub account: Option<Uuid>,
    /// `MAIL FROM`; empty for bounces.
    pub from: &'a str,
    /// Lower case, the domain in ASCII.
    pub recipients: &'a [String],
    pub raw: Bytes,
    /// How long kernoid tries before it gives up and bounces.
    pub lifetime: Duration,
}

/// One recipient taken from the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leased {
    pub message: Uuid,
    pub address: String,
    pub attempts: i32,
    pub tenant: Uuid,
    pub envelope_from: String,
    pub expires_at: DateTime<Utc>,
}

/// The due recipients of one domain, leased to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub domain: String,
    pub recipients: Vec<Leased>,
}

/// A recipient's state, for the queue's overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedRecipient {
    pub message: Uuid,
    pub address: String,
    pub status: String,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

fn blob_key(message: Uuid) -> String {
    format!("outbound/{message}")
}

impl Mail {
    /// Puts a message into the queue for its recipients; returns its id.
    pub async fn enqueue(&self, outgoing: Outgoing<'_>) -> Result<Uuid> {
        if outgoing.recipients.is_empty() {
            return Err(MailError::Invalid("a message to send needs a recipient".into()));
        }
        let id = Uuid::now_v7();
        let key = blob_key(id);
        garbage::pending(&self.pool, outgoing.tenant, &key).await?;
        self.blobs.put(outgoing.tenant, &key, outgoing.raw.clone()).await?;
        let mut tx = self.pool.begin().await?;
        if !garbage::keep(&mut tx, outgoing.tenant, &key).await? {
            return Err(MailError::Invalid("queueing the message took too long".into()));
        }
        sqlx::query!(
            "INSERT INTO outbound_messages (id, tenant_id, account_id, envelope_from, size, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            outgoing.tenant,
            outgoing.account,
            outgoing.from,
            outgoing.raw.len() as i64,
            Utc::now() + outgoing.lifetime,
        )
        .execute(&mut *tx)
        .await?;
        let mut recipients: Vec<&String> = outgoing.recipients.iter().collect();
        recipients.sort();
        recipients.dedup();
        for address in recipients {
            let domain = address.rsplit_once('@').map(|(_, domain)| domain).unwrap_or_default();
            sqlx::query!(
                "INSERT INTO outbound_recipients (message_id, address, domain) VALUES ($1, $2, $3)",
                id,
                address,
                domain,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    /// Leases up to `limit` due recipients of one domain for `lease`; `None` if nothing is due.
    pub async fn lease_due(&self, lease: Duration, limit: i64) -> Result<Option<Batch>> {
        let mut tx = self.pool.begin().await?;
        let domain = sqlx::query_scalar!(
            "SELECT domain FROM outbound_recipients
             WHERE status = 'queued' AND next_attempt_at <= now() AND (leased_until IS NULL OR leased_until < now())
             ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(domain) = domain else { return Ok(None) };
        let recipients = sqlx::query!(
            r#"WITH taken AS (
                   SELECT message_id, address FROM outbound_recipients
                   WHERE domain = $1 AND status = 'queued' AND next_attempt_at <= now()
                     AND (leased_until IS NULL OR leased_until < now())
                   ORDER BY next_attempt_at LIMIT $2 FOR UPDATE SKIP LOCKED)
               UPDATE outbound_recipients r SET leased_until = now() + make_interval(secs => $3)
               FROM taken, outbound_messages m
               WHERE r.message_id = taken.message_id AND r.address = taken.address AND m.id = r.message_id
               RETURNING r.message_id, r.address, r.attempts, m.tenant_id, m.envelope_from, m.expires_at"#,
            domain,
            limit,
            lease.num_seconds() as f64,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(Batch {
            domain,
            recipients: recipients
                .into_iter()
                .map(|row| Leased {
                    message: row.message_id,
                    address: row.address,
                    attempts: row.attempts,
                    tenant: row.tenant_id,
                    envelope_from: row.envelope_from,
                    expires_at: row.expires_at,
                })
                .collect(),
        }))
    }

    /// The message of the queue, as it is sent.
    pub async fn outbound_message(&self, tenant: Uuid, message: Uuid) -> Result<Bytes> {
        Ok(self.blobs.get(tenant, &blob_key(message)).await?)
    }

    /// The recipient has the message.
    pub async fn outbound_delivered(&self, message: Uuid, address: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE outbound_recipients SET status = 'delivered', attempts = attempts + 1, leased_until = NULL,
                 last_error = NULL
             WHERE message_id = $1 AND address = $2",
            message,
            address,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delivery failed for now: try again at `next`.
    pub async fn outbound_retry(&self, message: Uuid, address: &str, error: &str, next: DateTime<Utc>) -> Result<()> {
        sqlx::query!(
            "UPDATE outbound_recipients SET attempts = attempts + 1, next_attempt_at = $3, leased_until = NULL,
                 last_error = $4
             WHERE message_id = $1 AND address = $2",
            message,
            address,
            next,
            error,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delivery failed for good.
    pub async fn outbound_failed(&self, message: Uuid, address: &str, error: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE outbound_recipients SET status = 'failed', attempts = attempts + 1, leased_until = NULL,
                 last_error = $3
             WHERE message_id = $1 AND address = $2",
            message,
            address,
            error,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Removes a message whose recipients are all done; its object is collected by the worker. `false` if some still
    /// wait.
    pub async fn outbound_finish(&self, message: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query!(
            r#"SELECT tenant_id,
                      EXISTS (SELECT 1 FROM outbound_recipients WHERE message_id = m.id AND status = 'queued') AS "waiting!"
               FROM outbound_messages m WHERE id = $1 FOR UPDATE"#,
            message,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else { return Ok(true) };
        if row.waiting {
            return Ok(false);
        }
        sqlx::query!("DELETE FROM outbound_messages WHERE id = $1", message).execute(&mut *tx).await?;
        garbage::mark(&mut tx, row.tenant_id, &blob_key(message), Utc::now()).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The queue of the tenants of one instance (the administration API, RFC 0002, 12.3).
    pub async fn instance_queue(&self, instance: Uuid, limit: i64) -> Result<Vec<QueuedRecipient>> {
        Ok(sqlx::query_as!(
            QueuedRecipient,
            "SELECT r.message_id AS message, r.address, r.status, r.attempts, r.next_attempt_at, r.last_error
             FROM outbound_recipients r JOIN outbound_messages m ON m.id = r.message_id
             JOIN tenants t ON t.id = m.tenant_id
             WHERE t.instance_id = $1 ORDER BY r.message_id DESC, r.address LIMIT $2",
            instance,
            limit,
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// The recipients in the queue, newest message first – for operators.
    pub async fn queue(&self, limit: i64) -> Result<Vec<QueuedRecipient>> {
        Ok(sqlx::query_as!(
            QueuedRecipient,
            "SELECT message_id AS message, address, status, attempts, next_attempt_at, last_error
             FROM outbound_recipients ORDER BY message_id DESC, address LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
