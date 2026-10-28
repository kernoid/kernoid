// SPDX-License-Identifier: AGPL-3.0-or-later
//! Full-text search (RFC 0002, 13.1) – the words of each email's text in `emails.body_search`, indexed at import and
//! by the worker for older emails – and retention (13.2): Trash and Junk emptied after a tenant's days.

use std::collections::{BTreeSet, HashSet};

use uuid::Uuid;

use crate::{Mail, Result, parse};

impl Mail {
    /// The emails of the account whose text has every word of `text` (as a word or a word's beginning).
    pub async fn search_text(&self, account: Uuid, text: &str) -> Result<HashSet<Uuid>> {
        let Some(query) = parse::search_query(text) else { return Ok(HashSet::new()) };
        Ok(sqlx::query_scalar!(
            "SELECT id FROM emails WHERE account_id = $1 AND body_search @@ to_tsquery('simple', $2)",
            account,
            query,
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .collect())
    }

    /// Indexes up to `limit` emails stored before the index; returns how many. For one worker at a time.
    pub async fn index_pending(&self, limit: i64) -> Result<u64> {
        let pending = sqlx::query!(
            "SELECT e.id, e.account_id FROM emails e WHERE e.body_search IS NULL ORDER BY e.id LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut done = 0;
        for email in pending {
            let text = match self.raw_email(email.account_id, email.id).await {
                Ok(raw) => tokio::task::spawn_blocking(move || parse::search_text_of(&raw)).await.unwrap_or_default(),
                // Gone meanwhile, or its object unreadable: an empty index, so that it is not tried again and again.
                Err(error) => {
                    tracing::warn!(%error, email = %email.id, "indexing an email");
                    String::new()
                }
            };
            sqlx::query!(
                "UPDATE emails SET body_search = to_tsvector('simple', $2) WHERE id = $1 AND body_search IS NULL",
                email.id,
                text,
            )
            .execute(&self.pool)
            .await?;
            done += 1;
        }
        Ok(done)
    }

    /// Removes the emails that have been in a Trash or Junk longer than their tenant keeps them, up to `limit`
    /// mailbox entries; returns how many left. For one worker at a time.
    pub async fn apply_retention(&self, limit: i64) -> Result<u64> {
        let due = sqlx::query!(
            r#"SELECT m.account_id, em.mailbox_id, em.uid
               FROM email_mailboxes em
               JOIN mailboxes m ON m.id = em.mailbox_id
               JOIN accounts a ON a.id = m.account_id
               JOIN tenants t ON t.id = a.tenant_id
               WHERE (m.role = 'trash' AND em.added_at < now() - make_interval(days => t.trash_retention_days))
                  OR (m.role = 'junk' AND em.added_at < now() - make_interval(days => t.junk_retention_days))
               ORDER BY m.account_id, em.mailbox_id
               LIMIT $1"#,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut batches: Vec<(Uuid, Uuid, BTreeSet<u32>)> = Vec::new();
        for row in due {
            match batches.last_mut() {
                Some((account, mailbox, uids)) if *account == row.account_id && *mailbox == row.mailbox_id => {
                    uids.insert(row.uid as u32);
                }
                _ => batches.push((row.account_id, row.mailbox_id, BTreeSet::from([row.uid as u32]))),
            }
        }
        let mut removed = 0;
        for (account, mailbox, uids) in batches {
            removed += self.remove_from_mailbox(account, mailbox, &uids).await?.len() as u64;
        }
        Ok(removed)
    }
}
