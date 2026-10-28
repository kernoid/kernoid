// SPDX-License-Identifier: AGPL-3.0-or-later
//! What IMAP needs of the store beyond JMAP (RFC 0002, 11.2): a mailbox's emails by UID, the UIDs that left it, and
//! copying, moving and expunging several emails in one change.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    Mail, MailError, Result,
    changes::{Change, ObjectType, record},
    email::{destroy_in, leave_mailbox},
    mailbox::{next_uid, owned},
};

/// An email as a mailbox holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    pub uid: u32,
    pub email: Uuid,
    pub thread: Uuid,
    /// The modification sequence of the email's last change in this mailbox.
    pub modseq: u64,
    pub keywords: Vec<String>,
    pub size: u64,
    pub received_at: DateTime<Utc>,
}

impl Mail {
    /// The emails of a mailbox of the account, by UID.
    pub async fn mailbox_entries(&self, account: Uuid, mailbox: Uuid) -> Result<Vec<MailboxEntry>> {
        let rows = sqlx::query!(
            "SELECT em.uid, em.modseq, e.id, e.thread_id, e.keywords, e.size, e.received_at
             FROM email_mailboxes em JOIN emails e ON e.id = em.email_id
             WHERE em.mailbox_id = $1 AND e.account_id = $2 ORDER BY em.uid",
            mailbox,
            account,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| MailboxEntry {
                uid: row.uid as u32,
                email: row.id,
                thread: row.thread_id,
                modseq: row.modseq as u64,
                keywords: row.keywords,
                size: row.size as u64,
                received_at: row.received_at,
            })
            .collect())
    }

    /// The UIDs that left the mailbox after `modseq` (QRESYNC's `VANISHED`).
    pub async fn expunged_since(&self, mailbox: Uuid, modseq: u64) -> Result<Vec<u32>> {
        Ok(sqlx::query_scalar!(
            "SELECT uid FROM mailbox_expunged WHERE mailbox_id = $1 AND modseq > $2 ORDER BY uid",
            mailbox,
            modseq as i64,
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|uid| uid as u32)
        .collect())
    }

    /// Puts emails into `target` as well (IMAP `COPY`), each with a new UID there; an email already in it keeps its
    /// UID. Returns each email's UID in `target`, in the order given.
    pub async fn copy_to_mailbox(&self, account: Uuid, emails: &[Uuid], target: Uuid) -> Result<Vec<u32>> {
        self.place(account, emails, target, None).await
    }

    /// Moves emails from `source` to `target` (IMAP `MOVE`): into `target` with new UIDs, out of `source`.
    pub async fn move_to_mailbox(
        &self,
        account: Uuid,
        emails: &[Uuid],
        source: Uuid,
        target: Uuid,
    ) -> Result<Vec<u32>> {
        if source == target {
            return Err(MailError::Invalid("source and target are the same mailbox".into()));
        }
        self.place(account, emails, target, Some(source)).await
    }

    async fn place(&self, account: Uuid, emails: &[Uuid], target: Uuid, source: Option<Uuid>) -> Result<Vec<u32>> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        owned(&mut tx, account, target).await?;
        let modseq = locked.next_modseq(&mut tx).await?;
        let mut uids = Vec::with_capacity(emails.len());
        for email in emails {
            let existing = sqlx::query_scalar!(
                "SELECT em.uid FROM email_mailboxes em JOIN emails e ON e.id = em.email_id
                 WHERE em.email_id = $1 AND em.mailbox_id = $2 AND e.account_id = $3",
                email,
                target,
                account,
            )
            .fetch_optional(&mut *tx)
            .await?;
            let uid = match existing {
                Some(uid) => uid,
                None => {
                    let known = sqlx::query_scalar!(
                        r#"SELECT EXISTS (SELECT 1 FROM emails WHERE id = $1 AND account_id = $2) AS "known!""#,
                        email,
                        account
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    if !known {
                        return Err(MailError::NotFound("the email"));
                    }
                    let uid = next_uid(&mut tx, target).await?;
                    sqlx::query!(
                        "INSERT INTO email_mailboxes (email_id, mailbox_id, uid, modseq) VALUES ($1, $2, $3, $4)",
                        email,
                        target,
                        uid,
                        modseq,
                    )
                    .execute(&mut *tx)
                    .await?;
                    uid
                }
            };
            if let Some(source) = source {
                leave_mailbox(&mut tx, &locked, modseq, *email, source).await?;
            }
            sqlx::query!("UPDATE email_mailboxes SET modseq = $2 WHERE email_id = $1", email, modseq)
                .execute(&mut *tx)
                .await?;
            record(&mut tx, account, modseq, ObjectType::Email, *email, Change::Updated).await?;
            uids.push(uid as u32);
        }
        record(&mut tx, account, modseq, ObjectType::Mailbox, target, Change::Updated).await?;
        if let Some(source) = source {
            record(&mut tx, account, modseq, ObjectType::Mailbox, source, Change::Updated).await?;
        }
        tx.commit().await?;
        Ok(uids)
    }

    /// Removes the emails of `mailbox` that have `$deleted` (and, if given, one of `uids`) from it (IMAP `EXPUNGE`):
    /// an email in no other mailbox is destroyed. Returns the UIDs removed.
    pub async fn expunge(&self, account: Uuid, mailbox: Uuid, uids: Option<&BTreeSet<u32>>) -> Result<Vec<u32>> {
        self.remove(account, mailbox, uids, true).await
    }

    /// Removes these emails from `mailbox` whatever their keywords (POP3 `DELE`); as with [`Mail::expunge`], an
    /// email in no other mailbox is destroyed.
    pub async fn remove_from_mailbox(&self, account: Uuid, mailbox: Uuid, uids: &BTreeSet<u32>) -> Result<Vec<u32>> {
        self.remove(account, mailbox, Some(uids), false).await
    }

    async fn remove(
        &self,
        account: Uuid,
        mailbox: Uuid,
        uids: Option<&BTreeSet<u32>>,
        only_deleted: bool,
    ) -> Result<Vec<u32>> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        owned(&mut tx, account, mailbox).await?;
        let rows = sqlx::query!(
            r#"SELECT em.uid, em.email_id,
                      EXISTS (SELECT 1 FROM email_mailboxes o WHERE o.email_id = em.email_id AND o.mailbox_id <> em.mailbox_id) AS "elsewhere!"
               FROM email_mailboxes em JOIN emails e ON e.id = em.email_id
               WHERE em.mailbox_id = $1 AND (NOT $2 OR '$deleted' = ANY(e.keywords)) ORDER BY em.uid"#,
            mailbox,
            only_deleted,
        )
        .fetch_all(&mut *tx)
        .await?;
        let rows: Vec<_> =
            rows.into_iter().filter(|row| uids.is_none_or(|uids| uids.contains(&(row.uid as u32)))).collect();
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let modseq = locked.next_modseq(&mut tx).await?;
        let mut removed = Vec::with_capacity(rows.len());
        for row in rows {
            if row.elsewhere {
                leave_mailbox(&mut tx, &locked, modseq, row.email_id, mailbox).await?;
            } else {
                destroy_in(&mut tx, &mut locked, modseq, row.email_id).await?;
            }
            removed.push(row.uid as u32);
        }
        tx.commit().await?;
        Ok(removed)
    }
}
