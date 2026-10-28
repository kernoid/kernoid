// SPDX-License-Identifier: AGPL-3.0-or-later
//! Emails (RFC 0002, 4): import, keywords, the mailboxes an email is in, destroying, reading and listing.

use std::collections::BTreeSet;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use kernoid_store::garbage;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    Locked, Mail, MailError, Result, blob_key,
    changes::{Change, ObjectType, record},
    mailbox::{next_uid, owned},
    parse::{self, Mailbox, Summary},
    thread,
};

/// A JMAP keyword, an IMAP flag: 1–255 printable ASCII characters without `( ) { ] % * " \`, kept lower case since
/// keywords are case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keyword(String);

impl Keyword {
    pub const SEEN: &'static str = "$seen";
    pub const DRAFT: &'static str = "$draft";
    pub const FLAGGED: &'static str = "$flagged";
    pub const ANSWERED: &'static str = "$answered";

    pub fn parse(keyword: &str) -> Result<Self> {
        let valid = (1..=255).contains(&keyword.len())
            && keyword.bytes().all(|b| (0x21..=0x7e).contains(&b) && !b"(){]%*\"\\".contains(&b));
        if !valid {
            return Err(MailError::Invalid(format!("{keyword:?} is not a keyword")));
        }
        Ok(Self(keyword.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a message enters the store.
#[derive(Debug, Clone, Default)]
pub struct NewEmail {
    /// At least one mailbox of the account.
    pub mailbox_ids: Vec<Uuid>,
    pub keywords: Vec<Keyword>,
    /// When it was received; now if not given (JMAP `Email/import` may set it).
    pub received_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Imported {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailInfo {
    pub id: Uuid,
    pub thread_id: Uuid,
    /// The mailboxes it is in, with its UID in each.
    pub mailboxes: Vec<(Uuid, u32)>,
    pub keywords: Vec<String>,
    pub size: u64,
    pub received_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub subject: Option<String>,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub sender: Vec<Mailbox>,
    pub preview: String,
    pub has_attachment: bool,
}

/// Which emails a query returns; all conditions must hold.
#[derive(Debug, Clone, Default)]
pub struct EmailQuery {
    pub in_mailbox: Option<Uuid>,
    pub has_keyword: Option<Keyword>,
    pub not_keyword: Option<Keyword>,
}

fn addresses(list: &[Mailbox]) -> serde_json::Value {
    serde_json::to_value(list).expect("addresses serialize")
}

fn read_addresses(value: serde_json::Value) -> Vec<Mailbox> {
    serde_json::from_value(value).unwrap_or_default()
}

fn unique(ids: &[Uuid]) -> Vec<Uuid> {
    ids.iter().copied().collect::<BTreeSet<_>>().into_iter().collect()
}

/// Whether a set of keywords counts the email as unread (RFC 8621, 2).
fn unread(keywords: &BTreeSet<String>) -> bool {
    !keywords.contains(Keyword::SEEN) && !keywords.contains(Keyword::DRAFT)
}

/// Removes an email from one mailbox it is not only in.
pub(crate) async fn leave_mailbox(
    tx: &mut Transaction<'static, Postgres>,
    locked: &Locked,
    modseq: i64,
    email: Uuid,
    mailbox: Uuid,
) -> Result<()> {
    let uid = sqlx::query_scalar!(
        "DELETE FROM email_mailboxes WHERE email_id = $1 AND mailbox_id = $2 RETURNING uid",
        email,
        mailbox
    )
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(uid) = uid {
        expunged(tx, mailbox, uid, modseq).await?;
    }
    sqlx::query!("UPDATE email_mailboxes SET modseq = $2 WHERE email_id = $1", email, modseq)
        .execute(&mut **tx)
        .await?;
    record(tx, locked.account, modseq, ObjectType::Email, email, Change::Updated).await?;
    record(tx, locked.account, modseq, ObjectType::Mailbox, mailbox, Change::Updated).await?;
    Ok(())
}

/// Keeps that `uid` left `mailbox` at `modseq`, for IMAP's `VANISHED`.
async fn expunged(tx: &mut Transaction<'static, Postgres>, mailbox: Uuid, uid: i64, modseq: i64) -> Result<()> {
    sqlx::query!(
        "INSERT INTO mailbox_expunged (mailbox_id, uid, modseq) VALUES ($1, $2, $3)
         ON CONFLICT (mailbox_id, uid) DO UPDATE SET modseq = $3",
        mailbox,
        uid,
        modseq,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Destroys an email in a change in progress: its rows go, its object becomes garbage, its thread ends with it if
/// it was the last one.
pub(crate) async fn destroy_in(
    tx: &mut Transaction<'static, Postgres>,
    locked: &mut Locked,
    modseq: i64,
    email: Uuid,
) -> Result<()> {
    let account = locked.account;
    let row = sqlx::query!(
        r#"SELECT thread_id, size,
                  array(SELECT mailbox_id FROM email_mailboxes WHERE email_id = e.id ORDER BY mailbox_id) AS "mailboxes!",
                  array(SELECT uid FROM email_mailboxes WHERE email_id = e.id ORDER BY mailbox_id) AS "uids!"
           FROM emails e WHERE id = $1 AND account_id = $2"#,
        email,
        account,
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(MailError::NotFound("the email"))?;
    sqlx::query!("DELETE FROM emails WHERE id = $1", email).execute(&mut **tx).await?;
    for (mailbox, uid) in row.mailboxes.into_iter().zip(row.uids) {
        expunged(tx, mailbox, uid, modseq).await?;
        record(tx, account, modseq, ObjectType::Mailbox, mailbox, Change::Updated).await?;
    }
    let others =
        sqlx::query_scalar!(r#"SELECT EXISTS (SELECT 1 FROM emails WHERE thread_id = $1) AS "others!""#, row.thread_id)
            .fetch_one(&mut **tx)
            .await?;
    if others {
        record(tx, account, modseq, ObjectType::Thread, row.thread_id, Change::Updated).await?;
    } else {
        sqlx::query!("DELETE FROM threads WHERE id = $1", row.thread_id).execute(&mut **tx).await?;
        record(tx, account, modseq, ObjectType::Thread, row.thread_id, Change::Destroyed).await?;
    }
    locked.used_bytes = sqlx::query_scalar!(
        "UPDATE mail_accounts SET used_bytes = greatest(used_bytes - $2, 0) WHERE account_id = $1 RETURNING used_bytes",
        account,
        row.size,
    )
    .fetch_one(&mut **tx)
    .await?;
    garbage::mark(tx, locked.tenant, &blob_key(account, email), Utc::now()).await?;
    record(tx, account, modseq, ObjectType::Email, email, Change::Destroyed).await?;
    Ok(())
}

impl Mail {
    /// Stores a raw message in the account: parsed, checked against size and quota, sealed into object storage,
    /// threaded and put into the given mailboxes. Delivery and JMAP `Email/import` both come here.
    pub async fn import_email(&self, account: Uuid, raw: Bytes, new: NewEmail) -> Result<Imported> {
        let size = raw.len() as u64;
        if size > self.limits.max_message_size {
            return Err(MailError::TooLarge { limit: self.limits.max_message_size });
        }
        let mailboxes = unique(&new.mailbox_ids);
        if mailboxes.is_empty() {
            return Err(MailError::Invalid("an email is in at least one mailbox".into()));
        }
        let parsed = raw.clone();
        let summary = tokio::task::spawn_blocking(move || parse::summarize(&parsed))
            .await
            .map_err(|_| MailError::Unparsable)?
            .ok_or(MailError::Unparsable)?;

        // A first look at the quota, before anything is written; checked again under the lock.
        let tenant = {
            let mut tx = self.pool.begin().await?;
            let locked = self.open(&mut tx, account).await?;
            tx.commit().await?;
            over_quota(&locked, size)?;
            locked.tenant
        };
        let id = Uuid::now_v7();
        let key = blob_key(account, id);
        garbage::pending(&self.pool, tenant, &key).await?;
        self.blobs.put(tenant, &key, raw).await?;
        match self.store_imported(account, id, size, &mailboxes, &new, &summary).await {
            Ok(imported) => Ok(imported),
            Err(error) => {
                // The mark collects it later if this fails as well.
                if let Err(blob_error) = self.blobs.delete(tenant, &key).await {
                    tracing::warn!(error = %blob_error, "removing the object of a failed import");
                }
                Err(error)
            }
        }
    }

    async fn store_imported(
        &self,
        account: Uuid,
        id: Uuid,
        size: u64,
        mailboxes: &[Uuid],
        new: &NewEmail,
        summary: &Summary,
    ) -> Result<Imported> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        over_quota(&locked, size)?;
        for mailbox in mailboxes {
            owned(&mut tx, account, *mailbox).await?;
        }
        if !garbage::keep(&mut tx, locked.tenant, &blob_key(account, id)).await? {
            return Err(MailError::Invalid("the import took too long".into()));
        }
        let modseq = locked.next_modseq(&mut tx).await?;

        let references = thread::references(summary);
        let subject_hash = thread::subject_hash(&summary.base_subject);
        let thread_id = match thread::find(&mut tx, account, &subject_hash, &references).await? {
            Some(thread_id) => {
                record(&mut tx, account, modseq, ObjectType::Thread, thread_id, Change::Updated).await?;
                thread_id
            }
            None => {
                let thread_id = Uuid::now_v7();
                sqlx::query!("INSERT INTO threads (id, account_id) VALUES ($1, $2)", thread_id, account)
                    .execute(&mut *tx)
                    .await?;
                record(&mut tx, account, modseq, ObjectType::Thread, thread_id, Change::Created).await?;
                thread_id
            }
        };
        let keywords: Vec<String> = new
            .keywords
            .iter()
            .map(|keyword| keyword.as_str().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        sqlx::query!(
            r#"INSERT INTO emails (id, account_id, thread_id, size, received_at, sent_at, message_id, in_reply_to,
                                   "references", subject, from_addresses, to_addresses, cc_addresses, bcc_addresses,
                                   reply_to, sender, preview, has_attachment, keywords, body_search)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
                       to_tsvector('simple', $20))"#,
            id,
            account,
            thread_id,
            size as i64,
            new.received_at.unwrap_or_else(Utc::now),
            summary.sent_at,
            summary.message_id,
            &summary.in_reply_to,
            &summary.references,
            summary.subject,
            addresses(&summary.from),
            addresses(&summary.to),
            addresses(&summary.cc),
            addresses(&summary.bcc),
            addresses(&summary.reply_to),
            addresses(&summary.sender),
            summary.preview,
            summary.has_attachment,
            &keywords,
            summary.search_text,
        )
        .execute(&mut *tx)
        .await?;
        thread::remember(&mut tx, account, id, &subject_hash, &references).await?;
        for mailbox in mailboxes {
            let uid = next_uid(&mut tx, *mailbox).await?;
            sqlx::query!(
                "INSERT INTO email_mailboxes (email_id, mailbox_id, uid, modseq) VALUES ($1, $2, $3, $4)",
                id,
                mailbox,
                uid,
                modseq,
            )
            .execute(&mut *tx)
            .await?;
            record(&mut tx, account, modseq, ObjectType::Mailbox, *mailbox, Change::Updated).await?;
        }
        sqlx::query!(
            "UPDATE mail_accounts SET used_bytes = used_bytes + $2 WHERE account_id = $1",
            account,
            size as i64
        )
        .execute(&mut *tx)
        .await?;
        record(&mut tx, account, modseq, ObjectType::Email, id, Change::Created).await?;
        tx.commit().await?;
        Ok(Imported { id, thread_id, size })
    }

    /// Replaces the keywords of an email.
    pub async fn set_keywords(&self, account: Uuid, email: Uuid, keywords: &[Keyword]) -> Result<()> {
        let keywords: BTreeSet<String> = keywords.iter().map(|keyword| keyword.as_str().to_owned()).collect();
        self.change_keywords(account, email, |current| *current = keywords).await
    }

    /// Adds and removes keywords of an email; the others stay.
    pub async fn update_keywords(&self, account: Uuid, email: Uuid, add: &[Keyword], remove: &[Keyword]) -> Result<()> {
        self.change_keywords(account, email, |current| {
            for keyword in remove {
                current.remove(keyword.as_str());
            }
            for keyword in add {
                current.insert(keyword.as_str().to_owned());
            }
        })
        .await
    }

    async fn change_keywords(
        &self,
        account: Uuid,
        email: Uuid,
        change: impl FnOnce(&mut BTreeSet<String>),
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        let row = sqlx::query!(
            r#"SELECT keywords, array(SELECT mailbox_id FROM email_mailboxes WHERE email_id = e.id) AS "mailboxes!"
               FROM emails e WHERE id = $1 AND account_id = $2"#,
            email,
            account,
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MailError::NotFound("the email"))?;
        let before: BTreeSet<String> = row.keywords.into_iter().collect();
        let mut after = before.clone();
        change(&mut after);
        if after == before {
            return Ok(());
        }
        let modseq = locked.next_modseq(&mut tx).await?;
        let keywords: Vec<String> = after.iter().cloned().collect();
        sqlx::query!("UPDATE emails SET keywords = $2 WHERE id = $1", email, &keywords).execute(&mut *tx).await?;
        sqlx::query!("UPDATE email_mailboxes SET modseq = $2 WHERE email_id = $1", email, modseq)
            .execute(&mut *tx)
            .await?;
        record(&mut tx, account, modseq, ObjectType::Email, email, Change::Updated).await?;
        if unread(&before) != unread(&after) {
            // The unread counts of its mailboxes changed.
            for mailbox in row.mailboxes {
                record(&mut tx, account, modseq, ObjectType::Mailbox, mailbox, Change::Updated).await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Puts an email into exactly these mailboxes (JMAP `mailboxIds`): it gets a new UID in each one it enters.
    /// Moving is leaving one and entering another.
    pub async fn set_mailboxes(&self, account: Uuid, email: Uuid, mailbox_ids: &[Uuid]) -> Result<()> {
        let wanted: BTreeSet<Uuid> = mailbox_ids.iter().copied().collect();
        if wanted.is_empty() {
            return Err(MailError::Invalid("an email is in at least one mailbox; destroy it instead".into()));
        }
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        let current: BTreeSet<Uuid> = sqlx::query_scalar!(
            r#"SELECT array(SELECT mailbox_id FROM email_mailboxes WHERE email_id = e.id) AS "mailboxes!"
               FROM emails e WHERE id = $1 AND account_id = $2"#,
            email,
            account,
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MailError::NotFound("the email"))?
        .into_iter()
        .collect();
        if current == wanted {
            return Ok(());
        }
        for mailbox in wanted.difference(&current) {
            owned(&mut tx, account, *mailbox).await?;
        }
        let modseq = locked.next_modseq(&mut tx).await?;
        for mailbox in current.difference(&wanted) {
            let uid = sqlx::query_scalar!(
                "DELETE FROM email_mailboxes WHERE email_id = $1 AND mailbox_id = $2 RETURNING uid",
                email,
                mailbox
            )
            .fetch_one(&mut *tx)
            .await?;
            expunged(&mut tx, *mailbox, uid, modseq).await?;
            record(&mut tx, account, modseq, ObjectType::Mailbox, *mailbox, Change::Updated).await?;
        }
        sqlx::query!("UPDATE email_mailboxes SET modseq = $2 WHERE email_id = $1", email, modseq)
            .execute(&mut *tx)
            .await?;
        for mailbox in wanted.difference(&current) {
            let uid = next_uid(&mut tx, *mailbox).await?;
            sqlx::query!(
                "INSERT INTO email_mailboxes (email_id, mailbox_id, uid, modseq) VALUES ($1, $2, $3, $4)",
                email,
                mailbox,
                uid,
                modseq,
            )
            .execute(&mut *tx)
            .await?;
            record(&mut tx, account, modseq, ObjectType::Mailbox, *mailbox, Change::Updated).await?;
        }
        record(&mut tx, account, modseq, ObjectType::Email, email, Change::Updated).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Destroys an email; its object is removed by the worker.
    pub async fn destroy_email(&self, account: Uuid, email: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        let modseq = locked.next_modseq(&mut tx).await?;
        destroy_in(&mut tx, &mut locked, modseq, email).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The emails of the account with these ids; ids it does not have are left out.
    pub async fn emails(&self, account: Uuid, ids: &[Uuid]) -> Result<Vec<EmailInfo>> {
        let rows = sqlx::query!(
            r#"SELECT id, thread_id, size, received_at, sent_at, message_id, in_reply_to, "references", subject,
                      from_addresses, to_addresses, cc_addresses, bcc_addresses, reply_to, sender, preview,
                      has_attachment, keywords,
                      array(SELECT mailbox_id FROM email_mailboxes WHERE email_id = e.id ORDER BY mailbox_id) AS "mailboxes!",
                      array(SELECT uid FROM email_mailboxes WHERE email_id = e.id ORDER BY mailbox_id) AS "uids!"
               FROM emails e WHERE account_id = $1 AND id = ANY($2)
               ORDER BY received_at DESC, id DESC"#,
            account,
            ids,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| EmailInfo {
                id: row.id,
                thread_id: row.thread_id,
                mailboxes: row.mailboxes.into_iter().zip(row.uids.into_iter().map(|uid| uid as u32)).collect(),
                keywords: row.keywords,
                size: row.size as u64,
                received_at: row.received_at,
                sent_at: row.sent_at,
                message_id: row.message_id,
                in_reply_to: row.in_reply_to,
                references: row.references,
                subject: row.subject,
                from: read_addresses(row.from_addresses),
                to: read_addresses(row.to_addresses),
                cc: read_addresses(row.cc_addresses),
                bcc: read_addresses(row.bcc_addresses),
                reply_to: read_addresses(row.reply_to),
                sender: read_addresses(row.sender),
                preview: row.preview,
                has_attachment: row.has_attachment,
            })
            .collect())
    }

    pub async fn email(&self, account: Uuid, id: Uuid) -> Result<EmailInfo> {
        self.emails(account, &[id]).await?.pop().ok_or(MailError::NotFound("the email"))
    }

    /// The raw message as it was received, from object storage.
    pub async fn raw_email(&self, account: Uuid, id: Uuid) -> Result<Bytes> {
        let tenant = sqlx::query_scalar!(
            "SELECT m.tenant_id FROM emails e JOIN mail_accounts m ON m.account_id = e.account_id
             WHERE e.id = $1 AND e.account_id = $2",
            id,
            account,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MailError::NotFound("the email"))?;
        Ok(self.blobs.get(tenant, &blob_key(account, id)).await?)
    }

    /// The emails of a thread, oldest first.
    pub async fn thread(&self, account: Uuid, thread: Uuid) -> Result<Vec<Uuid>> {
        let ids = sqlx::query_scalar!(
            "SELECT id FROM emails WHERE account_id = $1 AND thread_id = $2 ORDER BY received_at, id",
            account,
            thread,
        )
        .fetch_all(&self.pool)
        .await?;
        if ids.is_empty() {
            return Err(MailError::NotFound("the thread"));
        }
        Ok(ids)
    }

    /// Ids of the emails that match, newest first, from `position` on, at most `limit`; and how many match in all.
    pub async fn query(
        &self,
        account: Uuid,
        query: &EmailQuery,
        position: u64,
        limit: u64,
    ) -> Result<(Vec<Uuid>, u64)> {
        let in_mailbox = query.in_mailbox;
        let has = query.has_keyword.as_ref().map(Keyword::as_str);
        let not = query.not_keyword.as_ref().map(Keyword::as_str);
        // One snapshot for the page and the total.
        let mut tx = self.pool.begin().await?;
        sqlx::query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
        let total = sqlx::query_scalar!(
            r#"SELECT count(*) AS "total!" FROM emails e
               WHERE account_id = $1
                 AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM email_mailboxes em WHERE em.email_id = e.id AND em.mailbox_id = $2))
                 AND ($3::text IS NULL OR $3 = ANY(keywords))
                 AND ($4::text IS NULL OR NOT $4 = ANY(keywords))"#,
            account,
            in_mailbox,
            has,
            not,
        )
        .fetch_one(&mut *tx)
        .await?;
        let ids = sqlx::query_scalar!(
            r#"SELECT id FROM emails e
               WHERE account_id = $1
                 AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM email_mailboxes em WHERE em.email_id = e.id AND em.mailbox_id = $2))
                 AND ($3::text IS NULL OR $3 = ANY(keywords))
                 AND ($4::text IS NULL OR NOT $4 = ANY(keywords))
               ORDER BY received_at DESC, id DESC
               OFFSET $5 LIMIT $6"#,
            account,
            in_mailbox,
            has,
            not,
            i64::try_from(position).unwrap_or(i64::MAX),
            i64::try_from(limit).unwrap_or(i64::MAX),
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((ids, total as u64))
    }
}

fn over_quota(locked: &Locked, size: u64) -> Result<()> {
    match locked.quota {
        Some(quota) if locked.used_bytes.saturating_add(size as i64) > quota => Err(MailError::OverQuota),
        _ => Ok(()),
    }
}
