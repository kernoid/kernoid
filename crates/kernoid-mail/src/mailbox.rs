// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mailboxes (RFC 0002, 3): a tree per account, with roles, IMAP UIDs and counts computed when asked.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    Locked, Mail, MailError, Result,
    changes::{Change, ObjectType, record},
    email,
};

/// What a mailbox is for (the IANA registry RFC 8621 uses); each at most once per account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Inbox,
    Drafts,
    Sent,
    Archive,
    Junk,
    Trash,
}

impl Role {
    pub const ALL: [Self; 6] = [Self::Inbox, Self::Drafts, Self::Sent, Self::Archive, Self::Junk, Self::Trash];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Drafts => "drafts",
            Self::Sent => "sent",
            Self::Archive => "archive",
            Self::Junk => "junk",
            Self::Trash => "trash",
        }
    }

    pub fn parse(role: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|candidate| candidate.as_str().eq_ignore_ascii_case(role))
    }

    /// The name of the default mailbox with this role; clients show their own by role.
    fn default_name(self) -> &'static str {
        match self {
            Self::Inbox => "Inbox",
            Self::Drafts => "Drafts",
            Self::Sent => "Sent",
            Self::Archive => "Archive",
            Self::Junk => "Junk",
            Self::Trash => "Trash",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxInfo {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub role: Option<Role>,
    pub sort_order: u32,
    pub is_subscribed: bool,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub total_emails: u64,
    /// Emails with neither `$seen` nor `$draft` (RFC 8621, 2).
    pub unread_emails: u64,
    pub total_threads: u64,
    /// Threads with an email in this mailbox and an unread email.
    pub unread_threads: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NewMailbox {
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub role: Option<Role>,
    pub sort_order: u32,
    pub is_subscribed: bool,
}

/// Changes to a mailbox; `None` leaves a field as it is.
#[derive(Debug, Clone, Default)]
pub struct MailboxUpdate {
    pub name: Option<String>,
    pub parent_id: Option<Option<Uuid>>,
    pub role: Option<Option<Role>>,
    pub sort_order: Option<u32>,
    pub is_subscribed: Option<bool>,
}

/// 1–255 characters, no control characters and no `/`, IMAP's hierarchy separator in kernoid.
fn valid_name(name: &str) -> Result<&str> {
    let length = name.chars().count();
    if name.trim().is_empty() || length > 255 {
        return Err(MailError::Invalid("a mailbox name has 1 to 255 characters".into()));
    }
    if name.chars().any(|c| c.is_control() || c == '/') {
        return Err(MailError::Invalid("a mailbox name has no control characters and no '/'".into()));
    }
    Ok(name)
}

/// A new UIDVALIDITY: random, so that a mailbox made again under the same name gets another one.
fn uid_validity() -> i64 {
    loop {
        let value = getrandom::u32().expect("the system's random source");
        if value != 0 {
            return i64::from(value);
        }
    }
}

fn unique_violation(error: sqlx::Error) -> MailError {
    match error.as_database_error().and_then(|error| error.constraint()) {
        Some("mailboxes_one_role") => MailError::Exists("a mailbox with this role"),
        Some("mailboxes_unique_name") => MailError::Exists("a mailbox with this name"),
        _ => error.into(),
    }
}

/// The default mailboxes of a new mail store, in one change.
pub(crate) async fn create_defaults(tx: &mut Transaction<'static, Postgres>, locked: &mut Locked) -> Result<()> {
    let modseq = locked.next_modseq(tx).await?;
    for (position, role) in Role::ALL.into_iter().enumerate() {
        let id = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO mailboxes (id, account_id, name, role, sort_order, uid_validity) VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            locked.account,
            role.default_name(),
            role.as_str(),
            position as i32,
            uid_validity(),
        )
        .execute(&mut **tx)
        .await?;
        record(tx, locked.account, modseq, ObjectType::Mailbox, id, Change::Created).await?;
    }
    Ok(())
}

/// Checks that `mailbox` belongs to the account.
pub(crate) async fn owned(tx: &mut Transaction<'static, Postgres>, account: Uuid, mailbox: Uuid) -> Result<()> {
    sqlx::query_scalar!("SELECT 1 AS \"one!\" FROM mailboxes WHERE id = $1 AND account_id = $2", mailbox, account)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(MailError::NotFound("the mailbox"))?;
    Ok(())
}

/// Hands out the next UID of `mailbox`.
pub(crate) async fn next_uid(tx: &mut Transaction<'static, Postgres>, mailbox: Uuid) -> Result<i64> {
    let uid = sqlx::query_scalar!(
        "UPDATE mailboxes SET uid_next = uid_next + 1 WHERE id = $1 AND uid_next <= 4294967295 RETURNING uid_next - 1 AS \"uid!\"",
        mailbox,
    )
    .fetch_optional(&mut **tx)
    .await?;
    uid.ok_or_else(|| MailError::Invalid("the mailbox has no UIDs left; make a new one".into()))
}

impl Mail {
    /// The account's mailboxes with their counts.
    pub async fn mailboxes(&self, account: Uuid) -> Result<Vec<MailboxInfo>> {
        let mut tx = self.pool.begin().await?;
        self.open(&mut tx, account).await?;
        let rows = sqlx::query!(
            r#"SELECT m.id, m.parent_id, m.name, m.role, m.sort_order, m.is_subscribed, m.uid_validity, m.uid_next,
                      count(em.email_id) AS "total!",
                      count(em.email_id) FILTER (WHERE NOT e.keywords && ARRAY['$seen', '$draft']) AS "unread!",
                      count(DISTINCT e.thread_id) AS "threads!",
                      count(DISTINCT e.thread_id) FILTER (WHERE EXISTS (
                          SELECT 1 FROM emails t WHERE t.thread_id = e.thread_id
                          AND NOT t.keywords && ARRAY['$seen', '$draft'])) AS "unread_threads!"
               FROM mailboxes m
               LEFT JOIN email_mailboxes em ON em.mailbox_id = m.id
               LEFT JOIN emails e ON e.id = em.email_id
               WHERE m.account_id = $1
               GROUP BY m.id
               ORDER BY m.sort_order, m.name"#,
            account,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|row| MailboxInfo {
                id: row.id,
                parent_id: row.parent_id,
                name: row.name,
                role: row.role.as_deref().and_then(Role::parse),
                sort_order: row.sort_order as u32,
                is_subscribed: row.is_subscribed,
                uid_validity: row.uid_validity as u32,
                uid_next: row.uid_next.min(i64::from(u32::MAX)) as u32,
                total_emails: row.total as u64,
                unread_emails: row.unread as u64,
                total_threads: row.threads as u64,
                unread_threads: row.unread_threads as u64,
            })
            .collect())
    }

    /// The account's mailbox with `role`.
    pub async fn mailbox_with_role(&self, account: Uuid, role: Role) -> Result<Uuid> {
        let mut tx = self.pool.begin().await?;
        self.open(&mut tx, account).await?;
        let id =
            sqlx::query_scalar!("SELECT id FROM mailboxes WHERE account_id = $1 AND role = $2", account, role.as_str())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(MailError::NotFound("a mailbox with this role"))?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn create_mailbox(&self, account: Uuid, new: NewMailbox) -> Result<Uuid> {
        let name = valid_name(&new.name)?;
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        if let Some(parent) = new.parent_id {
            owned(&mut tx, account, parent).await?;
        }
        let id = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO mailboxes (id, account_id, parent_id, name, role, sort_order, is_subscribed, uid_validity)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            id,
            account,
            new.parent_id,
            name,
            new.role.map(Role::as_str),
            i32::try_from(new.sort_order).unwrap_or(i32::MAX),
            new.is_subscribed,
            uid_validity(),
        )
        .execute(&mut *tx)
        .await
        .map_err(unique_violation)?;
        let modseq = locked.next_modseq(&mut tx).await?;
        record(&mut tx, account, modseq, ObjectType::Mailbox, id, Change::Created).await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn update_mailbox(&self, account: Uuid, id: Uuid, update: MailboxUpdate) -> Result<()> {
        if let Some(name) = &update.name {
            valid_name(name)?;
        }
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        let current = sqlx::query!("SELECT role FROM mailboxes WHERE id = $1 AND account_id = $2", id, account)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(MailError::NotFound("the mailbox"))?;
        if let Some(Some(parent)) = update.parent_id {
            owned(&mut tx, account, parent).await?;
            // The new parent must not be the mailbox itself or below it.
            let below = sqlx::query_scalar!(
                r#"WITH RECURSIVE up (id, parent_id) AS (
                       SELECT id, parent_id FROM mailboxes WHERE id = $1
                       UNION ALL
                       SELECT m.id, m.parent_id FROM mailboxes m JOIN up ON m.id = up.parent_id)
                   SELECT EXISTS (SELECT 1 FROM up WHERE id = $2) AS "below!""#,
                parent,
                id,
            )
            .fetch_one(&mut *tx)
            .await?;
            if below {
                return Err(MailError::Invalid("a mailbox cannot move below itself".into()));
            }
        }
        if current.role.as_deref() == Some(Role::Inbox.as_str())
            && matches!(update.role, Some(role) if role != Some(Role::Inbox))
        {
            return Err(MailError::Invalid("the inbox keeps its role".into()));
        }
        sqlx::query!(
            "UPDATE mailboxes SET
                 name = coalesce($3, name),
                 parent_id = CASE WHEN $4 THEN $5 ELSE parent_id END,
                 role = CASE WHEN $6 THEN $7 ELSE role END,
                 sort_order = coalesce($8, sort_order),
                 is_subscribed = coalesce($9, is_subscribed)
             WHERE id = $1 AND account_id = $2",
            id,
            account,
            update.name,
            update.parent_id.is_some(),
            update.parent_id.flatten(),
            update.role.is_some(),
            update.role.flatten().map(Role::as_str),
            update.sort_order.map(|order| i32::try_from(order).unwrap_or(i32::MAX)),
            update.is_subscribed,
        )
        .execute(&mut *tx)
        .await
        .map_err(unique_violation)?;
        let modseq = locked.next_modseq(&mut tx).await?;
        record(&mut tx, account, modseq, ObjectType::Mailbox, id, Change::Updated).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Destroys a mailbox without children. Its emails stop it from going unless `remove_emails`: then emails in
    /// no other mailbox are destroyed and the others only leave it. The inbox cannot be destroyed.
    pub async fn destroy_mailbox(&self, account: Uuid, id: Uuid, remove_emails: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let mut locked = self.lock(&mut tx, account).await?;
        let mailbox = sqlx::query!(
            r#"SELECT role,
                      EXISTS (SELECT 1 FROM mailboxes c WHERE c.parent_id = m.id) AS "has_child!",
                      EXISTS (SELECT 1 FROM email_mailboxes em WHERE em.mailbox_id = m.id) AS "has_email!"
               FROM mailboxes m WHERE id = $1 AND account_id = $2"#,
            id,
            account,
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(MailError::NotFound("the mailbox"))?;
        if mailbox.role.as_deref() == Some(Role::Inbox.as_str()) {
            return Err(MailError::Invalid("the inbox cannot be destroyed".into()));
        }
        if mailbox.has_child {
            return Err(MailError::MailboxHasChild);
        }
        if mailbox.has_email && !remove_emails {
            return Err(MailError::MailboxHasEmail);
        }
        let modseq = locked.next_modseq(&mut tx).await?;
        let emails = sqlx::query!(
            r#"SELECT em.email_id,
                      EXISTS (SELECT 1 FROM email_mailboxes o WHERE o.email_id = em.email_id AND o.mailbox_id <> em.mailbox_id) AS "elsewhere!"
               FROM email_mailboxes em WHERE em.mailbox_id = $1"#,
            id,
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in emails {
            if row.elsewhere {
                email::leave_mailbox(&mut tx, &locked, modseq, row.email_id, id).await?;
            } else {
                email::destroy_in(&mut tx, &mut locked, modseq, row.email_id).await?;
            }
        }
        sqlx::query!("DELETE FROM mailboxes WHERE id = $1", id).execute(&mut *tx).await?;
        // Emails that left it recorded it as updated; destroyed wins.
        sqlx::query!(
            "DELETE FROM mail_changes WHERE account_id = $1 AND object_type = 'mailbox' AND modseq = $2 AND object_id = $3",
            account,
            modseq,
            id,
        )
        .execute(&mut *tx)
        .await?;
        record(&mut tx, account, modseq, ObjectType::Mailbox, id, Change::Destroyed).await?;
        tx.commit().await?;
        Ok(())
    }
}
