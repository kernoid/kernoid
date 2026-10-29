// SPDX-License-Identifier: AGPL-3.0-or-later
//! The mail store of each account (RFC 0002): mailboxes, emails and threads in PostgreSQL, the raw messages in
//! object storage, sealed per tenant, and a journal of changes for JMAP and IMAP.
//!
//! Mail is data, not events: changes are ordinary transactions. Each takes the account's `mail_accounts` row first,
//! so that changes to one account happen one after another and each gets the next modification sequence. Who may
//! reach which account is decided by the protocols above; the functions here act on the account they are given.

mod access;
mod changes;
mod deliver;
mod email;
mod events;
mod imap;
mod mailbox;
mod mbox;
mod outbox;
mod parse;
mod scripts;
mod search;
pub mod srs;
mod store;
mod thread;
mod uploads;
mod vacation;

pub use access::{Access, Rights, SharedStore};
pub use changes::{Changes, ObjectType};
pub use deliver::{Delivered, Delivery, Recipient, without_subaddress};
pub use email::{EmailInfo, EmailQuery, Imported, Keyword, NewEmail};
pub use events::MailEvents;
pub use imap::MailboxEntry;
pub use mailbox::{MailboxInfo, MailboxUpdate, NewMailbox, Role};
pub use mbox::{MboxImport, MboxMessage, mbox_entry, read_mbox};
pub use outbox::{Batch, Leased, Outgoing, QueuedRecipient};
pub use parse::{Mailbox as AddressInfo, search_query};
pub use scripts::{SieveScript, check_script};
pub use store::{StoreChange, StoreRead};
pub use uploads::{UPLOAD_LIFETIME, Upload};
pub use vacation::VacationResponse;

use kernoid_store::{BlobError, BlobStore, PgPool};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("{0} does not exist")]
    NotFound(&'static str),
    #[error("{0} exists already")]
    Exists(&'static str),
    #[error("{0}")]
    Invalid(String),
    /// The message is larger than the installation accepts.
    #[error("the message is larger than {limit} bytes")]
    TooLarge { limit: u64 },
    /// Storing it would take the account over its quota (JMAP `overQuota`).
    #[error("the account's quota does not leave room for it")]
    OverQuota,
    #[error("the mailbox has child mailboxes")]
    MailboxHasChild,
    #[error("the mailbox has emails")]
    MailboxHasEmail,
    /// The state is older than the journal kept (JMAP `cannotCalculateChanges`).
    #[error("the changes since this state are no longer known")]
    CannotCalculateChanges,
    #[error("the message could not be parsed")]
    Unparsable,
    #[error(transparent)]
    Store(#[from] sqlx::Error),
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// The malware scanner refused the content (`kernoid_store::scan`).
    #[error(transparent)]
    Refused(#[from] kernoid_store::scan::Refused),
}

pub type Result<T> = std::result::Result<T, MailError>;

/// Limits of the mail store, from `[mail]` and `[smtp]` in the configuration.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest raw message accepted, in bytes.
    pub max_message_size: u64,
    /// How long the queue tries what the store sends itself (Sieve).
    pub queue_lifetime: chrono::Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_message_size: 50 * 1024 * 1024, queue_lifetime: chrono::Duration::days(5) }
    }
}

#[derive(Debug, Clone)]
pub struct Mail {
    pool: PgPool,
    blobs: BlobStore,
    limits: Limits,
}

/// An account's mail store as a transaction sees it after taking its row.
#[derive(Debug, Clone, Copy)]
struct Locked {
    account: Uuid,
    tenant: Uuid,
    modseq: i64,
    used_bytes: i64,
    quota: Option<i64>,
}

impl Mail {
    pub fn new(pool: PgPool, blobs: BlobStore, limits: Limits) -> Self {
        Self { pool, blobs, limits }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// How long the queue tries what the store sends itself.
    pub fn queue_lifetime(&self) -> chrono::Duration {
        self.limits.queue_lifetime
    }

    /// Creates the account's mail store with its default mailboxes, unless it exists.
    pub async fn ensure_account(&self, account: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.lock(&mut tx, account).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Starts a change: creates the mail store if needed and takes its row until the transaction ends.
    async fn lock(&self, tx: &mut Transaction<'static, Postgres>, account: Uuid) -> Result<Locked> {
        let created = sqlx::query_scalar!(
            "INSERT INTO mail_accounts (account_id, tenant_id)
             SELECT id, tenant_id FROM accounts WHERE id = $1
             ON CONFLICT (account_id) DO NOTHING
             RETURNING account_id",
            account,
        )
        .fetch_optional(&mut **tx)
        .await?;
        let row = sqlx::query!(
            "SELECT m.tenant_id, m.modseq, m.used_bytes, coalesce(a.mail_quota, t.default_mail_quota) AS mail_quota
             FROM mail_accounts m JOIN accounts a ON a.id = m.account_id JOIN tenants t ON t.id = a.tenant_id
             WHERE m.account_id = $1 FOR UPDATE OF m",
            account,
        )
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(MailError::NotFound("the account"))?;
        let mut locked = Locked {
            account,
            tenant: row.tenant_id,
            modseq: row.modseq,
            used_bytes: row.used_bytes,
            quota: row.mail_quota,
        };
        if created.is_some() {
            mailbox::create_defaults(tx, &mut locked).await?;
        }
        Ok(locked)
    }

    /// Starts a read: the mail store as it is, created first if needed, without taking its row.
    async fn open(&self, tx: &mut Transaction<'static, Postgres>, account: Uuid) -> Result<Locked> {
        let row = sqlx::query!(
            "SELECT m.tenant_id, m.modseq, m.used_bytes, coalesce(a.mail_quota, t.default_mail_quota) AS mail_quota
             FROM mail_accounts m JOIN accounts a ON a.id = m.account_id JOIN tenants t ON t.id = a.tenant_id
             WHERE m.account_id = $1",
            account,
        )
        .fetch_optional(&mut **tx)
        .await?;
        match row {
            Some(row) => Ok(Locked {
                account,
                tenant: row.tenant_id,
                modseq: row.modseq,
                used_bytes: row.used_bytes,
                quota: row.mail_quota,
            }),
            None => self.lock(tx, account).await,
        }
    }

    /// The account's current state: the modification sequence of its last change (JMAP state, IMAP
    /// `HIGHESTMODSEQ`).
    pub async fn state(&self, account: Uuid) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        tx.commit().await?;
        Ok(locked.modseq as u64)
    }

    /// Bytes used by the account's emails and its quota – its own, or else the tenant's default – if any.
    pub async fn quota(&self, account: Uuid) -> Result<(u64, Option<u64>)> {
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        tx.commit().await?;
        Ok((locked.used_bytes as u64, locked.quota.map(|quota| quota as u64)))
    }
}

impl Locked {
    /// Takes the next modification sequence for the change in progress.
    /// Takes the next modification sequence for the change in progress, and tells whoever listens on
    /// [`CHANNEL`] – at the commit, with the transaction (JMAP push, IMAP `IDLE`).
    async fn next_modseq(&mut self, connection: &mut PgConnection) -> Result<i64> {
        self.modseq = sqlx::query_scalar!(
            "UPDATE mail_accounts SET modseq = modseq + 1 WHERE account_id = $1 RETURNING modseq",
            self.account
        )
        .fetch_one(&mut *connection)
        .await?;
        sqlx::query!("SELECT pg_notify('kernoid_mail', $1)", self.account.to_string()).execute(connection).await?;
        Ok(self.modseq)
    }
}

/// The PostgreSQL channel every change to an account's mail is announced on, with the account's id as payload.
pub const CHANNEL: &str = "kernoid_mail";

/// The object key of an email's raw message, below the tenant's prefix.
fn blob_key(account: Uuid, email: Uuid) -> String {
    format!("mail/{account}/{email}")
}
