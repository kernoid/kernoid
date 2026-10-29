// SPDX-License-Identifier: AGPL-3.0-or-later
//! The file store of each account (RFC 0005): directories and files in PostgreSQL, their content and its versions in
//! object storage, sealed per tenant and stored in parts, a journal of changes for JMAP's `FileNode` and WebDAV, who
//! may do what (`access`), and WebDAV's locks. A drive is the store of an account of the tenant nobody logs in as.
//!
//! Files are data, not events: changes are ordinary transactions. Each takes the account's `file_accounts` row first,
//! so that changes to one account happen one after another and each gets the next modification sequence. It is a
//! store of its own beside the mail store – an account may have files without a mailbox. Who may reach which account
//! is decided here: the functions that change a store take the [`FileAccess`] of whoever acts.

mod access;
mod changes;
mod content;
pub mod copy;
pub mod housekeeping;
mod locks;
mod node;

pub use access::{FileAccess, Rights, SharedStore, View};
pub use changes::{Changes, prune_changes};
pub use content::{Content, ContentInfo, Readable};
pub use locks::{Lock, LockRequest};
pub use node::{
    FORBIDDEN_CHARS, MAX_DEPTH, MAX_DESTROY, MAX_NAME, NewNode, NodeInfo, NodeType, NodeUpdate, OnExists, Role,
    SetOptions, Written, check_media_type, check_name,
};

use kernoid_store::{BlobError, BlobStore, PgPool};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error("{0} does not exist")]
    NotFound(&'static str),
    #[error("{0}")]
    Invalid(String),
    /// A sibling has the name already (JMAP `alreadyExists`); its id.
    #[error("a node of this name exists already")]
    AlreadyExists(Uuid),
    /// Not allowed whoever asks: changing a directory with a role (JMAP `forbidden`).
    #[error("{0}")]
    Forbidden(String),
    /// The directory has children and the caller did not say to remove them (JMAP `nodeHasChildren`).
    #[error("the directory is not empty")]
    HasChildren,
    #[error("the file is larger than {limit} bytes")]
    TooLarge { limit: u64 },
    /// A WebDAV lock of someone else holds the node (HTTP 423).
    #[error("the node is locked")]
    Locked,
    /// Storing it would take the account over its quota (JMAP `overQuota`).
    #[error("the account's quota does not leave room for it")]
    OverQuota,
    /// The state is older than the journal kept (JMAP `cannotCalculateChanges`).
    #[error("the changes since this state are no longer known")]
    CannotCalculateChanges,
    #[error(transparent)]
    Store(#[from] sqlx::Error),
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// The malware scanner refused the content (`kernoid_store::scan`).
    #[error(transparent)]
    Refused(#[from] kernoid_store::scan::Refused),
}

pub type Result<T> = std::result::Result<T, FilesError>;

/// Limits of the file store, from `[files]` in the configuration.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest file accepted, in bytes.
    pub max_file_size: u64,
    /// Earlier contents kept per file.
    pub versions_kept: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_file_size: 10 * 1024 * 1024 * 1024, versions_kept: 10 }
    }
}

#[derive(Debug, Clone)]
pub struct Files {
    pool: PgPool,
    blobs: BlobStore,
    limits: Limits,
}

/// An account's file store as a transaction sees it after taking its row.
#[derive(Debug, Clone, Copy)]
struct Locked {
    account: Uuid,
    tenant: Uuid,
    modseq: i64,
    used_bytes: i64,
    quota: Option<i64>,
}

impl Files {
    pub fn new(pool: PgPool, blobs: BlobStore, limits: Limits) -> Self {
        Self { pool, blobs, limits }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Starts a change: creates the file store if needed and takes its row until the transaction ends.
    async fn lock_store(&self, tx: &mut Transaction<'static, Postgres>, account: Uuid) -> Result<Locked> {
        let created = sqlx::query_scalar!(
            "INSERT INTO file_accounts (account_id, tenant_id)
             SELECT id, tenant_id FROM accounts WHERE id = $1
             ON CONFLICT (account_id) DO NOTHING
             RETURNING account_id",
            account,
        )
        .fetch_optional(&mut **tx)
        .await?;
        let row = sqlx::query!(
            "SELECT f.tenant_id, f.modseq, f.used_bytes, coalesce(a.files_quota, t.default_files_quota) AS files_quota
             FROM file_accounts f JOIN accounts a ON a.id = f.account_id JOIN tenants t ON t.id = a.tenant_id
             WHERE f.account_id = $1 FOR UPDATE OF f",
            account,
        )
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(FilesError::NotFound("the account"))?;
        let mut locked = Locked {
            account,
            tenant: row.tenant_id,
            modseq: row.modseq,
            used_bytes: row.used_bytes,
            quota: row.files_quota,
        };
        if created.is_some() {
            node::create_defaults(tx, &mut locked).await?;
        }
        Ok(locked)
    }

    /// Starts a read: the file store as it is, created first if needed, without taking its row.
    async fn open(&self, tx: &mut Transaction<'static, Postgres>, account: Uuid) -> Result<Locked> {
        let row = sqlx::query!(
            "SELECT f.tenant_id, f.modseq, f.used_bytes, coalesce(a.files_quota, t.default_files_quota) AS files_quota
             FROM file_accounts f JOIN accounts a ON a.id = f.account_id JOIN tenants t ON t.id = a.tenant_id
             WHERE f.account_id = $1",
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
                quota: row.files_quota,
            }),
            None => self.lock_store(tx, account).await,
        }
    }

    /// The account's current state: the modification sequence of its last change (JMAP state of `FileNode`).
    pub async fn state(&self, account: Uuid) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        tx.commit().await?;
        Ok(locked.modseq)
    }

    /// Bytes used by the account's files and its quota – its own, or else the tenant's default – if any.
    pub async fn quota(&self, account: Uuid) -> Result<(u64, Option<u64>)> {
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        tx.commit().await?;
        Ok((locked.used_bytes as u64, locked.quota.map(|quota| quota as u64)))
    }

    /// Like [`Files::quota`], without creating the store: nothing used for an account that has none (administration).
    pub async fn usage(&self, account: Uuid) -> Result<(u64, Option<u64>)> {
        let row = sqlx::query!(
            r#"SELECT coalesce(f.used_bytes, 0) AS "used_bytes!", coalesce(a.files_quota, t.default_files_quota) AS quota
               FROM accounts a JOIN tenants t ON t.id = a.tenant_id
               LEFT JOIN file_accounts f ON f.account_id = a.id
               WHERE a.id = $1"#,
            account,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FilesError::NotFound("the account"))?;
        Ok((row.used_bytes as u64, row.quota.map(|quota| quota as u64)))
    }

    /// The tenant of an account, without creating its store.
    async fn tenant_of(&self, account: Uuid) -> Result<Uuid> {
        sqlx::query_scalar!("SELECT tenant_id FROM accounts WHERE id = $1", account)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(FilesError::NotFound("the account"))
    }
}

impl Locked {
    /// Takes the next modification sequence for the change in progress, and tells whoever listens on the mail
    /// channel – at the commit, with the transaction (JMAP push).
    async fn next_modseq(&mut self, connection: &mut PgConnection) -> Result<i64> {
        self.modseq = sqlx::query_scalar!(
            "UPDATE file_accounts SET modseq = modseq + 1 WHERE account_id = $1 RETURNING modseq",
            self.account
        )
        .fetch_one(&mut *connection)
        .await?;
        sqlx::query!("SELECT pg_notify('kernoid_mail', $1)", self.account.to_string()).execute(connection).await?;
        Ok(self.modseq)
    }

    /// Counts `delta` bytes more (or fewer) against the quota; more is refused if it would go over it.
    async fn charge(&mut self, connection: &mut PgConnection, delta: i64) -> Result<()> {
        if delta > 0
            && let Some(quota) = self.quota
            && self.used_bytes.saturating_add(delta) > quota
        {
            return Err(FilesError::OverQuota);
        }
        self.used_bytes = sqlx::query_scalar!(
            "UPDATE file_accounts SET used_bytes = greatest(used_bytes + $2, 0) WHERE account_id = $1 RETURNING used_bytes",
            self.account,
            delta,
        )
        .fetch_one(connection)
        .await?;
        Ok(())
    }
}
