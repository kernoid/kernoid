// SPDX-License-Identifier: AGPL-3.0-or-later
//! The account's store for what lives beside mail in it – calendars and contacts (RFC 0004, 2): a change takes the
//! same row, the same modification sequence and the same quota as a change to mail.

use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{Locked, Mail, MailError, Result};

/// A change in progress to an account's store: its row is taken until [`StoreChange::commit`].
#[derive(Debug)]
pub struct StoreChange {
    tx: Transaction<'static, Postgres>,
    locked: Locked,
}

/// A read of an account's store, without taking its row.
#[derive(Debug)]
pub struct StoreRead {
    tx: Transaction<'static, Postgres>,
    locked: Locked,
}

impl Mail {
    /// Starts a change: creates the store if needed and takes its row.
    pub async fn begin_change(&self, account: Uuid) -> Result<StoreChange> {
        let mut tx = self.pool.begin().await?;
        let locked = self.lock(&mut tx, account).await?;
        Ok(StoreChange { tx, locked })
    }

    /// Starts a read of the store as it is.
    pub async fn begin_read(&self, account: Uuid) -> Result<StoreRead> {
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        Ok(StoreRead { tx, locked })
    }
}

impl StoreChange {
    pub fn account(&self) -> Uuid {
        self.locked.account
    }

    pub fn tenant(&self) -> Uuid {
        self.locked.tenant
    }

    /// The modification sequence of the last change committed or taken in this transaction.
    pub fn modseq(&self) -> i64 {
        self.locked.modseq
    }

    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Takes the next modification sequence and announces the change at the commit (JMAP push, IMAP `IDLE`).
    pub async fn next_modseq(&mut self) -> Result<i64> {
        self.locked.next_modseq(&mut self.tx).await
    }

    /// Counts `delta` bytes more (or fewer) against the quota; more is refused if it would go over it.
    pub async fn charge(&mut self, delta: i64) -> Result<()> {
        if delta > 0
            && let Some(quota) = self.locked.quota
            && self.locked.used_bytes.saturating_add(delta) > quota
        {
            return Err(MailError::OverQuota);
        }
        self.locked.used_bytes = sqlx::query_scalar!(
            "UPDATE mail_accounts SET used_bytes = greatest(used_bytes + $2, 0) WHERE account_id = $1 RETURNING used_bytes",
            self.locked.account,
            delta,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(())
    }

    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}

impl StoreRead {
    pub fn account(&self) -> Uuid {
        self.locked.account
    }

    pub fn tenant(&self) -> Uuid {
        self.locked.tenant
    }

    /// The store's current state (JMAP state, the sync token of RFC 0004, 8.1).
    pub fn modseq(&self) -> i64 {
        self.locked.modseq
    }

    /// The oldest state the journal can still bring up to date.
    pub async fn changes_floor(&mut self) -> Result<i64> {
        Ok(sqlx::query_scalar!("SELECT changes_floor FROM mail_accounts WHERE account_id = $1", self.locked.account)
            .fetch_one(&mut *self.tx)
            .await?)
    }

    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    pub async fn finish(self) -> Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}
