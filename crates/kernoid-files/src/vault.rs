// SPDX-License-Identifier: AGPL-3.0-or-later
//! The keys of vaults (RFC 0006, 6): a vault's secret key, encrypted by a member's app to the key of each account that
//! may read the vault. kernoid keeps them and hands each account its own; it cannot open any. Sharing a vault with
//! someone means a member who may share also gives them the key – until then the grant waits.

use uuid::Uuid;

use crate::{
    FileAccess, Files, FilesError, Result, Rights,
    node::{acting_on, rights_of},
};

/// The largest wrapped key taken (the table's limit).
const MAX_SEALED: usize = 65_536;

impl Files {
    /// The vault's root, checked: a node of the store that is a vault's root.
    async fn vault_root(&self, connection: &mut sqlx::PgConnection, access: &FileAccess, vault: Uuid) -> Result<()> {
        let node = acting_on(&mut *connection, access, vault, Rights::NONE).await?;
        if node.vault != Some(vault) || node.vault_key.is_none() {
            return Err(FilesError::NotFound("the vault"));
        }
        Ok(())
    }

    /// The vault's secret key wrapped for the caller – `None` if no member gave it to them yet.
    pub async fn vault_key(&self, access: &FileAccess, vault: Uuid) -> Result<Option<Vec<u8>>> {
        let mut connection = self.pool.acquire().await?;
        self.vault_root(&mut connection, access, vault).await?;
        if !rights_of(&mut connection, access, vault).await?.contains(Rights::READ) {
            return Err(FilesError::Forbidden("reading the vault".into()));
        }
        Ok(sqlx::query_scalar!(
            "SELECT sealed FROM file_vault_keys WHERE vault_id = $1 AND account_id = $2",
            vault,
            access.user,
        )
        .fetch_optional(&mut *connection)
        .await?)
    }

    /// The accounts that have the vault's key – so that an app sees whom it still has to give it.
    pub async fn vault_members(&self, access: &FileAccess, vault: Uuid) -> Result<Vec<Uuid>> {
        let mut connection = self.pool.acquire().await?;
        self.vault_root(&mut connection, access, vault).await?;
        Ok(sqlx::query_scalar!("SELECT account_id FROM file_vault_keys WHERE vault_id = $1 ORDER BY account_id", vault)
            .fetch_all(&mut *connection)
            .await?)
    }

    /// Gives an account the vault's key (or replaces it): only who may share the vault – and has its key, which the
    /// caller's app proves by wrapping it.
    pub async fn set_vault_key(&self, access: &FileAccess, vault: Uuid, account: Uuid, sealed: &[u8]) -> Result<()> {
        if sealed.is_empty() || sealed.len() > MAX_SEALED {
            return Err(FilesError::Invalid("a wrapped key has 1 to 65536 bytes".into()));
        }
        let mut connection = self.pool.acquire().await?;
        self.vault_root(&mut connection, access, vault).await?;
        let own = account == access.user;
        if !own && !rights_of(&mut connection, access, vault).await?.contains(Rights::SHARE) {
            return Err(FilesError::Forbidden("sharing the vault".into()));
        }
        sqlx::query!(
            "INSERT INTO file_vault_keys (vault_id, account_id, sealed) VALUES ($1, $2, $3)
             ON CONFLICT (vault_id, account_id) DO UPDATE SET sealed = $3, created_at = now()",
            vault,
            account,
            sealed,
        )
        .execute(&mut *connection)
        .await?;
        Ok(())
    }

    /// Takes an account's key of the vault away (after its grant ended). What it decrypted before stays decrypted:
    /// a new vault key needs the files encrypted anew (**OPEN**).
    pub async fn remove_vault_key(&self, access: &FileAccess, vault: Uuid, account: Uuid) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        self.vault_root(&mut connection, access, vault).await?;
        if account != access.user && !rights_of(&mut connection, access, vault).await?.contains(Rights::SHARE) {
            return Err(FilesError::Forbidden("sharing the vault".into()));
        }
        sqlx::query!("DELETE FROM file_vault_keys WHERE vault_id = $1 AND account_id = $2", vault, account)
            .execute(&mut *connection)
            .await?;
        Ok(())
    }
}
