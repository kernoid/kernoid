// SPDX-License-Identifier: AGPL-3.0-or-later
//! Administration of files (RFC 0005, 10–12): the quota of an account and the default of a tenant, who may use whose
//! files, and drives – file stores of the tenant nobody logs in as. The files themselves are data in
//! `kernoid-files`; what an administrator or an owner decides about them is events here.

use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::AccountEvent,
    role::{Admin, Permission, Principal},
    tenant::TenantEvent,
    valid_name,
};

/// The rights of RFC 0005, 11 as letters: read, add children, rename, delete, write content, share.
pub const FILE_RIGHTS: &str = "randws";

/// Rights as letters, checked and in canonical order; at least one.
pub fn normalize_file_rights(rights: &str) -> Result<String> {
    if let Some(unknown) = rights.chars().find(|c| !FILE_RIGHTS.contains(*c)) {
        return Err(IdentityError::Refused(format!("{unknown:?} is not a right; rights are letters of {FILE_RIGHTS}")));
    }
    let normalized: String = FILE_RIGHTS.chars().filter(|c| rights.contains(*c)).collect();
    if normalized.is_empty() {
        return Err(IdentityError::Refused("a grant needs at least one right".into()));
    }
    Ok(normalized)
}

/// A grant on an account's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileGrant {
    pub owner: Uuid,
    /// A directory, or none for the whole store.
    pub node: Option<Uuid>,
    pub grantee: Principal,
    /// The grantee's primary address or contact address, or `$` and a group's name.
    pub grantee_name: String,
    pub rights: String,
}

/// A drive of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveInfo {
    pub id: Uuid,
    pub name: String,
    pub active: bool,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Creates a drive of `tenant` (RFC 0005, 12): a file store nobody logs in as, used through grants.
    pub async fn add_drive(&self, tenant: Uuid, name: &str, creator: &str) -> Result<Uuid> {
        let name = valid_name(name)?;
        let instance = self.tenant_instance(tenant).await?;
        let id = Uuid::now_v7();
        self.account_command(instance, tenant, id, creator, None, |account| {
            if account.exists {
                return Err(IdentityError::Exists("the account"));
            }
            Ok(vec![AccountEvent::DriveAdded { display_name: name.clone() }])
        })
        .await?;
        Ok(id)
    }

    /// What an id of the tenant names, for sharing: a person's account or a group; `None` for anything else.
    pub async fn principal(&self, tenant: Uuid, id: Uuid) -> Result<Option<Principal>> {
        let row = sqlx::query!(
            r#"SELECT EXISTS (SELECT 1 FROM accounts WHERE id = $1 AND tenant_id = $2 AND kind = 'person') AS "account!",
                      EXISTS (SELECT 1 FROM groups WHERE id = $1 AND tenant_id = $2) AS "group!""#,
            id,
            tenant,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        Ok(match (row.account, row.group) {
            (true, _) => Some(Principal::Account(id)),
            (_, true) => Some(Principal::Group(id)),
            _ => None,
        })
    }

    /// The drives of a tenant.
    pub async fn drives(&self, tenant: Uuid) -> Result<Vec<DriveInfo>> {
        let rows = sqlx::query!(
            "SELECT id, display_name, active FROM accounts WHERE tenant_id = $1 AND kind = 'drive' ORDER BY display_name",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows.into_iter().map(|row| DriveInfo { id: row.id, name: row.display_name, active: row.active }).collect())
    }

    /// Grants `grantee` `rights` on one of `owner`'s directories, or on the whole store, replacing an earlier grant
    /// there. Unchecked: the callers decide who may.
    pub async fn set_file_access(
        &self,
        owner: Uuid,
        node: Option<Uuid>,
        grantee: Principal,
        rights: &str,
        creator: &str,
    ) -> Result<()> {
        let rights = normalize_file_rights(rights)?;
        if grantee == Principal::Account(owner) {
            return Err(IdentityError::Refused("an owner has every right on its own files".into()));
        }
        if let Some(node) = node {
            let directory = sqlx::query_scalar!(
                "SELECT node_type = 'directory' FROM file_nodes WHERE id = $1 AND account_id = $2",
                node,
                owner,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .flatten()
            .ok_or(IdentityError::NotFound("the directory"))?;
            if !directory {
                return Err(IdentityError::Refused("files are shared with their directory".into()));
            }
        }
        let (instance, tenant) = self.account_owner(owner).await?;
        self.check_grantee(tenant, grantee).await?;
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            if state.file_access.get(&(grantee, node)) == Some(&rights) {
                return Ok(Vec::new());
            }
            Ok(vec![AccountEvent::FileAccessSet { grantee, node, rights: rights.clone() }])
        })
        .await
    }

    pub async fn remove_file_access(
        &self,
        owner: Uuid,
        node: Option<Uuid>,
        grantee: Principal,
        creator: &str,
    ) -> Result<()> {
        let (instance, tenant) = self.account_owner(owner).await?;
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.file_access.contains_key(&(grantee, node)) {
                return Err(IdentityError::NotFound("the grant"));
            }
            Ok(vec![AccountEvent::FileAccessRemoved { grantee, node }])
        })
        .await
    }

    /// The grants on an account's files, or on one directory of them.
    pub async fn file_access(&self, owner: Uuid, node: Option<Uuid>) -> Result<Vec<FileGrant>> {
        let rows = sqlx::query!(
            r#"SELECT f.node_id, f.grantee_account, f.grantee_group, f.rights,
                      coalesce(a.primary_address, a.email, a.display_name, '$' || g.name) AS "name!"
               FROM file_access f
               LEFT JOIN accounts a ON a.id = f.grantee_account
               LEFT JOIN groups g ON g.id = f.grantee_group
               WHERE f.owner_id = $1 AND ($2::uuid IS NULL OR f.node_id = $2)
               ORDER BY f.node_id NULLS FIRST, 5"#,
            owner,
            node,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let grantee = match (row.grantee_account, row.grantee_group) {
                    (Some(account), _) => Principal::Account(account),
                    (_, Some(group)) => Principal::Group(group),
                    _ => return None,
                };
                Some(FileGrant { owner, node: row.node_id, grantee, grantee_name: row.name, rights: row.rights })
            })
            .collect())
    }

    /// Sets the files quota of every account of `tenant` without its own; `None` for no limit.
    pub async fn set_default_files_quota(&self, tenant: Uuid, bytes: Option<u64>, creator: &str) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if state.default_files_quota == bytes {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::DefaultFilesQuotaSet { bytes }])
        })
        .await
    }

    /// The tenant's default files quota.
    pub async fn default_files_quota(&self, tenant: Uuid) -> Result<Option<u64>> {
        let bytes = sqlx::query_scalar!("SELECT default_files_quota FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the tenant"))?;
        Ok(bytes.map(|bytes| bytes as u64))
    }

    /// An account's own files quota; `None` when the tenant's default holds.
    pub async fn files_quota(&self, account: Uuid) -> Result<Option<u64>> {
        let bytes = sqlx::query_scalar!("SELECT files_quota FROM accounts WHERE id = $1", account)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the account"))?;
        Ok(bytes.map(|bytes| bytes as u64))
    }

    // Administration

    pub async fn admin_add_drive(&self, admin: &Admin, name: &str) -> Result<Uuid> {
        admin.require(Permission::AccountsManage)?;
        self.add_drive(admin.tenant(), name, &admin.creator()).await
    }

    pub async fn admin_drives(&self, admin: &Admin) -> Result<Vec<DriveInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.drives(admin.tenant()).await
    }

    pub async fn admin_file_access(&self, admin: &Admin, owner: Uuid) -> Result<Vec<FileGrant>> {
        self.managed_account(admin, owner).await?;
        self.file_access(owner, None).await
    }

    pub async fn admin_set_file_access(
        &self,
        admin: &Admin,
        owner: Uuid,
        node: Option<Uuid>,
        grantee: Principal,
        rights: &str,
    ) -> Result<()> {
        self.managed_account(admin, owner).await?;
        self.set_file_access(owner, node, grantee, rights, &admin.creator()).await
    }

    pub async fn admin_remove_file_access(
        &self,
        admin: &Admin,
        owner: Uuid,
        node: Option<Uuid>,
        grantee: Principal,
    ) -> Result<()> {
        self.managed_account(admin, owner).await?;
        self.remove_file_access(owner, node, grantee, &admin.creator()).await
    }

    /// An account's own files quota, for an administrator who manages it.
    pub async fn admin_files_quota(&self, admin: &Admin, account: Uuid) -> Result<Option<u64>> {
        self.managed_account(admin, account).await?;
        self.files_quota(account).await
    }

    pub async fn admin_set_files_quota(&self, admin: &Admin, account: Uuid, bytes: Option<u64>) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.set_files_quota(account, bytes, &admin.creator()).await
    }

    pub async fn admin_default_files_quota(&self, admin: &Admin) -> Result<Option<u64>> {
        admin.require(Permission::DirectoryRead)?;
        self.default_files_quota(admin.tenant()).await
    }

    pub async fn admin_set_default_files_quota(&self, admin: &Admin, bytes: Option<u64>) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.set_default_files_quota(admin.tenant(), bytes, &admin.creator()).await
    }
}
