// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sharing and administration of mail (RFC 0002, 12): shared mailboxes, who may use whose mail, and the quotas. The
//! mail itself is data in `kernoid-mail`; what an administrator or an owner decides about it is events here.

use uuid::Uuid;

use crate::{
    Address, Identity, IdentityError, Result,
    account::{AccountEvent, on_verified_domain},
    role::{Admin, Permission, Principal},
    tenant::TenantEvent,
    valid_name,
};

/// The rights of RFC 4314, in their canonical order.
pub const RIGHTS: &str = "lrswipkxtea";

/// Rights as letters, checked and in canonical order; at least one.
pub fn normalize_rights(rights: &str) -> Result<String> {
    if let Some(unknown) = rights.chars().find(|c| !RIGHTS.contains(*c)) {
        return Err(IdentityError::Refused(format!("{unknown:?} is not a right; rights are letters of {RIGHTS}")));
    }
    let normalized: String = RIGHTS.chars().filter(|c| rights.contains(*c)).collect();
    if normalized.is_empty() {
        return Err(IdentityError::Refused("a grant needs at least one right".into()));
    }
    Ok(normalized)
}

/// A grant on an account's mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailGrant {
    pub owner: Uuid,
    /// `None`: the whole store.
    pub mailbox: Option<Uuid>,
    pub grantee: Principal,
    /// The grantee's primary address, or a group's name.
    pub grantee_name: String,
    pub rights: String,
    pub send_as: bool,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Creates a shared mailbox of `tenant` with `address`; returns its id.
    pub async fn add_shared_mailbox(
        &self,
        tenant: Uuid,
        address: &Address,
        display_name: &str,
        creator: &str,
    ) -> Result<Uuid> {
        let display_name = valid_name(display_name)?;
        let instance = self.tenant_instance(tenant).await?;
        let tenant_state = self.tenant(instance, tenant).await?.state;
        if !tenant_state.active {
            return Err(IdentityError::Refused("the tenant is deactivated".into()));
        }
        on_verified_domain(&tenant_state, address)?;
        let id = Uuid::now_v7();
        self.account_command(instance, tenant, id, creator, Some(address), |account| {
            if account.exists {
                return Err(IdentityError::Exists("the account"));
            }
            Ok(vec![AccountEvent::SharedAdded { address: address.clone(), display_name: display_name.clone() }])
        })
        .await?;
        Ok(id)
    }

    /// Sets the mail quota of every account of `tenant` without its own; `None` for no limit.
    pub async fn set_default_mail_quota(&self, tenant: Uuid, bytes: Option<u64>, creator: &str) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if state.default_mail_quota == bytes {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::DefaultMailQuotaSet { bytes }])
        })
        .await
    }

    /// Sets how many days emails stay in the Trash and the Junk of the tenant's accounts (RFC 0002, 13.2); `None`
    /// keeps them. At most ten years.
    pub async fn set_mail_retention(
        &self,
        tenant: Uuid,
        trash_days: Option<u32>,
        junk_days: Option<u32>,
        creator: &str,
    ) -> Result<()> {
        if [trash_days, junk_days].into_iter().flatten().any(|days| days == 0 || days > 3650) {
            return Err(IdentityError::Refused("retention is 1 to 3650 days".into()));
        }
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if state.mail_retention == (trash_days, junk_days) {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::MailRetentionSet { trash_days, junk_days }])
        })
        .await
    }

    /// Days in Trash and in Junk.
    pub async fn mail_retention(&self, tenant: Uuid) -> Result<(Option<u32>, Option<u32>)> {
        let row = sqlx::query!("SELECT trash_retention_days, junk_retention_days FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the tenant"))?;
        Ok((row.trash_retention_days.map(|days| days as u32), row.junk_retention_days.map(|days| days as u32)))
    }

    /// The tenant's default quota.
    pub async fn default_mail_quota(&self, tenant: Uuid) -> Result<Option<u64>> {
        let bytes = sqlx::query_scalar!("SELECT default_mail_quota FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the tenant"))?;
        Ok(bytes.map(|bytes| bytes as u64))
    }

    /// An account's own quota; `None` when the tenant's default holds.
    pub async fn mail_quota(&self, account: Uuid) -> Result<Option<u64>> {
        let bytes = sqlx::query_scalar!("SELECT mail_quota FROM accounts WHERE id = $1", account)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the account"))?;
        Ok(bytes.map(|bytes| bytes as u64))
    }

    /// Grants `grantee` `rights` on `owner`'s mail – its whole store, or one mailbox of it – replacing an earlier
    /// grant there. Unchecked: the callers decide who may (RFC 0002, 12.2).
    pub async fn set_mail_access(
        &self,
        owner: Uuid,
        grantee: Principal,
        mailbox: Option<Uuid>,
        rights: &str,
        send_as: bool,
        creator: &str,
    ) -> Result<()> {
        let rights = normalize_rights(rights)?;
        if send_as && mailbox.is_some() {
            return Err(IdentityError::Refused("sending as the owner is granted for the whole store only".into()));
        }
        if grantee == Principal::Account(owner) {
            return Err(IdentityError::Refused("an owner has every right on its own mail".into()));
        }
        let (instance, tenant) = self.account_owner(owner).await?;
        self.check_grantee(tenant, grantee).await?;
        if let Some(mailbox) = mailbox {
            let known = sqlx::query_scalar!(
                r#"SELECT EXISTS (SELECT 1 FROM mailboxes WHERE id = $1 AND account_id = $2) AS "known!""#,
                mailbox,
                owner,
            )
            .fetch_one(self.pool())
            .await
            .map_err(store_error)?;
            if !known {
                return Err(IdentityError::NotFound("the mailbox"));
            }
        }
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            // Written even when nothing changed: removing a group removes its grants from the read model.
            Ok(vec![AccountEvent::MailAccessSet { grantee, mailbox, rights: rights.clone(), send_as }])
        })
        .await
    }

    pub async fn remove_mail_access(
        &self,
        owner: Uuid,
        grantee: Principal,
        mailbox: Option<Uuid>,
        creator: &str,
    ) -> Result<()> {
        let (instance, tenant) = self.account_owner(owner).await?;
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.mail_access.contains_key(&(grantee, mailbox)) {
                return Err(IdentityError::NotFound("the grant"));
            }
            Ok(vec![AccountEvent::MailAccessRemoved { grantee, mailbox }])
        })
        .await
    }

    /// A grantee must be an account or a group of the owner's tenant.
    pub(crate) async fn check_grantee(&self, tenant: Uuid, grantee: Principal) -> Result<()> {
        let found = match grantee {
            Principal::Account(account) => sqlx::query_scalar!(
                r#"SELECT EXISTS (SELECT 1 FROM accounts WHERE id = $1 AND tenant_id = $2) AS "found!""#,
                account,
                tenant,
            )
            .fetch_one(self.pool())
            .await
            .map_err(store_error)?,
            Principal::Group(group) => sqlx::query_scalar!(
                r#"SELECT EXISTS (SELECT 1 FROM groups WHERE id = $1 AND tenant_id = $2) AS "found!""#,
                group,
                tenant,
            )
            .fetch_one(self.pool())
            .await
            .map_err(store_error)?,
        };
        if found {
            Ok(())
        } else {
            Err(IdentityError::NotFound(match grantee {
                Principal::Account(_) => "the account",
                Principal::Group(_) => "the group",
            }))
        }
    }

    /// The grantee an identifier names in `tenant`: an address of an account, or `$` and a group's name (IMAP ACL).
    pub async fn mail_grantee(&self, tenant: Uuid, identifier: &str) -> Result<Principal> {
        if let Some(name) = identifier.strip_prefix('$') {
            return sqlx::query_scalar!("SELECT id FROM groups WHERE tenant_id = $1 AND name = $2", tenant, name)
                .fetch_optional(self.pool())
                .await
                .map_err(store_error)?
                .map(Principal::Group)
                .ok_or(IdentityError::NotFound("the group"));
        }
        let address = Address::parse(identifier).map_err(|_| IdentityError::NotFound("the account"))?;
        match self.account_by_address(&address).await? {
            Some(account) if account.tenant == tenant => Ok(Principal::Account(account.id)),
            _ => Err(IdentityError::NotFound("the account")),
        }
    }

    /// The grants on an account's mail.
    pub async fn mail_access(&self, owner: Uuid) -> Result<Vec<MailGrant>> {
        let rows = sqlx::query!(
            r#"SELECT m.mailbox_id, m.grantee_account, m.grantee_group, m.rights, m.send_as,
                      coalesce(a.primary_address, '$' || g.name) AS "name!"
               FROM mail_access m
               LEFT JOIN accounts a ON a.id = m.grantee_account
               LEFT JOIN groups g ON g.id = m.grantee_group
               WHERE m.owner_id = $1 ORDER BY m.mailbox_id NULLS FIRST, 6"#,
            owner,
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
                Some(MailGrant {
                    owner,
                    mailbox: row.mailbox_id,
                    grantee,
                    grantee_name: row.name,
                    rights: row.rights,
                    send_as: row.send_as,
                })
            })
            .collect())
    }

    // Administration (RFC 0002, 12.3)

    pub async fn admin_add_shared_mailbox(&self, admin: &Admin, address: &Address, display_name: &str) -> Result<Uuid> {
        admin.require(Permission::AccountsManage)?;
        self.add_shared_mailbox(admin.tenant(), address, display_name, &admin.creator()).await
    }

    pub async fn admin_set_mail_quota(&self, admin: &Admin, account: Uuid, bytes: Option<u64>) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.set_mail_quota(account, bytes, &admin.creator()).await
    }

    pub async fn admin_set_default_mail_quota(&self, admin: &Admin, bytes: Option<u64>) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.set_default_mail_quota(admin.tenant(), bytes, &admin.creator()).await
    }

    pub async fn admin_mail_retention(&self, admin: &Admin) -> Result<(Option<u32>, Option<u32>)> {
        admin.require(Permission::DirectoryRead)?;
        self.mail_retention(admin.tenant()).await
    }

    pub async fn admin_set_mail_retention(
        &self,
        admin: &Admin,
        trash_days: Option<u32>,
        junk_days: Option<u32>,
    ) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.set_mail_retention(admin.tenant(), trash_days, junk_days, &admin.creator()).await
    }

    pub async fn admin_default_mail_quota(&self, admin: &Admin) -> Result<Option<u64>> {
        admin.require(Permission::DirectoryRead)?;
        self.default_mail_quota(admin.tenant()).await
    }

    pub async fn admin_mail_access(&self, admin: &Admin, owner: Uuid) -> Result<Vec<MailGrant>> {
        self.managed_account(admin, owner).await?;
        self.mail_access(owner).await
    }

    pub async fn admin_set_mail_access(
        &self,
        admin: &Admin,
        owner: Uuid,
        grantee: Principal,
        mailbox: Option<Uuid>,
        rights: &str,
        send_as: bool,
    ) -> Result<()> {
        self.managed_account(admin, owner).await?;
        self.set_mail_access(owner, grantee, mailbox, rights, send_as, &admin.creator()).await
    }

    pub async fn admin_remove_mail_access(
        &self,
        admin: &Admin,
        owner: Uuid,
        grantee: Principal,
        mailbox: Option<Uuid>,
    ) -> Result<()> {
        self.managed_account(admin, owner).await?;
        self.remove_mail_access(owner, grantee, mailbox, &admin.creator()).await
    }

    // The owner's own sharing

    /// An account shares its own mail; sending as it stays the administrators' to grant.
    pub async fn share_own_mail(
        &self,
        account: Uuid,
        grantee: Principal,
        mailbox: Option<Uuid>,
        rights: &str,
    ) -> Result<()> {
        self.set_mail_access(account, grantee, mailbox, rights, false, &format!("account:{account}")).await
    }

    pub async fn unshare_own_mail(&self, account: Uuid, grantee: Principal, mailbox: Option<Uuid>) -> Result<()> {
        // A grant with send as stays the administrators' to remove as well.
        if self.mail_access(account).await?.iter().any(|g| g.grantee == grantee && g.mailbox == mailbox && g.send_as) {
            return Err(IdentityError::Refused("an administrator granted this; ask them to remove it".into()));
        }
        self.remove_mail_access(account, grantee, mailbox, &format!("account:{account}")).await
    }
}
