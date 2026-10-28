// SPDX-License-Identifier: AGPL-3.0-or-later
//! Administration through the API: each operation checks the permission it needs, so that REST and GraphQL – which
//! both call these – cannot differ. Operators use the unchecked functions from the command line.
//!
//! - Tenant operations act on [`Admin::tenant`]: the administrator's own tenant, or another one of the instance for
//!   instance administrators.
//! - Instance operations act on the administrator's instance and need instance permissions.
//! - **Nobody takes over a stronger account:** setting a password, resetting second factors, deactivating an account
//!   or ending its sessions needs every permission that account holds.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::{
    Address, DomainName, Identity, IdentityError, InstanceInfo, Result, TenantInfo, TxtLookup,
    account::AccountInfo,
    group::GroupInfo,
    project::{ProjectAccess, ProjectAuthorization, ProjectGrant, ProjectInfo},
    role::{Admin, Assignment, InstanceRoleInfo, Permission, Principal, Role, RoleInfo},
    session::SessionSummary,
};

/// A mail domain of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantDomainInfo {
    pub domain: String,
    pub verified: bool,
    /// For a domain not verified yet: the value of the TXT record that proves it.
    pub token: Option<String>,
}

/// The tenant as its administrators see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPolicy {
    pub tenant: TenantInfo,
    pub mfa_required: bool,
    /// Days an account without a second factor may still log in without one.
    pub mfa_grace_days: u32,
    pub domains: Vec<TenantDomainInfo>,
    pub modules: Vec<String>,
}

/// The instance as its administrators see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceOverview {
    pub instance: InstanceInfo,
    pub domains: Vec<String>,
}

impl Identity {
    // The tenant

    pub async fn admin_tenant(&self, admin: &Admin) -> Result<TenantPolicy> {
        admin.require(Permission::DirectoryRead)?;
        let tenant = self.tenant(admin.instance(), admin.tenant()).await?.state;
        Ok(TenantPolicy {
            tenant: TenantInfo {
                instance: admin.instance(),
                id: admin.tenant(),
                name: tenant.name,
                active: tenant.active,
            },
            mfa_required: tenant.mfa_required,
            mfa_grace_days: tenant.mfa_grace_days,
            domains: tenant
                .domains
                .into_iter()
                .map(|(domain, claim)| TenantDomainInfo {
                    domain: domain.to_string(),
                    verified: claim.verified,
                    token: (!claim.verified).then_some(claim.token),
                })
                .collect(),
            modules: tenant.modules.into_iter().collect(),
        })
    }

    pub async fn admin_rename_tenant(&self, admin: &Admin, name: &str) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.rename_tenant(admin.instance(), admin.tenant(), name, &admin.creator()).await
    }

    /// Switches a module on or off for the tenant; `known` are the modules compiled in.
    pub async fn admin_set_module(&self, admin: &Admin, module: &str, enabled: bool, known: &[&str]) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.set_tenant_module(admin.instance(), admin.tenant(), module, enabled, known, &admin.creator()).await
    }

    pub async fn admin_set_mfa_grace(&self, admin: &Admin, days: u32) -> Result<()> {
        admin.require(Permission::PoliciesManage)?;
        self.set_tenant_mfa_grace(admin.instance(), admin.tenant(), days, &admin.creator()).await
    }

    pub async fn admin_set_mfa_required(&self, admin: &Admin, required: bool) -> Result<()> {
        admin.require(Permission::PoliciesManage)?;
        self.set_tenant_mfa_required(admin.instance(), admin.tenant(), required, &admin.creator()).await
    }

    /// Claims a mail domain; returns the token to publish.
    pub async fn admin_add_domain(&self, admin: &Admin, domain: &DomainName) -> Result<String> {
        admin.require(Permission::DomainsManage)?;
        self.add_tenant_domain(admin.instance(), admin.tenant(), domain, &admin.creator()).await
    }

    pub async fn admin_verify_domain(&self, admin: &Admin, domain: &DomainName, dns: &impl TxtLookup) -> Result<()> {
        admin.require(Permission::DomainsManage)?;
        self.verify_tenant_domain(admin.instance(), admin.tenant(), domain, dns, &admin.creator()).await
    }

    /// Marks a domain verified without DNS – for instance administrators, like `--trust` for operators.
    pub async fn admin_trust_domain(&self, admin: &Admin, domain: &DomainName) -> Result<()> {
        admin.require(Permission::TenantsManage)?;
        self.trust_tenant_domain(admin.instance(), admin.tenant(), domain, &admin.creator()).await
    }

    pub async fn admin_remove_domain(&self, admin: &Admin, domain: &DomainName) -> Result<()> {
        admin.require(Permission::DomainsManage)?;
        self.remove_tenant_domain(admin.instance(), admin.tenant(), domain, &admin.creator()).await
    }

    // Accounts

    /// An account of the administered tenant; one of another tenant is unknown.
    pub async fn admin_account(&self, admin: &Admin, account: Uuid) -> Result<AccountInfo> {
        admin.require(Permission::DirectoryRead)?;
        let info = self.account(account).await?;
        if info.tenant != admin.tenant() {
            return Err(IdentityError::NotFound("the account"));
        }
        Ok(info)
    }

    pub async fn admin_accounts(&self, admin: &Admin) -> Result<Vec<AccountInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.accounts(admin.tenant()).await
    }

    /// The account, if the administrator may manage it at all.
    pub async fn managed_account(&self, admin: &Admin, account: Uuid) -> Result<AccountInfo> {
        admin.require(Permission::AccountsManage)?;
        self.admin_account(admin, account).await
    }

    /// The account, if the administrator also holds every permission it holds.
    pub async fn weaker_account(&self, admin: &Admin, account: Uuid) -> Result<AccountInfo> {
        let info = self.managed_account(admin, account).await?;
        let held = self.permissions(info.tenant, account).await?;
        if let Some(missing) = held.difference(&admin.permissions).next() {
            return Err(IdentityError::Forbidden(*missing));
        }
        Ok(info)
    }

    pub async fn admin_add_account(&self, admin: &Admin, address: &Address, display_name: &str) -> Result<Uuid> {
        admin.require(Permission::AccountsManage)?;
        self.add_account(admin.tenant(), address, display_name, &admin.creator()).await
    }

    pub async fn admin_rename_account(&self, admin: &Admin, account: Uuid, display_name: &str) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.rename_account(account, display_name, &admin.creator()).await
    }

    pub async fn admin_add_alias(&self, admin: &Admin, account: Uuid, address: &Address) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.add_alias(account, address, &admin.creator()).await
    }

    pub async fn admin_remove_alias(&self, admin: &Admin, account: Uuid, address: &Address) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.remove_alias(account, address, &admin.creator()).await
    }

    pub async fn admin_set_primary_address(&self, admin: &Admin, account: Uuid, address: &Address) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.set_primary_address(account, address, &admin.creator()).await
    }

    /// Deactivates (ending every session) or reactivates an account.
    pub async fn admin_set_account_active(&self, admin: &Admin, account: Uuid, active: bool) -> Result<()> {
        self.weaker_account(admin, account).await?;
        self.set_account_active(account, active, &admin.creator()).await?;
        if !active {
            self.terminate_account_sessions(account, &admin.creator()).await?;
        }
        Ok(())
    }

    /// Sets an account's password and ends its sessions.
    pub async fn admin_set_password(&self, admin: &Admin, account: Uuid, password: &str) -> Result<()> {
        self.weaker_account(admin, account).await?;
        self.set_password(account, password, &admin.creator()).await?;
        self.terminate_account_sessions(account, &admin.creator()).await.map(drop)
    }

    /// Removes all TOTP, passkeys and recovery codes of an account – when someone lost their devices.
    pub async fn admin_reset_second_factors(&self, admin: &Admin, account: Uuid) -> Result<()> {
        self.weaker_account(admin, account).await?;
        self.reset_second_factors(account, &admin.creator()).await
    }

    pub async fn admin_account_sessions(&self, admin: &Admin, account: Uuid) -> Result<Vec<SessionSummary>> {
        self.managed_account(admin, account).await?;
        self.account_sessions(account).await
    }

    pub async fn admin_terminate_session(&self, admin: &Admin, account: Uuid, session: Uuid) -> Result<()> {
        self.weaker_account(admin, account).await?;
        self.terminate_account_session(account, session, &admin.creator()).await
    }

    // Groups

    pub async fn admin_groups(&self, admin: &Admin) -> Result<Vec<GroupInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.groups(admin.tenant()).await
    }

    pub async fn admin_add_group(&self, admin: &Admin, name: &str) -> Result<Uuid> {
        admin.require(Permission::GroupsManage)?;
        self.add_group(admin.tenant(), name, &admin.creator()).await
    }

    pub async fn admin_rename_group(&self, admin: &Admin, group: Uuid, name: &str) -> Result<()> {
        admin.require(Permission::GroupsManage)?;
        self.rename_group(admin.tenant(), group, name, &admin.creator()).await
    }

    pub async fn admin_remove_group(&self, admin: &Admin, group: Uuid) -> Result<()> {
        admin.require(Permission::GroupsManage)?;
        self.remove_group(admin.tenant(), group, &admin.creator()).await
    }

    /// Members of a group gain or lose what it holds – that needs the permission to assign it as well.
    async fn may_change_members(&self, admin: &Admin, group: Uuid) -> Result<()> {
        admin.require(Permission::GroupsManage)?;
        self.group_of(admin.tenant(), group).await?;
        for permission in self.group_holdings(group).await?.permissions_to_change_members() {
            admin.require(permission)?;
        }
        Ok(())
    }

    pub async fn admin_add_group_member(&self, admin: &Admin, group: Uuid, account: Uuid) -> Result<()> {
        self.may_change_members(admin, group).await?;
        self.add_group_member(admin.tenant(), group, account, &admin.creator()).await
    }

    pub async fn admin_remove_group_member(&self, admin: &Admin, group: Uuid, account: Uuid) -> Result<()> {
        self.may_change_members(admin, group).await?;
        self.remove_group_member(admin.tenant(), group, account, &admin.creator()).await
    }

    pub async fn admin_add_group_address(&self, admin: &Admin, group: Uuid, address: &Address) -> Result<()> {
        admin.require(Permission::GroupsManage)?;
        self.add_group_address(admin.tenant(), group, address, &admin.creator()).await
    }

    pub async fn admin_remove_group_address(&self, admin: &Admin, group: Uuid, address: &Address) -> Result<()> {
        admin.require(Permission::GroupsManage)?;
        self.remove_group_address(admin.tenant(), group, address, &admin.creator()).await
    }

    // Tenant roles

    pub async fn admin_tenant_roles(&self, admin: &Admin) -> Result<Vec<RoleInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.tenant_roles(admin.tenant()).await
    }

    pub async fn admin_define_role(
        &self,
        admin: &Admin,
        role: &Role,
        permissions: &BTreeSet<Permission>,
    ) -> Result<()> {
        admin.require(Permission::RolesManage)?;
        self.define_role(admin.tenant(), role, permissions, &admin.creator()).await
    }

    pub async fn admin_delete_role(&self, admin: &Admin, role: &Role) -> Result<()> {
        admin.require(Permission::RolesManage)?;
        self.delete_role(admin.tenant(), role, &admin.creator()).await
    }

    pub async fn admin_role_assignments(&self, admin: &Admin) -> Result<Vec<Assignment>> {
        admin.require(Permission::DirectoryRead)?;
        self.role_assignments(admin.tenant()).await
    }

    pub async fn admin_grant_role(&self, admin: &Admin, principal: Principal, role: &Role) -> Result<()> {
        admin.require(Permission::RolesManage)?;
        self.grant_role(admin.tenant(), principal, role, &admin.creator()).await
    }

    pub async fn admin_revoke_role(&self, admin: &Admin, principal: Principal, role: &Role) -> Result<()> {
        admin.require(Permission::RolesManage)?;
        self.revoke_role(admin.tenant(), principal, role, &admin.creator()).await
    }

    // Projects

    pub async fn admin_projects(&self, admin: &Admin) -> Result<Vec<ProjectInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.projects(admin.tenant()).await
    }

    pub async fn admin_project(&self, admin: &Admin, project: Uuid) -> Result<ProjectInfo> {
        admin.require(Permission::DirectoryRead)?;
        self.project_of(admin.tenant(), project).await?;
        self.project(project).await
    }

    pub async fn admin_add_project(&self, admin: &Admin, name: &str) -> Result<Uuid> {
        admin.require(Permission::ProjectsManage)?;
        self.add_project(admin.tenant(), name, &admin.creator()).await
    }

    pub async fn admin_rename_project(&self, admin: &Admin, project: Uuid, name: &str) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.rename_project(admin.tenant(), project, name, &admin.creator()).await
    }

    pub async fn admin_set_project_settings(
        &self,
        admin: &Admin,
        project: Uuid,
        role_assertion: bool,
        role_check: bool,
    ) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.set_project_settings(admin.tenant(), project, role_assertion, role_check, &admin.creator()).await
    }

    pub async fn admin_set_project_role(
        &self,
        admin: &Admin,
        project: Uuid,
        key: &str,
        display_name: &str,
        group: Option<&str>,
    ) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.set_project_role(admin.tenant(), project, key, display_name, group, &admin.creator()).await
    }

    pub async fn admin_remove_project_role(&self, admin: &Admin, project: Uuid, key: &str) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.remove_project_role(admin.tenant(), project, key, &admin.creator()).await
    }

    pub async fn admin_remove_project(&self, admin: &Admin, project: Uuid) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.remove_project(admin.tenant(), project, &admin.creator()).await
    }

    pub async fn admin_project_authorizations(
        &self,
        admin: &Admin,
        project: Uuid,
    ) -> Result<Vec<ProjectAuthorization>> {
        admin.require(Permission::DirectoryRead)?;
        // The project's own tenant sees every tenant's authorizations, a tenant it is granted to its own.
        let only = match self.project_access(admin.tenant(), project).await? {
            ProjectAccess::Own => None,
            ProjectAccess::Granted(_) => Some(admin.tenant()),
        };
        self.project_authorizations(project, only).await
    }

    /// A tenant of the administrator's instance, by its id or by one of its verified mail domains.
    pub async fn admin_find_tenant(&self, admin: &Admin, tenant: &str) -> Result<Uuid> {
        let found = match Uuid::parse_str(tenant) {
            Ok(id) => Some(id),
            Err(_) => match DomainName::parse(tenant) {
                Ok(domain) => self.tenant_by_domain(&domain).await?.map(|info| info.id),
                Err(_) => None,
            },
        };
        match found {
            Some(id) if self.tenant_instance(id).await.ok() == Some(admin.instance()) => Ok(id),
            _ => Err(IdentityError::NotFound("the tenant")),
        }
    }

    pub async fn admin_project_grants(&self, admin: &Admin, project: Uuid) -> Result<Vec<ProjectGrant>> {
        admin.require(Permission::DirectoryRead)?;
        self.project_of(admin.tenant(), project).await?;
        self.project_grants(project).await
    }

    /// Grants a project of the tenant to another tenant of the instance (needs `projects.manage`).
    pub async fn admin_grant_project(
        &self,
        admin: &Admin,
        project: Uuid,
        grantee: Uuid,
        roles: &BTreeSet<String>,
    ) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.grant_project(admin.tenant(), project, grantee, roles, &admin.creator()).await
    }

    pub async fn admin_revoke_project_grant(&self, admin: &Admin, project: Uuid, grantee: Uuid) -> Result<()> {
        admin.require(Permission::ProjectsManage)?;
        self.revoke_project_grant(admin.tenant(), project, grantee, &admin.creator()).await
    }

    /// The projects other tenants have granted to the tenant administered.
    pub async fn admin_granted_projects(&self, admin: &Admin) -> Result<Vec<ProjectGrant>> {
        admin.require(Permission::DirectoryRead)?;
        self.granted_projects(admin.tenant()).await
    }

    pub async fn admin_grant_project_role(
        &self,
        admin: &Admin,
        project: Uuid,
        principal: Principal,
        role: &str,
    ) -> Result<()> {
        admin.require(Permission::AuthorizationsManage)?;
        self.grant_project_role(admin.tenant(), project, principal, role, &admin.creator()).await
    }

    pub async fn admin_revoke_project_role(
        &self,
        admin: &Admin,
        project: Uuid,
        principal: Principal,
        role: &str,
    ) -> Result<()> {
        admin.require(Permission::AuthorizationsManage)?;
        self.revoke_project_role(admin.tenant(), project, principal, role, &admin.creator()).await
    }

    // The instance

    pub async fn admin_instance(&self, admin: &Admin) -> Result<InstanceOverview> {
        admin.require(Permission::InstanceRead)?;
        let state = self.instance(admin.instance()).await?.state;
        Ok(InstanceOverview {
            instance: InstanceInfo {
                id: admin.instance(),
                name: state.name,
                primary_domain: state.primary.map(|domain| domain.to_string()).unwrap_or_default(),
                login_ui: state.login_ui,
                passkey_rp_id: state.passkey_rp_id.map(|rp_id| rp_id.to_string()).unwrap_or_default(),
                domains: state.domains.iter().map(ToString::to_string).collect(),
            },
            domains: state.domains.iter().map(ToString::to_string).collect(),
        })
    }

    pub async fn admin_rename_instance(&self, admin: &Admin, name: &str) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.rename_instance(admin.instance(), name, &admin.creator()).await
    }

    pub async fn admin_set_passkey_rp_id(&self, admin: &Admin, rp_id: &DomainName) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.set_passkey_rp_id(admin.instance(), rp_id, &admin.creator()).await
    }

    pub async fn admin_set_login_ui(&self, admin: &Admin, url: Option<&str>) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.set_login_ui(admin.instance(), url, &admin.creator()).await
    }

    pub async fn admin_add_instance_domain(&self, admin: &Admin, domain: &DomainName) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.add_instance_domain(admin.instance(), domain, &admin.creator()).await
    }

    pub async fn admin_remove_instance_domain(&self, admin: &Admin, domain: &DomainName) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.remove_instance_domain(admin.instance(), domain, &admin.creator()).await
    }

    pub async fn admin_set_primary_domain(&self, admin: &Admin, domain: &DomainName) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.set_primary_domain(admin.instance(), domain, &admin.creator()).await
    }

    pub async fn admin_tenants(&self, admin: &Admin) -> Result<Vec<TenantInfo>> {
        admin.require(Permission::InstanceRead)?;
        self.tenants(admin.instance()).await
    }

    pub async fn admin_add_tenant(&self, admin: &Admin, name: &str) -> Result<Uuid> {
        admin.require(Permission::TenantsManage)?;
        self.add_tenant(admin.instance(), name, &admin.creator()).await
    }

    /// Renames, deactivates or reactivates a tenant of the instance – not one's own by deactivation.
    pub async fn admin_update_tenant(
        &self,
        admin: &Admin,
        tenant: Uuid,
        name: Option<&str>,
        active: Option<bool>,
    ) -> Result<()> {
        admin.require(Permission::TenantsManage)?;
        if self.tenant_instance(tenant).await? != admin.instance() {
            return Err(IdentityError::NotFound("the tenant"));
        }
        if active == Some(false) && tenant == admin.session.account.tenant {
            return Err(IdentityError::Refused("an administrator cannot deactivate their own tenant".into()));
        }
        if let Some(name) = name {
            self.rename_tenant(admin.instance(), tenant, name, &admin.creator()).await?;
        }
        if let Some(active) = active {
            self.set_tenant_active(admin.instance(), tenant, active, &admin.creator()).await?;
        }
        Ok(())
    }

    pub async fn admin_instance_role_assignments(&self, admin: &Admin) -> Result<Vec<Assignment>> {
        admin.require(Permission::InstanceRead)?;
        self.instance_role_assignments(admin.instance()).await
    }

    pub async fn admin_instance_roles(&self, admin: &Admin) -> Result<Vec<InstanceRoleInfo>> {
        admin.require(Permission::InstanceRead)?;
        self.instance_roles(admin.instance()).await
    }

    pub async fn admin_define_instance_role(
        &self,
        admin: &Admin,
        role: &Role,
        permissions: &BTreeSet<Permission>,
    ) -> Result<()> {
        admin.require(Permission::InstanceRolesManage)?;
        self.define_instance_role(admin.instance(), role, permissions, &admin.creator()).await
    }

    pub async fn admin_delete_instance_role(&self, admin: &Admin, role: &Role) -> Result<()> {
        admin.require(Permission::InstanceRolesManage)?;
        self.delete_instance_role(admin.instance(), role, &admin.creator()).await
    }

    pub async fn admin_grant_instance_role(&self, admin: &Admin, principal: Principal, role: &Role) -> Result<()> {
        admin.require(Permission::InstanceRolesManage)?;
        self.grant_instance_role(admin.instance(), principal, role, &admin.creator()).await
    }

    pub async fn admin_revoke_instance_role(&self, admin: &Admin, principal: Principal, role: &Role) -> Result<()> {
        admin.require(Permission::InstanceRolesManage)?;
        self.revoke_instance_role(admin.instance(), principal, role, &admin.creator()).await
    }
}
