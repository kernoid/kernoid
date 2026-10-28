// SPDX-License-Identifier: AGPL-3.0-or-later
//! Roles and permissions of tenants and instances (RFC 0001, section 7.4).
//!
//! - A **permission** allows one kind of administration. Tenant permissions act within one tenant; instance
//!   permissions act on the instance and its tenants.
//! - A **role** is a named set of permissions. Built-in tenant roles (`tenant_admin`, `user_manager`,
//!   `application_manager`, `auditor`) exist in every tenant; a tenant may define further roles of its own from tenant
//!   permissions (`tenant.role_defined`, `tenant.role_deleted`). Built-in instance roles (`instance_admin`,
//!   `instance_auditor`) are held at the instance; an instance may define further ones (`instance.role_defined`,
//!   `instance.role_deleted`), whose instance permissions apply at the instance and tenant permissions in every
//!   tenant.
//! - Roles are assigned to an account or a group – tenant roles as events of the tenant (`tenant.role_granted`,
//!   `tenant.role_revoked`), instance roles as events of the instance (`instance.role_granted`,
//!   `instance.role_revoked`). An account holds the roles assigned to it and to its groups.
//! - Administration goes through [`Identity::admin`]: a valid session, the MFA policies met, the permissions for the
//!   tenant administered – the account's own, or another of the instance for instance administrators.
//! - **No escalation by the back door:** changing the members of a group that holds roles needs the permission to
//!   assign those roles, and the last `tenant_admin` of a tenant and the last `instance_admin` of an instance stay.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    instance::InstanceEvent,
    session::{SessionInfo, is_multi_factor},
    tenant::TenantEvent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Permission {
    /// See the tenant, its accounts, groups, roles, projects and applications.
    #[serde(rename = "directory.read")]
    DirectoryRead,
    /// The tenant's name and modules.
    #[serde(rename = "tenant.manage")]
    TenantManage,
    /// Claim, verify and remove mail domains.
    #[serde(rename = "domains.manage")]
    DomainsManage,
    /// The tenant's policies, such as requiring a second factor.
    #[serde(rename = "policies.manage")]
    PoliciesManage,
    /// Accounts: create, change, deactivate, set passwords, reset second factors, end sessions.
    #[serde(rename = "accounts.manage")]
    AccountsManage,
    #[serde(rename = "groups.manage")]
    GroupsManage,
    /// Define tenant roles and grant and revoke them.
    #[serde(rename = "roles.manage")]
    RolesManage,
    /// Projects and their roles.
    #[serde(rename = "projects.manage")]
    ProjectsManage,
    #[serde(rename = "applications.manage")]
    ApplicationsManage,
    /// Assign project roles to accounts and groups.
    #[serde(rename = "authorizations.manage")]
    AuthorizationsManage,
    /// External identity providers accounts log in with.
    #[serde(rename = "identity_providers.manage")]
    IdentityProvidersManage,
    /// Tokens for provisioning with SCIM.
    #[serde(rename = "provisioning.manage")]
    ProvisioningManage,
    /// See the instance, its domains, signing keys, tenants and instance roles.
    #[serde(rename = "instance.read")]
    InstanceRead,
    /// The instance's name, domains and signing keys.
    #[serde(rename = "instance.manage")]
    InstanceManage,
    /// Create, rename, deactivate tenants; mark their domains verified.
    #[serde(rename = "tenants.manage")]
    TenantsManage,
    /// Grant and revoke instance roles.
    #[serde(rename = "instance_roles.manage")]
    InstanceRolesManage,
}

impl Permission {
    /// Permissions within one tenant – the ones a tenant's own roles may contain.
    pub const TENANT: [Self; 12] = [
        Self::DirectoryRead,
        Self::TenantManage,
        Self::DomainsManage,
        Self::PoliciesManage,
        Self::AccountsManage,
        Self::GroupsManage,
        Self::RolesManage,
        Self::ProjectsManage,
        Self::ApplicationsManage,
        Self::AuthorizationsManage,
        Self::IdentityProvidersManage,
        Self::ProvisioningManage,
    ];
    pub const INSTANCE: [Self; 4] =
        [Self::InstanceRead, Self::InstanceManage, Self::TenantsManage, Self::InstanceRolesManage];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryRead => "directory.read",
            Self::TenantManage => "tenant.manage",
            Self::DomainsManage => "domains.manage",
            Self::PoliciesManage => "policies.manage",
            Self::AccountsManage => "accounts.manage",
            Self::GroupsManage => "groups.manage",
            Self::RolesManage => "roles.manage",
            Self::ProjectsManage => "projects.manage",
            Self::ApplicationsManage => "applications.manage",
            Self::AuthorizationsManage => "authorizations.manage",
            Self::IdentityProvidersManage => "identity_providers.manage",
            Self::ProvisioningManage => "provisioning.manage",
            Self::InstanceRead => "instance.read",
            Self::InstanceManage => "instance.manage",
            Self::TenantsManage => "tenants.manage",
            Self::InstanceRolesManage => "instance_roles.manage",
        }
    }

    pub fn is_tenant(self) -> bool {
        Self::TENANT.contains(&self)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for Permission {
    type Err = IdentityError;

    fn from_str(name: &str) -> Result<Self> {
        Self::TENANT
            .into_iter()
            .chain(Self::INSTANCE)
            .find(|permission| permission.as_str() == name)
            .ok_or_else(|| IdentityError::Refused(format!("there is no permission {name:?}")))
    }
}

/// The name of a role: lower-case letters, digits and `_`, starting with a letter, at most 64 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Role(String);

const TENANT_ADMIN: &str = "tenant_admin";
const INSTANCE_ADMIN: &str = "instance_admin";

/// The built-in tenant roles and their permissions.
pub const TENANT_ROLES: [(&str, &[Permission]); 4] = {
    use Permission::*;
    [
        (TENANT_ADMIN, &Permission::TENANT),
        ("user_manager", &[DirectoryRead, AccountsManage, GroupsManage, AuthorizationsManage]),
        ("application_manager", &[DirectoryRead, ProjectsManage, ApplicationsManage]),
        ("auditor", &[DirectoryRead]),
    ]
};

/// The built-in instance roles: their permissions at the instance, and in every tenant of it.
pub const INSTANCE_ROLES: [(&str, &[Permission], &[Permission]); 2] = [
    (INSTANCE_ADMIN, &Permission::INSTANCE, &Permission::TENANT),
    ("instance_auditor", &[Permission::InstanceRead], &[Permission::DirectoryRead]),
];

impl Role {
    pub fn parse(name: &str) -> Result<Self> {
        let valid = name.len() <= 64
            && name.starts_with(|c: char| c.is_ascii_lowercase())
            && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid {
            return Err(IdentityError::Refused(format!(
                "a role name has lower-case letters, digits and _, starts with a letter, at most 64 characters: \
                 {name:?}"
            )));
        }
        Ok(Self(name.to_owned()))
    }

    pub fn tenant_admin() -> Self {
        Self(TENANT_ADMIN.into())
    }

    pub fn instance_admin() -> Self {
        Self(INSTANCE_ADMIN.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The permissions of a built-in tenant role.
    pub fn builtin_tenant(&self) -> Option<&'static [Permission]> {
        TENANT_ROLES.iter().find(|(name, _)| *name == self.0).map(|(_, permissions)| *permissions)
    }

    /// The permissions of a built-in instance role: at the instance, and in every tenant.
    pub fn builtin_instance(&self) -> Option<(&'static [Permission], &'static [Permission])> {
        INSTANCE_ROLES.iter().find(|(name, ..)| *name == self.0).map(|(_, instance, tenants)| (*instance, *tenants))
    }

    pub fn is_builtin(&self) -> bool {
        self.builtin_tenant().is_some() || self.builtin_instance().is_some()
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

impl FromStr for Role {
    type Err = IdentityError;

    fn from_str(name: &str) -> Result<Self> {
        Self::parse(name)
    }
}

/// Who holds a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Principal {
    Account(Uuid),
    Group(Uuid),
}

impl Principal {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Account(_) => "account",
            Self::Group(_) => "group",
        }
    }

    pub fn id(self) -> Uuid {
        match self {
            Self::Account(id) | Self::Group(id) => id,
        }
    }

    pub fn new(kind: &str, id: Uuid) -> Result<Self> {
        match kind {
            "account" => Ok(Self::Account(id)),
            "group" => Ok(Self::Group(id)),
            _ => Err(IdentityError::Refused(format!("a role is held by an account or a group, not {kind:?}"))),
        }
    }

    fn not_found(self) -> IdentityError {
        IdentityError::NotFound(match self {
            Self::Account(_) => "the account",
            Self::Group(_) => "the group",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Assignment {
    pub principal: Principal,
    pub role: Role,
}

/// A role as a tenant sees it: built in, or defined by the tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInfo {
    pub role: Role,
    pub permissions: BTreeSet<Permission>,
    pub builtin: bool,
}

/// An account administering a tenant, as [`Identity::admin`] found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admin {
    pub session: SessionInfo,
    /// The tenant administered: the account's own, or – for instance administrators – another of the instance.
    pub tenant: Uuid,
    /// Instance permissions, and tenant permissions for [`Admin::tenant`].
    pub permissions: BTreeSet<Permission>,
}

impl Admin {
    pub fn tenant(&self) -> Uuid {
        self.tenant
    }

    pub fn instance(&self) -> Uuid {
        self.session.account.instance
    }

    pub fn account(&self) -> Uuid {
        self.session.account.id
    }

    /// Who the events this administrator causes name as their creator.
    pub fn creator(&self) -> String {
        format!("account:{}", self.session.account.id)
    }

    pub fn require(&self, permission: Permission) -> Result<()> {
        if self.permissions.contains(&permission) { Ok(()) } else { Err(IdentityError::Forbidden(permission)) }
    }
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

/// Permissions stored as text; ones the code no longer knows grant nothing.
fn parse_permissions(names: &[String]) -> BTreeSet<Permission> {
    names.iter().filter_map(|name| name.parse().ok()).collect()
}

impl Identity {
    /// The permissions an account holds in a tenant through tenant roles, directly and through its groups.
    async fn tenant_role_permissions(&self, tenant: Uuid, account: Uuid) -> Result<BTreeSet<Permission>> {
        let rows = sqlx::query!(
            r#"SELECT DISTINCT a.role, r.permissions AS "permissions?"
               FROM role_assignments a
               LEFT JOIN tenant_roles r ON r.tenant_id = a.tenant_id AND r.name = a.role
               WHERE a.tenant_id = $1
                 AND ((a.principal_kind = 'account' AND a.principal_id = $2)
                   OR (a.principal_kind = 'group'
                       AND a.principal_id IN (SELECT group_id FROM group_members WHERE account_id = $2)))"#,
            tenant,
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let mut permissions = BTreeSet::new();
        for row in rows {
            match Role::parse(&row.role).ok().and_then(|role| role.builtin_tenant()) {
                Some(builtin) => permissions.extend(builtin.iter().copied()),
                None => permissions.extend(
                    parse_permissions(&row.permissions.unwrap_or_default()).into_iter().filter(|p| p.is_tenant()),
                ),
            }
        }
        Ok(permissions)
    }

    /// The permissions an account holds through instance roles: at the instance, and in every tenant of it.
    async fn instance_role_permissions(
        &self,
        instance: Uuid,
        account: Uuid,
    ) -> Result<(BTreeSet<Permission>, BTreeSet<Permission>)> {
        let rows = sqlx::query!(
            r#"SELECT DISTINCT a.role, r.permissions AS "permissions?"
               FROM instance_role_assignments a
               LEFT JOIN instance_roles r ON r.instance_id = a.instance_id AND r.name = a.role
               WHERE a.instance_id = $1
                 AND ((a.principal_kind = 'account' AND a.principal_id = $2)
                   OR (a.principal_kind = 'group'
                       AND a.principal_id IN (SELECT group_id FROM group_members WHERE account_id = $2)))"#,
            instance,
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let (mut at_instance, mut everywhere) = (BTreeSet::new(), BTreeSet::new());
        for row in rows {
            match Role::parse(&row.role).ok().and_then(|role| role.builtin_instance()) {
                Some((instance_permissions, tenant_permissions)) => {
                    at_instance.extend(instance_permissions.iter().copied());
                    everywhere.extend(tenant_permissions.iter().copied());
                }
                None => {
                    let (tenant, own): (BTreeSet<_>, BTreeSet<_>) =
                        parse_permissions(&row.permissions.unwrap_or_default())
                            .into_iter()
                            .partition(|p| p.is_tenant());
                    at_instance.extend(own);
                    everywhere.extend(tenant);
                }
            }
        }
        Ok((at_instance, everywhere))
    }

    /// Everything an account may do in `tenant`: tenant permissions there (from its tenant roles, if it is its own
    /// tenant, and from instance roles) and its instance permissions.
    pub async fn permissions(&self, tenant: Uuid, account: Uuid) -> Result<BTreeSet<Permission>> {
        let (instance, own) = self.account_owner(account).await?;
        let (mut permissions, everywhere) = self.instance_role_permissions(instance, account).await?;
        if tenant == own {
            permissions.extend(self.tenant_role_permissions(tenant, account).await?);
            permissions.extend(everywhere);
        } else if self.tenant_instance(tenant).await? == instance {
            permissions.extend(everywhere);
        }
        Ok(permissions)
    }

    /// The account behind a session token, administering its own tenant or – with `tenant`, for instance
    /// administrators – another tenant of the instance. The session must be valid at `instance` and have a second
    /// factor if the account's tenant or the tenant administered requires one. Each operation then checks its own
    /// permission.
    pub async fn admin(&self, instance: Uuid, token: &str, tenant: Option<Uuid>) -> Result<Admin> {
        let session = self.session(instance, token).await?;
        let own = session.account.tenant;
        let target = tenant.unwrap_or(own);
        let permissions = self.permissions(target, session.account.id).await?;
        // Someone without an instance role learns nothing about other tenants.
        if target != own && !permissions.iter().any(|permission| permission.is_tenant()) {
            return Err(IdentityError::NotFound("the tenant"));
        }
        // The account's own tenant may grant a grace period; another tenant administered requires without one.
        let mfa = self.mfa_required_now(session.account.id).await?
            || (target != own && self.tenant_requires_mfa(target).await?);
        if mfa && !is_multi_factor(&session.checks) {
            return Err(IdentityError::MfaRequired);
        }
        Ok(Admin { session, tenant: target, permissions })
    }

    /// Like [`Identity::admin`] for the account's own tenant, and the account must hold `permission`.
    pub async fn authorize(&self, instance: Uuid, token: &str, permission: Permission) -> Result<Admin> {
        let admin = self.admin(instance, token, None).await?;
        admin.require(permission)?;
        Ok(admin)
    }

    // Tenant roles

    /// The roles of a tenant: the built-in ones and its own.
    pub async fn tenant_roles(&self, tenant: Uuid) -> Result<Vec<RoleInfo>> {
        let custom =
            sqlx::query!("SELECT name, permissions FROM tenant_roles WHERE tenant_id = $1 ORDER BY name", tenant)
                .fetch_all(self.pool())
                .await
                .map_err(store_error)?;
        let builtin = TENANT_ROLES.iter().map(|(name, permissions)| RoleInfo {
            role: Role(name.to_string()),
            permissions: permissions.iter().copied().collect(),
            builtin: true,
        });
        Ok(builtin
            .chain(custom.into_iter().map(|row| RoleInfo {
                role: Role(row.name),
                permissions: parse_permissions(&row.permissions),
                builtin: false,
            }))
            .collect())
    }

    /// Defines a role of the tenant's own, or changes the permissions of one; only tenant permissions, at least one.
    pub async fn define_role(
        &self,
        tenant: Uuid,
        role: &Role,
        permissions: &BTreeSet<Permission>,
        creator: &str,
    ) -> Result<()> {
        if role.is_builtin() {
            return Err(IdentityError::Refused(format!("{role} is a built-in role")));
        }
        if permissions.is_empty() || permissions.iter().any(|permission| !permission.is_tenant()) {
            return Err(IdentityError::Refused("a tenant role has at least one permission, all of the tenant".into()));
        }
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            crate::existing_tenant(state)?;
            Ok(if state.custom_roles.get(role) == Some(permissions) {
                Vec::new()
            } else {
                vec![TenantEvent::RoleDefined { role: role.clone(), permissions: permissions.clone() }]
            })
        })
        .await
    }

    /// Deletes a role of the tenant's own – once nobody holds it.
    pub async fn delete_role(&self, tenant: Uuid, role: &Role, creator: &str) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            crate::existing_tenant(state)?;
            if !state.custom_roles.contains_key(role) {
                return Err(IdentityError::NotFound("the role"));
            }
            if state.roles.iter().any(|held| &held.role == role) {
                return Err(IdentityError::Refused(format!("{role} is assigned; revoke it first")));
            }
            Ok(vec![TenantEvent::RoleDeleted { role: role.clone() }])
        })
        .await
    }

    pub async fn role_assignments(&self, tenant: Uuid) -> Result<Vec<Assignment>> {
        let rows = sqlx::query!(
            "SELECT principal_kind, principal_id, role FROM role_assignments
             WHERE tenant_id = $1 ORDER BY role, principal_kind, principal_id",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some(Assignment {
                    principal: Principal::new(&row.principal_kind, row.principal_id).ok()?,
                    role: Role::parse(&row.role).ok()?,
                })
            })
            .collect())
    }

    /// The tenant an account or group belongs to.
    pub(crate) async fn principal_tenant(&self, principal: Principal) -> Result<Uuid> {
        match principal {
            Principal::Account(account) => Ok(self.account_owner(account).await?.1),
            Principal::Group(group) => self.group_tenant(group).await,
        }
    }

    /// The principal must belong to the tenant.
    pub(crate) async fn principal_of(&self, tenant: Uuid, principal: Principal) -> Result<()> {
        if self.principal_tenant(principal).await? == tenant { Ok(()) } else { Err(principal.not_found()) }
    }

    /// Assigns a built-in or own role of the tenant to an account or group of it; assigning it twice changes nothing.
    pub async fn grant_role(&self, tenant: Uuid, principal: Principal, role: &Role, creator: &str) -> Result<()> {
        self.principal_of(tenant, principal).await?;
        let instance = self.tenant_instance(tenant).await?;
        let assignment = Assignment { principal, role: role.clone() };
        self.tenant_command(instance, tenant, creator, None, |state| {
            crate::existing_tenant(state)?;
            if role.builtin_tenant().is_none() && !state.custom_roles.contains_key(role) {
                return Err(IdentityError::NotFound("the role"));
            }
            Ok(if state.roles.contains(&assignment) {
                Vec::new()
            } else {
                vec![TenantEvent::RoleGranted { principal, role: role.clone() }]
            })
        })
        .await
    }

    /// Takes a role back. The tenant's last `tenant_admin` assignment stays, and so does the last one through which
    /// an active account administers it: someone must be able to.
    pub async fn revoke_role(&self, tenant: Uuid, principal: Principal, role: &Role, creator: &str) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        let last_holders = role.as_str() == TENANT_ADMIN
            && leaves_none(&self.admin_holders(AdminScope::Tenant(tenant)).await?, |held| held.principal == principal);
        let assignment = Assignment { principal, role: role.clone() };
        self.tenant_command(instance, tenant, creator, None, |state| {
            crate::existing_tenant(state)?;
            if !state.roles.contains(&assignment) {
                return Err(IdentityError::NotFound("the role assignment"));
            }
            let admins = state.roles.iter().filter(|held| held.role.as_str() == TENANT_ADMIN).count();
            if role.as_str() == TENANT_ADMIN && (admins == 1 || last_holders) {
                return Err(IdentityError::Refused("the last tenant_admin assignment cannot be revoked".into()));
            }
            Ok(vec![TenantEvent::RoleRevoked { principal, role: role.clone() }])
        })
        .await
    }

    // Instance roles

    /// The instance roles – built in and the instance's own – with their permissions at the instance and in every
    /// tenant.
    pub async fn instance_roles(&self, instance: Uuid) -> Result<Vec<InstanceRoleInfo>> {
        let custom =
            sqlx::query!("SELECT name, permissions FROM instance_roles WHERE instance_id = $1 ORDER BY name", instance)
                .fetch_all(self.pool())
                .await
                .map_err(store_error)?;
        let builtin = INSTANCE_ROLES.iter().map(|(name, at_instance, tenants)| InstanceRoleInfo {
            role: Role(name.to_string()),
            permissions: at_instance.iter().copied().collect(),
            tenant_permissions: tenants.iter().copied().collect(),
            builtin: true,
        });
        Ok(builtin
            .chain(custom.into_iter().map(|row| {
                let (tenant_permissions, permissions) =
                    parse_permissions(&row.permissions).into_iter().partition(|p| p.is_tenant());
                InstanceRoleInfo { role: Role(row.name), permissions, tenant_permissions, builtin: false }
            }))
            .collect())
    }

    /// Defines an instance role of the instance's own, or changes its permissions: at least one, of the instance
    /// (applied there) or of tenants (applied in every tenant).
    pub async fn define_instance_role(
        &self,
        instance: Uuid,
        role: &Role,
        permissions: &BTreeSet<Permission>,
        creator: &str,
    ) -> Result<()> {
        if role.is_builtin() {
            return Err(IdentityError::Refused(format!("{role} is a built-in role")));
        }
        if permissions.is_empty() {
            return Err(IdentityError::Refused("an instance role has at least one permission".into()));
        }
        self.instance_command(instance, creator, None, |state| {
            crate::existing_instance(state)?;
            Ok(if state.custom_roles.get(role) == Some(permissions) {
                Vec::new()
            } else {
                vec![InstanceEvent::RoleDefined { role: role.clone(), permissions: permissions.clone() }]
            })
        })
        .await
    }

    /// Deletes an instance role of the instance's own – once nobody holds it.
    pub async fn delete_instance_role(&self, instance: Uuid, role: &Role, creator: &str) -> Result<()> {
        self.instance_command(instance, creator, None, |state| {
            crate::existing_instance(state)?;
            if !state.custom_roles.contains_key(role) {
                return Err(IdentityError::NotFound("the instance role"));
            }
            if state.roles.iter().any(|held| &held.role == role) {
                return Err(IdentityError::Refused(format!("{role} is assigned; revoke it first")));
            }
            Ok(vec![InstanceEvent::RoleDeleted { role: role.clone() }])
        })
        .await
    }

    pub async fn instance_role_assignments(&self, instance: Uuid) -> Result<Vec<Assignment>> {
        let rows = sqlx::query!(
            "SELECT principal_kind, principal_id, role FROM instance_role_assignments
             WHERE instance_id = $1 ORDER BY role, principal_kind, principal_id",
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some(Assignment {
                    principal: Principal::new(&row.principal_kind, row.principal_id).ok()?,
                    role: Role::parse(&row.role).ok()?,
                })
            })
            .collect())
    }

    /// Assigns an instance role to an account or group of any tenant of the instance.
    pub async fn grant_instance_role(
        &self,
        instance: Uuid,
        principal: Principal,
        role: &Role,
        creator: &str,
    ) -> Result<()> {
        let tenant = self.principal_tenant(principal).await?;
        if self.tenant_instance(tenant).await? != instance {
            return Err(principal.not_found());
        }
        let assignment = Assignment { principal, role: role.clone() };
        self.instance_command(instance, creator, None, |state| {
            crate::existing_instance(state)?;
            if role.builtin_instance().is_none() && !state.custom_roles.contains_key(role) {
                return Err(IdentityError::NotFound("the instance role"));
            }
            Ok(if state.roles.contains(&assignment) {
                Vec::new()
            } else {
                vec![InstanceEvent::RoleGranted { principal, role: role.clone() }]
            })
        })
        .await
    }

    /// Takes an instance role back; the instance's last `instance_admin` assignment stays, and so does the last one
    /// through which an active account administers it.
    pub async fn revoke_instance_role(
        &self,
        instance: Uuid,
        principal: Principal,
        role: &Role,
        creator: &str,
    ) -> Result<()> {
        let last_holders = role.as_str() == INSTANCE_ADMIN
            && leaves_none(&self.admin_holders(AdminScope::Instance(instance)).await?, |held| {
                held.principal == principal
            });
        let assignment = Assignment { principal, role: role.clone() };
        self.instance_command(instance, creator, None, |state| {
            crate::existing_instance(state)?;
            if !state.roles.contains(&assignment) {
                return Err(IdentityError::NotFound("the role assignment"));
            }
            let admins = state.roles.iter().filter(|held| held.role.as_str() == INSTANCE_ADMIN).count();
            if role.as_str() == INSTANCE_ADMIN && (admins == 1 || last_holders) {
                return Err(IdentityError::Refused("the last instance_admin assignment cannot be revoked".into()));
            }
            Ok(vec![InstanceEvent::RoleRevoked { principal, role: role.clone() }])
        })
        .await
    }

    /// The active accounts that administer a tenant (`tenant_admin`) or an instance (`instance_admin`), and through
    /// which assignment – directly or as members of a group. Deactivated accounts, accounts of deactivated tenants and
    /// empty groups do not count.
    pub(crate) async fn admin_holders(&self, scope: AdminScope) -> Result<Vec<Holder>> {
        let rows = match scope {
            AdminScope::Tenant(tenant) => sqlx::query!(
                r#"SELECT r.principal_kind, r.principal_id, a.id AS account, a.tenant_id
                   FROM role_assignments r
                   JOIN accounts a ON a.tenant_id = r.tenant_id AND a.active
                    AND ((r.principal_kind = 'account' AND a.id = r.principal_id)
                      OR (r.principal_kind = 'group' AND EXISTS (SELECT 1 FROM group_members m
                              WHERE m.group_id = r.principal_id AND m.account_id = a.id)))
                   JOIN tenants t ON t.id = a.tenant_id AND t.active
                   WHERE r.tenant_id = $1 AND r.role = $2"#,
                tenant,
                TENANT_ADMIN,
            )
            .fetch_all(self.pool())
            .await
            .map_err(store_error)?
            .into_iter()
            .map(|row| (row.principal_kind, row.principal_id, row.account, row.tenant_id))
            .collect::<Vec<_>>(),
            AdminScope::Instance(instance) => sqlx::query!(
                r#"SELECT r.principal_kind, r.principal_id, a.id AS account, a.tenant_id
                   FROM instance_role_assignments r
                   JOIN accounts a ON a.active
                    AND ((r.principal_kind = 'account' AND a.id = r.principal_id)
                      OR (r.principal_kind = 'group' AND EXISTS (SELECT 1 FROM group_members m
                              WHERE m.group_id = r.principal_id AND m.account_id = a.id)))
                   JOIN tenants t ON t.id = a.tenant_id AND t.active AND t.instance_id = r.instance_id
                   WHERE r.instance_id = $1 AND r.role = $2"#,
                instance,
                INSTANCE_ADMIN,
            )
            .fetch_all(self.pool())
            .await
            .map_err(store_error)?
            .into_iter()
            .map(|row| (row.principal_kind, row.principal_id, row.account, row.tenant_id))
            .collect(),
        };
        Ok(rows
            .into_iter()
            .filter_map(|(kind, id, account, tenant)| {
                Some(Holder { principal: Principal::new(&kind, id).ok()?, account, tenant })
            })
            .collect())
    }

    /// Refuses a change that would leave the tenant – and the instance – without an active administrator: `gone`
    /// says which holders the change takes away.
    pub(crate) async fn keep_an_admin(
        &self,
        tenant: Option<Uuid>,
        instance: Uuid,
        gone: impl Fn(&Holder) -> bool,
    ) -> Result<()> {
        if let Some(tenant) = tenant
            && leaves_none(&self.admin_holders(AdminScope::Tenant(tenant)).await?, &gone)
        {
            return Err(IdentityError::Refused("this would leave the tenant without an active tenant_admin".into()));
        }
        if leaves_none(&self.admin_holders(AdminScope::Instance(instance)).await?, &gone) {
            return Err(IdentityError::Refused(
                "this would leave the instance without an active instance_admin".into(),
            ));
        }
        Ok(())
    }

    /// What a group holds that its members gain: tenant roles, instance roles, project roles.
    pub async fn group_holdings(&self, group: Uuid) -> Result<GroupHoldings> {
        let row = sqlx::query!(
            r#"SELECT
                 EXISTS (SELECT 1 FROM role_assignments WHERE principal_kind = 'group' AND principal_id = $1)
                     AS "tenant_roles!",
                 EXISTS (SELECT 1 FROM instance_role_assignments WHERE principal_kind = 'group' AND principal_id = $1)
                     AS "instance_roles!",
                 EXISTS (SELECT 1 FROM project_authorizations WHERE principal_kind = 'group' AND principal_id = $1)
                     AS "project_roles!""#,
            group,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        Ok(GroupHoldings {
            tenant_roles: row.tenant_roles,
            instance_roles: row.instance_roles,
            project_roles: row.project_roles,
        })
    }
}

/// See [`Identity::group_holdings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupHoldings {
    pub tenant_roles: bool,
    pub instance_roles: bool,
    pub project_roles: bool,
}

impl GroupHoldings {
    pub fn any(self) -> bool {
        self.tenant_roles || self.instance_roles || self.project_roles
    }

    /// The permissions needed to change the group's members, beyond `groups.manage`.
    pub fn permissions_to_change_members(self) -> Vec<Permission> {
        let mut needed = Vec::new();
        if self.tenant_roles {
            needed.push(Permission::RolesManage);
        }
        if self.instance_roles {
            needed.push(Permission::InstanceRolesManage);
        }
        if self.project_roles {
            needed.push(Permission::AuthorizationsManage);
        }
        needed
    }
}

/// An instance role with its permissions at the instance and in every tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRoleInfo {
    pub role: Role,
    pub permissions: BTreeSet<Permission>,
    pub tenant_permissions: BTreeSet<Permission>,
    pub builtin: bool,
}

/// Whose administration [`Identity::admin_holders`] looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminScope {
    Tenant(Uuid),
    Instance(Uuid),
}

/// An active account administering through an assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Holder {
    pub principal: Principal,
    pub account: Uuid,
    pub tenant: Uuid,
}

/// Whether taking away the holders `gone` picks would leave none – where there were some.
fn leaves_none(holders: &[Holder], gone: impl Fn(&Holder) -> bool) -> bool {
    !holders.is_empty() && holders.iter().all(gone)
}

/// For [`BTreeMap`] keys in aggregates.
pub(crate) type CustomRoles = BTreeMap<Role, BTreeSet<Permission>>;
