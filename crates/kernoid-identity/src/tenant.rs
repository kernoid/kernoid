// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tenant: an organisation within an instance, with its mail domains, the modules it uses, its policies and who
//! holds which role. A tenant owns its
//! own events.

use std::collections::{BTreeMap, BTreeSet};

use kernoid_events::{
    Error, Event,
    aggregate::{Aggregate, DomainEvent},
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    DomainName,
    role::{Assignment, CustomRoles, Permission, Principal, Role},
    services::{Assign, Service, ServicePolicy},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum TenantEvent {
    #[serde(rename = "tenant.added")]
    Added { instance: Uuid, name: String },
    #[serde(rename = "tenant.renamed")]
    Renamed { name: String },
    /// Nobody of the tenant can log in, receive or send mail until it is reactivated.
    #[serde(rename = "tenant.deactivated")]
    Deactivated,
    #[serde(rename = "tenant.reactivated")]
    Reactivated,
    /// Claimed; usable once verified through DNS.
    #[serde(rename = "tenant.domain_added")]
    DomainAdded { domain: DomainName, token: String },
    #[serde(rename = "tenant.domain_verified")]
    DomainVerified { domain: DomainName },
    #[serde(rename = "tenant.domain_removed")]
    DomainRemoved { domain: DomainName },
    #[serde(rename = "tenant.module_enabled")]
    ModuleEnabled { module: String },
    #[serde(rename = "tenant.module_disabled")]
    ModuleDisabled { module: String },
    /// Whether logins to applications need a second factor for every account of the tenant.
    #[serde(rename = "tenant.mfa_requirement_set")]
    MfaRequirementSet { required: bool },
    /// Accounts without a second factor may log in without one for this many days after the requirement (or the
    /// account) began – time to set one up.
    #[serde(rename = "tenant.mfa_grace_set")]
    MfaGraceSet { days: u32 },
    #[serde(rename = "tenant.role_granted")]
    RoleGranted { principal: Principal, role: Role },
    #[serde(rename = "tenant.role_revoked")]
    RoleRevoked { principal: Principal, role: Role },
    /// A role of the tenant's own, created or with changed permissions.
    #[serde(rename = "tenant.role_defined")]
    RoleDefined { role: Role, permissions: BTreeSet<Permission> },
    #[serde(rename = "tenant.role_deleted")]
    RoleDeleted { role: Role },
    /// A token for provisioning with SCIM; the token itself is in `scim_tokens`, hashed.
    #[serde(rename = "tenant.scim_token_added")]
    ScimTokenAdded { id: Uuid, name: String },
    #[serde(rename = "tenant.scim_token_removed")]
    ScimTokenRemoved { id: Uuid },
    /// The mail quota of every account without its own (RFC 0002, 8); `None` for no limit.
    #[serde(rename = "tenant.default_mail_quota_set")]
    DefaultMailQuotaSet { bytes: Option<u64> },
    /// The files quota of every account without its own (RFC 0005, 10); `None` for no limit.
    #[serde(rename = "tenant.default_files_quota_set")]
    DefaultFilesQuotaSet { bytes: Option<u64> },
    /// Days after which emails leave the accounts' Trash and Junk (RFC 0002, 13.2); `None` keeps them.
    #[serde(rename = "tenant.mail_retention_set")]
    MailRetentionSet { trash_days: Option<u32>, junk_days: Option<u32> },
    /// How the tenant's accounts log in (RFC 0003, 2): with usernames, with their verified contact address.
    #[serde(rename = "tenant.login_policy_set")]
    LoginPolicySet { usernames: bool, email_login: bool },
    /// Whether people may register, and on which verified domains new accounts may take an address (RFC 0003, 5).
    #[serde(rename = "tenant.registration_set")]
    RegistrationSet { allowed: bool, domains: Vec<DomainName> },
    /// Who gets a service when an account is created, and whether it needs approval (RFC 0003, 4).
    #[serde(rename = "tenant.service_policy_set")]
    ServicePolicySet { service: Service, assign: Assign, approval: bool },
}

impl DomainEvent for TenantEvent {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantDomain {
    pub token: String,
    pub verified: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub exists: bool,
    pub instance: Uuid,
    pub name: String,
    pub active: bool,
    pub domains: BTreeMap<DomainName, TenantDomain>,
    pub modules: BTreeSet<String>,
    pub mfa_required: bool,
    pub mfa_grace_days: u32,
    pub roles: BTreeSet<Assignment>,
    pub custom_roles: CustomRoles,
    pub scim_tokens: BTreeSet<Uuid>,
    pub default_mail_quota: Option<u64>,
    pub default_files_quota: Option<u64>,
    /// Days in Trash and in Junk.
    pub mail_retention: (Option<u32>, Option<u32>),
    pub login_policy: LoginPolicy,
    pub registration: Registration,
    pub service_policies: BTreeMap<Service, ServicePolicy>,
}

/// How a tenant's accounts log in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginPolicy {
    pub usernames: bool,
    pub email_login: bool,
}

impl Default for LoginPolicy {
    fn default() -> Self {
        Self { usernames: false, email_login: true }
    }
}

/// Whether people may register with a tenant, and on which of its domains.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registration {
    pub allowed: bool,
    pub domains: Vec<DomainName>,
}

impl Aggregate for Tenant {
    const TYPE: &'static str = "tenant";
    type Event = TenantEvent;

    fn apply(&mut self, event: TenantEvent) {
        match event {
            TenantEvent::Added { instance, name } => {
                *self = Self { exists: true, instance, name, active: true, ..Self::default() };
            }
            TenantEvent::Renamed { name } => self.name = name,
            TenantEvent::Deactivated => self.active = false,
            TenantEvent::Reactivated => self.active = true,
            TenantEvent::DomainAdded { domain, token } => {
                self.domains.insert(domain, TenantDomain { token, verified: false });
            }
            TenantEvent::DomainVerified { domain } => {
                if let Some(entry) = self.domains.get_mut(&domain) {
                    entry.verified = true;
                }
            }
            TenantEvent::DomainRemoved { domain } => {
                self.domains.remove(&domain);
            }
            TenantEvent::ModuleEnabled { module } => {
                self.modules.insert(module);
            }
            TenantEvent::ModuleDisabled { module } => {
                self.modules.remove(&module);
            }
            TenantEvent::MfaRequirementSet { required } => self.mfa_required = required,
            TenantEvent::MfaGraceSet { days } => self.mfa_grace_days = days,
            TenantEvent::RoleGranted { principal, role } => {
                self.roles.insert(Assignment { principal, role });
            }
            TenantEvent::RoleRevoked { principal, role } => {
                self.roles.remove(&Assignment { principal, role });
            }
            TenantEvent::RoleDefined { role, permissions } => {
                self.custom_roles.insert(role, permissions);
            }
            TenantEvent::RoleDeleted { role } => {
                self.custom_roles.remove(&role);
            }
            TenantEvent::ScimTokenAdded { id, .. } => {
                self.scim_tokens.insert(id);
            }
            TenantEvent::ScimTokenRemoved { id } => {
                self.scim_tokens.remove(&id);
            }
            TenantEvent::DefaultMailQuotaSet { bytes } => self.default_mail_quota = bytes,
            TenantEvent::DefaultFilesQuotaSet { bytes } => self.default_files_quota = bytes,
            TenantEvent::MailRetentionSet { trash_days, junk_days } => self.mail_retention = (trash_days, junk_days),
            TenantEvent::LoginPolicySet { usernames, email_login } => {
                self.login_policy = LoginPolicy { usernames, email_login };
            }
            TenantEvent::RegistrationSet { allowed, domains } => self.registration = Registration { allowed, domains },
            TenantEvent::ServicePolicySet { service, assign, approval } => {
                self.service_policies.insert(service, ServicePolicy { assign, approval });
            }
        }
    }
}

/// Keeps `tenants`, `tenant_domains`, `tenant_modules`, `role_assignments` and `tenant_roles` current, in the transaction of the events.
pub(crate) async fn project(connection: &mut PgConnection, events: &[Event]) -> Result<(), Error> {
    for event in events {
        let id = event.owner;
        match TenantEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            TenantEvent::Added { instance, name } => {
                sqlx::query!("INSERT INTO tenants (id, instance_id, name) VALUES ($1, $2, $3)", id, instance, name)
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::Renamed { name } => {
                sqlx::query!("UPDATE tenants SET name = $2 WHERE id = $1", id, name).execute(&mut *connection).await?;
            }
            TenantEvent::Deactivated => {
                sqlx::query!("UPDATE tenants SET active = false WHERE id = $1", id).execute(&mut *connection).await?;
            }
            TenantEvent::Reactivated => {
                sqlx::query!("UPDATE tenants SET active = true WHERE id = $1", id).execute(&mut *connection).await?;
            }
            TenantEvent::DomainAdded { domain, token } => {
                sqlx::query!(
                    "INSERT INTO tenant_domains (tenant_id, domain, token) VALUES ($1, $2, $3)",
                    id,
                    domain.as_str(),
                    token,
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::DomainVerified { domain } => {
                sqlx::query!(
                    "UPDATE tenant_domains SET verified = true WHERE tenant_id = $1 AND domain = $2",
                    id,
                    domain.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::DomainRemoved { domain } => {
                sqlx::query!("DELETE FROM tenant_domains WHERE tenant_id = $1 AND domain = $2", id, domain.as_str())
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::ModuleEnabled { module } => {
                sqlx::query!("INSERT INTO tenant_modules (tenant_id, module) VALUES ($1, $2)", id, module)
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::ModuleDisabled { module } => {
                sqlx::query!("DELETE FROM tenant_modules WHERE tenant_id = $1 AND module = $2", id, module)
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::MfaRequirementSet { required } => {
                sqlx::query!(
                    "UPDATE tenants SET mfa_required = $2,
                         mfa_required_since = CASE WHEN $2 THEN $3::timestamptz END WHERE id = $1",
                    id,
                    required,
                    event.created_at,
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::MfaGraceSet { days } => {
                sqlx::query!("UPDATE tenants SET mfa_grace_days = $2 WHERE id = $1", id, days as i32)
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::LoginPolicySet { usernames, email_login } => {
                sqlx::query!(
                    "UPDATE tenants SET usernames = $2, email_login = $3 WHERE id = $1",
                    id,
                    usernames,
                    email_login
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::RegistrationSet { allowed, domains } => {
                let domains: Vec<String> = domains.iter().map(|domain| domain.as_str().to_owned()).collect();
                sqlx::query!(
                    "UPDATE tenants SET registration_allowed = $2, registration_domains = $3 WHERE id = $1",
                    id,
                    allowed,
                    &domains,
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::ServicePolicySet { service, assign, approval } => {
                sqlx::query!(
                    "INSERT INTO tenant_service_policies (tenant_id, service, assign, approval) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (tenant_id, service) DO UPDATE SET assign = $3, approval = $4",
                    id,
                    service.as_str(),
                    assign.as_str(),
                    approval,
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::MailRetentionSet { trash_days, junk_days } => {
                sqlx::query!(
                    "UPDATE tenants SET trash_retention_days = $2, junk_retention_days = $3 WHERE id = $1",
                    id,
                    trash_days.map(|days| days as i32),
                    junk_days.map(|days| days as i32),
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::DefaultMailQuotaSet { bytes } => {
                let bytes = bytes.map(|bytes| i64::try_from(bytes).unwrap_or(i64::MAX));
                sqlx::query!("UPDATE tenants SET default_mail_quota = $2 WHERE id = $1", id, bytes)
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::DefaultFilesQuotaSet { bytes } => {
                let bytes = bytes.map(|bytes| i64::try_from(bytes).unwrap_or(i64::MAX));
                sqlx::query!("UPDATE tenants SET default_files_quota = $2 WHERE id = $1", id, bytes)
                    .execute(&mut *connection)
                    .await?;
            }
            TenantEvent::RoleGranted { principal, role } => {
                sqlx::query!(
                    "INSERT INTO role_assignments (tenant_id, principal_kind, principal_id, role) VALUES ($1, $2, $3, $4)",
                    id,
                    principal.kind(),
                    principal.id(),
                    role.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::RoleRevoked { principal, role } => {
                sqlx::query!(
                    "DELETE FROM role_assignments
                     WHERE tenant_id = $1 AND principal_kind = $2 AND principal_id = $3 AND role = $4",
                    id,
                    principal.kind(),
                    principal.id(),
                    role.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::RoleDefined { role, permissions } => {
                let permissions: Vec<String> = permissions.iter().map(|p| p.as_str().to_owned()).collect();
                sqlx::query!(
                    "INSERT INTO tenant_roles (tenant_id, name, permissions) VALUES ($1, $2, $3)
                     ON CONFLICT (tenant_id, name) DO UPDATE SET permissions = excluded.permissions",
                    id,
                    role.as_str(),
                    &permissions,
                )
                .execute(&mut *connection)
                .await?;
            }
            TenantEvent::RoleDeleted { role } => {
                sqlx::query!("DELETE FROM tenant_roles WHERE tenant_id = $1 AND name = $2", id, role.as_str())
                    .execute(&mut *connection)
                    .await?;
            }
            // Written by the command, which holds the token's hash.
            TenantEvent::ScimTokenAdded { .. } => {}
            TenantEvent::ScimTokenRemoved { id: token } => {
                sqlx::query!("DELETE FROM scim_tokens WHERE id = $1 AND tenant_id = $2", token, id)
                    .execute(&mut *connection)
                    .await?;
            }
        }
    }
    Ok(())
}
