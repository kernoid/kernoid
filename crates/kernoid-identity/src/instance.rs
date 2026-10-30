// SPDX-License-Identifier: AGPL-3.0-or-later
//! The instance: one identity provider with its own domains and its administrators. Its events are owned by the instance itself.

use std::collections::BTreeSet;

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
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum InstanceEvent {
    /// Created with its first domain, which is primary.
    #[serde(rename = "instance.added")]
    Added { name: String, domain: DomainName },
    #[serde(rename = "instance.renamed")]
    Renamed { name: String },
    #[serde(rename = "instance.domain_added")]
    DomainAdded { domain: DomainName },
    #[serde(rename = "instance.domain_removed")]
    DomainRemoved { domain: DomainName },
    /// The domain links (invitations, password resets) and the issuer use.
    #[serde(rename = "instance.primary_domain_set")]
    PrimaryDomainSet { domain: DomainName },
    #[serde(rename = "instance.role_granted")]
    RoleGranted { principal: Principal, role: Role },
    #[serde(rename = "instance.role_revoked")]
    RoleRevoked { principal: Principal, role: Role },
    /// A login UI of the instance's own, instead of kernoid's at `/login`; `None` goes back to kernoid's.
    #[serde(rename = "instance.login_ui_set")]
    LoginUiSet { url: Option<String> },
    /// The WebAuthn RP ID passkeys are bound to: one of the instance's domains or a parent of one. It starts as the
    /// first domain and does not follow the primary domain – passkeys registered under another RP ID stop working.
    #[serde(rename = "instance.passkey_rp_id_set")]
    PasskeyRpIdSet { rp_id: DomainName },
    /// An instance role of the instance's own, created or with changed permissions: instance permissions apply at the
    /// instance, tenant permissions in every tenant.
    #[serde(rename = "instance.role_defined")]
    RoleDefined { role: Role, permissions: BTreeSet<Permission> },
    #[serde(rename = "instance.role_deleted")]
    RoleDeleted { role: Role },
    /// Where people without an address of a tenant register (RFC 0003, 5); `None`: nowhere.
    #[serde(rename = "instance.registration_tenant_set")]
    RegistrationTenantSet { tenant: Option<Uuid> },
}

impl DomainEvent for InstanceEvent {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Instance {
    pub exists: bool,
    pub name: String,
    pub domains: BTreeSet<DomainName>,
    pub primary: Option<DomainName>,
    pub roles: BTreeSet<Assignment>,
    pub login_ui: Option<String>,
    pub passkey_rp_id: Option<DomainName>,
    pub custom_roles: CustomRoles,
    pub registration_tenant: Option<Uuid>,
}

impl Aggregate for Instance {
    const TYPE: &'static str = "instance";
    type Event = InstanceEvent;

    fn apply(&mut self, event: InstanceEvent) {
        match event {
            InstanceEvent::Added { name, domain } => {
                self.exists = true;
                self.name = name;
                self.domains.insert(domain.clone());
                self.primary = Some(domain.clone());
                self.passkey_rp_id = Some(domain);
            }
            InstanceEvent::Renamed { name } => self.name = name,
            InstanceEvent::DomainAdded { domain } => {
                self.domains.insert(domain);
            }
            InstanceEvent::DomainRemoved { domain } => {
                self.domains.remove(&domain);
            }
            InstanceEvent::PrimaryDomainSet { domain } => self.primary = Some(domain),
            InstanceEvent::RoleGranted { principal, role } => {
                self.roles.insert(Assignment { principal, role });
            }
            InstanceEvent::RoleRevoked { principal, role } => {
                self.roles.remove(&Assignment { principal, role });
            }
            InstanceEvent::LoginUiSet { url } => self.login_ui = url,
            InstanceEvent::PasskeyRpIdSet { rp_id } => self.passkey_rp_id = Some(rp_id),
            InstanceEvent::RoleDefined { role, permissions } => {
                self.custom_roles.insert(role, permissions);
            }
            InstanceEvent::RoleDeleted { role } => {
                self.custom_roles.remove(&role);
            }
            InstanceEvent::RegistrationTenantSet { tenant } => self.registration_tenant = tenant,
        }
    }
}

/// Keeps `instances`, `instance_domains` and `instance_role_assignments` current, in the transaction of the events.
pub(crate) async fn project(connection: &mut PgConnection, events: &[Event]) -> Result<(), Error> {
    for event in events {
        let id = event.owner;
        match InstanceEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            InstanceEvent::Added { name, domain } => {
                sqlx::query!(
                    "INSERT INTO instances (id, name, passkey_rp_id) VALUES ($1, $2, $3)",
                    id,
                    name,
                    domain.as_str(),
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query!(
                    "INSERT INTO instance_domains (domain, instance_id, is_primary) VALUES ($1, $2, true)",
                    domain.as_str(),
                    id,
                )
                .execute(&mut *connection)
                .await?;
                // The client of kernoid's own apps, built in (RFC 0001, 7.2; migration 0051).
                sqlx::query!(
                    "INSERT INTO applications (id, tenant_id, instance_id, name, kind, redirect_uris, offline_access, builtin)
                     VALUES (uuidv7(), NULL, $1, 'kernoid', 'public', $2, true, true)",
                    id,
                    &crate::APPS_REDIRECT_URIS.map(str::to_owned),
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::Renamed { name } => {
                sqlx::query!("UPDATE instances SET name = $2 WHERE id = $1", id, name)
                    .execute(&mut *connection)
                    .await?;
            }
            InstanceEvent::PasskeyRpIdSet { rp_id } => {
                sqlx::query!("UPDATE instances SET passkey_rp_id = $2 WHERE id = $1", id, rp_id.as_str())
                    .execute(&mut *connection)
                    .await?;
            }
            InstanceEvent::LoginUiSet { url } => {
                sqlx::query!("UPDATE instances SET login_ui_url = $2 WHERE id = $1", id, url)
                    .execute(&mut *connection)
                    .await?;
            }
            InstanceEvent::RegistrationTenantSet { tenant } => {
                sqlx::query!("UPDATE instances SET registration_tenant = $2 WHERE id = $1", id, tenant)
                    .execute(&mut *connection)
                    .await?;
            }
            InstanceEvent::DomainAdded { domain } => {
                sqlx::query!(
                    "INSERT INTO instance_domains (domain, instance_id) VALUES ($1, $2)",
                    domain.as_str(),
                    id,
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::DomainRemoved { domain } => {
                sqlx::query!(
                    "DELETE FROM instance_domains WHERE domain = $1 AND instance_id = $2",
                    domain.as_str(),
                    id,
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::PrimaryDomainSet { domain } => {
                // Unset first: at most one primary domain per instance (instance_domains_one_primary).
                sqlx::query!("UPDATE instance_domains SET is_primary = false WHERE instance_id = $1", id)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query!(
                    "UPDATE instance_domains SET is_primary = true WHERE instance_id = $1 AND domain = $2",
                    id,
                    domain.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::RoleGranted { principal, role } => {
                sqlx::query!(
                    "INSERT INTO instance_role_assignments (instance_id, principal_kind, principal_id, role)
                     VALUES ($1, $2, $3, $4)",
                    id,
                    principal.kind(),
                    principal.id(),
                    role.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::RoleRevoked { principal, role } => {
                sqlx::query!(
                    "DELETE FROM instance_role_assignments
                     WHERE instance_id = $1 AND principal_kind = $2 AND principal_id = $3 AND role = $4",
                    id,
                    principal.kind(),
                    principal.id(),
                    role.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::RoleDefined { role, permissions } => {
                let names: Vec<String> = permissions.iter().map(ToString::to_string).collect();
                sqlx::query!(
                    "INSERT INTO instance_roles (instance_id, name, permissions) VALUES ($1, $2, $3)
                     ON CONFLICT (instance_id, name) DO UPDATE SET permissions = $3",
                    id,
                    role.as_str(),
                    &names,
                )
                .execute(&mut *connection)
                .await?;
            }
            InstanceEvent::RoleDeleted { role } => {
                sqlx::query!("DELETE FROM instance_roles WHERE instance_id = $1 AND name = $2", id, role.as_str())
                    .execute(&mut *connection)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Whether `rp_id` may be the RP ID for an origin on `domain`: the same, or a parent domain of it (WebAuthn, 5.1.3:
/// a registrable domain suffix) – and not a bare top-level domain.
pub(crate) fn rp_id_covers(rp_id: &DomainName, domain: &DomainName) -> bool {
    let (rp, host) = (rp_id.as_str(), domain.as_str());
    rp.contains('.') && (host == rp || host.ends_with(&format!(".{rp}")))
}
