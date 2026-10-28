// SPDX-License-Identifier: AGPL-3.0-or-later
//! What an account uses (RFC 0003, 4): `mail` and `files`, each off, requested or on, by the tenant's rules or an
//! administrator's hand. `mail` needs a native account – one with an address on a verified domain of its tenant.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::{Account, AccountEvent},
    role::{Admin, Permission},
    tenant::TenantEvent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Mail,
    Files,
}

impl Service {
    pub const ALL: [Self; 2] = [Self::Mail, Self::Files];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mail => "mail",
            Self::Files => "files",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|service| service.as_str() == value)
            .ok_or_else(|| IdentityError::Refused(format!("{value:?} is not a service; mail or files")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// Waits for an administrator.
    Requested,
    On,
}

impl ServiceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::On => "on",
        }
    }
}

/// Who gets a service when an account is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assign {
    None,
    /// Accounts with a native address.
    Native,
    All,
}

impl Assign {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Native => "native",
            Self::All => "all",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "native" => Ok(Self::Native),
            "all" => Ok(Self::All),
            _ => Err(IdentityError::Refused(format!("{value:?} is none, native or all"))),
        }
    }
}

/// A tenant's rule for one service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicePolicy {
    pub assign: Assign,
    /// New accounts get the service only as requested, until an administrator grants it.
    pub approval: bool,
}

impl ServicePolicy {
    /// Mail for native accounts without approval – kernoid's behaviour before RFC 0003 – and no files.
    pub fn default_for(service: Service) -> Self {
        match service {
            Service::Mail => Self { assign: Assign::Native, approval: false },
            Service::Files => Self { assign: Assign::None, approval: false },
        }
    }
}

/// A tenant's rules, with the defaults for services it has no rule for.
pub fn policy(policies: &BTreeMap<Service, ServicePolicy>, service: Service) -> ServicePolicy {
    policies.get(&service).copied().unwrap_or(ServicePolicy::default_for(service))
}

/// The services a new account gets by the tenant's rules: those on, and those requested.
pub(crate) fn initial(policies: &BTreeMap<Service, ServicePolicy>, native: bool) -> (Vec<Service>, Vec<Service>) {
    let (mut on, mut requested) = (Vec::new(), Vec::new());
    for service in Service::ALL {
        let rule = policy(policies, service);
        let applies = match rule.assign {
            Assign::None => false,
            Assign::Native => native,
            Assign::All => true,
        };
        if !applies || (service == Service::Mail && !native) {
            continue;
        }
        if rule.approval { requested.push(service) } else { on.push(service) }
    }
    (on, requested)
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Grants `service` to an account. `mail` only to a native account.
    pub async fn grant_service(&self, account: Uuid, service: Service, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state: &Account| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            if service == Service::Mail && state.primary.is_none() {
                return Err(IdentityError::Refused("only an account with an address of the tenant has mail".into()));
            }
            if state.services.get(&service) == Some(&ServiceState::On) {
                return Ok(Vec::new());
            }
            Ok(vec![AccountEvent::ServiceGranted { service }])
        })
        .await
    }

    pub async fn revoke_service(&self, account: Uuid, service: Service, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state: &Account| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            if state.shared && service == Service::Mail {
                return Err(IdentityError::Refused("a shared mailbox always has mail".into()));
            }
            if state.drive && service == Service::Files {
                return Err(IdentityError::Refused("a drive always has files".into()));
            }
            if !state.services.contains_key(&service) {
                return Ok(Vec::new());
            }
            Ok(vec![AccountEvent::ServiceRevoked { service }])
        })
        .await
    }

    /// An account's services and their states.
    pub async fn services(&self, account: Uuid) -> Result<Vec<(Service, ServiceState)>> {
        let rows =
            sqlx::query!("SELECT service, state FROM account_services WHERE account_id = $1 ORDER BY service", account)
                .fetch_all(self.pool())
                .await
                .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let service = Service::parse(&row.service).ok()?;
                let state = if row.state == "on" { ServiceState::On } else { ServiceState::Requested };
                Some((service, state))
            })
            .collect())
    }

    /// Whether an account has `service` on.
    pub async fn has_service(&self, account: Uuid, service: Service) -> Result<bool> {
        sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM account_services WHERE account_id = $1 AND service = $2 AND state = 'on')
               AS "on!""#,
            account,
            service.as_str(),
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)
    }

    /// Sets a tenant's rule for a service.
    pub async fn set_service_policy(
        &self,
        tenant: Uuid,
        service: Service,
        rule: ServicePolicy,
        creator: &str,
    ) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if policy(&state.service_policies, service) == rule && state.service_policies.contains_key(&service) {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::ServicePolicySet { service, assign: rule.assign, approval: rule.approval }])
        })
        .await
    }

    /// A tenant's rules for every service.
    pub async fn service_policies(&self, tenant: Uuid) -> Result<Vec<(Service, ServicePolicy)>> {
        let instance = self.tenant_instance(tenant).await?;
        let state = self.tenant(instance, tenant).await?.state;
        Ok(Service::ALL.into_iter().map(|service| (service, policy(&state.service_policies, service))).collect())
    }

    // Administration

    pub async fn admin_services(&self, admin: &Admin, account: Uuid) -> Result<Vec<(Service, ServiceState)>> {
        self.admin_account(admin, account).await?;
        self.services(account).await
    }

    pub async fn admin_grant_service(&self, admin: &Admin, account: Uuid, service: Service) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.grant_service(account, service, &admin.creator()).await
    }

    pub async fn admin_revoke_service(&self, admin: &Admin, account: Uuid, service: Service) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.revoke_service(account, service, &admin.creator()).await
    }

    pub async fn admin_service_policies(&self, admin: &Admin) -> Result<Vec<(Service, ServicePolicy)>> {
        admin.require(Permission::DirectoryRead)?;
        self.service_policies(admin.tenant()).await
    }

    pub async fn admin_set_service_policy(&self, admin: &Admin, service: Service, rule: ServicePolicy) -> Result<()> {
        admin.require(Permission::PoliciesManage)?;
        self.set_service_policy(admin.tenant(), service, rule, &admin.creator()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_decide_new_accounts_services() {
        let mut rules = BTreeMap::new();
        assert_eq!(initial(&rules, true), (vec![Service::Mail], vec![]));
        assert_eq!(initial(&rules, false), (vec![], vec![]));
        rules.insert(Service::Mail, ServicePolicy { assign: Assign::All, approval: true });
        rules.insert(Service::Files, ServicePolicy { assign: Assign::All, approval: false });
        assert_eq!(initial(&rules, true), (vec![Service::Files], vec![Service::Mail]));
        assert_eq!(initial(&rules, false), (vec![Service::Files], vec![]), "no mail without a native address");
    }
}
