// SPDX-License-Identifier: AGPL-3.0-or-later
//! Registration (RFC 0003, 5): a person registers with an email address and a password – and, where a tenant offers
//! it, an address of their own on one of its domains, or a username. Nothing becomes an event before the person
//! enters the code sent to the email address: until then the registration is a row in `registrations`, removed
//! after a day.

use std::net::IpAddr;

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    Address, DomainName, Identity, IdentityError, Result,
    instance::InstanceEvent,
    role::{Admin, Permission},
    session::address_key,
    tenant::TenantEvent,
};

/// How long a code is good for.
const LIFETIME: Duration = Duration::days(1);
/// Wrong codes before a registration is dropped.
const MAX_ATTEMPTS: i32 = 5;
/// Registrations started from one client address within the failure window (RFC 0001, 7).
const PER_ADDRESS: i32 = 10;
/// Who registrations' events name.
pub const CREATOR: &str = "registration";

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn code_hash(code: &str) -> Vec<u8> {
    Sha256::digest(code.trim().as_bytes()).to_vec()
}

/// What a person registers with.
#[derive(Debug, Clone)]
pub struct NewRegistration<'a> {
    /// Where the code goes; becomes the verified contact address.
    pub email: &'a str,
    pub password: &'a str,
    pub display_name: &'a str,
    /// An address of their own on a registration domain of a tenant: a native account.
    pub native_address: Option<&'a str>,
    /// A username, where the tenant uses them.
    pub username: Option<&'a str>,
}

/// A registration waiting for its code; the code goes to `email` and is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub id: Uuid,
    pub tenant: Uuid,
    pub email: String,
    pub code: String,
}

/// What the login UI offers for registering at an instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationOptions {
    /// People without an address of their own may register (with the instance's registration tenant).
    pub open: bool,
    /// Domains new accounts may take an address on.
    pub domains: Vec<String>,
    /// Usernames may be chosen.
    pub usernames: bool,
}

impl Identity {
    /// What registering offers at `instance`.
    pub async fn registration_options(&self, instance: Uuid) -> Result<RegistrationOptions> {
        let rows = sqlx::query!(
            r#"SELECT t.id, t.registration_domains, t.usernames,
                      (i.registration_tenant = t.id) AS "is_default!"
               FROM tenants t JOIN instances i ON i.id = t.instance_id
               WHERE t.instance_id = $1 AND t.active AND t.registration_allowed"#,
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let mut options = RegistrationOptions::default();
        for row in rows {
            options.open |= row.is_default;
            options.usernames |= row.usernames && row.is_default;
            options.domains.extend(row.registration_domains);
        }
        options.domains.sort();
        Ok(options)
    }

    /// The tenant a registration goes to: the one whose registration domain the native address is on, or the
    /// instance's registration tenant.
    async fn registration_tenant(&self, instance: Uuid, native: Option<&Address>) -> Result<Uuid> {
        let refused = || IdentityError::Refused("registering is not possible here".into());
        let tenant = match native {
            Some(address) => {
                let holder = self.tenant_by_domain(&address.domain()).await?.ok_or_else(refused)?;
                if holder.instance != instance {
                    return Err(refused());
                }
                let state = self.tenant(instance, holder.id).await?.state;
                if !state.registration.domains.contains(&address.domain()) {
                    return Err(refused());
                }
                holder.id
            }
            None => self.instance(instance).await?.state.registration_tenant.ok_or_else(refused)?,
        };
        let state = self.tenant(instance, tenant).await?.state;
        if !state.active || !state.registration.allowed {
            return Err(refused());
        }
        Ok(tenant)
    }

    /// Begins a registration: checks it, refuses what is taken, and keeps it with a new code – which the caller sends
    /// to the email address.
    pub async fn start_registration(
        &self,
        instance: Uuid,
        new: NewRegistration<'_>,
        client: Option<IpAddr>,
    ) -> Result<Started> {
        if let Some(address) = client {
            let key = format!("register:{}", address_key(address));
            self.refuse_if_throttled(instance, &key, PER_ADDRESS).await?;
            self.count_failure(instance, &key).await?;
        }
        let display_name = crate::valid_name(new.display_name)?;
        let email = Address::parse(new.email).map_err(|error| IdentityError::Refused(error.to_string()))?;
        let native = new
            .native_address
            .map(|address| Address::parse(address).map_err(|error| IdentityError::Refused(error.to_string())))
            .transpose()?;
        let username = new.username.map(crate::login::valid_username).transpose()?;
        crate::password::check_policy(new.password)?;
        let tenant = self.registration_tenant(instance, native.as_ref()).await?;
        if username.is_some() && !self.tenant(instance, tenant).await?.state.login_policy.usernames {
            return Err(IdentityError::Refused("this tenant does not use usernames".into()));
        }
        // Duplicates: a taken address leads to logging in to that account instead.
        if self.contact_holder(instance, email.as_str()).await?.is_some() {
            return Err(IdentityError::Exists("an account with this address"));
        }
        if let Some(native) = &native
            && self.login_taken(instance, native.as_str()).await?
        {
            return Err(IdentityError::AddressTaken(native.clone()));
        }
        if let Some(username) = &username
            && self.login_taken(instance, username).await?
        {
            return Err(IdentityError::Exists("the username"));
        }
        let password = new.password.to_owned();
        let hash = tokio::task::spawn_blocking(move || crate::password::hash(&password))
            .await
            .map_err(|_| IdentityError::Refused("cannot hash the password".into()))??;
        // Eight digits, without the bias of a plain modulo: values from the top of the range are drawn again.
        let code = loop {
            let mut bytes = [0u8; 4];
            getrandom::fill(&mut bytes).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
            let value = u32::from_le_bytes(bytes);
            if value < 4_200_000_000 {
                break format!("{:08}", value % 100_000_000);
            }
        };
        let id = Uuid::now_v7();
        let mut tx = self.pool().begin().await.map_err(store_error)?;
        // A new registration replaces an earlier one for the same address.
        sqlx::query!("DELETE FROM registrations WHERE instance_id = $1 AND email = $2", instance, email.as_str())
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
        sqlx::query!(
            "INSERT INTO registrations
                 (id, instance_id, tenant_id, email, native_address, username, display_name, password_hash, code_hash,
                  expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            id,
            instance,
            tenant,
            email.as_str(),
            native.as_ref().map(Address::as_str),
            username,
            display_name,
            hash,
            code_hash(&code),
            Utc::now() + LIFETIME,
        )
        .execute(&mut *tx)
        .await
        .map_err(store_error)?;
        tx.commit().await.map_err(store_error)?;
        Ok(Started { id, tenant, email: email.as_str().to_owned(), code })
    }

    /// Finishes a registration with its code: the account is created – native with the chosen address, else
    /// external – with the email address as verified contact address, the password and the username. Returns it.
    pub async fn finish_registration(&self, instance: Uuid, id: Uuid, code: &str) -> Result<Uuid> {
        let row = sqlx::query!(
            "SELECT tenant_id, email, native_address, username, display_name, password_hash, code_hash, attempts
             FROM registrations WHERE id = $1 AND instance_id = $2 AND expires_at > now()",
            id,
            instance,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::InvalidCode)?;
        if row.code_hash != code_hash(code) {
            let attempts = row.attempts + 1;
            if attempts >= MAX_ATTEMPTS {
                sqlx::query!("DELETE FROM registrations WHERE id = $1", id)
                    .execute(self.pool())
                    .await
                    .map_err(store_error)?;
            } else {
                sqlx::query!("UPDATE registrations SET attempts = $2 WHERE id = $1", id, attempts)
                    .execute(self.pool())
                    .await
                    .map_err(store_error)?;
            }
            return Err(IdentityError::InvalidCode);
        }
        // Once only, even if what follows fails.
        sqlx::query!("DELETE FROM registrations WHERE id = $1", id).execute(self.pool()).await.map_err(store_error)?;
        let account = match row.native_address.as_deref() {
            Some(native) => {
                let native = Address::parse(native).map_err(|error| IdentityError::Refused(error.to_string()))?;
                let account = self.add_account(row.tenant_id, &native, &row.display_name, CREATOR).await?;
                if row.email != native.as_str() {
                    self.set_contact_email(account, Some(&row.email), true, CREATOR).await?;
                }
                account
            }
            None => {
                self.add_external_account(row.tenant_id, &row.display_name, Some((&row.email, true)), CREATOR).await?
            }
        };
        self.set_password_hash(account, row.password_hash, CREATOR).await?;
        if let Some(username) = row.username.as_deref() {
            self.set_username(account, Some(username), CREATOR).await?;
        }
        Ok(account)
    }

    /// Removes registrations whose code ran out.
    pub async fn prune_registrations(&self) -> Result<u64> {
        Ok(sqlx::query!("DELETE FROM registrations WHERE expires_at <= now()")
            .execute(self.pool())
            .await
            .map_err(store_error)?
            .rows_affected())
    }

    /// Whether people may register with a tenant, and on which of its verified domains new accounts may take an
    /// address.
    pub async fn set_registration(
        &self,
        tenant: Uuid,
        allowed: bool,
        domains: &[DomainName],
        creator: &str,
    ) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        let domains = domains.to_vec();
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if let Some(domain) = domains.iter().find(|domain| !state.domains.get(*domain).is_some_and(|d| d.verified))
            {
                return Err(IdentityError::Refused(format!("{domain} is not a verified domain of the tenant")));
            }
            if state.registration.allowed == allowed && state.registration.domains == domains {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::RegistrationSet { allowed, domains: domains.clone() }])
        })
        .await
    }

    /// The tenant where people without an address of a tenant register; `None`: nowhere.
    pub async fn set_registration_tenant(&self, instance: Uuid, tenant: Option<Uuid>, creator: &str) -> Result<()> {
        if let Some(tenant) = tenant
            && self.tenant_instance(tenant).await? != instance
        {
            return Err(IdentityError::NotFound("the tenant"));
        }
        self.instance_command(instance, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the instance"));
            }
            if state.registration_tenant == tenant {
                return Ok(Vec::new());
            }
            Ok(vec![InstanceEvent::RegistrationTenantSet { tenant }])
        })
        .await
    }

    // Administration

    pub async fn admin_registration(&self, admin: &Admin) -> Result<(bool, Vec<String>)> {
        admin.require(Permission::DirectoryRead)?;
        let state = self.tenant(admin.instance(), admin.tenant()).await?.state;
        Ok((state.registration.allowed, state.registration.domains.iter().map(|d| d.as_str().to_owned()).collect()))
    }

    pub async fn admin_set_registration(&self, admin: &Admin, allowed: bool, domains: &[DomainName]) -> Result<()> {
        admin.require(Permission::PoliciesManage)?;
        self.set_registration(admin.tenant(), allowed, domains, &admin.creator()).await
    }

    pub async fn admin_set_registration_tenant(&self, admin: &Admin, tenant: Option<Uuid>) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.set_registration_tenant(admin.instance(), tenant, &admin.creator()).await
    }
}
