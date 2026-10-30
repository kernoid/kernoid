// SPDX-License-Identifier: AGPL-3.0-or-later
//! Identity: instances, tenants, accounts, sessions, groups, roles and projects (RFC 0001).
//!
//! - An **instance** is reached under its domains; [`Identity::instance_by_host`] finds it for a request. A domain
//!   names one instance in the whole installation.
//! - A **tenant** belongs to an instance and owns mail domains. A domain is claimed first and used only once the
//!   tenant has proved it through DNS: a TXT record `_kernoid-challenge.<domain>` with the value
//!   `kernoid-verification=<token>`. Any tenant may claim a domain; only one can have it verified.
//!
//! Read models are written in the transaction of the events (inline projections), so lookups are current at once
//! and PostgreSQL enforces the uniqueness rules.

/// Where the built-in client of kernoid's own apps may send the browser back: the apps' private scheme (RFC 8252,
/// 7.1) and the loopback addresses, on any port (7.3).
pub const APPS_REDIRECT_URIS: [&str; 3] =
    ["dev.kernoid.kernoid:/oauth", "http://127.0.0.1/oauth", "http://[::1]/oauth"];

pub mod account;
mod address;
pub mod admin;
pub mod app_password;
pub mod audit;
pub mod collection_access;
pub mod consent;
pub mod directory;
mod dns;
mod domain;
pub mod file_link;
pub mod files_quota;
pub mod group;
pub mod instance;
pub mod language;
pub mod link;
pub mod login;
pub mod mail_access;
pub mod mfa;
pub mod openpgp;
pub mod passkey;
mod password;
pub mod project;
pub mod provisioning;
pub mod registration;
pub mod role;
pub mod services;
pub mod session;
pub mod tenant;

pub use address::{Address, InvalidAddress};
pub use dns::{DnsResolver, TxtLookup};
pub use domain::{DomainName, InvalidDomain};
pub use password::{MAX_BYTES as PASSWORD_MAX_BYTES, MIN_CHARS as PASSWORD_MIN_CHARS};

use chrono::{DateTime, Utc};
use kernoid_events::{
    EventStore,
    aggregate::{CommandError, Loaded},
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    instance::{Instance, InstanceEvent},
    tenant::{Tenant, TenantEvent},
};

/// Where a tenant publishes the proof that a domain is theirs.
pub const CHALLENGE_LABEL: &str = "_kernoid-challenge";
const CHALLENGE_PREFIX: &str = "kernoid-verification=";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("{0} does not exist")]
    NotFound(&'static str),
    #[error("{0} exists already")]
    Exists(&'static str),
    #[error("{0} is in use elsewhere")]
    DomainTaken(DomainName),
    #[error("{0} is in use elsewhere")]
    AddressTaken(Address),
    /// Wrong address or password – deliberately not saying which.
    #[error("the address or the password is wrong")]
    InvalidCredentials,
    /// A TOTP code that is wrong, too old or already used.
    #[error("the code is not valid or was used already")]
    InvalidCode,
    /// A passkey that did not pass: unknown, not verified, from another site, or a challenge used up.
    #[error("the passkey was not accepted")]
    PasskeyRejected,
    /// Adding or removing a way to log in needs a session from the last minutes.
    #[error("log in again to change how you log in")]
    RecentLoginRequired,
    /// The right password, but the account or its tenant is deactivated.
    #[error("the account is deactivated")]
    AccountDeactivated,
    /// Too many failed attempts for this login name or client address.
    #[error("too many failed attempts; try again in {} seconds", retry_after.as_secs())]
    TooManyAttempts { retry_after: std::time::Duration },
    /// The token is wrong, or its session expired or ended – deliberately not saying which.
    #[error("the session is not valid")]
    InvalidSession,
    /// The session is valid, but its account lacks the permission.
    #[error("this needs the permission {0}")]
    Forbidden(role::Permission),
    /// The tenant requires a second factor, and the session has passed only one.
    #[error("this needs a login with a second factor")]
    MfaRequired,
    #[error("{0}")]
    Refused(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error(transparent)]
    Store(kernoid_events::Error),
}

pub(crate) type Result<T> = std::result::Result<T, IdentityError>;

/// Turns a command's failure into an [`IdentityError`]; a broken uniqueness rule means the domain is taken.
fn command_error(error: CommandError<IdentityError>, domain: Option<&DomainName>) -> IdentityError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(kernoid_events::Error::Database(sqlx::Error::Database(database)))
            if database.is_unique_violation() && domain.is_some() =>
        {
            IdentityError::DomainTaken(domain.expect("checked").clone())
        }
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

pub(crate) fn valid_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return Err(IdentityError::Refused("a name has 1 to 200 characters and no control characters".into()));
    }
    Ok(name.to_owned())
}

fn valid_module(module: &str, known: &[&str]) -> Result<()> {
    if !known.contains(&module) {
        return Err(IdentityError::Refused(format!("there is no module {module:?}")));
    }
    Ok(())
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceInfo {
    pub id: Uuid,
    pub name: String,
    pub primary_domain: String,
    /// The instance's own login UI, if it has one (otherwise kernoid's at `/login`).
    pub login_ui: Option<String>,
    /// The WebAuthn RP ID of its passkeys.
    pub passkey_rp_id: String,
    /// All its domains, primary first.
    pub domains: Vec<String>,
}

/// See [`Identity::mfa_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfaStatus {
    /// The tenant requires a second factor.
    pub required: bool,
    /// The account has none yet and may log in without one until then.
    pub grace_until: Option<DateTime<Utc>>,
}

impl MfaStatus {
    pub fn enforced(self) -> bool {
        self.required && self.grace_until.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantInfo {
    pub instance: Uuid,
    pub id: Uuid,
    pub name: String,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct Identity {
    events: EventStore,
    /// Seals secrets kernoid must read again (TOTP); without it, TOTP is not available.
    secrets: Option<kernoid_store::MainKeys>,
}

impl Identity {
    pub fn new(events: EventStore) -> Self {
        Self { events, secrets: None }
    }

    /// With the main keys, for TOTP.
    pub fn with_secrets(events: EventStore, secrets: kernoid_store::MainKeys) -> Self {
        Self { events, secrets: Some(secrets) }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        self.events.pool()
    }

    async fn instance_command(
        &self,
        instance: Uuid,
        creator: &str,
        domain: Option<&DomainName>,
        decide: impl Fn(&Instance) -> Result<Vec<InstanceEvent>>,
    ) -> Result<()> {
        self.events
            .execute_with(instance, instance, &instance.to_string(), creator, decide, |c, e| {
                Box::pin(instance::project(c, e))
            })
            .await
            .map(drop)
            .map_err(|error| command_error(error, domain))
    }

    async fn tenant_command(
        &self,
        instance: Uuid,
        tenant: Uuid,
        creator: &str,
        domain: Option<&DomainName>,
        decide: impl Fn(&Tenant) -> Result<Vec<TenantEvent>>,
    ) -> Result<()> {
        self.events
            .execute_with(instance, tenant, &tenant.to_string(), creator, decide, |c, e| {
                Box::pin(tenant::project(c, e))
            })
            .await
            .map(drop)
            .map_err(|error| command_error(error, domain))
    }

    // Instances

    /// Creates an instance reached under `domain`; returns its id.
    pub async fn add_instance(&self, name: &str, domain: &DomainName, creator: &str) -> Result<Uuid> {
        let name = valid_name(name)?;
        let id = Uuid::now_v7();
        self.instance_command(id, creator, Some(domain), |instance| {
            if instance.exists {
                return Err(IdentityError::Exists("the instance"));
            }
            Ok(vec![InstanceEvent::Added { name: name.clone(), domain: domain.clone() }])
        })
        .await?;
        Ok(id)
    }

    /// Sends logins to a login UI of the instance's own: an HTTPS URL (HTTP only on `localhost`) without query or
    /// fragment; kernoid adds `authRequest` to it, and allows its origin to call the API from the browser.
    pub async fn set_login_ui(&self, instance: Uuid, url: Option<&str>, creator: &str) -> Result<()> {
        let url = match url.map(str::trim).filter(|url| !url.is_empty()) {
            None => None,
            Some(url) => {
                let parsed =
                    url::Url::parse(url).map_err(|_| IdentityError::Refused(format!("{url:?} is not a URL")))?;
                let local = parsed.scheme() == "http" && parsed.host_str() == Some("localhost");
                if !(parsed.scheme() == "https" || local)
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                    || !parsed.username().is_empty()
                    || url.len() > 2000
                {
                    return Err(IdentityError::Refused(
                        "the login UI is an HTTPS URL without query, fragment or user".into(),
                    ));
                }
                Some(parsed.to_string())
            }
        };
        self.instance_command(instance, creator, None, |state| {
            existing_instance(state)?;
            Ok(if state.login_ui == url { Vec::new() } else { vec![InstanceEvent::LoginUiSet { url: url.clone() }] })
        })
        .await
    }

    pub async fn rename_instance(&self, instance: Uuid, name: &str, creator: &str) -> Result<()> {
        let name = valid_name(name)?;
        self.instance_command(instance, creator, None, |state| {
            existing_instance(state)?;
            Ok(vec![InstanceEvent::Renamed { name: name.clone() }])
        })
        .await
    }

    pub async fn add_instance_domain(&self, instance: Uuid, domain: &DomainName, creator: &str) -> Result<()> {
        self.instance_command(instance, creator, Some(domain), |state| {
            existing_instance(state)?;
            if state.domains.contains(domain) {
                return Err(IdentityError::Exists("the domain"));
            }
            Ok(vec![InstanceEvent::DomainAdded { domain: domain.clone() }])
        })
        .await
    }

    /// Removes a domain; the primary domain cannot be removed – set another one first –, nor the last domain the
    /// passkey RP ID covers.
    pub async fn remove_instance_domain(&self, instance: Uuid, domain: &DomainName, creator: &str) -> Result<()> {
        self.instance_command(instance, creator, None, |state| {
            existing_instance(state)?;
            if !state.domains.contains(domain) {
                return Err(IdentityError::NotFound("the domain"));
            }
            if state.primary.as_ref() == Some(domain) {
                return Err(IdentityError::Refused("the primary domain cannot be removed".into()));
            }
            if let Some(rp_id) = &state.passkey_rp_id
                && !state.domains.iter().any(|other| other != domain && instance::rp_id_covers(rp_id, other))
            {
                return Err(IdentityError::Refused(format!(
                    "passkeys are bound to {rp_id}; set another passkey RP ID first"
                )));
            }
            Ok(vec![InstanceEvent::DomainRemoved { domain: domain.clone() }])
        })
        .await
    }

    /// Binds new passkeys to another RP ID: one of the instance's domains or a parent domain of one. Passkeys
    /// registered under the former RP ID no longer work – their accounts need another way in (a password, recovery
    /// codes, an administrator resetting their factors).
    pub async fn set_passkey_rp_id(&self, instance: Uuid, rp_id: &DomainName, creator: &str) -> Result<()> {
        self.instance_command(instance, creator, None, |state| {
            existing_instance(state)?;
            if !state.domains.iter().any(|domain| instance::rp_id_covers(rp_id, domain)) {
                return Err(IdentityError::Refused(format!(
                    "{rp_id} is neither a domain of the instance nor a parent domain of one"
                )));
            }
            Ok(if state.passkey_rp_id.as_ref() == Some(rp_id) {
                Vec::new()
            } else {
                vec![InstanceEvent::PasskeyRpIdSet { rp_id: rp_id.clone() }]
            })
        })
        .await
    }

    pub async fn set_primary_domain(&self, instance: Uuid, domain: &DomainName, creator: &str) -> Result<()> {
        self.instance_command(instance, creator, None, |state| {
            existing_instance(state)?;
            if !state.domains.contains(domain) {
                return Err(IdentityError::NotFound("the domain"));
            }
            if state.primary.as_ref() == Some(domain) {
                return Ok(Vec::new());
            }
            Ok(vec![InstanceEvent::PrimaryDomainSet { domain: domain.clone() }])
        })
        .await
    }

    pub async fn instance(&self, instance: Uuid) -> Result<Loaded<Instance>> {
        let loaded =
            self.events.load::<Instance>(instance, &instance.to_string()).await.map_err(IdentityError::Store)?;
        if !loaded.state.exists {
            return Err(IdentityError::NotFound("the instance"));
        }
        Ok(loaded)
    }

    /// The instance reached under `host` (a host name, as the request named it, without port).
    pub async fn instance_by_host(&self, host: &str) -> Result<Option<InstanceInfo>> {
        let Ok(domain) = DomainName::parse(host) else { return Ok(None) };
        let row = sqlx::query!(
            r#"SELECT i.id, i.name, i.login_ui_url, i.passkey_rp_id, p.domain AS "primary_domain?",
                      ARRAY(SELECT x.domain FROM instance_domains x WHERE x.instance_id = i.id
                            ORDER BY x.is_primary DESC, x.domain) AS "domains!"
               FROM instance_domains d
               JOIN instances i ON i.id = d.instance_id
               LEFT JOIN instance_domains p ON p.instance_id = i.id AND p.is_primary
               WHERE d.domain = $1"#,
            domain.as_str(),
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?;
        Ok(row.map(|row| InstanceInfo {
            id: row.id,
            name: row.name,
            passkey_rp_id: row.passkey_rp_id.or_else(|| row.primary_domain.clone()).unwrap_or_default(),
            primary_domain: row.primary_domain.unwrap_or_default(),
            login_ui: row.login_ui_url,
            domains: row.domains,
        }))
    }

    pub async fn instances(&self) -> Result<Vec<InstanceInfo>> {
        let rows = sqlx::query!(
            r#"SELECT i.id, i.name, i.login_ui_url, i.passkey_rp_id, p.domain AS "primary_domain?",
                      ARRAY(SELECT x.domain FROM instance_domains x WHERE x.instance_id = i.id
                            ORDER BY x.is_primary DESC, x.domain) AS "domains!"
               FROM instances i LEFT JOIN instance_domains p ON p.instance_id = i.id AND p.is_primary
               ORDER BY i.name, i.id"#
        )
        .fetch_all(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?;
        Ok(rows
            .into_iter()
            .map(|row| InstanceInfo {
                id: row.id,
                name: row.name,
                passkey_rp_id: row.passkey_rp_id.or_else(|| row.primary_domain.clone()).unwrap_or_default(),
                primary_domain: row.primary_domain.unwrap_or_default(),
                login_ui: row.login_ui_url,
                domains: row.domains,
            })
            .collect())
    }

    // Tenants

    /// Creates a tenant in `instance`; returns its id.
    pub async fn add_tenant(&self, instance: Uuid, name: &str, creator: &str) -> Result<Uuid> {
        let name = valid_name(name)?;
        self.instance(instance).await?;
        let id = Uuid::now_v7();
        self.tenant_command(instance, id, creator, None, |tenant| {
            if tenant.exists {
                return Err(IdentityError::Exists("the tenant"));
            }
            Ok(vec![TenantEvent::Added { instance, name: name.clone() }])
        })
        .await?;
        Ok(id)
    }

    pub async fn rename_tenant(&self, instance: Uuid, tenant: Uuid, name: &str, creator: &str) -> Result<()> {
        let name = valid_name(name)?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            existing_tenant(state)?;
            Ok(vec![TenantEvent::Renamed { name: name.clone() }])
        })
        .await
    }

    /// Deactivates or reactivates a tenant; nothing happens if it is already in that state.
    pub async fn set_tenant_active(&self, instance: Uuid, tenant: Uuid, active: bool, creator: &str) -> Result<()> {
        if !active {
            self.keep_an_admin(None, instance, |held| held.tenant == tenant).await?;
        }
        self.tenant_command(instance, tenant, creator, None, |state| {
            existing_tenant(state)?;
            Ok(match (state.active, active) {
                (true, false) => vec![TenantEvent::Deactivated],
                (false, true) => vec![TenantEvent::Reactivated],
                _ => Vec::new(),
            })
        })
        .await
    }

    /// Claims `domain` for the tenant; returns the token to publish (see [`CHALLENGE_LABEL`]).
    pub async fn add_tenant_domain(
        &self,
        instance: Uuid,
        tenant: Uuid,
        domain: &DomainName,
        creator: &str,
    ) -> Result<String> {
        let token = random_token()?;
        self.tenant_command(instance, tenant, creator, Some(domain), |state| {
            existing_tenant(state)?;
            if !state.active {
                return Err(IdentityError::Refused("the tenant is deactivated".into()));
            }
            if state.domains.contains_key(domain) {
                return Err(IdentityError::Exists("the domain"));
            }
            Ok(vec![TenantEvent::DomainAdded { domain: domain.clone(), token: token.clone() }])
        })
        .await?;
        Ok(token)
    }

    /// Looks up the tenant's proof in DNS and, if it is there, marks the domain verified. Fails if another tenant
    /// has verified the domain first.
    pub async fn verify_tenant_domain(
        &self,
        instance: Uuid,
        tenant: Uuid,
        domain: &DomainName,
        dns: &impl TxtLookup,
        creator: &str,
    ) -> Result<()> {
        let loaded = self.events.load::<Tenant>(instance, &tenant.to_string()).await.map_err(IdentityError::Store)?;
        existing_tenant(&loaded.state)?;
        let claim = loaded.state.domains.get(domain).ok_or(IdentityError::NotFound("the domain"))?;
        if claim.verified {
            return Ok(());
        }
        let name = format!("{CHALLENGE_LABEL}.{domain}");
        let expected = format!("{CHALLENGE_PREFIX}{}", claim.token);
        let records = dns.txt(&name).await.map_err(IdentityError::Verification)?;
        if !records.iter().any(|record| record.trim() == expected) {
            return Err(IdentityError::Verification(format!("no TXT record {name} with the value {expected}")));
        }
        let token = claim.token.clone();
        self.tenant_command(instance, tenant, creator, Some(domain), |state| {
            existing_tenant(state)?;
            match state.domains.get(domain) {
                // Only the claim that was checked: a domain removed and claimed again has a new token.
                Some(claim) if claim.token == token && !claim.verified => {
                    Ok(vec![TenantEvent::DomainVerified { domain: domain.clone() }])
                }
                Some(claim) if claim.verified => Ok(Vec::new()),
                _ => Err(IdentityError::Refused("the domain changed while it was verified".into())),
            }
        })
        .await
    }

    /// Marks a claimed domain verified without asking DNS – for operators, when a domain has no public DNS (an
    /// internal name) or was checked by other means. The event names who did it; uniqueness still holds.
    pub async fn trust_tenant_domain(
        &self,
        instance: Uuid,
        tenant: Uuid,
        domain: &DomainName,
        creator: &str,
    ) -> Result<()> {
        self.tenant_command(instance, tenant, creator, Some(domain), |state| {
            existing_tenant(state)?;
            match state.domains.get(domain) {
                None => Err(IdentityError::NotFound("the domain")),
                Some(claim) if claim.verified => Ok(Vec::new()),
                Some(_) => Ok(vec![TenantEvent::DomainVerified { domain: domain.clone() }]),
            }
        })
        .await
    }

    /// Removes a domain from the tenant – unless addresses still use it.
    pub async fn remove_tenant_domain(
        &self,
        instance: Uuid,
        tenant: Uuid,
        domain: &DomainName,
        creator: &str,
    ) -> Result<()> {
        let in_use = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM addresses WHERE tenant_id = $1 AND domain = $2) AS "used!""#,
            tenant,
            domain.as_str(),
        )
        .fetch_one(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?;
        if in_use {
            return Err(IdentityError::Refused(format!("addresses on {domain} are still in use")));
        }
        self.tenant_command(instance, tenant, creator, None, |state| {
            existing_tenant(state)?;
            if !state.domains.contains_key(domain) {
                return Err(IdentityError::NotFound("the domain"));
            }
            Ok(vec![TenantEvent::DomainRemoved { domain: domain.clone() }])
        })
        .await
    }

    /// Switches a module on or off for the tenant; `known` are the modules compiled into kernoid. Whether the module
    /// runs at all is decided by the installation's configuration.
    pub async fn set_tenant_module(
        &self,
        instance: Uuid,
        tenant: Uuid,
        module: &str,
        enabled: bool,
        known: &[&str],
        creator: &str,
    ) -> Result<()> {
        // Switching off works also for a module the installation no longer offers.
        if enabled {
            valid_module(module, known)?;
        }
        self.tenant_command(instance, tenant, creator, None, |state| {
            existing_tenant(state)?;
            let module = module.to_owned();
            Ok(match (state.modules.contains(&module), enabled) {
                (false, true) => vec![TenantEvent::ModuleEnabled { module }],
                (true, false) => vec![TenantEvent::ModuleDisabled { module }],
                _ => Vec::new(),
            })
        })
        .await
    }

    pub async fn tenant(&self, instance: Uuid, tenant: Uuid) -> Result<Loaded<Tenant>> {
        let loaded = self.events.load::<Tenant>(instance, &tenant.to_string()).await.map_err(IdentityError::Store)?;
        existing_tenant(&loaded.state)?;
        Ok(loaded)
    }

    /// The instance a tenant belongs to.
    pub async fn tenant_instance(&self, tenant: Uuid) -> Result<Uuid> {
        sqlx::query_scalar!("SELECT instance_id FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(|error| IdentityError::Store(error.into()))?
            .ok_or(IdentityError::NotFound("the tenant"))
    }

    /// The tenant that has verified `domain` – the tenant of every address `…@domain`.
    pub async fn tenant_by_domain(&self, domain: &DomainName) -> Result<Option<TenantInfo>> {
        let row = sqlx::query!(
            "SELECT t.instance_id, t.id, t.name, t.active
             FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id
             WHERE d.domain = $1 AND d.verified",
            domain.as_str(),
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?;
        Ok(row.map(|row| TenantInfo { instance: row.instance_id, id: row.id, name: row.name, active: row.active }))
    }

    pub async fn tenants(&self, instance: Uuid) -> Result<Vec<TenantInfo>> {
        let rows = sqlx::query!(
            "SELECT instance_id, id, name, active FROM tenants WHERE instance_id = $1 ORDER BY name, id",
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?;
        Ok(rows
            .into_iter()
            .map(|row| TenantInfo { instance: row.instance_id, id: row.id, name: row.name, active: row.active })
            .collect())
    }

    /// Requires (or no longer requires) a second factor for logins to applications by the tenant's accounts.
    pub async fn set_tenant_mfa_required(
        &self,
        instance: Uuid,
        tenant: Uuid,
        required: bool,
        creator: &str,
    ) -> Result<()> {
        self.tenant_command(instance, tenant, creator, None, |state| {
            existing_tenant(state)?;
            Ok(if state.mfa_required == required {
                Vec::new()
            } else {
                vec![TenantEvent::MfaRequirementSet { required }]
            })
        })
        .await
    }

    /// Lets accounts without a second factor log in without one for `days` (0 to 365) after the tenant's
    /// requirement – or the account – began.
    pub async fn set_tenant_mfa_grace(&self, instance: Uuid, tenant: Uuid, days: u32, creator: &str) -> Result<()> {
        if days > 365 {
            return Err(IdentityError::Refused("a grace period is at most 365 days".into()));
        }
        self.tenant_command(instance, tenant, creator, None, |state| {
            existing_tenant(state)?;
            Ok(if state.mfa_grace_days == days { Vec::new() } else { vec![TenantEvent::MfaGraceSet { days }] })
        })
        .await
    }

    /// What the tenant's second-factor requirement means for an account now: whether it applies, and – for an account
    /// without a second factor, within the tenant's grace period – until when it may still log in without one.
    pub async fn mfa_status(&self, account: Uuid) -> Result<MfaStatus> {
        let row = sqlx::query!(
            r#"SELECT t.mfa_required, t.mfa_grace_days,
                      greatest(t.mfa_required_since, a.created_at) + make_interval(days => t.mfa_grace_days)
                          AS "grace_until?",
                      (EXISTS (SELECT 1 FROM account_totp WHERE account_id = a.id AND confirmed_at IS NOT NULL)
                       OR EXISTS (SELECT 1 FROM account_passkeys WHERE account_id = a.id)) AS "has_factor!"
               FROM accounts a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1"#,
            account,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?
        .ok_or(IdentityError::NotFound("the account"))?;
        let grace_until = row
            .grace_until
            .filter(|until| row.mfa_required && row.mfa_grace_days > 0 && !row.has_factor && *until > Utc::now());
        Ok(MfaStatus { required: row.mfa_required, grace_until })
    }

    /// Whether a login of the account needs a second factor now by its tenant's policy (grace period considered).
    pub async fn mfa_required_now(&self, account: Uuid) -> Result<bool> {
        Ok(self.mfa_status(account).await?.enforced())
    }

    /// Whether the tenant requires a second factor.
    pub async fn tenant_requires_mfa(&self, tenant: Uuid) -> Result<bool> {
        sqlx::query_scalar!("SELECT mfa_required FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(|error| IdentityError::Store(error.into()))?
            .ok_or(IdentityError::NotFound("the tenant"))
    }

    /// Whether the tenant has switched `module` on.
    pub async fn tenant_uses_module(&self, tenant: Uuid, module: &str) -> Result<bool> {
        sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM tenant_modules WHERE tenant_id = $1 AND module = $2) AS "used!""#,
            tenant,
            module,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))
    }
}

/// Equal in time whatever the contents.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn existing_instance(instance: &Instance) -> Result<()> {
    if instance.exists { Ok(()) } else { Err(IdentityError::NotFound("the instance")) }
}

fn existing_tenant(tenant: &Tenant) -> Result<()> {
    if tenant.exists { Ok(()) } else { Err(IdentityError::NotFound("the tenant")) }
}
