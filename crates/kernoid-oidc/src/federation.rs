// SPDX-License-Identifier: AGPL-3.0-or-later
//! Logging in with an external identity provider (RFC 0001, 7.7): a tenant connects another OpenID provider – its
//! Entra ID, Google Workspace, Okta, Keycloak … – and its accounts log in there instead of with a password.
//!
//! - **Providers** (`identity_provider` aggregate, owned by the tenant – or by the instance, serving all its tenants):
//!   issuer, client id, scopes, the mail domains whose logins go there, whether the first login creates an account
//!   (`auto_create`) or links one with the same verified address (`auto_link`), and whether later logins update the
//!   display name (`sync_profile`). The client secret is sealed with the main key, never in an event.
//! - **SAML** providers get kernoid's SAML key of the instance (signed requests, encrypted assertions) and single
//!   logout both ways.
//! - **The flow:** the login UI asks which provider an address belongs to (`login_options`), starts a login there
//!   (`start_idp_login`, with PKCE, `state` and `nonce`), the provider sends the browser to `/idp/callback`, kernoid
//!   exchanges the code and verifies the ID token, finds or creates the account, and sends the browser back to the
//!   login UI with a one-time code. The UI exchanges it for a session (`exchange_idp_login`) – so no session token
//!   ever appears in a URL.
//! - Requests to providers go through [`crate::outbound`]: HTTPS to public addresses only, unless the installation
//!   allows more.

use std::{collections::BTreeSet, time::Duration};

use chrono::Utc;
use kernoid_events::{
    Error, Event, InlineFuture,
    aggregate::{Aggregate, CommandError, DomainEvent},
    inline,
};
use kernoid_identity::{
    Address, DomainName, IdentityError, InstanceInfo,
    link::LinkInfo,
    role::{Admin, Permission},
    session::{ClientMeta, NewSession},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use url::Url;
use uuid::Uuid;

use crate::{
    Oidc, OidcError, Result,
    external::{self, Expected},
    flow::pkce_challenge,
    internal, random_secret, sha256,
};

/// How long a login at a provider may take, from start to the exchange of its result.
const LOGIN_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The settings of an identity provider, as administrators set them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdpSettings {
    pub name: String,
    /// OpenID Connect: the provider's issuer, e.g. `https://login.microsoftonline.com/<tenant>/v2.0`. SAML: its entity
    /// ID.
    pub issuer: String,
    /// OpenID Connect only.
    pub client_id: String,
    /// At least `openid`; `email` and `profile` let kernoid create and link accounts.
    pub scopes: Vec<String>,
    /// Verified mail domains of the tenant whose logins go to this provider.
    pub domains: Vec<String>,
    /// Create an account at the first login, from the provider's verified email address.
    pub auto_create: bool,
    /// Link an existing account with the provider's verified email address at the first login.
    pub auto_link: bool,
    /// Take the display name from the provider at every login.
    #[serde(default)]
    pub sync_profile: bool,
    /// Offered on the login page to everyone ("Sign in with …"), not only for its domains: a login that finds no
    /// account creates an external one in the tenant (RFC 0003, 5) where that tenant allows registration.
    #[serde(default)]
    pub register: bool,
    /// Set for a SAML 2.0 provider; without it, the provider speaks OpenID Connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<SamlSettings>,
}

/// What kernoid needs to know of a SAML 2.0 provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlSettings {
    /// Where to send the AuthnRequest (HTTP-Redirect binding).
    pub sso_url: String,
    /// The provider's signing certificates, base64 DER; one is enough, more allow a key change.
    pub certificates: Vec<String>,
    /// The attribute with the email address; common names are tried if left out.
    #[serde(default)]
    pub email_attribute: Option<String>,
    /// The attribute with the display name; common names are tried if left out.
    #[serde(default)]
    pub name_attribute: Option<String>,
    /// Sign AuthnRequests with kernoid's SAML key (some providers require it).
    #[serde(default)]
    pub sign_requests: bool,
    /// The provider's single logout service (HTTP-Redirect binding); without it, logging out ends kernoid's session
    /// only.
    #[serde(default)]
    pub slo_url: Option<String>,
}

/// Who owns an identity provider: a tenant, or the instance – whose provider serves the domains of all its tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpOwner {
    Tenant(Uuid),
    Instance(Uuid),
}

impl From<Uuid> for IdpOwner {
    fn from(tenant: Uuid) -> Self {
        Self::Tenant(tenant)
    }
}

impl IdpSettings {
    pub fn kind(&self) -> &'static str {
        if self.saml.is_some() { "saml" } else { "oidc" }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum IdpEvent {
    #[serde(rename = "identity_provider.added")]
    Added { settings: IdpSettings },
    #[serde(rename = "identity_provider.changed")]
    Changed { settings: IdpSettings },
    /// The secret itself is sealed in `identity_provider_secrets`.
    #[serde(rename = "identity_provider.secret_changed")]
    SecretChanged,
    #[serde(rename = "identity_provider.secret_removed")]
    SecretRemoved,
    #[serde(rename = "identity_provider.deactivated")]
    Deactivated,
    #[serde(rename = "identity_provider.reactivated")]
    Reactivated,
    #[serde(rename = "identity_provider.removed")]
    Removed,
}

impl DomainEvent for IdpEvent {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdentityProvider {
    pub exists: bool,
    pub settings: Option<IdpSettings>,
    pub has_secret: bool,
    pub active: bool,
}

impl Aggregate for IdentityProvider {
    const TYPE: &'static str = "identity_provider";
    type Event = IdpEvent;

    fn apply(&mut self, event: IdpEvent) {
        match event {
            IdpEvent::Added { settings } => {
                *self = Self { exists: true, settings: Some(settings), has_secret: false, active: true };
            }
            IdpEvent::Changed { settings } => self.settings = Some(settings),
            IdpEvent::SecretChanged => self.has_secret = true,
            IdpEvent::SecretRemoved => self.has_secret = false,
            IdpEvent::Deactivated => self.active = false,
            IdpEvent::Reactivated => self.active = true,
            IdpEvent::Removed => *self = Self::default(),
        }
    }
}

async fn projection(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        let instance = event.aggregate.instance_id;
        let tenant = (event.owner != instance).then_some(event.owner);
        let id = Uuid::parse_str(&event.aggregate.aggregate_id).map_err(|error| Error::Decode {
            event_type: event.event_type.clone(),
            revision: event.revision,
            message: format!("identity provider id: {error}"),
        })?;
        match IdpEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            IdpEvent::Added { settings } => {
                let saml = settings.saml.as_ref();
                sqlx::query!(
                    "INSERT INTO identity_providers
                         (id, tenant_id, name, kind, issuer, client_id, scopes, domains, auto_create, auto_link,
                          saml_sso_url, saml_certificates, saml_email_attribute, saml_name_attribute, instance_id,
                          sync_profile, saml_sign_requests, saml_slo_url, register)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
                    id,
                    tenant,
                    settings.name,
                    settings.kind(),
                    settings.issuer,
                    settings.client_id,
                    &settings.scopes,
                    &settings.domains,
                    settings.auto_create,
                    settings.auto_link,
                    saml.map(|saml| saml.sso_url.as_str()),
                    &saml.map(|saml| saml.certificates.clone()).unwrap_or_default(),
                    saml.and_then(|saml| saml.email_attribute.as_deref()),
                    saml.and_then(|saml| saml.name_attribute.as_deref()),
                    instance,
                    settings.sync_profile,
                    saml.is_some_and(|saml| saml.sign_requests),
                    saml.and_then(|saml| saml.slo_url.as_deref()),
                    settings.register,
                )
                .execute(&mut *connection)
                .await?;
            }
            IdpEvent::Changed { settings } => {
                let saml = settings.saml.as_ref();
                sqlx::query!(
                    "UPDATE identity_providers SET name = $2, issuer = $3, client_id = $4, scopes = $5, domains = $6,
                         auto_create = $7, auto_link = $8, kind = $9, saml_sso_url = $10, saml_certificates = $11,
                         saml_email_attribute = $12, saml_name_attribute = $13, sync_profile = $14,
                         saml_sign_requests = $15, saml_slo_url = $16, register = $17
                     WHERE id = $1",
                    id,
                    settings.name,
                    settings.issuer,
                    settings.client_id,
                    &settings.scopes,
                    &settings.domains,
                    settings.auto_create,
                    settings.auto_link,
                    settings.kind(),
                    saml.map(|saml| saml.sso_url.as_str()),
                    &saml.map(|saml| saml.certificates.clone()).unwrap_or_default(),
                    saml.and_then(|saml| saml.email_attribute.as_deref()),
                    saml.and_then(|saml| saml.name_attribute.as_deref()),
                    settings.sync_profile,
                    saml.is_some_and(|saml| saml.sign_requests),
                    saml.and_then(|saml| saml.slo_url.as_deref()),
                    settings.register,
                )
                .execute(&mut *connection)
                .await?;
            }
            // Written by the command, which holds the sealed secret.
            IdpEvent::SecretChanged => {}
            IdpEvent::SecretRemoved => {
                sqlx::query!("DELETE FROM identity_provider_secrets WHERE idp_id = $1", id)
                    .execute(&mut *connection)
                    .await?;
            }
            IdpEvent::Deactivated => {
                sqlx::query!("UPDATE identity_providers SET active = false WHERE id = $1", id)
                    .execute(&mut *connection)
                    .await?;
            }
            IdpEvent::Reactivated => {
                sqlx::query!("UPDATE identity_providers SET active = true WHERE id = $1", id)
                    .execute(&mut *connection)
                    .await?;
            }
            IdpEvent::Removed => {
                sqlx::query!("DELETE FROM identity_providers WHERE id = $1", id).execute(&mut *connection).await?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpInfo {
    pub id: Uuid,
    /// The owning tenant; `None` for a provider of the whole instance.
    pub tenant: Option<Uuid>,
    pub instance: Uuid,
    pub settings: IdpSettings,
    pub has_secret: bool,
    pub active: bool,
}

/// The SAML login a session came from (`idp_sessions`).
#[derive(Debug, Clone)]
pub(crate) struct SamlSession {
    idp_id: Uuid,
    name_id: String,
    name_id_format: Option<String>,
    session_index: Option<String>,
}

/// One of kernoid's SAML keys of an instance (RFC 0001, 7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlKeyInfo {
    pub id: Uuid,
    /// `next` (in the metadata, not signing), `active` (signing) or `retired` (only decrypting).
    pub state: String,
    pub created_at: chrono::DateTime<Utc>,
    pub state_since: chrono::DateTime<Utc>,
    /// SHA-256 of the certificate, in hex – what providers show.
    pub fingerprint: String,
}

/// What the login UI learns about an address: whether its logins go to a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpSummary {
    pub id: Uuid,
    pub name: String,
}

/// A login waiting for a provider's answer.
struct PendingLogin {
    id: Uuid,
    idp: Uuid,
    verifier: String,
    nonce: String,
    auth_request: Option<String>,
    saml_request: Option<String>,
    /// Started from an account's page: the provider's identity is linked to this account.
    link_account: Option<Uuid>,
}

/// What a provider login found.
#[derive(Debug, Clone)]
pub(crate) enum Resolved {
    /// The account it logs in as, and the session's checks.
    Account(Uuid, Vec<String>),
    /// No linked account, but one with the provider's verified address: linking it is proposed (RFC 0003, 3).
    Proposal { existing: Uuid, subject: String, email: String, name: Option<String>, checks: Vec<String> },
}

/// A pending proposal, as stored.
struct ProposalRow {
    id: Uuid,
    existing: Uuid,
    subject: String,
    email: String,
    display_name: Option<String>,
    checks: Vec<String>,
    auth_request: Option<String>,
}

/// A proposal to link a provider login to an existing account, as the login UI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkProposal {
    /// The provider's verified address, which the existing account has.
    pub email: String,
    pub provider: String,
    /// A separate account may be created instead.
    pub may_register: bool,
}

/// Who logged in at a SAML provider – kept with the session for single logout.
#[derive(Debug, Clone, Default)]
struct SamlSubject {
    name_id: String,
    format: Option<String>,
    session_index: Option<String>,
}

/// The answer of [`Oidc::exchange_idp_login`].
#[derive(Debug, Clone)]
pub struct IdpLoginResult {
    pub session: NewSession,
    /// The auth request the login was for, to finish next.
    pub auth_request: Option<String>,
}

fn command_error(error: CommandError<OidcError>) -> OidcError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => internal(error),
    }
}

fn refused(message: impl Into<String>) -> OidcError {
    OidcError::Identity(IdentityError::Refused(message.into()))
}

fn secret_context(idp: Uuid) -> Vec<u8> {
    format!("kernoid identity provider secret {idp}").into_bytes()
}

/// A scope token (RFC 6749, 3.3).
fn valid_scope(scope: &str) -> bool {
    !scope.is_empty() && scope.bytes().all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

impl Oidc {
    /// The address an OpenID provider sends the browser back to – to register at the provider.
    pub fn idp_redirect_uri(&self, primary_domain: &str) -> String {
        format!("{}/idp/callback", self.issuer(primary_domain))
    }

    /// kernoid's SAML entity ID at an instance.
    pub fn saml_entity_id(&self, primary_domain: &str) -> String {
        format!("{}/idp/saml", self.issuer(primary_domain))
    }

    /// Where a SAML provider posts its Response (Assertion Consumer Service).
    pub fn saml_acs_url(&self, primary_domain: &str) -> String {
        format!("{}/idp/saml/acs", self.issuer(primary_domain))
    }

    /// kernoid's SAML single logout service.
    pub fn saml_slo_url(&self, primary_domain: &str) -> String {
        format!("{}/idp/saml/slo", self.issuer(primary_domain))
    }

    /// kernoid's SAML service provider metadata for an instance, with its SAML keys – the active one and, while a
    /// key changes, the next one.
    pub async fn saml_metadata(&self, instance: &InstanceInfo) -> Result<String> {
        self.saml_sp_key(instance).await?;
        let certificates: Vec<Vec<u8>> = self
            .saml_sp_keys(instance.id)
            .await?
            .into_iter()
            .filter(|(info, _)| info.state != "retired")
            .map(|(_, key)| key.certificate)
            .collect();
        let domain = &instance.primary_domain;
        Ok(crate::saml::metadata(
            &self.saml_entity_id(domain),
            &self.saml_acs_url(domain),
            &self.saml_slo_url(domain),
            &certificates,
        ))
    }

    /// kernoid's SAML keys of an instance, the active one first, then the next, then retired ones (newest first).
    async fn saml_sp_keys(&self, instance: Uuid) -> Result<Vec<(SamlKeyInfo, crate::saml::SpKey)>> {
        let context = format!("kernoid/saml-sp-key/v1/{instance}").into_bytes();
        let rows = sqlx::query!(
            "SELECT id, state, created_at, state_since, private_sealed, certificate FROM saml_sp_keys
             WHERE instance_id = $1
             ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'next' THEN 1 ELSE 2 END, created_at DESC",
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        let mut keys = Vec::new();
        for row in rows {
            let (private, _) = self.main.open_secret(&context, &row.private_sealed).map_err(internal)?;
            let fingerprint = Sha256::digest(&row.certificate).iter().map(|byte| format!("{byte:02X}")).collect();
            let info = SamlKeyInfo {
                id: row.id,
                state: row.state,
                created_at: row.created_at,
                state_since: row.state_since,
                fingerprint,
            };
            let key =
                crate::saml::SpKey { private: zeroize::Zeroizing::new(private.to_vec()), certificate: row.certificate };
            keys.push((info, key));
        }
        Ok(keys)
    }

    /// Makes a SAML key for the instance and stores it in `state`; false if another one in that state was quicker.
    async fn make_saml_key(&self, instance: &InstanceInfo, state: &str) -> Result<bool> {
        let context = format!("kernoid/saml-sp-key/v1/{}", instance.id).into_bytes();
        let entity = self.saml_entity_id(&instance.primary_domain);
        let key = tokio::task::spawn_blocking(move || crate::saml::SpKey::generate(&entity))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        let sealed = self.main.seal_secret(&context, &key.private).map_err(internal)?;
        let inserted = sqlx::query!(
            "INSERT INTO saml_sp_keys (id, instance_id, state, private_sealed, certificate) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
            Uuid::now_v7(),
            instance.id,
            state,
            sealed,
            key.certificate,
        )
        .execute(self.pool())
        .await
        .map_err(internal)?;
        Ok(inserted.rows_affected() == 1)
    }

    /// kernoid's active SAML key of the instance – made at first use, sealed with the main key.
    pub async fn saml_sp_key(&self, instance: &InstanceInfo) -> Result<crate::saml::SpKey> {
        for _ in 0..2 {
            if let Some((info, key)) = self.saml_sp_keys(instance.id).await?.into_iter().next()
                && info.state == "active"
            {
                return Ok(key);
            }
            // Another process may make one at the same time; the first one stays, and both read it.
            self.make_saml_key(instance, "active").await?;
        }
        Err(internal("kernoid's SAML key could not be stored"))
    }

    /// kernoid's SAML keys of the instance, as administrators see them.
    pub async fn saml_keys(&self, instance: Uuid) -> Result<Vec<SamlKeyInfo>> {
        Ok(self.saml_sp_keys(instance).await?.into_iter().map(|(info, _)| info).collect())
    }

    /// Starts a change of kernoid's SAML key: a new key, `next` – in the metadata and decrypting, not signing yet –
    /// until it is activated, once the providers have taken in the new metadata. Returns its id; if a key waits
    /// already, that one's.
    pub async fn add_saml_key(&self, instance: &InstanceInfo) -> Result<Uuid> {
        self.saml_sp_key(instance).await?;
        for _ in 0..2 {
            let keys = self.saml_sp_keys(instance.id).await?;
            if let Some((info, _)) = keys.into_iter().find(|(info, _)| info.state == "next") {
                return Ok(info.id);
            }
            self.make_saml_key(instance, "next").await?;
        }
        Err(internal("kernoid's SAML key could not be stored"))
    }

    /// Signs with the waiting key `key` from now on; the key active so far is retired: it leaves the metadata and only
    /// decrypts what providers still encrypt for it.
    pub async fn activate_saml_key(&self, instance: Uuid, key: Uuid) -> Result<()> {
        let mut transaction = self.pool().begin().await.map_err(internal)?;
        let waiting = sqlx::query_scalar!(
            "SELECT id FROM saml_sp_keys WHERE id = $1 AND instance_id = $2 AND state = 'next' FOR UPDATE",
            key,
            instance,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(internal)?;
        if waiting.is_none() {
            return Err(refused("only the waiting key can be activated"));
        }
        sqlx::query!(
            "UPDATE saml_sp_keys SET state = 'retired', state_since = now() WHERE instance_id = $1 AND state = 'active'",
            instance,
        )
        .execute(&mut *transaction)
        .await
        .map_err(internal)?;
        sqlx::query!("UPDATE saml_sp_keys SET state = 'active', state_since = now() WHERE id = $1", key)
            .execute(&mut *transaction)
            .await
            .map_err(internal)?;
        transaction.commit().await.map_err(internal)
    }

    /// What to register at a provider: the redirect URI (OpenID Connect) or the ACS URL (SAML).
    pub fn idp_return_address(&self, info: &IdpInfo, primary_domain: &str) -> String {
        if info.settings.saml.is_some() {
            self.saml_acs_url(primary_domain)
        } else {
            self.idp_redirect_uri(primary_domain)
        }
    }

    async fn checked_settings(
        &self,
        owner: IdpOwner,
        idp: Option<Uuid>,
        settings: &IdpSettings,
    ) -> Result<IdpSettings> {
        let name = settings.name.trim();
        if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
            return Err(refused("a name has 1 to 200 characters"));
        }
        let (issuer, client_id, scopes, saml) = match &settings.saml {
            Some(saml) => {
                // SAML: the entity ID is a URI, not necessarily a URL kernoid fetches.
                let entity = settings.issuer.trim().to_owned();
                if entity.is_empty() || entity.len() > 1024 || entity.chars().any(char::is_whitespace) {
                    return Err(refused("an entity ID has 1 to 1024 characters and no spaces"));
                }
                let sso =
                    Url::parse(saml.sso_url.trim()).map_err(|e| refused(format!("the SSO URL is not a URL: {e}")))?;
                crate::outbound::check_url(&sso, self.allow_private).map_err(refused)?;
                if saml.certificates.is_empty() {
                    return Err(refused("a SAML provider needs at least one signing certificate"));
                }
                let mut certificates = Vec::new();
                for certificate in &saml.certificates {
                    let der = crate::saml::certificate(certificate).map_err(|e| refused(e.to_string()))?;
                    certificates.push(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der));
                }
                let attribute = |name: &Option<String>| -> Result<Option<String>> {
                    match name.as_deref().map(str::trim).filter(|name| !name.is_empty()) {
                        Some(name) if name.len() > 255 => Err(refused("an attribute name has at most 255 characters")),
                        other => Ok(other.map(str::to_owned)),
                    }
                };
                let slo_url = match saml.slo_url.as_deref().map(str::trim).filter(|url| !url.is_empty()) {
                    Some(url) => {
                        let slo = Url::parse(url).map_err(|e| refused(format!("the SLO URL is not a URL: {e}")))?;
                        crate::outbound::check_url(&slo, self.allow_private).map_err(refused)?;
                        Some(slo.to_string())
                    }
                    None => None,
                };
                let checked = SamlSettings {
                    sso_url: sso.to_string(),
                    certificates,
                    email_attribute: attribute(&saml.email_attribute)?,
                    name_attribute: attribute(&saml.name_attribute)?,
                    sign_requests: saml.sign_requests,
                    slo_url,
                };
                (entity, String::new(), Vec::new(), Some(checked))
            }
            None => {
                let issuer = settings.issuer.trim().trim_end_matches('/').to_owned();
                let url = Url::parse(&issuer).map_err(|e| refused(format!("the issuer is not a URL: {e}")))?;
                crate::outbound::check_url(&url, self.allow_private).map_err(refused)?;
                if url.query().is_some() || url.fragment().is_some() {
                    return Err(refused("an issuer has no query or fragment"));
                }
                let client_id = settings.client_id.trim().to_owned();
                if client_id.is_empty() || client_id.len() > 255 {
                    return Err(refused("a client id has 1 to 255 characters"));
                }
                let mut scopes: Vec<String> = settings.scopes.iter().map(|scope| scope.trim().to_owned()).collect();
                if !scopes.iter().any(|scope| scope == "openid") {
                    scopes.insert(0, "openid".into());
                }
                if let Some(bad) = scopes.iter().find(|scope| !valid_scope(scope)) {
                    return Err(refused(format!("{bad:?} is not a scope")));
                }
                scopes.dedup();
                (issuer, client_id, scopes, None)
            }
        };
        let instance = self.owner_instance(owner).await?;
        let mut domains = BTreeSet::new();
        for domain in &settings.domains {
            let domain = DomainName::parse(domain).map_err(|e| refused(e.to_string()))?;
            let holder = self.identity.tenant_by_domain(&domain).await?;
            let fits = match owner {
                IdpOwner::Tenant(tenant) => holder.is_some_and(|holder| holder.id == tenant),
                IdpOwner::Instance(instance) => holder.is_some_and(|holder| holder.instance == instance),
            };
            if !fits {
                return Err(refused(format!("{domain} is not a verified domain of the tenant or instance")));
            }
            // One provider per domain in the instance – a tenant's own or the instance's.
            let taken = sqlx::query_scalar!(
                r#"SELECT EXISTS (SELECT 1 FROM identity_providers
                                  WHERE instance_id = $1 AND $2 = ANY (domains) AND id IS DISTINCT FROM $3) AS "taken!""#,
                instance,
                domain.as_str(),
                idp,
            )
            .fetch_one(self.pool())
            .await
            .map_err(internal)?;
            if taken {
                return Err(refused(format!("{domain} goes to another identity provider already")));
            }
            domains.insert(domain.to_string());
        }
        Ok(IdpSettings {
            name: name.to_owned(),
            issuer,
            client_id,
            scopes,
            domains: domains.into_iter().collect(),
            auto_create: settings.auto_create,
            auto_link: settings.auto_link,
            sync_profile: settings.sync_profile,
            register: settings.register,
            saml,
        })
    }

    async fn owner_instance(&self, owner: IdpOwner) -> Result<Uuid> {
        match owner {
            IdpOwner::Tenant(tenant) => Ok(self.identity.tenant_instance(tenant).await?),
            IdpOwner::Instance(instance) => Ok(instance),
        }
    }

    async fn idp_command(
        &self,
        owner: IdpOwner,
        idp: Uuid,
        creator: &str,
        decide: impl Fn(&IdentityProvider) -> Result<Vec<IdpEvent>>,
        secret: Option<Vec<u8>>,
    ) -> Result<()> {
        let instance = self.owner_instance(owner).await?;
        let aggregate_owner = match owner {
            IdpOwner::Tenant(tenant) => tenant,
            IdpOwner::Instance(instance) => instance,
        };
        let store = inline(move |connection, events| {
            let secret = secret.clone();
            Box::pin(async move {
                projection(connection, events).await?;
                if let Some(sealed) = secret {
                    sqlx::query!(
                        "INSERT INTO identity_provider_secrets (idp_id, sealed) VALUES ($1, $2)
                         ON CONFLICT (idp_id) DO UPDATE SET sealed = excluded.sealed",
                        idp,
                        sealed,
                    )
                    .execute(&mut *connection)
                    .await?;
                }
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(instance, aggregate_owner, &idp.to_string(), creator, decide, store)
            .await
            .map(drop)
            .map_err(command_error)
    }

    /// A provider of the owner; any other is unknown.
    async fn idp_of(&self, owner: IdpOwner, idp: Uuid) -> Result<IdpInfo> {
        match self.identity_provider(idp).await {
            Ok(info) if info.owner() == owner => Ok(info),
            Ok(_) => Err(IdentityError::NotFound("the identity provider").into()),
            Err(error) => Err(error),
        }
    }

    /// Connects an identity provider to a tenant; returns its id.
    pub async fn add_identity_provider(
        &self,
        owner: impl Into<IdpOwner>,
        settings: &IdpSettings,
        client_secret: Option<&str>,
        creator: &str,
    ) -> Result<Uuid> {
        let owner = owner.into();
        let settings = self.checked_settings(owner, None, settings).await?;
        let id = Uuid::now_v7();
        let sealed = match client_secret {
            Some(secret) => Some(self.main.seal_secret(&secret_context(id), secret.as_bytes()).map_err(internal)?),
            None => None,
        };
        let has_secret = sealed.is_some();
        self.idp_command(
            owner,
            id,
            creator,
            |state| {
                if state.exists {
                    return Err(refused("the identity provider exists already"));
                }
                let mut events = vec![IdpEvent::Added { settings: settings.clone() }];
                if has_secret {
                    events.push(IdpEvent::SecretChanged);
                }
                Ok(events)
            },
            sealed,
        )
        .await?;
        Ok(id)
    }

    pub async fn update_identity_provider(
        &self,
        owner: impl Into<IdpOwner>,
        idp: Uuid,
        settings: &IdpSettings,
        creator: &str,
    ) -> Result<()> {
        let owner = owner.into();
        self.idp_of(owner, idp).await?;
        let settings = self.checked_settings(owner, Some(idp), settings).await?;
        self.idp_command(
            owner,
            idp,
            creator,
            |state| {
                Ok(if state.settings.as_ref() == Some(&settings) {
                    Vec::new()
                } else {
                    vec![IdpEvent::Changed { settings: settings.clone() }]
                })
            },
            None,
        )
        .await
    }

    /// Sets or removes the client secret kernoid authenticates with at the provider.
    pub async fn set_identity_provider_secret(
        &self,
        owner: impl Into<IdpOwner>,
        idp: Uuid,
        client_secret: Option<&str>,
        creator: &str,
    ) -> Result<()> {
        let owner = owner.into();
        self.idp_of(owner, idp).await?;
        let sealed = match client_secret {
            Some(secret) if !secret.is_empty() && secret.len() <= 1024 => {
                Some(self.main.seal_secret(&secret_context(idp), secret.as_bytes()).map_err(internal)?)
            }
            Some(_) => return Err(refused("a client secret has 1 to 1024 bytes")),
            None => None,
        };
        let set = sealed.is_some();
        self.idp_command(
            owner,
            idp,
            creator,
            |state| {
                Ok(match (set, state.has_secret) {
                    (true, _) => vec![IdpEvent::SecretChanged],
                    (false, true) => vec![IdpEvent::SecretRemoved],
                    (false, false) => Vec::new(),
                })
            },
            sealed,
        )
        .await
    }

    pub async fn set_identity_provider_active(
        &self,
        owner: impl Into<IdpOwner>,
        idp: Uuid,
        active: bool,
        creator: &str,
    ) -> Result<()> {
        let owner = owner.into();
        self.idp_of(owner, idp).await?;
        self.idp_command(
            owner,
            idp,
            creator,
            |state| {
                Ok(match (state.active, active) {
                    (true, false) => vec![IdpEvent::Deactivated],
                    (false, true) => vec![IdpEvent::Reactivated],
                    _ => Vec::new(),
                })
            },
            None,
        )
        .await
    }

    /// Removes a provider – once no account is linked to it any more.
    pub async fn remove_identity_provider(&self, owner: impl Into<IdpOwner>, idp: Uuid, creator: &str) -> Result<()> {
        let owner = owner.into();
        self.idp_of(owner, idp).await?;
        let linked =
            sqlx::query_scalar!(r#"SELECT EXISTS (SELECT 1 FROM account_links WHERE idp_id = $1) AS "linked!""#, idp,)
                .fetch_one(self.pool())
                .await
                .map_err(internal)?;
        if linked {
            return Err(refused("accounts are linked to this identity provider; unlink them first"));
        }
        self.idp_command(
            owner,
            idp,
            creator,
            |state| {
                let mut events = Vec::new();
                if state.has_secret {
                    events.push(IdpEvent::SecretRemoved);
                }
                events.push(IdpEvent::Removed);
                Ok(events)
            },
            None,
        )
        .await
    }

    pub async fn identity_provider(&self, idp: Uuid) -> Result<IdpInfo> {
        let row = sqlx::query!(
            r#"SELECT p.id, p.tenant_id, p.instance_id, p.name, p.issuer, p.client_id, p.scopes, p.domains,
                      p.auto_create, p.auto_link, p.active, p.kind, p.saml_sso_url, p.saml_certificates,
                      p.saml_email_attribute, p.saml_name_attribute, p.sync_profile, p.saml_sign_requests,
                      p.saml_slo_url, p.register,
                      EXISTS (SELECT 1 FROM identity_provider_secrets s WHERE s.idp_id = p.id) AS "has_secret!"
               FROM identity_providers p WHERE p.id = $1"#,
            idp,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(internal)?
        .ok_or(IdentityError::NotFound("the identity provider"))?;
        Ok(IdpInfo {
            id: row.id,
            tenant: row.tenant_id,
            instance: row.instance_id,
            settings: IdpSettings {
                name: row.name,
                issuer: row.issuer,
                client_id: row.client_id,
                scopes: row.scopes,
                domains: row.domains,
                auto_create: row.auto_create,
                auto_link: row.auto_link,
                sync_profile: row.sync_profile,
                register: row.register,
                saml: (row.kind == "saml").then(|| SamlSettings {
                    sso_url: row.saml_sso_url.unwrap_or_default(),
                    certificates: row.saml_certificates,
                    email_attribute: row.saml_email_attribute,
                    name_attribute: row.saml_name_attribute,
                    sign_requests: row.saml_sign_requests,
                    slo_url: row.saml_slo_url,
                }),
            },
            has_secret: row.has_secret,
            active: row.active,
        })
    }

    /// The providers of a tenant, and those of its instance that serve all tenants.
    pub async fn identity_providers(&self, tenant: Uuid) -> Result<Vec<IdpInfo>> {
        let instance = self.identity.tenant_instance(tenant).await?;
        let ids = sqlx::query_scalar!(
            "SELECT id FROM identity_providers
             WHERE tenant_id = $1 OR (tenant_id IS NULL AND instance_id = $2) ORDER BY name, id",
            tenant,
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        let mut list = Vec::with_capacity(ids.len());
        for id in ids {
            list.push(self.identity_provider(id).await?);
        }
        Ok(list)
    }

    /// Fetches the provider's discovery document and keys – whether kernoid can reach it as configured.
    pub async fn check_identity_provider(&self, owner: impl Into<IdpOwner>, idp: Uuid) -> Result<()> {
        let info = self.idp_of(owner.into(), idp).await?;
        if let Some(saml) = &info.settings.saml {
            // Nothing to fetch: the certificates must load.
            for certificate in &saml.certificates {
                crate::saml::certificate(certificate).map_err(|e| refused(e.to_string()))?;
            }
            return Ok(());
        }
        let metadata = external::discover(&self.outbound, &info.settings.issuer, self.allow_private)
            .await
            .map_err(|e| refused(e.to_string()))?;
        external::keys(&self.outbound, &metadata, self.allow_private).await.map_err(|e| refused(e.to_string()))?;
        Ok(())
    }

    // The login

    /// Where logins of an address go: the active provider its domain is routed to, if any. Says nothing about
    /// whether the account exists.
    pub async fn login_options(&self, instance: Uuid, address: &str) -> Result<Option<IdpSummary>> {
        let Ok(address) = Address::parse(address) else { return Ok(None) };
        let Some(tenant) = self.identity.tenant_by_domain(&address.domain()).await? else { return Ok(None) };
        if tenant.instance != instance || !tenant.active {
            return Ok(None);
        }
        let domain = address.domain();
        let row = sqlx::query!(
            "SELECT id, name FROM identity_providers WHERE instance_id = $1 AND active AND $2 = ANY (domains)",
            instance,
            domain.as_str(),
        )
        .fetch_optional(self.pool())
        .await
        .map_err(internal)?;
        Ok(row.map(|row| IdpSummary { id: row.id, name: row.name }))
    }

    /// Starts a login at a provider of a tenant of `instance`; returns the URL to send the browser to.
    pub async fn start_idp_login(
        &self,
        instance: &InstanceInfo,
        idp: Uuid,
        auth_request: Option<&str>,
        login_hint: Option<&str>,
    ) -> Result<String> {
        self.start_login(instance, idp, auth_request, login_hint, None).await
    }

    /// Starts a login at a provider that links it to the account of `token` (from the account page, RFC 0003, 3).
    pub async fn start_idp_link(&self, instance: &InstanceInfo, token: &str, idp: Uuid) -> Result<String> {
        // A link is another way into the account, as a passkey is: only after a recent login.
        let session = self.identity.recent_session(instance.id, token).await?;
        let info = self.identity_provider(idp).await?;
        if info.tenant.is_some_and(|tenant| tenant != session.account.tenant) {
            return Err(IdentityError::NotFound("the identity provider").into());
        }
        self.start_login(instance, idp, None, None, Some(session.account.id)).await
    }

    async fn start_login(
        &self,
        instance: &InstanceInfo,
        idp: Uuid,
        auth_request: Option<&str>,
        login_hint: Option<&str>,
        link_account: Option<Uuid>,
    ) -> Result<String> {
        let info = self.identity_provider(idp).await?;
        if info.instance != instance.id || !info.active {
            return Err(IdentityError::NotFound("the identity provider").into());
        }
        if let Some(request) = auth_request {
            self.auth_request(instance, request).await?;
        }
        if let Some(saml) = &info.settings.saml {
            // An xs:ID: `_` and base64url characters.
            let (id, state, request_id) = (Uuid::now_v7(), random_secret("")?, random_secret("_")?);
            sqlx::query!(
                "INSERT INTO idp_logins
                     (id, instance_id, idp_id, state_hash, verifier, nonce, auth_request_id, saml_request_id, expires_at,
                      link_account)
                 VALUES ($1, $2, $3, $4, '', '', $5, $6, now() + make_interval(secs => $7), $8)",
                id,
                instance.id,
                idp,
                &sha256(&state)[..],
                auth_request,
                request_id,
                LOGIN_LIFETIME.as_secs() as f64,
                link_account,
            )
            .execute(self.pool())
            .await
            .map_err(internal)?;
            let (sp, acs) =
                (self.saml_entity_id(&instance.primary_domain), self.saml_acs_url(&instance.primary_domain));
            let key = if saml.sign_requests { Some(self.saml_sp_key(instance).await?) } else { None };
            return crate::saml::authn_request_url(
                &saml.sso_url,
                &request_id,
                &sp,
                &acs,
                &state,
                Utc::now(),
                key.as_ref(),
            )
            .map_err(|e| refused(e.to_string()));
        }
        let metadata = external::discover(&self.outbound, &info.settings.issuer, self.allow_private)
            .await
            .map_err(|e| refused(e.to_string()))?;
        let (id, state, verifier, nonce) = (Uuid::now_v7(), random_secret("")?, random_secret("")?, random_secret("")?);
        sqlx::query!(
            "INSERT INTO idp_logins
                 (id, instance_id, idp_id, state_hash, verifier, nonce, auth_request_id, expires_at, link_account)
             VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8), $9)",
            id,
            instance.id,
            idp,
            &sha256(&state)[..],
            verifier,
            nonce,
            auth_request,
            LOGIN_LIFETIME.as_secs() as f64,
            link_account,
        )
        .execute(self.pool())
        .await
        .map_err(internal)?;
        let mut url = Url::parse(&metadata.authorization_endpoint).map_err(internal)?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &info.settings.client_id)
                .append_pair("redirect_uri", &self.idp_redirect_uri(&instance.primary_domain))
                .append_pair("scope", &info.settings.scopes.join(" "))
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge", &pkce_challenge(&verifier))
                .append_pair("code_challenge_method", "S256");
            if let Some(hint) = login_hint.filter(|hint| hint.len() <= 320) {
                query.append_pair("login_hint", hint);
            }
        }
        Ok(url.into())
    }

    /// The login UI's address after a login at a provider – with a one-time code or with an error.
    fn ui_fragment(&self, instance: &InstanceInfo, pairs: &[(&str, &str)]) -> String {
        let mut fragment = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            fragment.append_pair(key, value);
        }
        format!("{}/idp#{}", self.login_url(instance), fragment.finish())
    }

    fn fail_to_ui(&self, instance: &InstanceInfo, message: &str, auth_request: Option<&str>) -> String {
        match auth_request {
            Some(request) => self.ui_fragment(instance, &[("error", message), ("authRequest", request)]),
            None => self.ui_fragment(instance, &[("error", message)]),
        }
    }

    /// Finds the login a provider answers by its `state` (OpenID Connect) or `RelayState` (SAML).
    async fn pending_login(&self, instance: &InstanceInfo, state: &str) -> std::result::Result<PendingLogin, String> {
        let row = sqlx::query!(
            "SELECT id, idp_id, verifier, nonce, auth_request_id, saml_request_id, link_account FROM idp_logins
             WHERE state_hash = $1 AND instance_id = $2 AND expires_at > now() AND handoff_hash IS NULL",
            &sha256(state)[..],
            instance.id,
        )
        .fetch_optional(self.pool())
        .await;
        match row {
            Ok(Some(row)) => Ok(PendingLogin {
                id: row.id,
                idp: row.idp_id,
                verifier: row.verifier,
                nonce: row.nonce,
                auth_request: row.auth_request_id,
                saml_request: row.saml_request_id,
                link_account: row.link_account,
            }),
            Ok(None) => Err(self.fail_to_ui(instance, "This login has expired. Please start again.", None)),
            Err(error) => {
                tracing::error!(%error, "reading an identity provider login");
                Err(self.fail_to_ui(instance, "The login could not be completed.", None))
            }
        }
    }

    /// Records who logged in and returns the login UI's address with the one-time code – or with the error.
    async fn hand_over(
        &self,
        instance: &InstanceInfo,
        login: &PendingLogin,
        outcome: Result<Resolved>,
        subject: Option<SamlSubject>,
    ) -> String {
        let request = login.auth_request.as_deref();
        let subject = subject.unwrap_or_default();
        let (account, checks) = match outcome {
            Ok(Resolved::Account(account, checks)) => (account, checks),
            Ok(Resolved::Proposal { existing, subject: external, email, name, checks }) => {
                return self
                    .hand_over_proposal(instance, login, existing, &external, &email, name.as_deref(), &checks)
                    .await;
            }
            Err(error) => {
                tracing::info!(idp = %login.idp, %error, "login at an identity provider refused");
                let message = match &error {
                    OidcError::Identity(IdentityError::Refused(message)) => message.clone(),
                    OidcError::Identity(IdentityError::AccountDeactivated) => "The account is deactivated.".into(),
                    _ => "The login could not be completed.".into(),
                };
                return self.fail_to_ui(instance, &message, request);
            }
        };
        let Ok(handoff) = random_secret("") else {
            return self.fail_to_ui(instance, "The login could not be completed.", request);
        };
        let stored = sqlx::query!(
            "UPDATE idp_logins SET account_id = $2, checks = $3, handoff_hash = $4, saml_name_id = $5,
                 saml_name_id_format = $6, saml_session_index = $7
             WHERE id = $1 AND handoff_hash IS NULL",
            login.id,
            account,
            &checks,
            &sha256(&handoff)[..],
            (!subject.name_id.is_empty()).then_some(subject.name_id.as_str()),
            subject.format,
            subject.session_index,
        )
        .execute(self.pool())
        .await;
        match stored {
            Ok(result) if result.rows_affected() == 1 => {
                self.ui_fragment(instance, &[("login", &format!("{}.{handoff}", login.id))])
            }
            _ => self.fail_to_ui(instance, "The login could not be completed.", request),
        }
    }

    /// Keeps a provider login that proposes linking an existing account, and returns the login UI's address with
    /// the one-time code for the proposal.
    #[allow(clippy::too_many_arguments, reason = "what the proposal keeps")]
    async fn hand_over_proposal(
        &self,
        instance: &InstanceInfo,
        login: &PendingLogin,
        existing: Uuid,
        subject: &str,
        email: &str,
        name: Option<&str>,
        checks: &[String],
    ) -> String {
        let request = login.auth_request.as_deref();
        let Ok(handoff) = random_secret("") else {
            return self.fail_to_ui(instance, "The login could not be completed.", request);
        };
        let stored = sqlx::query!(
            "UPDATE idp_logins SET proposal_account = $2, subject = $3, email = $4, display_name = $5, checks = $6,
                 handoff_hash = $7
             WHERE id = $1 AND handoff_hash IS NULL",
            login.id,
            existing,
            subject,
            email,
            name,
            checks,
            &sha256(&handoff)[..],
        )
        .execute(self.pool())
        .await;
        match stored {
            Ok(result) if result.rows_affected() == 1 => {
                let link = format!("{}.{handoff}", login.id);
                match request {
                    Some(request) => self.ui_fragment(instance, &[("link", &link), ("authRequest", request)]),
                    None => self.ui_fragment(instance, &[("link", &link)]),
                }
            }
            _ => self.fail_to_ui(instance, "The login could not be completed.", request),
        }
    }

    /// An OpenID provider's answer at `/idp/callback`; returns where to send the browser: the login UI, with a
    /// one-time code for the session or with an error to show.
    pub async fn idp_callback(
        &self,
        instance: &InstanceInfo,
        state: Option<&str>,
        code: Option<&str>,
        error: Option<&str>,
    ) -> String {
        let Some(state) = state else {
            return self.fail_to_ui(instance, "The identity provider's answer is incomplete.", None);
        };
        let login = match self.pending_login(instance, state).await {
            Ok(login) => login,
            Err(redirect) => return redirect,
        };
        let request = login.auth_request.as_deref();
        if let Some(error) = error {
            let message = if error == "access_denied" {
                "The login was cancelled."
            } else {
                "The identity provider refused the login."
            };
            return self.fail_to_ui(instance, message, request);
        }
        let Some(code) = code else {
            return self.fail_to_ui(instance, "The identity provider's answer is incomplete.", request);
        };
        let outcome = self
            .complete_oidc_login(instance, login.idp, code, &login.verifier, &login.nonce, login.link_account)
            .await;
        self.hand_over(instance, &login, outcome, None).await
    }

    /// A SAML provider's Response at `/idp/saml/acs` (HTTP-POST binding); returns where to send the browser.
    pub async fn saml_acs(&self, instance: &InstanceInfo, relay_state: Option<&str>, response: Option<&str>) -> String {
        let (Some(relay_state), Some(response)) = (relay_state, response) else {
            return self.fail_to_ui(instance, "The identity provider's answer is incomplete.", None);
        };
        let login = match self.pending_login(instance, relay_state).await {
            Ok(login) => login,
            Err(redirect) => return redirect,
        };
        let (outcome, subject) = match self.complete_saml_login(instance, &login, response).await {
            Ok((found, subject)) => (Ok(found), Some(subject)),
            Err(error) => (Err(error), None),
        };
        self.hand_over(instance, &login, outcome, subject).await
    }

    async fn complete_saml_login(
        &self,
        instance: &InstanceInfo,
        login: &PendingLogin,
        response: &str,
    ) -> Result<(Resolved, SamlSubject)> {
        let info = self.identity_provider(login.idp).await?;
        let (Some(saml), Some(request)) = (&info.settings.saml, &login.saml_request) else {
            return Err(refused("The login could not be completed."));
        };
        if !info.active {
            return Err(refused("The identity provider is switched off."));
        }
        let certificates: Vec<Vec<u8>> =
            saml.certificates.iter().filter_map(|certificate| crate::saml::certificate(certificate).ok()).collect();
        let (sp, acs) = (self.saml_entity_id(&instance.primary_domain), self.saml_acs_url(&instance.primary_domain));
        self.saml_sp_key(instance).await?;
        let keys: Vec<crate::saml::SpKey> =
            self.saml_sp_keys(instance.id).await?.into_iter().map(|(_, key)| key).collect();
        let expected = crate::saml::Expected {
            idp_entity_id: &info.settings.issuer,
            certificates: &certificates,
            sp_entity_id: &sp,
            acs_url: &acs,
            request_id: request,
            now: Utc::now(),
            decryption_keys: &keys,
        };
        let verified = crate::saml::verify_response(response, expected).map_err(|error| {
            tracing::warn!(idp = %login.idp, %error, "SAML response refused");
            refused("The identity provider's answer was not accepted.")
        })?;
        // The provider is the tenant's own: an address it asserts on a verified domain of the tenant counts as verified.
        let email = verified.email(saml.email_attribute.as_deref()).map(str::to_owned);
        let name = verified.name(saml.name_attribute.as_deref()).map(str::to_owned);
        let found = self
            .resolve_account(
                &info,
                &verified.subject,
                email.as_deref(),
                name.as_deref(),
                verified.multi_factor,
                login.link_account,
            )
            .await?;
        let subject = SamlSubject {
            name_id: verified.subject,
            format: verified.name_id_format,
            session_index: verified.session_index,
        };
        Ok((found, subject))
    }

    /// Exchanges the code, verifies the ID token and finds – or links, or creates – the account.
    async fn complete_oidc_login(
        &self,
        instance: &InstanceInfo,
        idp: Uuid,
        code: &str,
        verifier: &str,
        nonce: &str,
        link_account: Option<Uuid>,
    ) -> Result<Resolved> {
        let info = self.identity_provider(idp).await?;
        if !info.active {
            return Err(refused("The identity provider is switched off."));
        }
        let secret = self.idp_secret(idp).await?;
        let unreachable = |e: external::ExternalError| {
            tracing::warn!(%idp, error = %e, "identity provider");
            refused("The identity provider could not be reached or answered unexpectedly.")
        };
        let metadata =
            external::discover(&self.outbound, &info.settings.issuer, self.allow_private).await.map_err(unreachable)?;
        let tokens = external::exchange_code(
            &self.outbound,
            &metadata,
            code,
            &self.idp_redirect_uri(&instance.primary_domain),
            verifier,
            &info.settings.client_id,
            secret.as_ref().map(|secret| secret.as_str()),
            self.allow_private,
        )
        .await
        .map_err(unreachable)?;
        let keys = external::keys(&self.outbound, &metadata, self.allow_private).await.map_err(unreachable)?;
        let expected = Expected {
            issuer: &metadata.issuer,
            client_id: &info.settings.client_id,
            nonce,
            now: Utc::now().timestamp(),
        };
        let claims = external::verify_id_token(&tokens.id_token, &keys, expected).map_err(unreachable)?;
        let subject = claims["sub"].as_str().unwrap_or_default().to_owned();
        let multi_factor = claims["amr"].as_array().is_some_and(|amr| amr.iter().any(|method| method == "mfa"));
        // Linking and creating need an email address the provider vouches for.
        let email = claims["email"].as_str().filter(|_| claims["email_verified"].as_bool() == Some(true));
        let name = claims["name"].as_str();
        self.resolve_account(&info, &subject, email, name, multi_factor, link_account).await
    }

    /// The account of an external identity: the linked one; for a login from an account's page, that account, linked
    /// now; or – if the provider allows it and `email` is on a verified domain it serves (the tenant's, or any
    /// tenant's of the instance for an instance-wide provider) – an existing one linked now, or a new one in that
    /// tenant. Otherwise an account with the provider's verified address is proposed for linking, and a provider
    /// open for registration creates an external account (RFC 0003, 3 and 5). With `sync_profile`, the display name
    /// follows the provider's at every login.
    async fn resolve_account(
        &self,
        info: &IdpInfo,
        subject: &str,
        email: Option<&str>,
        name: Option<&str>,
        multi_factor: bool,
        link_account: Option<Uuid>,
    ) -> Result<Resolved> {
        let mut checks = vec![kernoid_identity::session::CHECK_IDP.to_owned()];
        if multi_factor {
            checks.push(kernoid_identity::session::CHECK_IDP_MFA.to_owned());
        }
        let creator = format!("identity_provider:{}", info.id);
        let name = name.map(str::trim).filter(|name| !name.is_empty());
        let linked = self.identity.account_by_link(info.id, subject).await?;
        if let Some(target) = link_account {
            return match linked {
                Some(account) if account.id != target => {
                    Err(refused("This login is linked to another account already."))
                }
                Some(_) => Ok(Resolved::Account(target, checks)),
                None => {
                    self.identity.link_account(target, info.id, subject, &format!("account:{target}")).await?;
                    Ok(Resolved::Account(target, checks))
                }
            };
        }
        if let Some(account) = linked {
            if account.instance != info.instance || info.tenant.is_some_and(|tenant| tenant != account.tenant) {
                return Err(refused("The login could not be completed."));
            }
            if info.settings.sync_profile
                && let Some(name) = name
                && name != account.display_name
                && self.identity.rename_account(account.id, name, &creator).await.is_err()
            {
                tracing::warn!(idp = %info.id, account = %account.id, "the display name from the provider is not usable");
            }
            return Ok(Resolved::Account(account.id, checks));
        }
        let address = email.and_then(|email| Address::parse(email).ok());
        let target = match &address {
            Some(address) => self.identity.tenant_by_domain(&address.domain()).await?.filter(|holder| {
                holder.instance == info.instance && info.tenant.is_none_or(|tenant| tenant == holder.id)
            }),
            None => None,
        };
        if let (Some(address), Some(target)) = (&address, target) {
            if info.settings.auto_link
                && let Some(account) = self.identity.account_by_address(address).await?
                && account.tenant == target.id
            {
                self.identity.link_account(account.id, info.id, subject, &creator).await?;
                return Ok(Resolved::Account(account.id, checks));
            }
            if info.settings.auto_create && self.identity.account_by_address(address).await?.is_none() {
                let name = name.unwrap_or(address.as_str());
                let account = self.identity.add_account(target.id, address, name, &creator).await?;
                self.identity.link_account(account, info.id, subject, &creator).await?;
                return Ok(Resolved::Account(account, checks));
            }
        }
        // An account of the instance with this verified address: proposed, never linked unasked.
        if let Some(address) = &address
            && let Some(existing) = self.identity.contact_holder(info.instance, address.as_str()).await?
        {
            return Ok(Resolved::Proposal {
                existing,
                subject: subject.to_owned(),
                email: address.as_str().to_owned(),
                name: name.map(str::to_owned),
                checks,
            });
        }
        if let Some(tenant) = self.registration_tenant(info).await? {
            let name = name.or(address.as_ref().map(Address::as_str)).unwrap_or("New account");
            let email = address.as_ref().map(|address| (address.as_str(), true));
            let account = self.identity.add_external_account(tenant, name, email, &creator).await?;
            self.identity.link_account(account, info.id, subject, &creator).await?;
            return Ok(Resolved::Account(account, checks));
        }
        Err(refused("There is no kernoid account for this login. Ask your administrator."))
    }

    /// Where a provider open for registration creates accounts: its tenant, or – for a provider of the whole instance
    /// – the instance's registration tenant; only if that tenant allows registration.
    async fn registration_tenant(&self, info: &IdpInfo) -> Result<Option<Uuid>> {
        if !info.settings.register {
            return Ok(None);
        }
        let tenant = match info.tenant {
            Some(tenant) => Some(tenant),
            None => self.identity.instance(info.instance).await?.state.registration_tenant,
        };
        let Some(tenant) = tenant else { return Ok(None) };
        let state = self.identity.tenant(info.instance, tenant).await?.state;
        Ok((state.active && state.registration.allowed).then_some(tenant))
    }

    /// The proposal behind a one-time code from `/idp#link=…` – without using the code up.
    pub async fn link_proposal(&self, instance: Uuid, handoff: &str) -> Result<LinkProposal> {
        let (row, info) = self.proposal(instance, handoff).await?;
        Ok(LinkProposal {
            email: row.email,
            provider: info.settings.name.clone(),
            may_register: self.registration_tenant(&info).await?.is_some(),
        })
    }

    /// Links the provider login of a proposal to the account the person proved to be theirs by logging in to it
    /// (the session of `token`, which must be that account's).
    pub async fn confirm_link(&self, instance: Uuid, handoff: &str, token: &str) -> Result<()> {
        let (row, info) = self.proposal(instance, handoff).await?;
        let session = self.identity.session(instance, token).await?;
        if session.account.id != row.existing {
            return Err(refused("Log in to the account with this address to link it."));
        }
        self.use_proposal(row.id).await?;
        self.identity.link_account(row.existing, info.id, &row.subject, &format!("account:{}", row.existing)).await?;
        Ok(())
    }

    /// Creates a separate account for the provider login of a proposal instead of linking it – where registration is
    /// open – and logs it in. Its contact address stays the other account's.
    pub async fn register_instead(
        &self,
        instance: Uuid,
        handoff: &str,
        lifetime: Option<Duration>,
        client: &ClientMeta,
    ) -> Result<IdpLoginResult> {
        let (row, info) = self.proposal(instance, handoff).await?;
        let tenant =
            self.registration_tenant(&info).await?.ok_or_else(|| refused("Registering is not possible here."))?;
        self.use_proposal(row.id).await?;
        let creator = format!("identity_provider:{}", info.id);
        let name = row.display_name.as_deref().unwrap_or(&row.email);
        let account = self.identity.add_external_account(tenant, name, None, &creator).await?;
        self.identity.link_account(account, info.id, &row.subject, &creator).await?;
        let multi_factor = row.checks.iter().any(|check| check == kernoid_identity::session::CHECK_IDP_MFA);
        let session = self.identity.create_external_session(instance, account, multi_factor, lifetime, client).await?;
        Ok(IdpLoginResult { session, auth_request: row.auth_request })
    }

    async fn proposal(&self, instance: Uuid, handoff: &str) -> Result<(ProposalRow, IdpInfo)> {
        let invalid = || OidcError::Identity(IdentityError::InvalidSession);
        let (id, code) = handoff.split_once('.').ok_or_else(invalid)?;
        let id = Uuid::parse_str(id).map_err(|_| invalid())?;
        let row = sqlx::query!(
            r#"SELECT idp_id, proposal_account AS "existing!", subject AS "subject!", email AS "email!", display_name,
                      checks, auth_request_id
               FROM idp_logins
               WHERE id = $1 AND instance_id = $2 AND handoff_hash = $3 AND used_at IS NULL AND expires_at > now()
                 AND proposal_account IS NOT NULL"#,
            id,
            instance,
            &sha256(code)[..],
        )
        .fetch_optional(self.pool())
        .await
        .map_err(internal)?
        .ok_or_else(invalid)?;
        let info = self.identity_provider(row.idp_id).await?;
        Ok((
            ProposalRow {
                id,
                existing: row.existing,
                subject: row.subject,
                email: row.email,
                display_name: row.display_name,
                checks: row.checks.unwrap_or_default(),
                auth_request: row.auth_request_id,
            },
            info,
        ))
    }

    async fn use_proposal(&self, id: Uuid) -> Result<()> {
        let used = sqlx::query!("UPDATE idp_logins SET used_at = now() WHERE id = $1 AND used_at IS NULL", id)
            .execute(self.pool())
            .await
            .map_err(internal)?;
        if used.rows_affected() == 1 { Ok(()) } else { Err(OidcError::Identity(IdentityError::InvalidSession)) }
    }

    /// The providers the token's account may link (RFC 0003, 3): the active ones of its tenant and of the whole
    /// instance.
    pub async fn linkable_providers(&self, instance: Uuid, token: &str) -> Result<Vec<IdpSummary>> {
        let session = self.identity.session(instance, token).await?;
        Ok(sqlx::query!(
            "SELECT id, name FROM identity_providers
             WHERE instance_id = $1 AND active AND (tenant_id IS NULL OR tenant_id = $2) ORDER BY name",
            instance,
            session.account.tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?
        .into_iter()
        .map(|row| IdpSummary { id: row.id, name: row.name })
        .collect())
    }

    /// The external identities linked to the token's account, with their providers' names.
    pub async fn own_links(&self, instance: Uuid, token: &str) -> Result<Vec<(LinkInfo, String)>> {
        let session = self.identity.session(instance, token).await?;
        Ok(sqlx::query!(
            "SELECT l.idp_id, l.subject, l.created_at, p.name FROM account_links l
             JOIN identity_providers p ON p.id = l.idp_id
             WHERE l.account_id = $1 ORDER BY l.created_at",
            session.account.id,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?
        .into_iter()
        .map(|row| (LinkInfo { idp: row.idp_id, subject: row.subject, created_at: row.created_at }, row.name))
        .collect())
    }

    /// The providers offered to everyone on the instance's login page.
    pub async fn open_providers(&self, instance: Uuid) -> Result<Vec<IdpSummary>> {
        Ok(sqlx::query!(
            "SELECT id, name FROM identity_providers WHERE instance_id = $1 AND active AND register ORDER BY name",
            instance,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?
        .into_iter()
        .map(|row| IdpSummary { id: row.id, name: row.name })
        .collect())
    }

    async fn idp_secret(&self, idp: Uuid) -> Result<Option<zeroize::Zeroizing<String>>> {
        let sealed = sqlx::query_scalar!("SELECT sealed FROM identity_provider_secrets WHERE idp_id = $1", idp)
            .fetch_optional(self.pool())
            .await
            .map_err(internal)?;
        match sealed {
            Some(sealed) => {
                let (secret, _) = self.main.open_secret(&secret_context(idp), &sealed).map_err(internal)?;
                let text = String::from_utf8(secret.to_vec()).map_err(internal)?;
                Ok(Some(zeroize::Zeroizing::new(text)))
            }
            None => Ok(None),
        }
    }

    /// Exchanges the one-time code from `/idp/callback` (`<login id>.<code>`) for a session – once.
    pub async fn exchange_idp_login(
        &self,
        instance: Uuid,
        handoff: &str,
        lifetime: Option<Duration>,
        client: &ClientMeta,
    ) -> Result<IdpLoginResult> {
        let invalid = || OidcError::Identity(IdentityError::InvalidSession);
        let (id, code) = handoff.split_once('.').ok_or_else(invalid)?;
        let id = Uuid::parse_str(id).map_err(|_| invalid())?;
        let row = sqlx::query!(
            "UPDATE idp_logins SET used_at = now()
             WHERE id = $1 AND instance_id = $2 AND handoff_hash = $3 AND used_at IS NULL AND expires_at > now()
                 AND account_id IS NOT NULL
             RETURNING account_id, checks, auth_request_id, idp_id, saml_name_id, saml_name_id_format,
                       saml_session_index",
            id,
            instance,
            &sha256(code)[..],
        )
        .fetch_optional(self.pool())
        .await
        .map_err(internal)?
        .ok_or_else(invalid)?;
        let account = row.account_id.ok_or_else(invalid)?;
        let multi_factor =
            row.checks.unwrap_or_default().iter().any(|check| check == kernoid_identity::session::CHECK_IDP_MFA);
        let session = self.identity.create_external_session(instance, account, multi_factor, lifetime, client).await?;
        if let Some(name_id) = row.saml_name_id {
            sqlx::query!(
                "INSERT INTO idp_sessions (session_id, idp_id, name_id, name_id_format, session_index)
                 VALUES ($1, $2, $3, $4, $5)",
                session.id,
                row.idp_id,
                name_id,
                row.saml_name_id_format,
                row.saml_session_index,
            )
            .execute(self.pool())
            .await
            .map_err(internal)?;
        }
        Ok(IdpLoginResult { session, auth_request: row.auth_request_id })
    }

    // Single logout (SAML)

    /// Logs out the session of `token`. If it came from a SAML provider with single logout, the answer is where to
    /// send the browser – the provider, with kernoid's signed LogoutRequest – so that the person is logged out there,
    /// too.
    pub async fn logout(&self, instance: &InstanceInfo, token: &str) -> Result<Option<String>> {
        let session = self.identity.session(instance.id, token).await?;
        let saml = self.saml_session(session.id).await?;
        self.identity.terminate_session(instance.id, token).await?;
        let Some(saml) = saml else { return Ok(None) };
        self.saml_logout_url(instance, saml, None).await
    }

    /// The SAML login a session came from, if any – read before the session ends.
    pub(crate) async fn saml_session(&self, session: Uuid) -> Result<Option<SamlSession>> {
        sqlx::query_as!(
            SamlSession,
            "SELECT idp_id, name_id, name_id_format, session_index FROM idp_sessions WHERE session_id = $1",
            session,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(internal)
    }

    /// Where to send the browser so that the person logs out at the SAML provider of an ended session, too: the
    /// provider's single logout service with kernoid's signed LogoutRequest – if the provider has one and is on.
    /// Once it answers, the browser goes on to `return_to`, else to the login UI.
    pub(crate) async fn saml_logout_url(
        &self,
        instance: &InstanceInfo,
        saml: SamlSession,
        return_to: Option<&str>,
    ) -> Result<Option<String>> {
        let info = self.identity_provider(saml.idp_id).await?;
        let Some(slo_url) = info.settings.saml.as_ref().and_then(|settings| settings.slo_url.clone()) else {
            return Ok(None);
        };
        if !info.active {
            return Ok(None);
        }
        let key = self.saml_sp_key(instance).await?;
        let request_id = random_secret("_")?;
        sqlx::query!(
            "INSERT INTO saml_logouts (request_id, instance_id, idp_id, expires_at, return_to)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5)",
            request_id,
            instance.id,
            info.id,
            LOGIN_LIFETIME.as_secs() as f64,
            return_to,
        )
        .execute(self.pool())
        .await
        .map_err(internal)?;
        let sp = self.saml_entity_id(&instance.primary_domain);
        let request = crate::saml::LogoutRequestOut {
            slo_url: &slo_url,
            request_id: &request_id,
            sp_entity_id: &sp,
            name_id: &saml.name_id,
            name_id_format: saml.name_id_format.as_deref(),
            session_index: saml.session_index.as_deref(),
            relay_state: "logout",
            now: Utc::now(),
        };
        crate::saml::logout_request_url(&request, &key).map(Some).map_err(|e| refused(e.to_string()))
    }

    /// kernoid's single logout service at `/idp/saml/slo` in the HTTP-Redirect binding, given the raw query; see
    /// [`Oidc::saml_slo_message`].
    pub async fn saml_slo(&self, instance: &InstanceInfo, raw_query: &str) -> Result<Option<String>> {
        let message = crate::saml::read_redirect(raw_query).map_err(|e| refused(e.to_string()))?;
        self.saml_slo_message(instance, message).await
    }

    /// kernoid's single logout service, for a message in either binding:
    /// - a provider's **LogoutRequest** – signed, or refused – ends the sessions of that NameID (and SessionIndex),
    ///   and kernoid answers with its signed LogoutResponse (HTTP-Redirect binding);
    /// - a provider's **LogoutResponse** to kernoid's request sends the browser on: to the application that asked to
    ///   log out (OpenID Connect), else to the login UI.
    ///
    /// Returns where to send the browser, or – with no address to answer – `None`.
    pub async fn saml_slo_message(
        &self,
        instance: &InstanceInfo,
        message: crate::saml::SloMessage,
    ) -> Result<Option<String>> {
        let slo_here = self.saml_slo_url(&instance.primary_domain);
        if !message.request {
            let (in_response_to, issuer, _) =
                crate::saml::read_logout_response(&message.xml).map_err(|e| refused(e.to_string()))?;
            let logout = sqlx::query!(
                "DELETE FROM saml_logouts WHERE request_id = $1 AND instance_id = $2 AND expires_at > now()
                 RETURNING idp_id, return_to",
                in_response_to,
                instance.id,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(internal)?
            .ok_or_else(|| refused("this logout is unknown or has expired"))?;
            let info = self.identity_provider(logout.idp_id).await?;
            if info.settings.issuer != issuer {
                return Err(refused("the logout response comes from another provider"));
            }
            return Ok(Some(logout.return_to.unwrap_or_else(|| format!("{}/account", self.login_url(instance)))));
        }
        let request = crate::saml::read_logout_request(&message.xml, &slo_here, Utc::now())
            .map_err(|e| refused(e.to_string()))?;
        let candidates = sqlx::query_scalar!(
            "SELECT id FROM identity_providers
             WHERE instance_id = $1 AND kind = 'saml' AND issuer = $2 AND active ORDER BY id",
            instance.id,
            request.issuer,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        let mut provider = None;
        for id in candidates {
            let info = self.identity_provider(id).await?;
            let certificates: Vec<Vec<u8>> = info
                .settings
                .saml
                .iter()
                .flat_map(|saml| saml.certificates.iter())
                .filter_map(|certificate| crate::saml::certificate(certificate).ok())
                .collect();
            if message.verify(&certificates).is_ok() {
                provider = Some(info);
                break;
            }
        }
        let info = provider.ok_or_else(|| refused("the logout request is not signed by a known provider"))?;
        let sessions = sqlx::query_scalar!(
            "SELECT session_id FROM idp_sessions
             WHERE idp_id = $1 AND name_id = $2 AND (cardinality($3::text[]) = 0 OR session_index = ANY ($3))",
            info.id,
            request.name_id,
            &request.session_indexes,
        )
        .fetch_all(self.pool())
        .await
        .map_err(internal)?;
        let creator = format!("identity_provider:{}", info.id);
        for session in sessions {
            match self.identity.terminate_session_by_id(instance.id, session, &creator).await {
                // Ended already: nothing to do.
                Ok(()) | Err(IdentityError::NotFound(_) | IdentityError::InvalidSession) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let Some(slo_url) = info.settings.saml.as_ref().and_then(|saml| saml.slo_url.clone()) else { return Ok(None) };
        let key = self.saml_sp_key(instance).await?;
        let sp = self.saml_entity_id(&instance.primary_domain);
        let response = crate::saml::logout_response_url(
            &slo_url,
            &random_secret("_")?,
            &request.id,
            &sp,
            message.relay_state.as_deref(),
            Utc::now(),
            &key,
        )
        .map_err(|e| refused(e.to_string()))?;
        Ok(Some(response))
    }

    // Administration

    /// A provider the administrator may see: one of the tenant, or one of its instance.
    async fn visible_idp(&self, admin: &Admin, idp: Uuid) -> Result<IdpInfo> {
        match self.identity_provider(idp).await {
            Ok(info) if info.tenant == Some(admin.tenant()) => Ok(info),
            Ok(info) if info.tenant.is_none() && info.instance == admin.instance() => Ok(info),
            Ok(_) => Err(IdentityError::NotFound("the identity provider").into()),
            Err(error) => Err(error),
        }
    }

    /// The owner of a provider the administrator may change: the tenant's own needs `identity_providers.manage`, the
    /// instance's `instance.manage`.
    async fn managed_idp(&self, admin: &Admin, idp: Uuid) -> Result<IdpOwner> {
        let info = self.visible_idp(admin, idp).await?;
        let owner = info.owner();
        admin.require(match owner {
            IdpOwner::Tenant(_) => Permission::IdentityProvidersManage,
            IdpOwner::Instance(_) => Permission::InstanceManage,
        })?;
        Ok(owner)
    }

    /// The instance an administrator administers.
    async fn admin_instance(&self, admin: &Admin) -> Result<InstanceInfo> {
        let instances = self.identity.instances().await?;
        instances
            .into_iter()
            .find(|instance| instance.id == admin.instance())
            .ok_or_else(|| IdentityError::NotFound("the instance").into())
    }

    pub async fn admin_saml_keys(&self, admin: &Admin) -> Result<Vec<SamlKeyInfo>> {
        admin.require(Permission::InstanceRead)?;
        self.saml_keys(admin.instance()).await
    }

    pub async fn admin_add_saml_key(&self, admin: &Admin) -> Result<Uuid> {
        admin.require(Permission::InstanceManage)?;
        self.add_saml_key(&self.admin_instance(admin).await?).await
    }

    pub async fn admin_activate_saml_key(&self, admin: &Admin, key: Uuid) -> Result<()> {
        admin.require(Permission::InstanceManage)?;
        self.activate_saml_key(admin.instance(), key).await
    }

    pub async fn admin_identity_providers(&self, admin: &Admin) -> Result<Vec<IdpInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.identity_providers(admin.tenant()).await
    }

    pub async fn admin_identity_provider(&self, admin: &Admin, idp: Uuid) -> Result<IdpInfo> {
        admin.require(Permission::DirectoryRead)?;
        self.visible_idp(admin, idp).await
    }

    /// Connects a provider to the administered tenant – or, with `instance_wide` (needs `instance.manage`), to the
    /// whole instance.
    pub async fn admin_add_identity_provider(
        &self,
        admin: &Admin,
        settings: &IdpSettings,
        client_secret: Option<&str>,
        instance_wide: bool,
    ) -> Result<Uuid> {
        let owner = if instance_wide {
            admin.require(Permission::InstanceManage)?;
            IdpOwner::Instance(admin.instance())
        } else {
            admin.require(Permission::IdentityProvidersManage)?;
            IdpOwner::Tenant(admin.tenant())
        };
        self.add_identity_provider(owner, settings, client_secret, &admin.creator()).await
    }

    pub async fn admin_update_identity_provider(&self, admin: &Admin, idp: Uuid, settings: &IdpSettings) -> Result<()> {
        let owner = self.managed_idp(admin, idp).await?;
        self.update_identity_provider(owner, idp, settings, &admin.creator()).await
    }

    pub async fn admin_set_identity_provider_secret(
        &self,
        admin: &Admin,
        idp: Uuid,
        secret: Option<&str>,
    ) -> Result<()> {
        let owner = self.managed_idp(admin, idp).await?;
        self.set_identity_provider_secret(owner, idp, secret, &admin.creator()).await
    }

    pub async fn admin_set_identity_provider_active(&self, admin: &Admin, idp: Uuid, active: bool) -> Result<()> {
        let owner = self.managed_idp(admin, idp).await?;
        self.set_identity_provider_active(owner, idp, active, &admin.creator()).await
    }

    pub async fn admin_remove_identity_provider(&self, admin: &Admin, idp: Uuid) -> Result<()> {
        let owner = self.managed_idp(admin, idp).await?;
        self.remove_identity_provider(owner, idp, &admin.creator()).await
    }

    pub async fn admin_check_identity_provider(&self, admin: &Admin, idp: Uuid) -> Result<()> {
        let owner = self.managed_idp(admin, idp).await?;
        self.check_identity_provider(owner, idp).await
    }
}

impl IdpInfo {
    pub fn owner(&self) -> IdpOwner {
        match self.tenant {
            Some(tenant) => IdpOwner::Tenant(tenant),
            None => IdpOwner::Instance(self.instance),
        }
    }
}
