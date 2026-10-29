// SPDX-License-Identifier: AGPL-3.0-or-later
//! The administration API in GraphQL – the same operations and permission checks as the REST routes in
//! `crate::admin`. The `kernoid-tenant` header names the tenant an instance administrator acts on.

use async_graphql::{Context, Json, Object, SimpleObject};
use chrono::{DateTime, Utc};
use kernoid_identity::{
    Address, CHALLENGE_LABEL, DomainName, Identity, IdentityError,
    account::AccountInfo,
    admin::TenantPolicy,
    audit::{AuditEntry, AuditQuery},
    consent::ConsentInfo,
    group::GroupInfo,
    project::ProjectInfo,
    role::{Admin, Principal, Role},
    session::SessionSummary,
};
use kernoid_oidc::{
    Oidc,
    application::{AppOptions, ApplicationInfo, TokenFormat},
    keys::KeyInfo,
};
use uuid::Uuid;

use super::{error, instance, oidc_error, token};
use crate::{AppState, admin::applications::kind};

/// The tenant a request names in the `kernoid-tenant` header, if any.
pub(super) struct TargetTenant(pub Result<Option<Uuid>, IdentityError>);

/// The administrator behind the bearer token, for the tenant the request names.
pub(super) async fn admin<'a>(context: &'a Context<'_>) -> async_graphql::Result<(&'a Identity, Admin)> {
    let identity = context.data::<Identity>()?;
    let tenant = match context.data_opt::<TargetTenant>() {
        Some(TargetTenant(Ok(tenant))) => *tenant,
        Some(TargetTenant(Err(_))) => return Err(error(IdentityError::NotFound("the tenant"))),
        None => None,
    };
    let admin = identity.admin(instance(context)?.id, token(context)?, tenant).await.map_err(error)?;
    Ok((identity, admin))
}

pub(super) fn uuid(value: &str, what: &'static str) -> async_graphql::Result<Uuid> {
    Uuid::parse_str(value).map_err(|_| error(IdentityError::NotFound(what)))
}

pub(super) fn principal(kind: &str, id: &str) -> async_graphql::Result<Principal> {
    Principal::new(kind, uuid(id, "the principal")?).map_err(error)
}

fn role(name: &str) -> async_graphql::Result<Role> {
    Role::parse(name).map_err(error)
}

fn domain(value: &str) -> async_graphql::Result<DomainName> {
    DomainName::parse(value).map_err(|e| error(IdentityError::Refused(e.to_string())))
}

pub(super) fn address(value: &str) -> async_graphql::Result<Address> {
    Address::parse(value).map_err(|e| error(IdentityError::Refused(e.to_string())))
}

/// A DNS record a mail domain needs.
#[derive(Debug, SimpleObject)]
pub struct RecordCheck {
    /// `MX`, `SPF`, `DKIM` or `DMARC`.
    kind: String,
    name: String,
    /// `MX` or `TXT`.
    record_type: String,
    expected: String,
    found: Vec<String>,
    /// `ok`, `missing` or `different`.
    status: String,
}

#[derive(Debug, SimpleObject)]
pub struct MailDns {
    domain: String,
    records: Vec<RecordCheck>,
}

#[derive(Debug, SimpleObject)]
pub struct TenantDomain {
    domain: String,
    verified: bool,
    /// For a domain not verified yet: the TXT record to publish.
    record_name: Option<String>,
    record_value: Option<String>,
}

#[derive(Debug, SimpleObject)]
pub struct Tenant {
    id: String,
    instance: String,
    name: String,
    active: bool,
    mfa_required: bool,
    mfa_grace_days: u32,
    domains: Vec<TenantDomain>,
    modules: Vec<String>,
}

#[derive(Debug, SimpleObject)]
pub struct TenantModule {
    name: String,
    /// Whether the tenant uses it.
    enabled: bool,
}

fn domain_object(domain: String, verified: bool, token: Option<&str>) -> TenantDomain {
    TenantDomain {
        record_name: token.map(|_| format!("{CHALLENGE_LABEL}.{domain}")),
        record_value: token.map(|token| format!("kernoid-verification={token}")),
        domain,
        verified,
    }
}

impl From<TenantPolicy> for Tenant {
    fn from(policy: TenantPolicy) -> Self {
        Self {
            id: policy.tenant.id.to_string(),
            instance: policy.tenant.instance.to_string(),
            name: policy.tenant.name,
            active: policy.tenant.active,
            mfa_required: policy.mfa_required,
            mfa_grace_days: policy.mfa_grace_days,
            domains: policy
                .domains
                .into_iter()
                .map(|claim| domain_object(claim.domain, claim.verified, claim.token.as_deref()))
                .collect(),
            modules: policy.modules,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct Permissions {
    account: String,
    tenant: String,
    permissions: Vec<String>,
}

/// An address of an account.
#[derive(Debug, SimpleObject)]
pub struct AccountAddress {
    address: String,
    /// The primary address – the login name; the others are aliases.
    primary: bool,
}

/// An event of the audit log.
#[derive(Debug, SimpleObject)]
pub struct AuditEntryObject {
    position: i64,
    aggregate_type: String,
    aggregate_id: String,
    sequence: i64,
    event_type: String,
    payload: Json<serde_json::Value>,
    /// An account id, `system`, `operator` or a service.
    creator: String,
    created_at: DateTime<Utc>,
}

impl From<AuditEntry> for AuditEntryObject {
    fn from(entry: AuditEntry) -> Self {
        Self {
            position: entry.position,
            aggregate_type: entry.aggregate_type,
            aggregate_id: entry.aggregate_id,
            sequence: entry.sequence,
            event_type: entry.event_type,
            payload: Json(entry.payload),
            creator: entry.creator,
            created_at: entry.created_at,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct AccountDetails {
    id: String,
    tenant: String,
    address: String,
    display_name: String,
    active: bool,
    /// A shared mailbox: nobody logs in as it.
    shared: bool,
    /// A drive: a file store of the tenant; nobody logs in as it.
    drive: bool,
}

impl From<AccountInfo> for AccountDetails {
    fn from(account: AccountInfo) -> Self {
        Self {
            id: account.id.to_string(),
            tenant: account.tenant.to_string(),
            address: account.address,
            display_name: account.display_name,
            active: account.active,
            shared: account.shared,
            drive: account.drive,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct SessionSummaryObject {
    id: String,
    checks: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    client_address: Option<String>,
    user_agent: Option<String>,
}

impl From<SessionSummary> for SessionSummaryObject {
    fn from(session: SessionSummary) -> Self {
        Self {
            id: session.id.to_string(),
            checks: session.checks,
            created_at: session.created_at,
            expires_at: session.expires_at,
            client_address: session.client_address,
            user_agent: session.user_agent,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct Group {
    id: String,
    name: String,
    /// Account ids.
    members: Vec<String>,
    /// Addresses mail to the group arrives at; it goes to every member.
    addresses: Vec<String>,
    /// The members may send from these addresses.
    members_send_as: bool,
}

impl From<GroupInfo> for Group {
    fn from(group: GroupInfo) -> Self {
        Self {
            id: group.id.to_string(),
            name: group.name,
            members: group.members.iter().map(Uuid::to_string).collect(),
            addresses: group.addresses,
            members_send_as: group.members_send_as,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct RoleInfo {
    name: String,
    permissions: Vec<String>,
    builtin: bool,
}

#[derive(Debug, SimpleObject)]
pub struct RoleAssignment {
    role: String,
    /// `account` or `group`.
    principal_kind: String,
    principal_id: String,
}

fn assignment(principal: Principal, role: impl ToString) -> RoleAssignment {
    RoleAssignment {
        role: role.to_string(),
        principal_kind: principal.kind().into(),
        principal_id: principal.id().to_string(),
    }
}

#[derive(Debug, SimpleObject)]
pub struct Roles {
    roles: Vec<RoleInfo>,
    assignments: Vec<RoleAssignment>,
}

#[derive(Debug, SimpleObject)]
pub struct ProjectRole {
    key: String,
    display_name: String,
    group: Option<String>,
}

#[derive(Debug, SimpleObject)]
pub struct Project {
    id: String,
    name: String,
    role_assertion: bool,
    role_check: bool,
    roles: Vec<ProjectRole>,
}

impl From<ProjectInfo> for Project {
    fn from(project: ProjectInfo) -> Self {
        Self {
            id: project.id.to_string(),
            name: project.name,
            role_assertion: project.role_assertion,
            role_check: project.role_check,
            roles: project
                .roles
                .into_iter()
                .map(|role| ProjectRole { key: role.key, display_name: role.display_name, group: role.group })
                .collect(),
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct ProjectAuthorization {
    role: String,
    /// The tenant that gave it.
    tenant: String,
    principal_kind: String,
    principal_id: String,
}

#[derive(Debug, SimpleObject)]
pub struct ProjectGrant {
    project: String,
    project_name: String,
    owner: String,
    tenant: String,
    tenant_name: String,
    roles: Vec<String>,
}

impl From<kernoid_identity::project::ProjectGrant> for ProjectGrant {
    fn from(grant: kernoid_identity::project::ProjectGrant) -> Self {
        Self {
            project: grant.project.to_string(),
            project_name: grant.project_name,
            owner: grant.owner.to_string(),
            tenant: grant.tenant.to_string(),
            tenant_name: grant.tenant_name,
            roles: grant.roles,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct Application {
    id: String,
    name: String,
    /// `confidential` or `public`.
    kind: String,
    project: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    mfa_required: bool,
    active: bool,
    options: ApplicationOptions,
}

/// What an application may do beyond the basic flow, and how it learns of logouts.
#[derive(Debug, SimpleObject)]
pub struct ApplicationOptions {
    /// `opaque` or `jwt` (RFC 9068).
    access_token_format: String,
    /// May ask for `offline_access`, with the person's consent.
    offline_access: bool,
    /// Asks the person to agree before the first login.
    consent_required: bool,
    backchannel_logout_uri: Option<String>,
    frontchannel_logout_uri: Option<String>,
}

impl From<AppOptions> for ApplicationOptions {
    fn from(options: AppOptions) -> Self {
        Self {
            access_token_format: options.access_token_format.as_str().into(),
            offline_access: options.offline_access,
            consent_required: options.consent_required,
            backchannel_logout_uri: options.backchannel_logout_uri,
            frontchannel_logout_uri: options.frontchannel_logout_uri,
        }
    }
}

/// What an account agreed an application may have.
#[derive(Debug, SimpleObject)]
pub struct Consent {
    application: String,
    application_name: String,
    scopes: Vec<String>,
    granted_at: DateTime<Utc>,
}

impl From<ConsentInfo> for Consent {
    fn from(info: ConsentInfo) -> Self {
        Self {
            application: info.application.to_string(),
            application_name: info.application_name,
            scopes: info.scopes,
            granted_at: info.granted_at,
        }
    }
}

impl From<ApplicationInfo> for Application {
    fn from(application: ApplicationInfo) -> Self {
        Self {
            id: application.id.to_string(),
            name: application.name,
            kind: application.kind.as_str().into(),
            project: application.project.map(|project| project.to_string()),
            redirect_uris: application.redirect_uris,
            post_logout_redirect_uris: application.post_logout_redirect_uris,
            mfa_required: application.mfa_required,
            active: application.active,
            options: application.options.into(),
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct ApplicationCreated {
    id: String,
    /// For a confidential application: its secret, shown this once.
    client_secret: Option<String>,
}

#[derive(Debug, SimpleObject)]
pub struct InstanceDetails {
    id: String,
    name: String,
    primary_domain: String,
    domains: Vec<String>,
    /// The instance's own login UI; without one, kernoid's at `/login`.
    login_ui_url: Option<String>,
    /// The WebAuthn RP ID its passkeys are bound to.
    passkey_rp_id: String,
}

#[derive(Debug, SimpleObject)]
pub struct TenantSummary {
    id: String,
    name: String,
    active: bool,
}

#[derive(Debug, SimpleObject)]
pub struct InstanceRole {
    name: String,
    permissions: Vec<String>,
    tenant_permissions: Vec<String>,
    builtin: bool,
}

#[derive(Debug, SimpleObject)]
pub struct InstanceRoles {
    roles: Vec<InstanceRole>,
    assignments: Vec<RoleAssignment>,
}

#[derive(Debug, SimpleObject)]
pub struct SigningKey {
    kid: String,
    algorithm: String,
    state: String,
    created_at: DateTime<Utc>,
    state_since: DateTime<Utc>,
}

impl From<KeyInfo> for SigningKey {
    fn from(key: KeyInfo) -> Self {
        Self {
            kid: key.kid,
            algorithm: key.algorithm,
            state: key.state.as_str().into(),
            created_at: key.created_at,
            state_since: key.state_since,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct SamlKey {
    id: String,
    /// `next` (in the metadata, not signing yet), `active` (signing) or `retired` (only decrypting).
    state: String,
    created_at: DateTime<Utc>,
    state_since: DateTime<Utc>,
    /// SHA-256 of the certificate, in hex.
    fingerprint: String,
}

impl From<kernoid_oidc::federation::SamlKeyInfo> for SamlKey {
    fn from(key: kernoid_oidc::federation::SamlKeyInfo) -> Self {
        Self {
            id: key.id.to_string(),
            state: key.state,
            created_at: key.created_at,
            state_since: key.state_since,
            fingerprint: key.fingerprint,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct IdentityProviderObject {
    id: String,
    name: String,
    kind: String,
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    domains: Vec<String>,
    auto_create: bool,
    auto_link: bool,
    has_secret: bool,
    active: bool,
    /// Register this at the provider: the redirect URI (OpenID Connect) or the ACS URL (SAML).
    redirect_uri: String,
    saml_sso_url: Option<String>,
    saml_certificates: Vec<String>,
    saml_email_attribute: Option<String>,
    saml_name_attribute: Option<String>,
    saml_sign_requests: bool,
    saml_slo_url: Option<String>,
    /// The display name follows the provider's at every login.
    sync_profile: bool,
    /// Offered to everyone on the login page; creates accounts where the tenant allows registration.
    register: bool,
    /// Serves the domains of every tenant of the instance.
    instance_wide: bool,
}

fn provider_object(info: kernoid_oidc::federation::IdpInfo, redirect_uri: String) -> IdentityProviderObject {
    IdentityProviderObject {
        id: info.id.to_string(),
        kind: info.settings.kind().into(),
        saml_sso_url: info.settings.saml.as_ref().map(|saml| saml.sso_url.clone()),
        saml_certificates: info.settings.saml.as_ref().map(|saml| saml.certificates.clone()).unwrap_or_default(),
        saml_email_attribute: info.settings.saml.as_ref().and_then(|saml| saml.email_attribute.clone()),
        saml_name_attribute: info.settings.saml.as_ref().and_then(|saml| saml.name_attribute.clone()),
        saml_sign_requests: info.settings.saml.as_ref().is_some_and(|saml| saml.sign_requests),
        saml_slo_url: info.settings.saml.as_ref().and_then(|saml| saml.slo_url.clone()),
        sync_profile: info.settings.sync_profile,
        register: info.settings.register,
        instance_wide: info.tenant.is_none(),
        name: info.settings.name,
        issuer: info.settings.issuer,
        client_id: info.settings.client_id,
        scopes: info.settings.scopes,
        domains: info.settings.domains,
        auto_create: info.settings.auto_create,
        auto_link: info.settings.auto_link,
        has_secret: info.has_secret,
        active: info.active,
        redirect_uri,
    }
}

/// The settings of a SAML 2.0 provider.
#[derive(Debug, async_graphql::InputObject)]
pub struct SamlInput {
    /// Where kernoid sends the AuthnRequest (HTTP-Redirect binding).
    sso_url: String,
    /// The provider's signing certificates, base64 DER or PEM.
    certificates: Vec<String>,
    email_attribute: Option<String>,
    name_attribute: Option<String>,
    /// Sign AuthnRequests with kernoid's SAML key.
    #[graphql(default)]
    sign_requests: bool,
    /// The provider's single logout service (HTTP-Redirect binding).
    slo_url: Option<String>,
}

impl From<SamlInput> for kernoid_oidc::federation::SamlSettings {
    fn from(input: SamlInput) -> Self {
        Self {
            sso_url: input.sso_url,
            certificates: input.certificates,
            email_attribute: input.email_attribute,
            name_attribute: input.name_attribute,
            sign_requests: input.sign_requests,
            slo_url: input.slo_url,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct AccountLink {
    identity_provider: String,
    subject: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SimpleObject)]
pub struct ScimToken {
    id: String,
    name: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, SimpleObject)]
pub struct ScimTokenCreated {
    id: String,
    /// Shown this once.
    token: String,
    /// The SCIM base URL to give the directory.
    endpoint: String,
}

#[derive(Debug, Default)]
pub struct AdminQuery;

#[Object]
impl AdminQuery {
    /// The tenant administered (needs `directory.read`).
    async fn tenant(&self, context: &Context<'_>) -> async_graphql::Result<Tenant> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_tenant(&admin).await.map_err(error)?.into())
    }

    /// The language of the emails kernoid writes to the tenant's accounts that chose none: `en`, `de`; null for
    /// English (needs `directory.read`).
    async fn tenant_language(&self, context: &Context<'_>) -> async_graphql::Result<Option<String>> {
        let (identity, admin) = admin(context).await?;
        identity.admin_tenant_language(&admin).await.map_err(error)
    }

    /// The modules the installation has switched on, which the tenant may use, and whether it does.
    async fn tenant_modules(&self, context: &Context<'_>) -> async_graphql::Result<Vec<TenantModule>> {
        let (identity, admin) = admin(context).await?;
        let tenant = identity.admin_tenant(&admin).await.map_err(error)?;
        let modules = &context.data::<AppState>()?.modules;
        Ok(modules
            .iter()
            .map(|name| TenantModule { name: (*name).to_owned(), enabled: tenant.modules.iter().any(|on| on == name) })
            .collect())
    }

    /// The tenant's verified domains as mail domains: the DNS records to publish and whether they are published
    /// (reads DNS, changes nothing).
    async fn mail_dns(&self, context: &Context<'_>) -> async_graphql::Result<Vec<MailDns>> {
        let (identity, admin) = admin(context).await?;
        let tenant = identity.admin_tenant(&admin).await.map_err(error)?;
        let Some(checker) = context.data::<AppState>()?.mail_dns.as_ref() else {
            return Err(error(IdentityError::Refused("this installation does not handle mail".into())));
        };
        let mut list = Vec::new();
        for domain in tenant.domains.into_iter().filter(|domain| domain.verified) {
            let records = checker
                .check(&domain.domain)
                .await
                .into_iter()
                .map(|check| RecordCheck {
                    kind: check.kind.into(),
                    name: check.name,
                    record_type: check.record_type.into(),
                    expected: check.expected,
                    found: check.found,
                    status: check.status.as_str().into(),
                })
                .collect();
            list.push(MailDns { domain: domain.domain, records });
        }
        Ok(list)
    }

    /// The caller's permissions for the tenant administered.
    async fn permissions(&self, context: &Context<'_>) -> async_graphql::Result<Permissions> {
        let (_, admin) = admin(context).await?;
        Ok(Permissions {
            account: admin.account().to_string(),
            tenant: admin.tenant().to_string(),
            permissions: admin.permissions.iter().map(ToString::to_string).collect(),
        })
    }

    /// The tenant's accounts (needs `directory.read`).
    async fn accounts(&self, context: &Context<'_>) -> async_graphql::Result<Vec<AccountDetails>> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_accounts(&admin).await.map_err(error)?.into_iter().map(Into::into).collect())
    }

    async fn account(&self, context: &Context<'_>, id: String) -> async_graphql::Result<AccountDetails> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_account(&admin, uuid(&id, "the account")?).await.map_err(error)?.into())
    }

    /// An account's addresses, the primary one first, then its aliases (needs `directory.read`).
    async fn account_addresses(&self, context: &Context<'_>, id: String) -> async_graphql::Result<Vec<AccountAddress>> {
        let (identity, admin) = admin(context).await?;
        let list = identity.admin_account_addresses(&admin, uuid(&id, "the account")?).await.map_err(error)?;
        Ok(list.into_iter().map(|(address, primary)| AccountAddress { address, primary }).collect())
    }

    /// An account's valid sessions (needs `accounts.manage`).
    async fn account_sessions(
        &self,
        context: &Context<'_>,
        account: String,
    ) -> async_graphql::Result<Vec<SessionSummaryObject>> {
        let (identity, admin) = admin(context).await?;
        let list = identity.admin_account_sessions(&admin, uuid(&account, "the account")?).await.map_err(error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// The applications an account agreed to (needs `accounts.manage`).
    async fn account_consents(&self, context: &Context<'_>, account: String) -> async_graphql::Result<Vec<Consent>> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let list = oidc.admin_account_consents(&admin, uuid(&account, "the account")?).await.map_err(oidc_error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// What happened in the tenant (`scope` "tenant", needs `directory.read`) or the instance ("instance", needs
    /// `instance.read`): the events, newest first; `before` is the `position` of the last entry of the page before.
    async fn audit_log(
        &self,
        context: &Context<'_>,
        scope: Option<String>,
        before: Option<i64>,
        limit: Option<i64>,
        aggregate_type: Option<String>,
        aggregate_id: Option<String>,
    ) -> async_graphql::Result<Vec<AuditEntryObject>> {
        let (identity, admin) = admin(context).await?;
        let scope = crate::admin::audit::scope(scope.as_deref()).map_err(error)?;
        let query = AuditQuery { before, limit, aggregate_type, aggregate_id };
        let list = identity.admin_audit_log(&admin, scope, &query).await.map_err(error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// The tenant's groups (needs `directory.read`).
    async fn groups(&self, context: &Context<'_>) -> async_graphql::Result<Vec<Group>> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_groups(&admin).await.map_err(error)?.into_iter().map(Into::into).collect())
    }

    /// The tenant's roles – built in and its own – and who holds them (needs `directory.read`).
    async fn roles(&self, context: &Context<'_>) -> async_graphql::Result<Roles> {
        let (identity, admin) = admin(context).await?;
        let roles = identity.admin_tenant_roles(&admin).await.map_err(error)?;
        let assignments = identity.admin_role_assignments(&admin).await.map_err(error)?;
        Ok(Roles {
            roles: roles
                .into_iter()
                .map(|info| RoleInfo {
                    name: info.role.to_string(),
                    permissions: info.permissions.iter().map(ToString::to_string).collect(),
                    builtin: info.builtin,
                })
                .collect(),
            assignments: assignments.into_iter().map(|a| assignment(a.principal, a.role)).collect(),
        })
    }

    /// The tenant's projects (needs `directory.read`).
    async fn projects(&self, context: &Context<'_>) -> async_graphql::Result<Vec<Project>> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_projects(&admin).await.map_err(error)?.into_iter().map(Into::into).collect())
    }

    async fn project(&self, context: &Context<'_>, id: String) -> async_graphql::Result<Project> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_project(&admin, uuid(&id, "the project")?).await.map_err(error)?.into())
    }

    /// Who holds which role of a project – for a granted project only the tenant's own (needs `directory.read`).
    async fn project_authorizations(
        &self,
        context: &Context<'_>,
        project: String,
    ) -> async_graphql::Result<Vec<ProjectAuthorization>> {
        let (identity, admin) = admin(context).await?;
        let list =
            identity.admin_project_authorizations(&admin, uuid(&project, "the project")?).await.map_err(error)?;
        Ok(list
            .into_iter()
            .map(|a| ProjectAuthorization {
                role: a.role,
                tenant: a.tenant.to_string(),
                principal_kind: a.principal.kind().into(),
                principal_id: a.principal.id().to_string(),
            })
            .collect())
    }

    /// The tenants a project is granted to (needs `directory.read`).
    async fn project_grants(&self, context: &Context<'_>, project: String) -> async_graphql::Result<Vec<ProjectGrant>> {
        let (identity, admin) = admin(context).await?;
        let list = identity.admin_project_grants(&admin, uuid(&project, "the project")?).await.map_err(error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// The projects other tenants have granted to this one (needs `directory.read`).
    async fn granted_projects(&self, context: &Context<'_>) -> async_graphql::Result<Vec<ProjectGrant>> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_granted_projects(&admin).await.map_err(error)?.into_iter().map(Into::into).collect())
    }

    /// The tenant's applications (needs `directory.read`).
    async fn applications(&self, context: &Context<'_>) -> async_graphql::Result<Vec<Application>> {
        let (_, admin) = admin(context).await?;
        let list = context.data::<Oidc>()?.admin_applications(&admin).await.map_err(oidc_error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    async fn application(&self, context: &Context<'_>, id: String) -> async_graphql::Result<Application> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        Ok(oidc.admin_application(&admin, uuid(&id, "the application")?).await.map_err(oidc_error)?.into())
    }

    /// The instance with all its domains (needs `instance.read`).
    async fn instance_details(&self, context: &Context<'_>) -> async_graphql::Result<InstanceDetails> {
        let (identity, admin) = admin(context).await?;
        let overview = identity.admin_instance(&admin).await.map_err(error)?;
        Ok(InstanceDetails {
            id: overview.instance.id.to_string(),
            name: overview.instance.name,
            primary_domain: overview.instance.primary_domain,
            domains: overview.domains,
            login_ui_url: overview.instance.login_ui,
            passkey_rp_id: overview.instance.passkey_rp_id,
        })
    }

    /// The instance's tenants (needs `instance.read`).
    async fn tenants(&self, context: &Context<'_>) -> async_graphql::Result<Vec<TenantSummary>> {
        let (identity, admin) = admin(context).await?;
        Ok(identity
            .admin_tenants(&admin)
            .await
            .map_err(error)?
            .into_iter()
            .map(|tenant| TenantSummary { id: tenant.id.to_string(), name: tenant.name, active: tenant.active })
            .collect())
    }

    /// The instance roles and who holds them (needs `instance.read`).
    async fn instance_roles(&self, context: &Context<'_>) -> async_graphql::Result<InstanceRoles> {
        let (identity, admin) = admin(context).await?;
        let assignments = identity.admin_instance_role_assignments(&admin).await.map_err(error)?;
        Ok(InstanceRoles {
            roles: identity
                .admin_instance_roles(&admin)
                .await
                .map_err(error)?
                .into_iter()
                .map(|info| InstanceRole {
                    name: info.role.to_string(),
                    permissions: info.permissions.iter().map(ToString::to_string).collect(),
                    tenant_permissions: info.tenant_permissions.iter().map(ToString::to_string).collect(),
                    builtin: info.builtin,
                })
                .collect(),
            assignments: assignments.into_iter().map(|a| assignment(a.principal, a.role)).collect(),
        })
    }

    /// The tenant's identity providers (needs `directory.read`).
    async fn identity_providers(&self, context: &Context<'_>) -> async_graphql::Result<Vec<IdentityProviderObject>> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let domain = instance(context)?.primary_domain;
        let list = oidc.admin_identity_providers(&admin).await.map_err(oidc_error)?;
        Ok(list
            .into_iter()
            .map(|info| {
                let address = oidc.idp_return_address(&info, &domain);
                provider_object(info, address)
            })
            .collect())
    }

    async fn identity_provider(
        &self,
        context: &Context<'_>,
        id: String,
    ) -> async_graphql::Result<IdentityProviderObject> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let info =
            oidc.admin_identity_provider(&admin, uuid(&id, "the identity provider")?).await.map_err(oidc_error)?;
        let address = oidc.idp_return_address(&info, &instance(context)?.primary_domain);
        Ok(provider_object(info, address))
    }

    /// The external identities linked to an account (needs `directory.read`).
    async fn account_links(&self, context: &Context<'_>, account: String) -> async_graphql::Result<Vec<AccountLink>> {
        let (identity, admin) = admin(context).await?;
        let list = identity.admin_account_links(&admin, uuid(&account, "the account")?).await.map_err(error)?;
        Ok(list
            .into_iter()
            .map(|link| AccountLink {
                identity_provider: link.idp.to_string(),
                subject: link.subject,
                created_at: link.created_at,
            })
            .collect())
    }

    /// The tenant's SCIM tokens (needs `directory.read`).
    async fn scim_tokens(&self, context: &Context<'_>) -> async_graphql::Result<Vec<ScimToken>> {
        let (identity, admin) = admin(context).await?;
        Ok(identity
            .admin_scim_tokens(&admin)
            .await
            .map_err(error)?
            .into_iter()
            .map(|t| ScimToken {
                id: t.id.to_string(),
                name: t.name,
                created_at: t.created_at,
                last_used_at: t.last_used_at,
            })
            .collect())
    }

    /// The instance's signing keys (needs `instance.read`).
    async fn signing_keys(&self, context: &Context<'_>) -> async_graphql::Result<Vec<SigningKey>> {
        let (_, admin) = admin(context).await?;
        let keys = context.data::<Oidc>()?.admin_signing_keys(&admin).await.map_err(oidc_error)?;
        Ok(keys.into_iter().map(Into::into).collect())
    }

    /// kernoid's SAML keys of the instance (needs `instance.read`).
    async fn saml_keys(&self, context: &Context<'_>) -> async_graphql::Result<Vec<SamlKey>> {
        let (_, admin) = admin(context).await?;
        let keys = context.data::<Oidc>()?.admin_saml_keys(&admin).await.map_err(oidc_error)?;
        Ok(keys.into_iter().map(Into::into).collect())
    }
}

#[derive(Debug, Default)]
pub struct AdminMutation;

#[Object]
impl AdminMutation {
    // The tenant

    async fn rename_tenant(&self, context: &Context<'_>, name: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_rename_tenant(&admin, &name).await.map_err(error)?;
        Ok(true)
    }

    /// Sets the language of the emails kernoid writes to the tenant's accounts that chose none: `en`, `de`, or null
    /// for English (needs `tenant.manage`).
    async fn set_tenant_language(
        &self,
        context: &Context<'_>,
        language: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_tenant_language(&admin, language.as_deref()).await.map_err(error)?;
        Ok(true)
    }

    /// Sets whether every login to an application of the tenant needs a second factor, and how many days accounts
    /// without one may still log in (`mfaGraceDays`, 0 to 365); needs `policies.manage`.
    async fn set_tenant_policy(
        &self,
        context: &Context<'_>,
        mfa_required: bool,
        mfa_grace_days: Option<u32>,
    ) -> async_graphql::Result<Tenant> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_mfa_required(&admin, mfa_required).await.map_err(error)?;
        if let Some(days) = mfa_grace_days {
            identity.admin_set_mfa_grace(&admin, days).await.map_err(error)?;
        }
        Ok(identity.admin_tenant(&admin).await.map_err(error)?.into())
    }

    /// Switches a module on or off for the tenant (needs `tenant.manage`); only a module the installation has switched
    /// on can be switched on.
    async fn set_tenant_module(
        &self,
        context: &Context<'_>,
        module: String,
        enabled: bool,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let modules = &context.data::<AppState>()?.modules;
        identity.admin_set_module(&admin, &module, enabled, modules).await.map_err(error)?;
        Ok(true)
    }

    /// Claims a mail domain; returns the TXT record that proves it (needs `domains.manage`).
    async fn add_tenant_domain(&self, context: &Context<'_>, domain: String) -> async_graphql::Result<TenantDomain> {
        let (identity, admin) = admin(context).await?;
        let domain = self::domain(&domain)?;
        let token = identity.admin_add_domain(&admin, &domain).await.map_err(error)?;
        Ok(domain_object(domain.to_string(), false, Some(&token)))
    }

    /// Verifies a domain by its TXT record (needs `domains.manage`), or without DNS with `trust` (needs
    /// `tenants.manage`).
    async fn verify_tenant_domain(
        &self,
        context: &Context<'_>,
        domain: String,
        #[graphql(default)] trust: bool,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let domain = self::domain(&domain)?;
        if trust {
            identity.admin_trust_domain(&admin, &domain).await.map_err(error)?;
        } else {
            let dns = context.data::<AppState>()?.dns.as_ref();
            let dns = dns.ok_or_else(|| error(IdentityError::Verification("no DNS resolver available".into())))?;
            identity.admin_verify_domain(&admin, &domain, dns).await.map_err(error)?;
        }
        Ok(true)
    }

    /// Starts a change of a verified mail domain's DKIM key (needs `domains.manage`); `algorithm` is `rsa` (the
    /// default) or `ed25519`. Returns the new key's selector; `mailDns` shows its record.
    async fn rotate_dkim_key(
        &self,
        context: &Context<'_>,
        domain: String,
        algorithm: Option<String>,
    ) -> async_graphql::Result<String> {
        let (identity, admin) = admin(context).await?;
        let domain = self::domain(&domain)?;
        identity.admin_mail_domain(&admin, &domain).await.map_err(error)?;
        let Some(checker) = context.data::<AppState>()?.mail_dns.as_ref() else {
            return Err(error(IdentityError::Refused("this installation does not handle mail".into())));
        };
        let algorithm = kernoid_smtp::dkim::Algorithm::parse(algorithm.as_deref().unwrap_or("rsa"))
            .ok_or_else(|| error(IdentityError::Refused("the algorithm is rsa or ed25519".into())))?;
        checker.rotate_dkim(domain.as_str(), algorithm).await.map_err(|failure| {
            tracing::warn!(error = %failure, "changing a DKIM key failed");
            async_graphql::Error::new("the key could not be made")
        })
    }

    async fn remove_tenant_domain(&self, context: &Context<'_>, domain: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_remove_domain(&admin, &self::domain(&domain)?).await.map_err(error)?;
        Ok(true)
    }

    // Accounts

    /// Creates an account (needs `accounts.manage`); returns its id.
    async fn add_account(
        &self,
        context: &Context<'_>,
        address: String,
        display_name: String,
        password: Option<String>,
    ) -> async_graphql::Result<String> {
        let (identity, admin) = admin(context).await?;
        let account =
            identity.admin_add_account(&admin, &self::address(&address)?, &display_name).await.map_err(error)?;
        if let Some(password) = password {
            identity.admin_set_password(&admin, account, &password).await.map_err(error)?;
        }
        Ok(account.to_string())
    }

    /// Changes an account's display name, login name or active state (needs `accounts.manage`).
    async fn update_account(
        &self,
        context: &Context<'_>,
        id: String,
        display_name: Option<String>,
        primary_address: Option<String>,
        active: Option<bool>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let account = uuid(&id, "the account")?;
        if let Some(name) = display_name {
            identity.admin_rename_account(&admin, account, &name).await.map_err(error)?;
        }
        if let Some(primary) = primary_address {
            identity.admin_set_primary_address(&admin, account, &self::address(&primary)?).await.map_err(error)?;
        }
        if let Some(active) = active {
            identity.admin_set_account_active(&admin, account, active).await.map_err(error)?;
        }
        Ok(true)
    }

    async fn add_alias(&self, context: &Context<'_>, account: String, address: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (account, address) = (uuid(&account, "the account")?, self::address(&address)?);
        identity.admin_add_alias(&admin, account, &address).await.map_err(error)?;
        Ok(true)
    }

    async fn remove_alias(
        &self,
        context: &Context<'_>,
        account: String,
        address: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (account, address) = (uuid(&account, "the account")?, self::address(&address)?);
        identity.admin_remove_alias(&admin, account, &address).await.map_err(error)?;
        Ok(true)
    }

    /// Sets an account's password and ends its sessions (needs `accounts.manage` and every permission it holds).
    async fn set_account_password(
        &self,
        context: &Context<'_>,
        account: String,
        password: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_password(&admin, uuid(&account, "the account")?, &password).await.map_err(error)?;
        Ok(true)
    }

    /// Removes all second factors of an account (needs `accounts.manage` and every permission it holds).
    async fn reset_second_factors(&self, context: &Context<'_>, account: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_reset_second_factors(&admin, uuid(&account, "the account")?).await.map_err(error)?;
        Ok(true)
    }

    async fn terminate_account_session(
        &self,
        context: &Context<'_>,
        account: String,
        session: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (account, session) = (uuid(&account, "the account")?, uuid(&session, "the session")?);
        identity.admin_terminate_session(&admin, account, session).await.map_err(error)?;
        Ok(true)
    }

    // Groups

    /// Creates a group (needs `groups.manage`); returns its id.
    async fn add_group(&self, context: &Context<'_>, name: String) -> async_graphql::Result<String> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_add_group(&admin, &name).await.map_err(error)?.to_string())
    }

    async fn rename_group(&self, context: &Context<'_>, id: String, name: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_rename_group(&admin, uuid(&id, "the group")?, &name).await.map_err(error)?;
        Ok(true)
    }

    /// Lets the group's members send from its addresses, or stops it (needs `groups.manage`).
    async fn set_group_send_as(&self, context: &Context<'_>, id: String, enabled: bool) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_group_send_as(&admin, uuid(&id, "the group")?, enabled).await.map_err(error)?;
        Ok(true)
    }

    /// Removes a group; refused while it holds roles.
    async fn remove_group(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_remove_group(&admin, uuid(&id, "the group")?).await.map_err(error)?;
        Ok(true)
    }

    /// Adds an account to a group; for a group holding roles also the permission to assign them.
    async fn add_group_member(
        &self,
        context: &Context<'_>,
        group: String,
        account: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (group, account) = (uuid(&group, "the group")?, uuid(&account, "the account")?);
        identity.admin_add_group_member(&admin, group, account).await.map_err(error)?;
        Ok(true)
    }

    async fn remove_group_member(
        &self,
        context: &Context<'_>,
        group: String,
        account: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (group, account) = (uuid(&group, "the group")?, uuid(&account, "the account")?);
        identity.admin_remove_group_member(&admin, group, account).await.map_err(error)?;
        Ok(true)
    }

    /// Gives a group an address on a verified domain of the tenant; mail to it goes to every member.
    async fn add_group_address(
        &self,
        context: &Context<'_>,
        group: String,
        address: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (group, address) = (uuid(&group, "the group")?, self::address(&address)?);
        identity.admin_add_group_address(&admin, group, &address).await.map_err(error)?;
        Ok(true)
    }

    async fn remove_group_address(
        &self,
        context: &Context<'_>,
        group: String,
        address: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (group, address) = (uuid(&group, "the group")?, self::address(&address)?);
        identity.admin_remove_group_address(&admin, group, &address).await.map_err(error)?;
        Ok(true)
    }

    // Tenant roles

    /// Defines a role of the tenant's own, or changes its permissions (needs `roles.manage`).
    async fn define_role(
        &self,
        context: &Context<'_>,
        name: String,
        permissions: Vec<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let permissions = crate::admin::directory::permissions(&permissions).map_err(error)?;
        identity.admin_define_role(&admin, &role(&name)?, &permissions).await.map_err(error)?;
        Ok(true)
    }

    async fn delete_role(&self, context: &Context<'_>, name: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_delete_role(&admin, &role(&name)?).await.map_err(error)?;
        Ok(true)
    }

    /// Assigns a role to an account or group of the tenant (needs `roles.manage`).
    async fn grant_role(
        &self,
        context: &Context<'_>,
        role: String,
        principal_kind: String,
        principal_id: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let principal = self::principal(&principal_kind, &principal_id)?;
        identity.admin_grant_role(&admin, principal, &self::role(&role)?).await.map_err(error)?;
        Ok(true)
    }

    /// Takes a role back; the tenant's last `tenant_admin` assignment cannot be revoked.
    async fn revoke_role(
        &self,
        context: &Context<'_>,
        role: String,
        principal_kind: String,
        principal_id: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let principal = self::principal(&principal_kind, &principal_id)?;
        identity.admin_revoke_role(&admin, principal, &self::role(&role)?).await.map_err(error)?;
        Ok(true)
    }

    // Projects

    /// Creates a project (needs `projects.manage`); returns its id.
    async fn add_project(&self, context: &Context<'_>, name: String) -> async_graphql::Result<String> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_add_project(&admin, &name).await.map_err(error)?.to_string())
    }

    /// Renames a project or changes its settings (needs `projects.manage`).
    async fn update_project(
        &self,
        context: &Context<'_>,
        id: String,
        name: Option<String>,
        role_assertion: Option<bool>,
        role_check: Option<bool>,
    ) -> async_graphql::Result<Project> {
        let (identity, admin) = admin(context).await?;
        let project = uuid(&id, "the project")?;
        if let Some(name) = name {
            identity.admin_rename_project(&admin, project, &name).await.map_err(error)?;
        }
        if role_assertion.is_some() || role_check.is_some() {
            let current = identity.admin_project(&admin, project).await.map_err(error)?;
            let assertion = role_assertion.unwrap_or(current.role_assertion);
            let check = role_check.unwrap_or(current.role_check);
            identity.admin_set_project_settings(&admin, project, assertion, check).await.map_err(error)?;
        }
        Ok(identity.admin_project(&admin, project).await.map_err(error)?.into())
    }

    /// Removes a project without applications and authorizations.
    async fn remove_project(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_remove_project(&admin, uuid(&id, "the project")?).await.map_err(error)?;
        Ok(true)
    }

    /// Adds a role to a project, or changes its display name and group (needs `projects.manage`).
    async fn set_project_role(
        &self,
        context: &Context<'_>,
        project: String,
        key: String,
        display_name: String,
        group: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let project = uuid(&project, "the project")?;
        identity.admin_set_project_role(&admin, project, &key, &display_name, group.as_deref()).await.map_err(error)?;
        Ok(true)
    }

    async fn remove_project_role(
        &self,
        context: &Context<'_>,
        project: String,
        key: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_remove_project_role(&admin, uuid(&project, "the project")?, &key).await.map_err(error)?;
        Ok(true)
    }

    /// Gives an account or group a role of a project (needs `authorizations.manage`).
    async fn grant_project_role(
        &self,
        context: &Context<'_>,
        project: String,
        role: String,
        principal_kind: String,
        principal_id: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (project, principal) = (uuid(&project, "the project")?, self::principal(&principal_kind, &principal_id)?);
        identity.admin_grant_project_role(&admin, project, principal, &role).await.map_err(error)?;
        Ok(true)
    }

    async fn revoke_project_role(
        &self,
        context: &Context<'_>,
        project: String,
        role: String,
        principal_kind: String,
        principal_id: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (project, principal) = (uuid(&project, "the project")?, self::principal(&principal_kind, &principal_id)?);
        identity.admin_revoke_project_role(&admin, project, principal, &role).await.map_err(error)?;
        Ok(true)
    }

    /// Grants a project to another tenant – by id or verified mail domain – with some of its roles (needs
    /// `projects.manage`).
    async fn grant_project(
        &self,
        context: &Context<'_>,
        project: String,
        tenant: String,
        roles: Vec<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let project = uuid(&project, "the project")?;
        let grantee = identity.admin_find_tenant(&admin, &tenant).await.map_err(error)?;
        let roles = roles.into_iter().collect();
        identity.admin_grant_project(&admin, project, grantee, &roles).await.map_err(error)?;
        Ok(true)
    }

    /// Takes a grant back, once that tenant holds none of the project's roles.
    async fn revoke_project_grant(
        &self,
        context: &Context<'_>,
        project: String,
        tenant: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let project = uuid(&project, "the project")?;
        let grantee = identity.admin_find_tenant(&admin, &tenant).await.map_err(error)?;
        identity.admin_revoke_project_grant(&admin, project, grantee).await.map_err(error)?;
        Ok(true)
    }

    // Applications

    /// Registers an application in a project (needs `applications.manage`).
    async fn add_application(
        &self,
        context: &Context<'_>,
        project: String,
        name: String,
        kind: String,
        redirect_uris: Vec<String>,
        #[graphql(default)] post_logout_redirect_uris: Vec<String>,
    ) -> async_graphql::Result<ApplicationCreated> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let (project, kind) = (uuid(&project, "the project")?, self::kind(&kind).map_err(oidc_error)?);
        let (id, client_secret) = oidc
            .admin_add_application(&admin, project, &name, kind, &redirect_uris, &post_logout_redirect_uris)
            .await
            .map_err(oidc_error)?;
        Ok(ApplicationCreated { id: id.to_string(), client_secret })
    }

    /// Changes an application (needs `applications.manage`).
    #[allow(clippy::too_many_arguments, reason = "each argument is a field of the GraphQL mutation")]
    async fn update_application(
        &self,
        context: &Context<'_>,
        id: String,
        name: Option<String>,
        project: Option<String>,
        redirect_uris: Option<Vec<String>>,
        post_logout_redirect_uris: Option<Vec<String>>,
        active: Option<bool>,
    ) -> async_graphql::Result<Application> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let application = uuid(&id, "the application")?;
        if let Some(name) = name {
            oidc.admin_rename_application(&admin, application, &name).await.map_err(oidc_error)?;
        }
        if let Some(project) = project {
            let project = uuid(&project, "the project")?;
            oidc.admin_set_application_project(&admin, application, project).await.map_err(oidc_error)?;
        }
        if let Some(uris) = redirect_uris {
            oidc.admin_set_redirect_uris(&admin, application, &uris).await.map_err(oidc_error)?;
        }
        if let Some(uris) = post_logout_redirect_uris {
            oidc.admin_set_post_logout_redirect_uris(&admin, application, &uris).await.map_err(oidc_error)?;
        }
        if let Some(active) = active {
            oidc.admin_set_application_active(&admin, application, active).await.map_err(oidc_error)?;
        }
        Ok(oidc.admin_application(&admin, application).await.map_err(oidc_error)?.into())
    }

    /// Sets whether logins to one application need a second factor (needs `applications.manage`).
    async fn set_application_policy(
        &self,
        context: &Context<'_>,
        id: String,
        mfa_required: bool,
    ) -> async_graphql::Result<Application> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let application = uuid(&id, "the application")?;
        oidc.admin_set_application_mfa_required(&admin, application, mfa_required).await.map_err(oidc_error)?;
        Ok(oidc.admin_application(&admin, application).await.map_err(oidc_error)?.into())
    }

    /// Sets an application's options (needs `applications.manage`): `accessTokenFormat` is `opaque` or `jwt`.
    #[allow(clippy::too_many_arguments, reason = "one GraphQL argument each")]
    async fn set_application_options(
        &self,
        context: &Context<'_>,
        id: String,
        access_token_format: Option<String>,
        offline_access: Option<bool>,
        consent_required: Option<bool>,
        backchannel_logout_uri: Option<String>,
        frontchannel_logout_uri: Option<String>,
    ) -> async_graphql::Result<Application> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let application = uuid(&id, "the application")?;
        let access_token_format = match access_token_format.as_deref().unwrap_or("opaque") {
            "opaque" => TokenFormat::Opaque,
            "jwt" => TokenFormat::Jwt,
            _ => return Err(error(IdentityError::Refused("accessTokenFormat is opaque or jwt".into()))),
        };
        let options = AppOptions {
            access_token_format,
            offline_access: offline_access.unwrap_or(false),
            consent_required: consent_required.unwrap_or(false),
            backchannel_logout_uri,
            frontchannel_logout_uri,
        };
        oidc.admin_set_application_options(&admin, application, &options).await.map_err(oidc_error)?;
        Ok(oidc.admin_application(&admin, application).await.map_err(oidc_error)?.into())
    }

    /// Withdraws an account's consent to an application, and the application's tokens for it (needs
    /// `accounts.manage` and every permission the account holds).
    async fn revoke_consent(
        &self,
        context: &Context<'_>,
        account: String,
        application: String,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let (account, application) = (uuid(&account, "the account")?, uuid(&application, "the consent")?);
        oidc.admin_revoke_consent(&admin, account, application).await.map_err(oidc_error)?;
        Ok(true)
    }

    /// Replaces the secret of a confidential application; returns it, shown this once.
    async fn new_client_secret(&self, context: &Context<'_>, id: String) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        oidc.admin_new_client_secret(&admin, uuid(&id, "the application")?).await.map_err(oidc_error)
    }

    // Identity providers

    /// Connects an identity provider (needs `identity_providers.manage`; with `instanceWide`, for every tenant of the
    /// instance, `instance.manage`); returns its id.
    #[allow(clippy::too_many_arguments, reason = "each argument is a field of the GraphQL mutation")]
    async fn add_identity_provider(
        &self,
        context: &Context<'_>,
        name: String,
        issuer: String,
        #[graphql(default)] client_id: String,
        client_secret: Option<String>,
        #[graphql(default)] scopes: Vec<String>,
        #[graphql(default)] domains: Vec<String>,
        #[graphql(default)] auto_create: bool,
        #[graphql(default)] auto_link: bool,
        #[graphql(default)] sync_profile: bool,
        #[graphql(default)] register: bool,
        #[graphql(default)] instance_wide: bool,
        saml: Option<SamlInput>,
    ) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let saml = saml.map(Into::into);
        let settings = kernoid_oidc::federation::IdpSettings {
            name,
            issuer,
            client_id,
            scopes,
            domains,
            auto_create,
            auto_link,
            sync_profile,
            register,
            saml,
        };
        let oidc = context.data::<Oidc>()?;
        let id = oidc
            .admin_add_identity_provider(&admin, &settings, client_secret.as_deref(), instance_wide)
            .await
            .map_err(oidc_error)?;
        Ok(id.to_string())
    }

    /// Changes an identity provider (needs `identity_providers.manage`).
    #[allow(clippy::too_many_arguments, reason = "each argument is a field of the GraphQL mutation")]
    async fn update_identity_provider(
        &self,
        context: &Context<'_>,
        id: String,
        name: Option<String>,
        issuer: Option<String>,
        client_id: Option<String>,
        scopes: Option<Vec<String>>,
        domains: Option<Vec<String>>,
        auto_create: Option<bool>,
        auto_link: Option<bool>,
        sync_profile: Option<bool>,
        register: Option<bool>,
        active: Option<bool>,
        saml: Option<SamlInput>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        let idp = uuid(&id, "the identity provider")?;
        let current = oidc.admin_identity_provider(&admin, idp).await.map_err(oidc_error)?.settings;
        let settings = kernoid_oidc::federation::IdpSettings {
            name: name.unwrap_or(current.name),
            issuer: issuer.unwrap_or(current.issuer),
            client_id: client_id.unwrap_or(current.client_id),
            scopes: scopes.unwrap_or(current.scopes),
            domains: domains.unwrap_or(current.domains),
            auto_create: auto_create.unwrap_or(current.auto_create),
            auto_link: auto_link.unwrap_or(current.auto_link),
            sync_profile: sync_profile.unwrap_or(current.sync_profile),
            register: register.unwrap_or(current.register),
            saml: saml.map(Into::into).or(current.saml),
        };
        oidc.admin_update_identity_provider(&admin, idp, &settings).await.map_err(oidc_error)?;
        if let Some(active) = active {
            oidc.admin_set_identity_provider_active(&admin, idp, active).await.map_err(oidc_error)?;
        }
        Ok(true)
    }

    /// Sets the client secret, or removes it with null (needs `identity_providers.manage`).
    async fn set_identity_provider_secret(
        &self,
        context: &Context<'_>,
        id: String,
        client_secret: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let idp = uuid(&id, "the identity provider")?;
        let oidc = context.data::<Oidc>()?;
        oidc.admin_set_identity_provider_secret(&admin, idp, client_secret.as_deref()).await.map_err(oidc_error)?;
        Ok(true)
    }

    async fn remove_identity_provider(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        oidc.admin_remove_identity_provider(&admin, uuid(&id, "the identity provider")?).await.map_err(oidc_error)?;
        Ok(true)
    }

    /// Whether kernoid reaches the provider as configured.
    async fn check_identity_provider(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let oidc = context.data::<Oidc>()?;
        oidc.admin_check_identity_provider(&admin, uuid(&id, "the identity provider")?).await.map_err(oidc_error)?;
        Ok(true)
    }

    /// Unlinks an external identity from an account (needs `accounts.manage`).
    async fn unlink_account(
        &self,
        context: &Context<'_>,
        account: String,
        identity_provider: String,
        subject: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let (account, idp) = (uuid(&account, "the account")?, uuid(&identity_provider, "the identity provider")?);
        identity.admin_unlink_account(&admin, account, idp, &subject).await.map_err(error)?;
        Ok(true)
    }

    /// A new SCIM token for the tenant's directory (needs `provisioning.manage`).
    async fn add_scim_token(&self, context: &Context<'_>, name: String) -> async_graphql::Result<ScimTokenCreated> {
        let (identity, admin) = admin(context).await?;
        let (id, token) = identity.admin_add_scim_token(&admin, &name).await.map_err(error)?;
        let endpoint = format!("{}/scim/v2", context.data::<Oidc>()?.issuer(&instance(context)?.primary_domain));
        Ok(ScimTokenCreated { id: id.to_string(), token, endpoint })
    }

    async fn remove_scim_token(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_remove_scim_token(&admin, uuid(&id, "the SCIM token")?).await.map_err(error)?;
        Ok(true)
    }

    // The instance

    async fn rename_instance(&self, context: &Context<'_>, name: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_rename_instance(&admin, &name).await.map_err(error)?;
        Ok(true)
    }

    async fn add_instance_domain(&self, context: &Context<'_>, domain: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_add_instance_domain(&admin, &self::domain(&domain)?).await.map_err(error)?;
        Ok(true)
    }

    async fn remove_instance_domain(&self, context: &Context<'_>, domain: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_remove_instance_domain(&admin, &self::domain(&domain)?).await.map_err(error)?;
        Ok(true)
    }

    async fn set_primary_domain(&self, context: &Context<'_>, domain: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_primary_domain(&admin, &self::domain(&domain)?).await.map_err(error)?;
        Ok(true)
    }

    /// Sends logins to a login UI of the instance's own (an HTTPS URL), or back to kernoid's (`null`); needs
    /// `instance.manage`.
    async fn set_login_ui(&self, context: &Context<'_>, url: Option<String>) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_login_ui(&admin, url.as_deref()).await.map_err(error)?;
        Ok(true)
    }

    /// Creates a tenant (needs `tenants.manage`); returns its id.
    async fn add_tenant(&self, context: &Context<'_>, name: String) -> async_graphql::Result<String> {
        let (identity, admin) = admin(context).await?;
        Ok(identity.admin_add_tenant(&admin, &name).await.map_err(error)?.to_string())
    }

    /// Renames, deactivates or reactivates a tenant (needs `tenants.manage`).
    async fn update_tenant(
        &self,
        context: &Context<'_>,
        id: String,
        name: Option<String>,
        active: Option<bool>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let tenant = uuid(&id, "the tenant")?;
        identity.admin_update_tenant(&admin, tenant, name.as_deref(), active).await.map_err(error)?;
        Ok(true)
    }

    /// Defines an instance role of the instance's own, or changes its permissions – instance permissions apply at the
    /// instance, tenant permissions in every tenant (needs `instance_roles.manage`).
    async fn define_instance_role(
        &self,
        context: &Context<'_>,
        name: String,
        permissions: Vec<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let permissions = crate::admin::directory::permissions(&permissions).map_err(error)?;
        identity.admin_define_instance_role(&admin, &role(&name)?, &permissions).await.map_err(error)?;
        Ok(true)
    }

    async fn delete_instance_role(&self, context: &Context<'_>, name: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_delete_instance_role(&admin, &role(&name)?).await.map_err(error)?;
        Ok(true)
    }

    /// Binds passkeys to another RP ID: a domain of the instance or a parent domain of one (needs
    /// `instance.manage`). Passkeys registered under the former RP ID stop working.
    async fn set_passkey_rp_id(&self, context: &Context<'_>, rp_id: String) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_passkey_rp_id(&admin, &self::domain(&rp_id)?).await.map_err(error)?;
        Ok(true)
    }

    /// Assigns an instance role (needs `instance_roles.manage`).
    async fn grant_instance_role(
        &self,
        context: &Context<'_>,
        role: String,
        principal_kind: String,
        principal_id: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let principal = self::principal(&principal_kind, &principal_id)?;
        identity.admin_grant_instance_role(&admin, principal, &self::role(&role)?).await.map_err(error)?;
        Ok(true)
    }

    /// Takes an instance role back; the last `instance_admin` stays.
    async fn revoke_instance_role(
        &self,
        context: &Context<'_>,
        role: String,
        principal_kind: String,
        principal_id: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let principal = self::principal(&principal_kind, &principal_id)?;
        identity.admin_revoke_instance_role(&admin, principal, &self::role(&role)?).await.map_err(error)?;
        Ok(true)
    }

    /// Creates a signing key (needs `instance.manage`); returns its id.
    async fn add_signing_key(&self, context: &Context<'_>) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        context.data::<Oidc>()?.admin_add_signing_key(&admin).await.map_err(oidc_error)
    }

    async fn activate_signing_key(&self, context: &Context<'_>, kid: String) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        context.data::<Oidc>()?.admin_activate_signing_key(&admin, &kid).await.map_err(oidc_error)?;
        Ok(true)
    }

    async fn remove_signing_key(&self, context: &Context<'_>, kid: String) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        context.data::<Oidc>()?.admin_remove_signing_key(&admin, &kid).await.map_err(oidc_error)?;
        Ok(true)
    }

    /// Starts a change of kernoid's SAML key (needs `instance.manage`): a new key, in the metadata at once and
    /// signing once activated. Returns its id; if a key waits already, that one's.
    async fn add_saml_key(&self, context: &Context<'_>) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        Ok(context.data::<Oidc>()?.admin_add_saml_key(&admin).await.map_err(oidc_error)?.to_string())
    }

    /// Signs with the waiting SAML key from now on; the active one leaves the metadata (needs `instance.manage`).
    async fn activate_saml_key(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let key = uuid(&id, "the key")?;
        context.data::<Oidc>()?.admin_activate_saml_key(&admin, key).await.map_err(oidc_error)?;
        Ok(true)
    }
}
