// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tenant administered: name, policy, modules, mail domains and the caller's permissions.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kernoid_identity::{
    CHALLENGE_LABEL, DomainName, IdentityError,
    admin::TenantPolicy,
    tenant::{E2ePolicy, E2eRule},
};
use serde::{Deserialize, Serialize};

use super::{AdminSession, no_content, respond};
use crate::{AppState, Problem};

fn domain(value: &str) -> Result<DomainName, IdentityError> {
    DomainName::parse(value).map_err(|error| IdentityError::Refused(error.to_string()))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct DomainView {
    domain: String,
    verified: bool,
    /// For a domain not verified yet: the TXT record that proves it.
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<DnsRecord>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct DnsRecord {
    /// E.g. `_kernoid-challenge.firma.de`.
    name: String,
    /// Always `TXT`.
    kind: &'static str,
    value: String,
}

fn record(domain: &str, token: &str) -> DnsRecord {
    DnsRecord {
        name: format!("{CHALLENGE_LABEL}.{domain}"),
        kind: "TXT",
        value: format!("kernoid-verification={token}"),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct TenantView {
    id: String,
    instance: String,
    name: String,
    active: bool,
    /// Logins to applications need a second factor, and so does administration.
    mfa_required: bool,
    /// Days an account without a second factor may still log in without one, after the requirement (or the account)
    /// began.
    mfa_grace_days: u32,
    domains: Vec<DomainView>,
    /// The modules the tenant has switched on.
    modules: Vec<String>,
}

impl From<TenantPolicy> for TenantView {
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
                .map(|claim| DomainView {
                    record: claim.token.as_deref().map(|token| record(&claim.domain, token)),
                    domain: claim.domain,
                    verified: claim.verified,
                })
                .collect(),
            modules: policy.modules,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Name {
    name: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[schema(as = TenantPolicy)]
pub(crate) struct Policy {
    mfa_required: bool,
    /// 0 to 365; left out, it stays as it is.
    mfa_grace_days: Option<u32>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Switch {
    pub(crate) enabled: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewDomain {
    domain: String,
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct Verification {
    /// Mark it verified without asking DNS – instance administrators only (`tenants.manage`).
    #[serde(default)]
    trust: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct PermissionsView {
    account: String,
    /// The tenant administered.
    tenant: String,
    /// E.g. `directory.read`, `groups.manage`, `instance.read`.
    permissions: Vec<String>,
}

/// The tenant administered (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant", tag = "tenant", params(TenantHeader), responses(
    (status = 200, body = TenantView),
    (status = 403, description = "needs directory.read", body = Problem),
))]
pub(crate) async fn get(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_tenant(&admin).await, |tenant| Json(TenantView::from(tenant)).into_response())
}

/// Renames the tenant (needs `tenant.manage`).
#[utoipa::path(patch, path = "/v1/tenant", tag = "tenant", params(TenantHeader), request_body = Name, responses(
    (status = 204), (status = 403, body = Problem),
))]
pub(crate) async fn rename(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<Name>,
) -> Response {
    respond(state.identity.admin_rename_tenant(&admin, &body.name).await, no_content)
}

/// Sets whether every login to an application of the tenant needs a second factor, and how long accounts without one
/// may still log in (needs `policies.manage`).
#[utoipa::path(put, path = "/v1/tenant/policy", tag = "tenant", params(TenantHeader), request_body = Policy, responses(
    (status = 200, body = TenantView), (status = 403, body = Problem),
))]
pub(crate) async fn set_policy(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(policy): Json<Policy>,
) -> Response {
    let result = async {
        state.identity.admin_set_mfa_required(&admin, policy.mfa_required).await?;
        if let Some(days) = policy.mfa_grace_days {
            state.identity.admin_set_mfa_grace(&admin, days).await?;
        }
        state.identity.admin_tenant(&admin).await
    }
    .await;
    respond(result, |tenant| Json(TenantView::from(tenant)).into_response())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ModuleView {
    name: String,
    /// Whether the tenant uses it.
    enabled: bool,
}

/// The modules the installation has switched on, which the tenant may use, and whether it does (needs
/// `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/modules", tag = "tenant", params(TenantHeader), responses(
    (status = 200, body = [ModuleView]),
    (status = 403, description = "needs directory.read", body = Problem),
))]
pub(crate) async fn modules(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_tenant(&admin).await, |tenant| {
        let views: Vec<ModuleView> = state
            .modules
            .iter()
            .map(|name| ModuleView { name: (*name).to_owned(), enabled: tenant.modules.iter().any(|on| on == name) })
            .collect();
        Json(views).into_response()
    })
}

/// Switches a module on or off for the tenant (needs `tenant.manage`); only a module the installation has switched
/// on can be switched on.
#[utoipa::path(put, path = "/v1/tenant/modules/{module}", tag = "tenant", params(TenantHeader), request_body = Switch,
    responses((status = 204), (status = 400, description = "no such module", body = Problem)))]
pub(crate) async fn set_module(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(module): Path<String>,
    Json(body): Json<Switch>,
) -> Response {
    respond(state.identity.admin_set_module(&admin, &module, body.enabled, &state.modules).await, no_content)
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct TenantLanguage {
    /// The language of the emails kernoid writes to accounts that chose none – `en` or `de`; null for English.
    language: Option<String>,
}

/// The language of the emails kernoid writes – invitations, notices – to the tenant's accounts that chose none (needs
/// `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/language", tag = "tenant", params(TenantHeader),
    responses((status = 200, body = TenantLanguage)))]
pub(crate) async fn language(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_tenant_language(&admin).await, |language| {
        Json(TenantLanguage { language }).into_response()
    })
}

/// Sets that language: `en`, `de`, or null for English (needs `tenant.manage`).
#[utoipa::path(put, path = "/v1/tenant/language", tag = "tenant", params(TenantHeader), request_body = TenantLanguage,
    responses((status = 204), (status = 400, description = "a language kernoid does not write", body = Problem)))]
pub(crate) async fn set_language(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<TenantLanguage>,
) -> Response {
    respond(state.identity.admin_set_tenant_language(&admin, body.language.as_deref()).await, no_content)
}

/// Whether accounts may use an end-to-end setting (RFC 0006, 8.1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum E2eRuleView {
    Allowed,
    Required,
    Forbidden,
}

impl From<E2eRule> for E2eRuleView {
    fn from(rule: E2eRule) -> Self {
        match rule {
            E2eRule::Allowed => E2eRuleView::Allowed,
            E2eRule::Required => E2eRuleView::Required,
            E2eRule::Forbidden => E2eRuleView::Forbidden,
        }
    }
}

impl From<E2eRuleView> for E2eRule {
    fn from(rule: E2eRuleView) -> Self {
        match rule {
            E2eRuleView::Allowed => E2eRule::Allowed,
            E2eRuleView::Required => E2eRule::Required,
            E2eRuleView::Forbidden => E2eRule::Forbidden,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct E2ePolicyBody {
    /// Mail encrypted on arrival to the account's key.
    mail: E2eRuleView,
    /// Vaults: directories only their members can read.
    vaults: E2eRuleView,
    /// Encrypted calendars and address books.
    collections: E2eRuleView,
    /// Whether every account's secret key must be recoverable with the tenant's recovery key.
    recovery: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RecoveryKeyView {
    fingerprint: String,
    /// The OpenPGP public key, base64 of its binary form.
    public_key: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct E2ePolicyView {
    #[serde(flatten)]
    policy: E2ePolicyBody,
    recovery_key: Option<RecoveryKeyView>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct RecoveryKeyBody {
    /// The OpenPGP public key an administrator's app made, base64 of its binary or armored form; its secret key stays
    /// with the administrators.
    public_key: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct Fingerprint {
    fingerprint: String,
}

fn base64_key(value: &str) -> Result<Vec<u8>, IdentityError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| IdentityError::Refused("the public key is base64".into()))
}

/// What the tenant's accounts may encrypt end to end, and its recovery key (needs `directory.read`; RFC 0006, 8).
#[utoipa::path(get, path = "/v1/tenant/e2e", tag = "tenant", params(TenantHeader),
    responses((status = 200, body = E2ePolicyView)))]
pub(crate) async fn e2e_policy(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_e2e_policy(&admin).await, |(policy, key)| {
        use base64::Engine;
        Json(E2ePolicyView {
            policy: E2ePolicyBody {
                mail: policy.mail.into(),
                vaults: policy.vaults.into(),
                collections: policy.collections.into(),
                recovery: policy.recovery,
            },
            recovery_key: key.map(|(fingerprint, key)| RecoveryKeyView {
                fingerprint,
                public_key: base64::engine::general_purpose::STANDARD.encode(key),
            }),
        })
        .into_response()
    })
}

/// Sets that policy (needs `tenant.manage`). Recovery through the tenant needs its recovery key first; `forbidden`
/// does not touch what is encrypted already.
#[utoipa::path(put, path = "/v1/tenant/e2e", tag = "tenant", params(TenantHeader), request_body = E2ePolicyBody,
    responses((status = 204), (status = 400, description = "recovery without a recovery key", body = Problem)))]
pub(crate) async fn set_e2e_policy(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<E2ePolicyBody>,
) -> Response {
    let policy = E2ePolicy {
        mail: body.mail.into(),
        vaults: body.vaults.into(),
        collections: body.collections.into(),
        recovery: body.recovery,
    };
    respond(state.identity.admin_set_e2e_policy(&admin, policy).await, no_content)
}

/// Sets the tenant's recovery key (needs `tenant.manage`; RFC 0006, 8.2).
#[utoipa::path(put, path = "/v1/tenant/e2e/recovery-key", tag = "tenant", params(TenantHeader),
    request_body = RecoveryKeyBody,
    responses((status = 200, body = Fingerprint), (status = 400, description = "not an OpenPGP key kernoid can use", body = Problem)))]
pub(crate) async fn set_recovery_key(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<RecoveryKeyBody>,
) -> Response {
    let key = match base64_key(&body.public_key) {
        Ok(key) => key,
        Err(error) => return respond(Err::<(), _>(error), no_content),
    };
    respond(state.identity.admin_set_recovery_key(&admin, &key).await, |fingerprint| {
        Json(Fingerprint { fingerprint }).into_response()
    })
}

/// The permissions of the caller for the tenant administered – for a UI to show what it may do.
#[utoipa::path(get, path = "/v1/tenant/permissions", tag = "tenant", params(TenantHeader),
    responses((status = 200, body = PermissionsView)))]
pub(crate) async fn permissions(AdminSession(admin): AdminSession) -> Json<PermissionsView> {
    Json(PermissionsView {
        account: admin.account().to_string(),
        tenant: admin.tenant().to_string(),
        permissions: admin.permissions.iter().map(ToString::to_string).collect(),
    })
}

/// Claims a mail domain (needs `domains.manage`); answers with the TXT record that proves it.
#[utoipa::path(post, path = "/v1/tenant/domains", tag = "tenant", params(TenantHeader), request_body = NewDomain,
    responses((status = 201, body = DomainView), (status = 409, description = "claimed already", body = Problem)))]
pub(crate) async fn add_domain(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewDomain>,
) -> Response {
    let result = async {
        let domain = domain(&body.domain)?;
        let token = state.identity.admin_add_domain(&admin, &domain).await?;
        Ok(DomainView { record: Some(record(domain.as_str(), &token)), domain: domain.to_string(), verified: false })
    }
    .await;
    respond(result, |view| (StatusCode::CREATED, Json(view)).into_response())
}

/// Verifies a claimed domain by its TXT record (needs `domains.manage`), or marks it verified without DNS
/// (`trust`, needs `tenants.manage`).
#[utoipa::path(post, path = "/v1/tenant/domains/{domain}/verify", tag = "tenant", params(TenantHeader),
    request_body = Verification, responses(
    (status = 204), (status = 400, description = "the record was not found", body = Problem),
))]
pub(crate) async fn verify_domain(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(name): Path<String>,
    body: Option<Json<Verification>>,
) -> Response {
    let trust = body.is_some_and(|Json(body)| body.trust);
    let result = async {
        let domain = domain(&name)?;
        if trust {
            return state.identity.admin_trust_domain(&admin, &domain).await;
        }
        let dns = state.dns.as_ref().ok_or_else(|| IdentityError::Verification("no DNS resolver available".into()))?;
        state.identity.admin_verify_domain(&admin, &domain, dns).await
    }
    .await;
    respond(result, no_content)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct DkimRotation {
    /// `rsa` (the default) or `ed25519`.
    #[serde(default)]
    algorithm: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct DkimRotationView {
    /// The new key's selector: its record belongs at `<selector>._domainkey.<domain>`; `mail-dns` shows it.
    selector: String,
}

fn dkim_problem(error: kernoid_smtp::dkim::DkimError) -> Response {
    tracing::warn!(%error, "changing a DKIM key failed");
    Problem::new(StatusCode::INTERNAL_SERVER_ERROR).detail("the key could not be made").into_response()
}

/// Starts a change of a verified mail domain's DKIM key (needs `domains.manage`): a new key, signing once DNS shows
/// its record; the key it replaces then stops signing. If a new key is waiting already, its selector.
#[utoipa::path(post, path = "/v1/tenant/domains/{domain}/dkim-rotate", tag = "tenant", params(TenantHeader),
    request_body = DkimRotation, responses(
    (status = 200, body = DkimRotationView),
    (status = 400, description = "this installation does not handle mail, or an unknown algorithm", body = Problem),
))]
pub(crate) async fn rotate_dkim(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(name): Path<String>,
    body: Option<Json<DkimRotation>>,
) -> Response {
    let algorithm = body.and_then(|Json(body)| body.algorithm).unwrap_or_else(|| "rsa".into());
    let checked = async {
        let domain = domain(&name)?;
        state.identity.admin_mail_domain(&admin, &domain).await?;
        let Some(checker) = &state.mail_dns else {
            return Err(IdentityError::Refused("this installation does not handle mail".into()));
        };
        let algorithm = kernoid_smtp::dkim::Algorithm::parse(&algorithm)
            .ok_or_else(|| IdentityError::Refused("the algorithm is rsa or ed25519".into()))?;
        Ok((checker.clone(), domain, algorithm))
    }
    .await;
    let (checker, domain, algorithm) = match checked {
        Ok(checked) => checked,
        Err(error) => return crate::sessions::problem(error),
    };
    match checker.rotate_dkim(domain.as_str(), algorithm).await {
        Ok(selector) => Json(DkimRotationView { selector }).into_response(),
        Err(error) => dkim_problem(error),
    }
}

/// Removes a mail domain – unless addresses use it (needs `domains.manage`).
#[utoipa::path(delete, path = "/v1/tenant/domains/{domain}", tag = "tenant", params(TenantHeader),
    responses((status = 204), (status = 400, description = "addresses use it", body = Problem)))]
pub(crate) async fn remove_domain(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(name): Path<String>,
) -> Response {
    let result = async { state.identity.admin_remove_domain(&admin, &domain(&name)?).await }.await;
    respond(result, no_content)
}

/// The `kernoid-tenant` header, for the OpenAPI description.
#[derive(utoipa::IntoParams)]
#[into_params(parameter_in = Header)]
pub(crate) struct TenantHeader {
    /// The tenant to act on – for instance administrators; the caller's own tenant if left out.
    #[param(rename = "kernoid-tenant")]
    #[allow(dead_code)]
    tenant: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RecordCheckView {
    /// `MX`, `SPF`, `DKIM` or `DMARC`.
    kind: String,
    /// The name the record belongs at.
    name: String,
    /// `MX` or `TXT`.
    record_type: String,
    /// What to publish.
    expected: String,
    /// What DNS has now.
    found: Vec<String>,
    /// `ok`, `missing` or `different`.
    status: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct MailDnsView {
    domain: String,
    records: Vec<RecordCheckView>,
}

/// The tenant's verified domains as mail domains of kernoid: the DNS records to publish (MX, SPF, DKIM, DMARC) and
/// whether they are published (needs `directory.read`; reads DNS, changes nothing).
#[utoipa::path(get, path = "/v1/tenant/mail-dns", tag = "tenant", params(TenantHeader), responses(
    (status = 200, body = [MailDnsView]),
    (status = 400, description = "this installation does not handle mail", body = Problem),
))]
pub(crate) async fn mail_dns(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    let tenant = match state.identity.admin_tenant(&admin).await {
        Ok(tenant) => tenant,
        Err(error) => return crate::sessions::problem(error),
    };
    let Some(checker) = &state.mail_dns else {
        return crate::sessions::problem(IdentityError::Refused("this installation does not handle mail".into()));
    };
    let mut views = Vec::new();
    for domain in tenant.domains.into_iter().filter(|domain| domain.verified) {
        let records = checker
            .check(&domain.domain)
            .await
            .into_iter()
            .map(|check| RecordCheckView {
                kind: check.kind.into(),
                name: check.name,
                record_type: check.record_type.into(),
                expected: check.expected,
                found: check.found,
                status: check.status.as_str().into(),
            })
            .collect();
        views.push(MailDnsView { domain: domain.domain, records });
    }
    Json(views).into_response()
}
