// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tenant administered: name, policy, modules, mail domains and the caller's permissions.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kernoid_identity::{CHALLENGE_LABEL, DomainName, IdentityError, admin::TenantPolicy};
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

/// Switches a module on or off for the tenant (needs `tenant.manage`). The module must be compiled in; whether it
/// runs is decided by the installation's configuration.
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
