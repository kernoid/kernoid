// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts, logins and services administered (RFC 0003): external accounts, usernames, contact addresses, the
//! services an account uses, and the tenant's rules for logins, registration and services.

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use kernoid_identity::{
    DomainName, IdentityError,
    services::{Assign, Service, ServicePolicy, ServiceState},
};
use serde::{Deserialize, Serialize};

use super::{AdminSession, created, id, no_content, respond, tenant::TenantHeader};
use crate::{AppState, Problem};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ServiceView {
    /// `mail` or `files`.
    service: String,
    /// `on`, or `requested` – waiting for an administrator.
    state: String,
}

fn services(list: Vec<(Service, ServiceState)>) -> Response {
    Json(
        list.into_iter()
            .map(|(service, state)| ServiceView { service: service.as_str().into(), state: state.as_str().into() })
            .collect::<Vec<_>>(),
    )
    .into_response()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewExternalAccount {
    display_name: String,
    /// A contact address of any domain; the person confirms it at their next login with it.
    email: Option<String>,
    /// Where the tenant uses usernames.
    username: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct UsernameChange {
    /// Null removes it.
    username: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ContactChange {
    /// Any domain; null removes it.
    email: Option<String>,
    /// Verified addresses log in and are unique in the instance.
    #[serde(default)]
    verified: bool,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct LoginPolicyView {
    /// Accounts may have usernames to log in with.
    usernames: bool,
    /// A verified contact address logs in as well.
    email_login: bool,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RegistrationView {
    allowed: bool,
    /// Verified domains of the tenant on which new accounts may take an address – a mailbox.
    domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ServicePolicyView {
    /// `mail` or `files`; ignored in a request.
    #[serde(default)]
    service: String,
    /// Who gets it when an account is created: `none`, `native` or `all`.
    assign: String,
    /// New accounts get it only as requested, until an administrator grants it.
    approval: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct RegistrationTenant {
    /// Where people without an address of a tenant register; null: nowhere.
    tenant: Option<String>,
}

/// Creates an account without an address of the tenant: for logins only – and files, if granted (needs
/// `accounts.manage`).
#[utoipa::path(post, path = "/v1/external-accounts", tag = "accounts", params(TenantHeader),
    request_body = NewExternalAccount, responses((status = 201, body = super::Created), (status = 409, body = Problem)))]
pub(crate) async fn add_external(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewExternalAccount>,
) -> Response {
    let result = state
        .identity
        .admin_add_external_account(&admin, &body.display_name, body.email.as_deref(), body.username.as_deref())
        .await;
    respond(result, created)
}

/// The services of an account (needs `directory.read`).
#[utoipa::path(get, path = "/v1/accounts/{id}/services", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = [ServiceView]), (status = 404, body = Problem)))]
pub(crate) async fn list_services(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.identity.admin_services(&admin, id(&account, "the account")?).await }.await;
    respond(result, services)
}

/// Grants a service – also one an account requested (needs `accounts.manage`); `mail` only to an account with an
/// address of the tenant.
#[utoipa::path(put, path = "/v1/accounts/{id}/services/{service}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 400, body = Problem), (status = 404, body = Problem)))]
pub(crate) async fn grant_service(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, service)): Path<(String, String)>,
) -> Response {
    let result = async {
        let service = Service::parse(&service)?;
        state.identity.admin_grant_service(&admin, id(&account, "the account")?, service).await
    }
    .await;
    respond(result, no_content)
}

/// Takes a service away (needs `accounts.manage`); a mail store stays until the account is removed.
#[utoipa::path(delete, path = "/v1/accounts/{id}/services/{service}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn revoke_service(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, service)): Path<(String, String)>,
) -> Response {
    let result = async {
        let service = Service::parse(&service)?;
        state.identity.admin_revoke_service(&admin, id(&account, "the account")?, service).await
    }
    .await;
    respond(result, no_content)
}

/// Gives an account a username, or takes it away (needs `accounts.manage`; the tenant must use usernames).
#[utoipa::path(put, path = "/v1/accounts/{id}/username", tag = "accounts", params(TenantHeader),
    request_body = UsernameChange, responses((status = 204), (status = 400, body = Problem), (status = 409, body = Problem)))]
pub(crate) async fn set_username(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<UsernameChange>,
) -> Response {
    let result = async {
        state.identity.admin_set_username(&admin, id(&account, "the account")?, body.username.as_deref()).await
    }
    .await;
    respond(result, no_content)
}

/// Sets an account's contact address (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/contact", tag = "accounts", params(TenantHeader),
    request_body = ContactChange, responses((status = 204), (status = 409, body = Problem)))]
pub(crate) async fn set_contact(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<ContactChange>,
) -> Response {
    let result = async {
        let account = id(&account, "the account")?;
        state.identity.admin_set_contact_email(&admin, account, body.email.as_deref(), body.verified).await
    }
    .await;
    respond(result, no_content)
}

/// How the tenant's accounts log in (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/login-policy", tag = "tenant", params(TenantHeader),
    responses((status = 200, body = LoginPolicyView)))]
pub(crate) async fn login_policy(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_login_policy(&admin).await, |policy| {
        Json(LoginPolicyView { usernames: policy.usernames, email_login: policy.email_login }).into_response()
    })
}

/// Sets how the tenant's accounts log in (needs `policies.manage`).
#[utoipa::path(put, path = "/v1/tenant/login-policy", tag = "tenant", params(TenantHeader),
    request_body = LoginPolicyView, responses((status = 204)))]
pub(crate) async fn set_login_policy(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<LoginPolicyView>,
) -> Response {
    respond(state.identity.admin_set_login_policy(&admin, body.usernames, body.email_login).await, no_content)
}

/// Whether people may register with the tenant, and on which domains (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/registration", tag = "tenant", params(TenantHeader),
    responses((status = 200, body = RegistrationView)))]
pub(crate) async fn registration(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_registration(&admin).await, |(allowed, domains)| {
        Json(RegistrationView { allowed, domains }).into_response()
    })
}

/// Opens or closes registration, and names the domains new accounts may take an address on (needs
/// `policies.manage`).
#[utoipa::path(put, path = "/v1/tenant/registration", tag = "tenant", params(TenantHeader),
    request_body = RegistrationView, responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn set_registration(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<RegistrationView>,
) -> Response {
    let result = async {
        let domains = body
            .domains
            .iter()
            .map(|domain| DomainName::parse(domain).map_err(|e| IdentityError::Refused(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        state.identity.admin_set_registration(&admin, body.allowed, &domains).await
    }
    .await;
    respond(result, no_content)
}

/// The tenant's rules for each service (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/service-policies", tag = "tenant", params(TenantHeader),
    responses((status = 200, body = [ServicePolicyView])))]
pub(crate) async fn service_policies(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_service_policies(&admin).await, |list| {
        Json(
            list.into_iter()
                .map(|(service, rule)| ServicePolicyView {
                    service: service.as_str().into(),
                    assign: rule.assign.as_str().into(),
                    approval: rule.approval,
                })
                .collect::<Vec<_>>(),
        )
        .into_response()
    })
}

/// Sets who gets a service when an account is created, and whether it needs approval (needs `policies.manage`).
#[utoipa::path(put, path = "/v1/tenant/service-policies/{service}", tag = "tenant", params(TenantHeader),
    request_body = ServicePolicyView, responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn set_service_policy(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(service): Path<String>,
    Json(body): Json<ServicePolicyView>,
) -> Response {
    let result = async {
        let service = Service::parse(&service)?;
        let rule = ServicePolicy { assign: Assign::parse(&body.assign)?, approval: body.approval };
        state.identity.admin_set_service_policy(&admin, service, rule).await
    }
    .await;
    respond(result, no_content)
}

/// Names the tenant where people without an address of a tenant register (needs `instance.manage`).
#[utoipa::path(put, path = "/v1/instance/registration-tenant", tag = "instance", request_body = RegistrationTenant,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn set_registration_tenant(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<RegistrationTenant>,
) -> Response {
    let result = async {
        let tenant = body.tenant.as_deref().map(|tenant| id(tenant, "the tenant")).transpose()?;
        state.identity.admin_set_registration_tenant(&admin, tenant).await
    }
    .await;
    respond(result, no_content)
}
