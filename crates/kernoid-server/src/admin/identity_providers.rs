// SPDX-License-Identifier: AGPL-3.0-or-later
//! The identity providers of the tenant administered, and the external identities linked to its accounts.

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::link::LinkInfo;
use kernoid_oidc::federation::{IdpInfo, IdpSettings, SamlSettings};
use serde::{Deserialize, Serialize};

use super::{AdminSession, created, id, no_content, respond, respond_oidc, tenant::TenantHeader};
use crate::{AppState, CurrentInstance, Problem};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ProviderView {
    id: String,
    name: String,
    /// `oidc` or `saml`.
    kind: &'static str,
    /// OpenID Connect: the issuer. SAML: the provider's entity ID.
    issuer: String,
    client_id: String,
    /// SAML only.
    #[serde(skip_serializing_if = "Option::is_none")]
    saml: Option<SamlView>,
    scopes: Vec<String>,
    /// Mail domains whose logins go to this provider.
    domains: Vec<String>,
    auto_create: bool,
    auto_link: bool,
    /// The display name follows the provider's at every login.
    sync_profile: bool,
    /// Offered to everyone on the login page; creates accounts where the tenant allows registration (RFC 0003).
    register: bool,
    /// Serves the domains of every tenant of the instance (changed with `instance.manage`).
    instance_wide: bool,
    has_secret: bool,
    active: bool,
    /// Register this at the provider: the redirect URI (OpenID Connect) or the Assertion Consumer Service URL (SAML).
    redirect_uri: String,
    /// SAML: kernoid's entity ID at this instance – metadata at `/idp/saml/metadata`.
    #[serde(skip_serializing_if = "Option::is_none")]
    sp_entity_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct SamlView {
    /// Where kernoid sends the AuthnRequest (HTTP-Redirect binding).
    sso_url: String,
    /// The provider's signing certificates, base64 DER (PEM is accepted too).
    certificates: Vec<String>,
    email_attribute: Option<String>,
    name_attribute: Option<String>,
    /// Sign AuthnRequests with kernoid's SAML key of the instance.
    #[serde(default)]
    sign_requests: bool,
    /// The provider's single logout service (HTTP-Redirect binding).
    #[serde(default)]
    slo_url: Option<String>,
}

impl From<SamlView> for SamlSettings {
    fn from(view: SamlView) -> Self {
        Self {
            sso_url: view.sso_url,
            certificates: view.certificates,
            email_attribute: view.email_attribute,
            name_attribute: view.name_attribute,
            sign_requests: view.sign_requests,
            slo_url: view.slo_url,
        }
    }
}

fn view(info: IdpInfo, redirect_uri: String, sp_entity_id: String) -> ProviderView {
    let saml = info.settings.saml.clone().map(|saml| SamlView {
        sso_url: saml.sso_url,
        certificates: saml.certificates,
        email_attribute: saml.email_attribute,
        name_attribute: saml.name_attribute,
        sign_requests: saml.sign_requests,
        slo_url: saml.slo_url,
    });
    ProviderView {
        instance_wide: info.tenant.is_none(),
        sync_profile: info.settings.sync_profile,
        register: info.settings.register,
        sp_entity_id: saml.as_ref().map(|_| sp_entity_id),
        saml,
        id: info.id.to_string(),
        kind: info.settings.kind(),
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewProvider {
    name: String,
    /// OpenID Connect: the issuer. SAML: the provider's entity ID.
    issuer: String,
    /// OpenID Connect only.
    #[serde(default)]
    client_id: String,
    /// Set for a SAML 2.0 provider.
    saml: Option<SamlView>,
    /// The secret kernoid authenticates with at the provider; stored sealed, never shown again.
    client_secret: Option<String>,
    /// `openid` is added; `email` and `profile` let kernoid create and link accounts.
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    auto_create: bool,
    #[serde(default)]
    auto_link: bool,
    #[serde(default)]
    sync_profile: bool,
    /// Offered to everyone on the login page; creates accounts where the tenant allows registration.
    #[serde(default)]
    register: bool,
    /// For every tenant of the instance – their verified domains may be routed to it (needs `instance.manage`).
    #[serde(default)]
    instance_wide: bool,
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct ProviderChange {
    name: Option<String>,
    /// SAML settings, replacing the earlier ones.
    saml: Option<SamlView>,
    issuer: Option<String>,
    client_id: Option<String>,
    scopes: Option<Vec<String>>,
    domains: Option<Vec<String>>,
    auto_create: Option<bool>,
    auto_link: Option<bool>,
    sync_profile: Option<bool>,
    register: Option<bool>,
    active: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Secret {
    client_secret: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = IdpLinkView)]
pub(crate) struct LinkView {
    identity_provider: String,
    /// The account's `sub` at the provider.
    subject: String,
    created_at: DateTime<Utc>,
}

impl From<LinkInfo> for LinkView {
    fn from(link: LinkInfo) -> Self {
        Self { identity_provider: link.idp.to_string(), subject: link.subject, created_at: link.created_at }
    }
}

/// The tenant's identity providers, and those of the instance that serve every tenant (needs `directory.read`).
#[utoipa::path(get, path = "/v1/identity-providers", tag = "identity providers", params(TenantHeader),
    responses((status = 200, body = [ProviderView])))]
pub(crate) async fn list(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    AdminSession(admin): AdminSession,
) -> Response {
    let domain = instance.primary_domain.clone();
    let sp = state.oidc.saml_entity_id(&domain);
    respond_oidc(state.oidc.admin_identity_providers(&admin).await, |list| {
        let views = list.into_iter().map(|info| {
            let address = state.oidc.idp_return_address(&info, &domain);
            view(info, address, sp.clone())
        });
        Json(views.collect::<Vec<_>>()).into_response()
    })
}

/// Connects an identity provider (needs `identity_providers.manage`; for the whole instance, `instance.manage`).
/// Register the `redirect_uri` from the answer of `GET /v1/identity-providers/{id}` at the provider.
#[utoipa::path(post, path = "/v1/identity-providers", tag = "identity providers", params(TenantHeader),
    request_body = NewProvider, responses((status = 201, body = super::Created), (status = 400, body = Problem)))]
pub(crate) async fn add(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewProvider>,
) -> Response {
    let settings = IdpSettings {
        name: body.name,
        issuer: body.issuer,
        client_id: body.client_id,
        scopes: body.scopes,
        domains: body.domains,
        auto_create: body.auto_create,
        auto_link: body.auto_link,
        sync_profile: body.sync_profile,
        register: body.register,
        saml: body.saml.map(Into::into),
    };
    let secret = body.client_secret.as_deref();
    let result = state.oidc.admin_add_identity_provider(&admin, &settings, secret, body.instance_wide).await;
    respond_oidc(result, created)
}

/// One identity provider (needs `directory.read`).
#[utoipa::path(get, path = "/v1/identity-providers/{id}", tag = "identity providers", params(TenantHeader),
    responses((status = 200, body = ProviderView), (status = 404, body = Problem)))]
pub(crate) async fn get(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    AdminSession(admin): AdminSession,
    Path(idp): Path<String>,
) -> Response {
    let result = async { state.oidc.admin_identity_provider(&admin, id(&idp, "the identity provider")?).await }.await;
    let sp = state.oidc.saml_entity_id(&instance.primary_domain);
    respond_oidc(result, |info| {
        let address = state.oidc.idp_return_address(&info, &instance.primary_domain);
        Json(view(info, address, sp)).into_response()
    })
}

/// Changes an identity provider's settings, or switches it off and on (needs `identity_providers.manage`).
#[utoipa::path(patch, path = "/v1/identity-providers/{id}", tag = "identity providers", params(TenantHeader),
    request_body = ProviderChange, responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn change(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(idp): Path<String>,
    Json(body): Json<ProviderChange>,
) -> Response {
    let result: Result<(), kernoid_oidc::OidcError> = async {
        let idp = id(&idp, "the identity provider")?;
        let current = state.oidc.admin_identity_provider(&admin, idp).await?.settings;
        let settings = IdpSettings {
            name: body.name.unwrap_or(current.name),
            issuer: body.issuer.unwrap_or(current.issuer),
            client_id: body.client_id.unwrap_or(current.client_id),
            scopes: body.scopes.unwrap_or(current.scopes),
            domains: body.domains.unwrap_or(current.domains),
            auto_create: body.auto_create.unwrap_or(current.auto_create),
            auto_link: body.auto_link.unwrap_or(current.auto_link),
            sync_profile: body.sync_profile.unwrap_or(current.sync_profile),
            register: body.register.unwrap_or(current.register),
            saml: body.saml.map(Into::into).or(current.saml),
        };
        state.oidc.admin_update_identity_provider(&admin, idp, &settings).await?;
        if let Some(active) = body.active {
            state.oidc.admin_set_identity_provider_active(&admin, idp, active).await?;
        }
        Ok(())
    }
    .await;
    respond_oidc(result, no_content)
}

/// Removes an identity provider, once no account is linked to it (needs `identity_providers.manage`).
#[utoipa::path(delete, path = "/v1/identity-providers/{id}", tag = "identity providers", params(TenantHeader),
    responses((status = 204), (status = 400, description = "accounts are linked", body = Problem)))]
pub(crate) async fn remove(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(idp): Path<String>,
) -> Response {
    let result =
        async { state.oidc.admin_remove_identity_provider(&admin, id(&idp, "the identity provider")?).await }.await;
    respond_oidc(result, no_content)
}

/// Sets the client secret (needs `identity_providers.manage`).
#[utoipa::path(put, path = "/v1/identity-providers/{id}/secret", tag = "identity providers", params(TenantHeader),
    request_body = Secret, responses((status = 204)))]
pub(crate) async fn set_secret(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(idp): Path<String>,
    Json(body): Json<Secret>,
) -> Response {
    let result = async {
        let idp = id(&idp, "the identity provider")?;
        state.oidc.admin_set_identity_provider_secret(&admin, idp, Some(&body.client_secret)).await
    }
    .await;
    respond_oidc(result, no_content)
}

/// Removes the client secret – for providers that take PKCE alone (needs `identity_providers.manage`).
#[utoipa::path(delete, path = "/v1/identity-providers/{id}/secret", tag = "identity providers", params(TenantHeader),
    responses((status = 204)))]
pub(crate) async fn remove_secret(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(idp): Path<String>,
) -> Response {
    let result =
        async { state.oidc.admin_set_identity_provider_secret(&admin, id(&idp, "the identity provider")?, None).await }
            .await;
    respond_oidc(result, no_content)
}

/// Fetches the provider's discovery document and keys: whether kernoid reaches it as configured (needs
/// `identity_providers.manage`).
#[utoipa::path(post, path = "/v1/identity-providers/{id}/check", tag = "identity providers", params(TenantHeader),
    responses((status = 204), (status = 400, description = "what went wrong", body = Problem)))]
pub(crate) async fn check(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(idp): Path<String>,
) -> Response {
    let result =
        async { state.oidc.admin_check_identity_provider(&admin, id(&idp, "the identity provider")?).await }.await;
    respond_oidc(result, no_content)
}

/// The external identities linked to an account (needs `directory.read`).
#[utoipa::path(get, path = "/v1/accounts/{id}/links", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = [LinkView])))]
pub(crate) async fn links(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.identity.admin_account_links(&admin, id(&account, "the account")?).await }.await;
    respond(result, |list| Json(list.into_iter().map(LinkView::from).collect::<Vec<_>>()).into_response())
}

/// Unlinks an external identity from an account (needs `accounts.manage`).
#[utoipa::path(delete, path = "/v1/accounts/{id}/links/{idp}/{subject}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn unlink(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, idp, subject)): Path<(String, String, String)>,
) -> Response {
    let result = async {
        let (account, idp) = (id(&account, "the account")?, id(&idp, "the identity provider")?);
        state.identity.admin_unlink_account(&admin, account, idp, &subject).await
    }
    .await;
    respond(result, no_content)
}
