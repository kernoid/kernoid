// SPDX-License-Identifier: AGPL-3.0-or-later
//! Applications (OpenID Connect clients) of the tenant administered.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kernoid_oidc::{
    OidcError,
    application::{AppOptions, ApplicationInfo, Kind, TokenFormat},
};
use serde::{Deserialize, Serialize};

use super::{AdminSession, id, no_content, respond_oidc, tenant::TenantHeader};
use crate::{AppState, Problem};

pub(crate) fn kind(value: &str) -> Result<Kind, OidcError> {
    match value {
        "confidential" => Ok(Kind::Confidential),
        "public" => Ok(Kind::Public),
        _ => Err(OidcError::InvalidRequest("an application is confidential or public".into())),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ApplicationView {
    /// The `client_id`.
    id: String,
    name: String,
    /// `confidential` or `public`.
    kind: String,
    project: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    mfa_required: bool,
    active: bool,
    options: OptionsView,
}

/// What an application may do beyond the basic flow, and how it learns of logouts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct OptionsView {
    /// `opaque` (checked with kernoid at userinfo or introspection) or `jwt` (RFC 9068, checked by the resource
    /// server itself).
    #[serde(default = "opaque")]
    access_token_format: String,
    /// May ask for `offline_access`: refresh tokens that outlive the session, with the person's consent.
    #[serde(default)]
    offline_access: bool,
    /// Asks the person to agree before the first login.
    #[serde(default)]
    consent_required: bool,
    /// Receives a logout token when a session it logged in to ends (Back-Channel Logout 1.0); HTTPS, public.
    #[serde(default)]
    backchannel_logout_uri: Option<String>,
    /// Loaded in a frame when the person logs out through kernoid (Front-Channel Logout 1.0); HTTPS.
    #[serde(default)]
    frontchannel_logout_uri: Option<String>,
}

fn opaque() -> String {
    "opaque".into()
}

impl From<AppOptions> for OptionsView {
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

impl OptionsView {
    pub(crate) fn options(&self) -> Result<AppOptions, OidcError> {
        let access_token_format = match self.access_token_format.as_str() {
            "opaque" => TokenFormat::Opaque,
            "jwt" => TokenFormat::Jwt,
            _ => return Err(OidcError::InvalidRequest("access_token_format is opaque or jwt".into())),
        };
        Ok(AppOptions {
            access_token_format,
            offline_access: self.offline_access,
            consent_required: self.consent_required,
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            frontchannel_logout_uri: self.frontchannel_logout_uri.clone(),
        })
    }
}

impl From<ApplicationInfo> for ApplicationView {
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewApplication {
    project: String,
    name: String,
    /// `confidential` (a server, with a secret) or `public` (browser and mobile apps, PKCE only).
    kind: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ApplicationCreated {
    /// The `client_id`.
    id: String,
    /// For a confidential application: its secret, shown this once.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct ApplicationChange {
    name: Option<String>,
    /// Move it to another project of the tenant.
    project: Option<String>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    active: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Policy {
    mfa_required: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ClientSecret {
    /// Shown this once.
    client_secret: String,
}

/// The tenant's applications (needs `directory.read`).
#[utoipa::path(get, path = "/v1/applications", tag = "applications", params(TenantHeader),
    responses((status = 200, body = [ApplicationView])))]
pub(crate) async fn list(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond_oidc(state.oidc.admin_applications(&admin).await, |list| {
        Json(list.into_iter().map(ApplicationView::from).collect::<Vec<_>>()).into_response()
    })
}

/// Registers an application in a project of the tenant (needs `applications.manage`).
#[utoipa::path(post, path = "/v1/applications", tag = "applications", params(TenantHeader),
    request_body = NewApplication, responses((status = 201, body = ApplicationCreated), (status = 400, body = Problem)))]
pub(crate) async fn add(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewApplication>,
) -> Response {
    let result = async {
        let project = id(&body.project, "the project")?;
        let kind = kind(&body.kind)?;
        let uris = (&body.redirect_uris, &body.post_logout_redirect_uris);
        state.oidc.admin_add_application(&admin, project, &body.name, kind, uris.0, uris.1).await
    }
    .await;
    respond_oidc(result, |(id, client_secret)| {
        (StatusCode::CREATED, Json(ApplicationCreated { id: id.to_string(), client_secret })).into_response()
    })
}

/// One application (needs `directory.read`).
#[utoipa::path(get, path = "/v1/applications/{id}", tag = "applications", params(TenantHeader),
    responses((status = 200, body = ApplicationView), (status = 404, body = Problem)))]
pub(crate) async fn get(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(application): Path<String>,
) -> Response {
    let result = async { state.oidc.admin_application(&admin, id(&application, "the application")?).await }.await;
    respond_oidc(result, |info| Json(ApplicationView::from(info)).into_response())
}

/// Changes an application (needs `applications.manage`).
#[utoipa::path(patch, path = "/v1/applications/{id}", tag = "applications", params(TenantHeader),
    request_body = ApplicationChange, responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn change(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(application): Path<String>,
    Json(body): Json<ApplicationChange>,
) -> Response {
    let result: Result<(), OidcError> = async {
        let application = id(&application, "the application")?;
        if let Some(name) = &body.name {
            state.oidc.admin_rename_application(&admin, application, name).await?;
        }
        if let Some(project) = &body.project {
            state.oidc.admin_set_application_project(&admin, application, id(project, "the project")?).await?;
        }
        if let Some(uris) = &body.redirect_uris {
            state.oidc.admin_set_redirect_uris(&admin, application, uris).await?;
        }
        if let Some(uris) = &body.post_logout_redirect_uris {
            state.oidc.admin_set_post_logout_redirect_uris(&admin, application, uris).await?;
        }
        if let Some(active) = body.active {
            state.oidc.admin_set_application_active(&admin, application, active).await?;
        }
        Ok(())
    }
    .await;
    respond_oidc(result, no_content)
}

/// Sets whether logins to the application need a second factor, on top of the tenant's policy (needs
/// `applications.manage`).
#[utoipa::path(put, path = "/v1/applications/{id}/policy", tag = "applications", params(TenantHeader),
    request_body = Policy, responses((status = 200, body = ApplicationView), (status = 404, body = Problem)))]
pub(crate) async fn set_policy(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(application): Path<String>,
    Json(policy): Json<Policy>,
) -> Response {
    let result = async {
        let application = id(&application, "the application")?;
        state.oidc.admin_set_application_mfa_required(&admin, application, policy.mfa_required).await?;
        state.oidc.admin_application(&admin, application).await
    }
    .await;
    respond_oidc(result, |info| Json(ApplicationView::from(info)).into_response())
}

/// Replaces the secret of a confidential application (needs `applications.manage`).
#[utoipa::path(post, path = "/v1/applications/{id}/secret", tag = "applications", params(TenantHeader),
    responses((status = 200, body = ClientSecret), (status = 400, description = "a public application", body = Problem)))]
pub(crate) async fn new_secret(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(application): Path<String>,
) -> Response {
    let result = async { state.oidc.admin_new_client_secret(&admin, id(&application, "the application")?).await }.await;
    respond_oidc(result, |client_secret| Json(ClientSecret { client_secret }).into_response())
}

/// Sets the application's options: token format, offline access, consent, logout notifications (needs
/// `applications.manage`).
#[utoipa::path(put, path = "/v1/applications/{id}/options", tag = "applications", params(TenantHeader),
    request_body = OptionsView, responses((status = 200, body = ApplicationView), (status = 400, body = Problem)))]
pub(crate) async fn set_options(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(application): Path<String>,
    Json(body): Json<OptionsView>,
) -> Response {
    let result = async {
        let application = id(&application, "the application")?;
        state.oidc.admin_set_application_options(&admin, application, &body.options()?).await?;
        state.oidc.admin_application(&admin, application).await
    }
    .await;
    respond_oidc(result, |info| Json(ApplicationView::from(info)).into_response())
}
