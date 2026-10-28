// SPDX-License-Identifier: AGPL-3.0-or-later
//! SCIM tokens of the tenant administered: what its directory provisions accounts and groups with (`/scim/v2`).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::provisioning::ScimTokenInfo;
use serde::{Deserialize, Serialize};

use super::{AdminSession, id, no_content, respond, tenant::TenantHeader};
use crate::{AppState, CurrentInstance};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ScimTokenView {
    id: String,
    name: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl From<ScimTokenInfo> for ScimTokenView {
    fn from(info: ScimTokenInfo) -> Self {
        Self { id: info.id.to_string(), name: info.name, created_at: info.created_at, last_used_at: info.last_used_at }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewScimToken {
    /// E.g. the directory's name.
    name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ScimTokenCreated {
    id: String,
    /// The bearer token for the directory – shown this once.
    token: String,
    /// The SCIM base URL to give the directory.
    endpoint: String,
}

/// The tenant's SCIM tokens (needs `directory.read`).
#[utoipa::path(get, path = "/v1/scim-tokens", tag = "provisioning", params(TenantHeader),
    responses((status = 200, body = [ScimTokenView])))]
pub(crate) async fn list(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_scim_tokens(&admin).await, |list| {
        Json(list.into_iter().map(ScimTokenView::from).collect::<Vec<_>>()).into_response()
    })
}

/// A new SCIM token for the tenant's directory (needs `provisioning.manage`).
#[utoipa::path(post, path = "/v1/scim-tokens", tag = "provisioning", params(TenantHeader), request_body = NewScimToken,
    responses((status = 201, body = ScimTokenCreated)))]
pub(crate) async fn add(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewScimToken>,
) -> Response {
    let endpoint = format!("{}/scim/v2", state.oidc.issuer(&instance.primary_domain));
    respond(state.identity.admin_add_scim_token(&admin, &body.name).await, |(id, token)| {
        (StatusCode::CREATED, Json(ScimTokenCreated { id: id.to_string(), token, endpoint })).into_response()
    })
}

/// Revokes a SCIM token (needs `provisioning.manage`).
#[utoipa::path(delete, path = "/v1/scim-tokens/{id}", tag = "provisioning", params(TenantHeader),
    responses((status = 204)))]
pub(crate) async fn remove(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(token): Path<String>,
) -> Response {
    let result = async { state.identity.admin_remove_scim_token(&admin, id(&token, "the SCIM token")?).await }.await;
    respond(result, no_content)
}
