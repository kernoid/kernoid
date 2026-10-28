// SPDX-License-Identifier: AGPL-3.0-or-later
//! App passwords of one's own account (`/v1/account/app-passwords`): for mail programs, which log in with an address
//! and a password and cannot ask for a second factor (RFC 0002, 10.1).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState, CurrentInstance, Problem,
    sessions::{SessionToken, problem},
};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AppPasswordView {
    id: String,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct AppPasswordName {
    /// Which device or program it is for, e.g. "Thunderbird at home".
    name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AppPasswordCreated {
    id: String,
    /// The app password – shown this once.
    password: String,
}

/// The app passwords of one's own account (never the passwords themselves).
#[utoipa::path(get, path = "/v1/account/app-passwords", tag = "account", responses((status = 200, body = Vec<AppPasswordView>)))]
pub(crate) async fn list(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    match state.identity.own_app_passwords(instance.id, &token).await {
        Ok(list) => Json(
            list.into_iter()
                .map(|info| AppPasswordView {
                    id: info.id.to_string(),
                    name: info.name,
                    created_at: info.created_at,
                    last_used_at: info.last_used_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => problem(error),
    }
}

/// Makes an app password for one's own account (needs a recent login); the answer holds it, this once.
#[utoipa::path(post, path = "/v1/account/app-passwords", tag = "account", request_body = AppPasswordName, responses(
    (status = 201, body = AppPasswordCreated),
    (status = 401, description = "no recent login", body = Problem),
))]
pub(crate) async fn add(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<AppPasswordName>,
) -> Response {
    match state.identity.add_own_app_password(instance.id, &token, &body.name).await {
        Ok((id, password)) => {
            (StatusCode::CREATED, Json(AppPasswordCreated { id: id.to_string(), password })).into_response()
        }
        Err(error) => problem(error),
    }
}

/// Removes an app password of one's own account: the program using it can no longer log in.
#[utoipa::path(delete, path = "/v1/account/app-passwords/{id}", tag = "account", params(("id" = String, Path)), responses(
    (status = 204, description = "removed"),
    (status = 404, description = "no such app password", body = Problem),
))]
pub(crate) async fn remove(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    match state.identity.remove_own_app_password(instance.id, &token, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}
