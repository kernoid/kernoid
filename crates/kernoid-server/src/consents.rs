// SPDX-License-Identifier: AGPL-3.0-or-later
//! Consents: what an account agreed applications may have – for the account itself (the account page) and for
//! administrators of its tenant. Withdrawing one also withdraws the application's tokens for the account.

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::consent::ConsentInfo;
use serde::Serialize;

use crate::{
    AppState, CurrentInstance, Problem,
    admin::{AdminSession, id, no_content, respond_oidc, tenant::TenantHeader},
    oidc, sessions,
};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ConsentView {
    application: String,
    application_name: String,
    scopes: Vec<String>,
    granted_at: DateTime<Utc>,
}

impl From<ConsentInfo> for ConsentView {
    fn from(info: ConsentInfo) -> Self {
        Self {
            application: info.application.to_string(),
            application_name: info.application_name,
            scopes: info.scopes,
            granted_at: info.granted_at,
        }
    }
}

fn list_response(list: Vec<ConsentInfo>) -> Response {
    Json(list.into_iter().map(ConsentView::from).collect::<Vec<_>>()).into_response()
}

/// The applications one's own account agreed to, with the scopes.
#[utoipa::path(get, path = "/v1/account/consents", tag = "account", responses(
    (status = 200, body = [ConsentView]),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn own(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
) -> Response {
    let result = async {
        let session = state.identity.session(instance.id, &token).await?;
        state.identity.consents(session.account.id).await
    }
    .await;
    match result {
        Ok(list) => list_response(list),
        Err(error) => sessions::problem(error),
    }
}

/// Withdraws one's own consent to an application, and the application's tokens – offline access included.
#[utoipa::path(delete, path = "/v1/account/consents/{application}", tag = "account", responses(
    (status = 204),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, body = Problem),
))]
pub(crate) async fn revoke_own(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Path(application): Path<String>,
) -> Response {
    let result = async {
        let application = id(&application, "the consent")?;
        state.oidc.revoke_own_consent(instance.id, &token, application).await
    }
    .await;
    match result {
        Ok(()) => no_content(()),
        Err(error) => oidc::problem(error),
    }
}

/// The applications an account agreed to (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/consents", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = [ConsentView]), (status = 404, body = Problem)))]
pub(crate) async fn list(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.oidc.admin_account_consents(&admin, id(&account, "the account")?).await }.await;
    respond_oidc(result, list_response)
}

/// Withdraws an account's consent to an application and the application's tokens for it (needs `accounts.manage`
/// and every permission the account holds).
#[utoipa::path(delete, path = "/v1/accounts/{id}/consents/{application}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn revoke(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, application)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (account, application) = (id(&account, "the account")?, id(&application, "the consent")?);
        state.oidc.admin_revoke_consent(&admin, account, application).await
    }
    .await;
    respond_oidc(result, no_content)
}
