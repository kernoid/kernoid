// SPDX-License-Identifier: AGPL-3.0-or-later
//! The settings of one's own mail store (`kernoid_mail::MailSettings`): how long its Trash keeps emails, and the
//! address new emails come from.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    AppState, CurrentInstance, Problem,
    mail_admin::{MailAdminError, mail, problem},
    sessions::SessionToken,
};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct MailSettingsView {
    /// Days the Trash keeps an email; null follows the tenant.
    trash_retention_days: Option<i32>,
    /// The tenant's days; null keeps emails in the Trash until they are deleted.
    tenant_trash_retention_days: Option<i32>,
    /// The address new emails come from; null is the account's primary address.
    default_from: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct MailSettingsChange {
    /// 1 to 3650; null follows the tenant.
    trash_retention_days: Option<i32>,
    /// An address the account may send from; null is its primary address.
    default_from: Option<String>,
}

#[utoipa::path(get, path = "/v1/account/mail-settings", tag = "account", responses(
    (status = 200, body = MailSettingsView),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, description = "the account has no mail", body = Problem),
))]
pub(crate) async fn get(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = async {
        let session = state.identity.session(instance.id, &token).await?;
        let settings = mail(&state)?.settings(session.account.id).await?;
        Ok::<_, MailAdminError>(MailSettingsView {
            trash_retention_days: settings.trash_retention_days,
            tenant_trash_retention_days: settings.tenant_trash_retention_days,
            default_from: settings.default_from,
        })
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(error) => problem(error),
    }
}

#[utoipa::path(put, path = "/v1/account/mail-settings", tag = "account", request_body = MailSettingsChange, responses(
    (status = 204),
    (status = 400, description = "days out of range, or an address the account may not send from", body = Problem),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, description = "the account has no mail", body = Problem),
))]
pub(crate) async fn set(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<MailSettingsChange>,
) -> Response {
    let result = async {
        let session = state.identity.session(instance.id, &token).await?;
        mail(&state)?.set_settings(session.account.id, body.trash_retention_days, body.default_from.as_deref()).await?;
        Ok::<_, MailAdminError>(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}
