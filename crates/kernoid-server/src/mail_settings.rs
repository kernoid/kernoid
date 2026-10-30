// SPDX-License-Identifier: AGPL-3.0-or-later
//! The settings of one's own mail store (`kernoid_mail::MailSettings`): how long its Trash keeps emails, and the
//! address new emails come from.

use axum::{
    Json,
    extract::{Path, State},
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
    /// Seconds an email waits before it goes out, to be taken back (0 to 30); 0 sends at once.
    undo_send_seconds: i32,
    /// The names the account gives its own and shared mailboxes, by their JMAP account id; others show their address.
    mailbox_names: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct MailSettingsChange {
    /// 1 to 3650; null follows the tenant.
    trash_retention_days: Option<i32>,
    /// An address the account may send from; null is its primary address.
    default_from: Option<String>,
    /// 0 to 30; left out, emails go out at once.
    #[serde(default)]
    undo_send_seconds: i32,
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
        let session = state.identity.data_session(instance.id, &token).await?;
        let settings = mail(&state)?.settings(session.account.id).await?;
        Ok::<_, MailAdminError>(MailSettingsView {
            trash_retention_days: settings.trash_retention_days,
            tenant_trash_retention_days: settings.tenant_trash_retention_days,
            default_from: settings.default_from,
            undo_send_seconds: settings.undo_send_seconds,
            mailbox_names: settings.mailbox_names.into_iter().map(|(store, name)| (store.to_string(), name)).collect(),
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
        let session = state.identity.data_session(instance.id, &token).await?;
        mail(&state)?
            .set_settings(
                session.account.id,
                body.trash_retention_days,
                body.default_from.as_deref(),
                body.undo_send_seconds,
            )
            .await?;
        Ok::<_, MailAdminError>(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct MailboxName {
    /// Up to 64 characters; empty shows the mailbox's address again.
    name: String,
}

/// Names one's own mailbox or a shared one, for oneself.
#[utoipa::path(put, path = "/v1/account/mail-settings/mailbox-names/{account}", tag = "account",
    params(("account" = String, Path, description = "the mailbox's JMAP account id")),
    request_body = MailboxName, responses(
    (status = 204),
    (status = 400, description = "too long", body = Problem),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, description = "not a mailbox the account reaches", body = Problem),
))]
pub(crate) async fn name_mailbox(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Path(store): Path<uuid::Uuid>,
    Json(body): Json<MailboxName>,
) -> Response {
    let result = async {
        let session = state.identity.data_session(instance.id, &token).await?;
        mail(&state)?.set_mailbox_name(session.account.id, store, &body.name).await?;
        Ok::<_, MailAdminError>(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}
