// SPDX-License-Identifier: AGPL-3.0-or-later
//! Registering over HTTP (RFC 0003, 5): what an instance offers, starting a registration – which sends a code to the
//! email address through the queue, from `mail.notification_from` – and finishing it with the code.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use kernoid_identity::{IdentityError, registration::NewRegistration};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, Client, CurrentInstance, Problem, admin::id, sessions};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RegistrationOptionsView {
    /// People without an address of their own may register.
    open: bool,
    /// Domains on which new accounts may take an address – a mailbox.
    domains: Vec<String>,
    /// A username may be chosen.
    usernames: bool,
    /// kernoid can send the code; without it, registering works only with the providers.
    by_email: bool,
}

/// What registering offers at this instance; the providers to register with are at `/v1/login-providers`.
#[utoipa::path(get, path = "/v1/registration", tag = "login", responses((status = 200, body = RegistrationOptionsView)))]
pub(crate) async fn options(State(state): State<AppState>, CurrentInstance(instance): CurrentInstance) -> Response {
    match state.identity.registration_options(instance.id).await {
        Ok(options) => Json(RegistrationOptionsView {
            open: options.open,
            domains: options.domains,
            usernames: options.usernames,
            by_email: state.notification_from.is_some() && state.jmap.is_some(),
        })
        .into_response(),
        Err(error) => sessions::problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewRegistrationBody {
    /// The code goes here; it becomes the verified contact address.
    email: String,
    password: String,
    display_name: String,
    /// An address of one's own on one of the offered domains: an account with a mailbox.
    native_address: Option<String>,
    /// Where usernames are offered.
    username: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RegistrationStarted {
    /// Confirm with the code at `/v1/registrations/{id}/confirm`.
    id: String,
}

/// The message with the code.
fn code_message(from: &str, to: &str, code: &str) -> Vec<u8> {
    let date = Utc::now().to_rfc2822();
    let host = from.rsplit_once('@').map(|(_, domain)| domain).unwrap_or("kernoid");
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {code} – your code / Ihr Code\r\nDate: {date}\r\n\
         Message-ID: <{id}@{host}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n\
         Your code to finish registering: {code}\r\nIt is good for a day. If you did not register, ignore this message.\r\n\r\n\
         Ihr Code, um die Registrierung abzuschließen: {code}\r\nEr gilt einen Tag. Wenn Sie sich nicht registriert haben, \
         ignorieren Sie diese Nachricht.\r\n",
        id = Uuid::now_v7(),
    )
    .into_bytes()
}

/// Starts a registration: checks it, refuses what is taken (`409`: log in instead), and sends a code to the email
/// address. Nothing is stored as an account before the code is confirmed.
#[utoipa::path(post, path = "/v1/registrations", tag = "login", request_body = NewRegistrationBody, responses(
    (status = 202, body = RegistrationStarted),
    (status = 400, description = "not possible here, or not valid", body = Problem),
    (status = 409, description = "the address, username or email address is taken", body = Problem),
    (status = 429, description = "too many registrations from this address", body = Problem),
))]
pub(crate) async fn start(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    client: Option<Extension<Client>>,
    Json(body): Json<NewRegistrationBody>,
) -> Response {
    let new = NewRegistration {
        email: &body.email,
        password: &body.password,
        display_name: &body.display_name,
        native_address: body.native_address.as_deref(),
        username: body.username.as_deref(),
    };
    match begin(&state, instance.id, new, client.as_ref().map(|client| client.0.address)).await {
        Ok(id) => (StatusCode::ACCEPTED, Json(RegistrationStarted { id: id.to_string() })).into_response(),
        Err(error) => sessions::problem(error),
    }
}

/// Starts a registration and sends its code – for REST and GraphQL.
pub(crate) async fn begin(
    state: &AppState,
    instance: Uuid,
    new: NewRegistration<'_>,
    client: Option<std::net::IpAddr>,
) -> Result<Uuid, IdentityError> {
    let (Some(from), Some(jmap)) = (state.notification_from.clone(), state.jmap.clone()) else {
        return Err(IdentityError::Refused("registering by email is not possible here".into()));
    };
    let started = state.identity.start_registration(instance, new, client).await?;
    let recipients = [started.email.clone()];
    let outgoing = kernoid_mail::Outgoing {
        tenant: started.tenant,
        account: None,
        from: &from,
        recipients: &recipients,
        raw: code_message(&from, &started.email, &started.code).into(),
        lifetime: chrono::Duration::days(1),
    };
    if let Err(error) = jmap.mail().enqueue(outgoing).await {
        tracing::error!(%error, "queueing a registration code");
        return Err(IdentityError::Refused("the code could not be sent; try again later".into()));
    }
    Ok(started.id)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Confirmation {
    code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct Registered {
    /// The new account; log in with the address or username and the password.
    account: String,
}

/// Finishes a registration with the code from the message: the account is created.
#[utoipa::path(post, path = "/v1/registrations/{id}/confirm", tag = "login", request_body = Confirmation, responses(
    (status = 201, body = Registered),
    (status = 401, description = "wrong, expired or used code", body = Problem),
))]
pub(crate) async fn confirm(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(registration): Path<String>,
    Json(body): Json<Confirmation>,
) -> Response {
    let result = async {
        let registration = id(&registration, "the registration").map_err(|_| IdentityError::InvalidCode)?;
        state.identity.finish_registration(instance.id, registration, &body.code).await
    }
    .await;
    match result {
        Ok(account) => (StatusCode::CREATED, Json(Registered { account: account.to_string() })).into_response(),
        Err(error) => sessions::problem(error),
    }
}
