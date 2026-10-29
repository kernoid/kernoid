// SPDX-License-Identifier: AGPL-3.0-or-later
//! The session API (RFC 0001, section 7): log in with address and password, look at the current session, log out.
//! The session token is sent as `Authorization: Bearer <token>`.

use std::time::Duration;

use axum::{
    Json,
    extract::{Extension, FromRef, FromRequestParts, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::{
    IdentityError,
    account::AccountInfo,
    session::{ClientMeta, NewSession, SessionInfo},
};
use serde::{Deserialize, Serialize};

use crate::{AppState, Client, CurrentInstance, Problem};

/// The problem an identity error is for the caller; internal errors are logged, never shown.
pub(crate) fn problem(error: IdentityError) -> Response {
    let status = match &error {
        IdentityError::InvalidCredentials
        | IdentityError::InvalidSession
        | IdentityError::InvalidCode
        | IdentityError::PasskeyRejected => StatusCode::UNAUTHORIZED,
        IdentityError::RecentLoginRequired => {
            // The login UI recognises this by its type and logs the person in again.
            let mut problem = Problem::new(StatusCode::UNAUTHORIZED).detail(error.to_string());
            problem.kind = "urn:kernoid:problem:login-required".into();
            return problem.into_response();
        }
        IdentityError::MfaRequired => {
            // The login UI recognises this by its type and asks for a second factor.
            let mut problem = Problem::new(StatusCode::UNAUTHORIZED).detail(error.to_string());
            problem.kind = "urn:kernoid:problem:mfa-required".into();
            return problem.into_response();
        }
        IdentityError::AccountDeactivated | IdentityError::Forbidden(_) => StatusCode::FORBIDDEN,
        IdentityError::TooManyAttempts { .. } => StatusCode::TOO_MANY_REQUESTS,
        IdentityError::NotFound(_) => StatusCode::NOT_FOUND,
        IdentityError::Exists(_) | IdentityError::DomainTaken(_) | IdentityError::AddressTaken(_) => {
            StatusCode::CONFLICT
        }
        IdentityError::Refused(_) | IdentityError::Verification(_) => StatusCode::BAD_REQUEST,
        IdentityError::Store(error) => {
            tracing::error!(%error, "identity store");
            return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
        }
    };
    let mut response = Problem::new(status).detail(error.to_string()).into_response();
    match error {
        IdentityError::TooManyAttempts { retry_after } => {
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry_after.as_secs()));
        }
        IdentityError::InvalidSession => {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        _ => {}
    }
    response
}

/// The bearer token of a request, if it has one.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim().to_owned())
}

/// Where a request comes from, as kept with a session.
pub(crate) fn client_meta(client: Option<&Client>, headers: &HeaderMap) -> ClientMeta {
    ClientMeta {
        address: client.map(|client| client.address),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

/// The session token – the bearer token, or the session cookie (with the CSRF check of [`crate::cookie`]) – or
/// `401`.
pub struct SessionToken(pub String);

impl<S> FromRequestParts<S> for SessionToken
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let state = AppState::from_ref(state);
        let instance = crate::instance::of_request(&state.identity, parts.extensions.get::<Client>())
            .await
            .map_err(IntoResponse::into_response)?;
        crate::cookie::session_token(&state, &parts.method, &parts.headers, instance.as_ref()).map(Self)
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateSession {
    /// The login name: an address of the account.
    address: String,
    password: String,
    /// How long the session lasts; 8 hours if left out, at most 30 days.
    lifetime_seconds: Option<u64>,
    /// The token of this device from an earlier login with this address: failed logins then count against the device,
    /// not the address, so others failing on purpose do not lock the account out here.
    device_token: Option<String>,
    /// For browsers: keep the session in an HttpOnly cookie instead of answering with the token.
    #[serde(default)]
    cookie: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AccountView {
    id: String,
    tenant: String,
    address: String,
    display_name: String,
}

impl From<AccountInfo> for AccountView {
    fn from(account: AccountInfo) -> Self {
        Self {
            id: account.id.to_string(),
            tenant: account.tenant.to_string(),
            address: account.address,
            display_name: account.display_name,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SessionCreated {
    id: String,
    /// The session token: shown this once, sent as `Authorization: Bearer <token>`. Left out when the session is kept
    /// in the cookie.
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    expires_at: DateTime<Utc>,
    account: AccountView,
    /// After a password login: keep it for this address, and send it with the next login (`device_token`).
    #[serde(skip_serializing_if = "Option::is_none")]
    device_token: Option<String>,
}

impl From<NewSession> for SessionCreated {
    fn from(session: NewSession) -> Self {
        Self {
            id: session.id.to_string(),
            token: Some(session.token),
            expires_at: session.expires_at,
            account: session.account.into(),
            device_token: session.device_token,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SessionView {
    id: String,
    account: AccountView,
    /// The checks the session passed, e.g. `password`.
    checks: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<SessionInfo> for SessionView {
    fn from(session: SessionInfo) -> Self {
        Self {
            id: session.id.to_string(),
            account: session.account.into(),
            checks: session.checks,
            created_at: session.created_at,
            expires_at: session.expires_at,
        }
    }
}

/// Logs in: checks address and password at the instance of this host and creates a session.
#[utoipa::path(post, path = "/v1/sessions", tag = "sessions", request_body = CreateSession, responses(
    (status = 201, body = SessionCreated),
    (status = 401, description = "address or password wrong", body = Problem),
    (status = 403, description = "the account or its tenant is deactivated", body = Problem),
    (status = 429, description = "too many failed attempts; see Retry-After", body = Problem),
))]
pub(crate) async fn create(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    client: Option<Extension<Client>>,
    headers: HeaderMap,
    Json(body): Json<CreateSession>,
) -> Response {
    let lifetime = body.lifetime_seconds.map(Duration::from_secs);
    let meta = client_meta(client.as_ref().map(|c| &c.0), &headers);
    let device = body.device_token.as_deref();
    match state
        .identity
        .create_session_on_device(instance.id, &body.address, &body.password, lifetime, &meta, device)
        .await
    {
        Ok(session) => session_created(&state, session, body.cookie),
        Err(error) => problem(error),
    }
}

/// The answer to a login: `201` with the session – and, for a browser that asked for it, the token in the HttpOnly
/// cookie instead of the body.
pub(crate) fn session_created(state: &AppState, session: NewSession, cookie: bool) -> Response {
    let set = cookie.then(|| crate::cookie::set(state, &session.token, session.expires_at));
    let mut created = SessionCreated::from(session);
    if set.is_some() {
        created.token = None;
    }
    let mut response = (StatusCode::CREATED, Json(created)).into_response();
    if let Some(set) = set {
        response.headers_mut().insert(header::SET_COOKIE, set);
    }
    response
}

impl SessionCreated {
    /// Without the token, which went into the cookie.
    pub(crate) fn without_token(mut self) -> Self {
        self.token = None;
        self
    }
}

/// The session of the bearer token.
#[utoipa::path(get, path = "/v1/sessions/current", tag = "sessions", responses(
    (status = 200, body = SessionView),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn current(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    match state.identity.session(instance.id, &token).await {
        Ok(session) => Json(SessionView::from(session)).into_response(),
        Err(error) => problem(error),
    }
}

/// Logs out: ends the session of the bearer token.
#[utoipa::path(delete, path = "/v1/sessions/current", tag = "sessions", responses(
    (status = 204, description = "ended"),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn terminate(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    match state.identity.terminate_session(instance.id, &token).await {
        Ok(()) => (StatusCode::NO_CONTENT, [(header::SET_COOKIE, crate::cookie::clear(&state))]).into_response(),
        Err(error) => problem(error),
    }
}

/// The valid sessions of the bearer token's account, newest first.
#[utoipa::path(get, path = "/v1/sessions", tag = "sessions", responses(
    (status = 200, body = [crate::admin::accounts::SessionSummaryView]),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn list(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    match state.identity.own_sessions(instance.id, &token).await {
        Ok(list) => Json(list.into_iter().map(crate::admin::accounts::SessionSummaryView::from).collect::<Vec<_>>())
            .into_response(),
        Err(error) => problem(error),
    }
}

/// Ends a session of the bearer token's own account – e.g. one left open on another device.
#[utoipa::path(delete, path = "/v1/sessions/{id}", tag = "sessions", responses(
    (status = 204, description = "ended"),
    (status = 404, description = "no such session of this account", body = Problem),
))]
pub(crate) async fn terminate_other(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let Ok(id) = uuid::Uuid::parse_str(&id) else { return problem(IdentityError::NotFound("the session")) };
    match state.identity.terminate_own_session(instance.id, &token, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct PasswordChange {
    current_password: String,
    new_password: String,
}

/// Changes the password of one's own account: needs a recent session and the current password. Every other session
/// of the account ends.
#[utoipa::path(put, path = "/v1/account/password", tag = "account", request_body = PasswordChange, responses(
    (status = 204),
    (status = 401, description = "wrong current password, or no recent session", body = Problem),
))]
pub(crate) async fn change_password(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<PasswordChange>,
) -> Response {
    let result =
        state.identity.change_own_password(instance.id, &token, &body.current_password, &body.new_password).await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct LanguageView {
    /// The account's own choice; null for the tenant's.
    language: Option<String>,
    /// What kernoid writes in for the account now.
    used: String,
    /// The languages kernoid writes in.
    available: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct LanguageChoice {
    /// `en`, `de`, or null for the tenant's.
    language: Option<String>,
}

/// The language of the emails kernoid writes to one's own account – invitations sent for it, notices.
#[utoipa::path(get, path = "/v1/account/language", tag = "account", responses(
    (status = 200, body = LanguageView),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn language(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    match state.identity.own_language(instance.id, &token).await {
        Ok((language, used)) => Json(LanguageView {
            language,
            used,
            available: kernoid_identity::language::LANGUAGES.iter().map(|code| (*code).to_owned()).collect(),
        })
        .into_response(),
        Err(error) => problem(error),
    }
}

/// Chooses that language; null follows the tenant's.
#[utoipa::path(put, path = "/v1/account/language", tag = "account", request_body = LanguageChoice, responses(
    (status = 204),
    (status = 400, description = "a language kernoid does not write", body = Problem),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn set_language(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<LanguageChoice>,
) -> Response {
    match state.identity.set_own_language(instance.id, &token, body.language.as_deref()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Profile {
    display_name: String,
}

/// Changes the display name of one's own account.
#[utoipa::path(patch, path = "/v1/account", tag = "account", request_body = Profile, responses(
    (status = 204),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn change_profile(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<Profile>,
) -> Response {
    match state.identity.rename_own_account(instance.id, &token, &body.display_name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(error),
    }
}
