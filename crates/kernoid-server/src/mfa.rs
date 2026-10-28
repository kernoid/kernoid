// SPDX-License-Identifier: AGPL-3.0-or-later
//! Further checks of a session over HTTP: TOTP and passkeys – setting them up for one's own account (`/v1/account/…`,
//! with a recent session), checking them (`/v1/sessions/current/…`) and logging in with a passkey alone
//! (`/v1/sessions/passkey/…`). WebAuthn options and answers are passed through as JSON, as the browser API uses them.

use std::time::Duration;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use kernoid_identity::{
    InstanceInfo,
    passkey::{Challenge, RelyingParty},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AppState, Client, CurrentInstance, Problem,
    sessions::{SessionCreated, SessionToken, SessionView, client_meta, problem},
};

/// The instance as the relying party of its passkeys.
pub(crate) fn relying_party(state: &AppState, instance: &InstanceInfo) -> RelyingParty {
    passkey_relying_party(&state.oidc, instance)
}

/// RP ID the instance's `passkey_rp_id`; origins every domain of the instance (with the issuer's scheme) and its own
/// login UI.
pub(crate) fn passkey_relying_party(oidc: &kernoid_oidc::Oidc, instance: &InstanceInfo) -> RelyingParty {
    RelyingParty {
        id: instance.passkey_rp_id.clone(),
        origins: passkey_origins(oidc, instance),
        name: instance.name.clone(),
    }
}

pub(crate) fn passkey_origins(oidc: &kernoid_oidc::Oidc, instance: &InstanceInfo) -> Vec<url::Url> {
    let mut origins: Vec<url::Url> =
        instance.domains.iter().filter_map(|domain| oidc.issuer(domain).parse().ok()).collect();
    let login_ui = instance.login_ui.as_deref().and_then(|url| url::Url::parse(url).ok());
    if let Some(origin) = login_ui.and_then(|url| url.origin().ascii_serialization().parse().ok()) {
        origins.push(origin);
    }
    origins
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RelatedOrigins {
    /// Origins that may use passkeys of this RP ID.
    origins: Vec<String>,
}

/// WebAuthn related origins (Level 3, 5.11): served at the RP ID, so that the instance's other domains and its own
/// login UI may use its passkeys.
pub(crate) async fn related_origins(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
) -> Response {
    let origins = passkey_origins(&state.oidc, &instance)
        .into_iter()
        .map(|origin| origin.origin().ascii_serialization())
        .collect();
    Json(RelatedOrigins { origins }).into_response()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ChallengeView {
    /// Send it back with the answer.
    challenge_id: String,
    /// For `navigator.credentials.create()` or `.get()`.
    #[schema(value_type = Object)]
    options: Value,
}

impl From<Challenge> for ChallengeView {
    fn from(challenge: Challenge) -> Self {
        Self { challenge_id: challenge.id, options: challenge.options }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Answer {
    challenge_id: String,
    /// What the browser returned, as JSON.
    #[schema(value_type = Object)]
    credential: Value,
    /// For a login: how long the session lasts; 8 hours if left out.
    lifetime_seconds: Option<u64>,
    /// For a registration: a name for the passkey, e.g. the device.
    name: Option<String>,
    /// For a login in a browser: keep the session in an HttpOnly cookie instead of answering with the token.
    #[serde(default)]
    cookie: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Code {
    /// Six digits from the app.
    code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct TotpSetupView {
    /// The secret in base32, for typing it in.
    secret: String,
    /// `otpauth://` URI for a QR code.
    uri: String,
    /// The URI as a QR code: an SVG image as a `data:` URL.
    qr_code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct PasskeyView {
    id: String,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct Created {
    id: String,
}

fn ok_or_problem<T>(result: Result<T, kernoid_identity::IdentityError>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => problem(error),
    }
}

/// Starts a login with a passkey – no address, no password.
#[utoipa::path(post, path = "/v1/sessions/passkey/start", tag = "sessions", responses(
    (status = 200, body = ChallengeView),
    (status = 429, description = "too many failed attempts", body = Problem),
))]
pub(crate) async fn start_login(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    client: Option<Extension<Client>>,
    headers: HeaderMap,
) -> Response {
    let meta = client_meta(client.as_ref().map(|c| &c.0), &headers);
    let result = state.identity.start_passkey_login(&relying_party(&state, &instance), instance.id, &meta).await;
    ok_or_problem(result, |challenge| Json(ChallengeView::from(challenge)).into_response())
}

/// Finishes a passkey login and creates a session.
#[utoipa::path(post, path = "/v1/sessions/passkey/finish", tag = "sessions", request_body = Answer, responses(
    (status = 201, body = SessionCreated),
    (status = 401, description = "the passkey did not pass", body = Problem),
))]
pub(crate) async fn finish_login(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    client: Option<Extension<Client>>,
    headers: HeaderMap,
    Json(answer): Json<Answer>,
) -> Response {
    let meta = client_meta(client.as_ref().map(|c| &c.0), &headers);
    let lifetime = answer.lifetime_seconds.map(Duration::from_secs);
    let rp = relying_party(&state, &instance);
    let result = state
        .identity
        .finish_passkey_login(&rp, instance.id, &answer.challenge_id, &answer.credential, lifetime, &meta)
        .await;
    ok_or_problem(result, |session| crate::sessions::session_created(&state, session, answer.cookie))
}

/// Checks a TOTP code as a further check of the current session.
#[utoipa::path(post, path = "/v1/sessions/current/totp", tag = "sessions", request_body = Code, responses(
    (status = 200, body = SessionView),
    (status = 401, description = "wrong code, or no valid session", body = Problem),
))]
pub(crate) async fn check_totp(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<Code>,
) -> Response {
    let result = state.identity.check_totp(instance.id, &token, &body.code).await;
    ok_or_problem(result, |session| Json(SessionView::from(session)).into_response())
}

/// Starts a passkey check of the current session.
#[utoipa::path(post, path = "/v1/sessions/current/passkey/start", tag = "sessions", responses((status = 200, body = ChallengeView)))]
pub(crate) async fn start_check(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = state.identity.start_passkey_check(&relying_party(&state, &instance), instance.id, &token).await;
    ok_or_problem(result, |challenge| Json(ChallengeView::from(challenge)).into_response())
}

/// Finishes a passkey check of the current session.
#[utoipa::path(post, path = "/v1/sessions/current/passkey/finish", tag = "sessions", request_body = Answer, responses(
    (status = 200, body = SessionView),
    (status = 401, description = "the passkey did not pass", body = Problem),
))]
pub(crate) async fn finish_check(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(answer): Json<Answer>,
) -> Response {
    let rp = relying_party(&state, &instance);
    let result =
        state.identity.finish_passkey_check(&rp, instance.id, &token, &answer.challenge_id, &answer.credential).await;
    ok_or_problem(result, |session| Json(SessionView::from(session)).into_response())
}

/// Proposes a TOTP secret for one's own account (needs a recent session).
#[utoipa::path(post, path = "/v1/account/totp", tag = "account", responses(
    (status = 200, body = TotpSetupView),
    (status = 401, description = "no valid or no recent session", body = Problem),
    (status = 409, description = "TOTP is already on", body = Problem),
))]
pub(crate) async fn start_totp(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = state.identity.start_totp(instance.id, &token, &instance.name).await;
    ok_or_problem(result, |setup| {
        Json(TotpSetupView { secret: setup.secret, uri: setup.uri, qr_code: setup.qr_code }).into_response()
    })
}

/// Confirms the proposed TOTP secret with a first code.
#[utoipa::path(post, path = "/v1/account/totp/confirm", tag = "account", request_body = Code, responses(
    (status = 204, description = "TOTP is on"),
    (status = 401, description = "wrong code, or no recent session", body = Problem),
))]
pub(crate) async fn confirm_totp(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<Code>,
) -> Response {
    let result = state.identity.confirm_totp(instance.id, &token, &body.code).await;
    ok_or_problem(result, |()| StatusCode::NO_CONTENT.into_response())
}

/// Removes TOTP from one's own account.
#[utoipa::path(delete, path = "/v1/account/totp", tag = "account", responses((status = 204, description = "removed")))]
pub(crate) async fn remove_totp(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = state.identity.remove_totp(instance.id, &token).await;
    ok_or_problem(result, |()| StatusCode::NO_CONTENT.into_response())
}

/// The passkeys of one's own account.
#[utoipa::path(get, path = "/v1/account/passkeys", tag = "account", responses((status = 200, body = Vec<PasskeyView>)))]
pub(crate) async fn passkeys(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = state.identity.passkeys(instance.id, &token).await;
    ok_or_problem(result, |passkeys| {
        let list: Vec<PasskeyView> = passkeys
            .into_iter()
            .map(|p| PasskeyView {
                id: p.id.to_string(),
                name: p.name,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            })
            .collect();
        Json(list).into_response()
    })
}

/// Starts registering a passkey for one's own account (needs a recent session).
#[utoipa::path(post, path = "/v1/account/passkeys/start", tag = "account", responses((status = 200, body = ChallengeView)))]
pub(crate) async fn start_registration(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result =
        state.identity.start_passkey_registration(&relying_party(&state, &instance), instance.id, &token).await;
    ok_or_problem(result, |challenge| Json(ChallengeView::from(challenge)).into_response())
}

/// Finishes registering a passkey.
#[utoipa::path(post, path = "/v1/account/passkeys/finish", tag = "account", request_body = Answer, responses(
    (status = 201, body = Created),
    (status = 401, description = "the registration did not pass, or no recent session", body = Problem),
))]
pub(crate) async fn finish_registration(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(answer): Json<Answer>,
) -> Response {
    let rp = relying_party(&state, &instance);
    let name = answer.name.as_deref().unwrap_or("Passkey");
    let result = state
        .identity
        .finish_passkey_registration(&rp, instance.id, &token, &answer.challenge_id, name, &answer.credential)
        .await;
    ok_or_problem(result, |id| (StatusCode::CREATED, Json(Created { id: id.to_string() })).into_response())
}

/// Removes a passkey of one's own account.
#[utoipa::path(delete, path = "/v1/account/passkeys/{id}", tag = "account", params(("id" = String, Path)), responses(
    (status = 204, description = "removed"),
    (status = 404, description = "no such passkey", body = Problem),
))]
pub(crate) async fn remove_passkey(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let result = state.identity.remove_passkey(instance.id, &token, id).await;
    ok_or_problem(result, |()| StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct FactorsView {
    totp: bool,
    passkeys: i64,
    recovery_codes_left: i64,
    /// The tenant requires a second factor.
    required: bool,
    /// The account has none yet and may log in without one until then (the tenant's grace period).
    setup_due: Option<chrono::DateTime<chrono::Utc>>,
}

/// The second factors of one's own account – for the login UI to ask for one, or to have one set up.
#[utoipa::path(get, path = "/v1/account/factors", tag = "account", responses((status = 200, body = FactorsView)))]
pub(crate) async fn factors(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = state.identity.second_factors(instance.id, &token).await;
    ok_or_problem(result, |f| {
        Json(FactorsView {
            totp: f.totp,
            passkeys: f.passkeys,
            recovery_codes_left: f.recovery_codes_left,
            required: f.required,
            setup_due: f.setup_due,
        })
        .into_response()
    })
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RecoveryCodes {
    /// Shown this once; each works once.
    codes: Vec<String>,
}

/// Generates new recovery codes for one's own account (needs a recent session); earlier ones stop working.
#[utoipa::path(post, path = "/v1/account/recovery-codes", tag = "account", responses(
    (status = 200, body = RecoveryCodes),
    (status = 401, description = "no valid or no recent session", body = Problem),
))]
pub(crate) async fn generate_recovery_codes(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let result = state.identity.generate_recovery_codes(instance.id, &token).await;
    ok_or_problem(result, |codes| (no_store(), Json(RecoveryCodes { codes })).into_response())
}

/// Uses a recovery code as a further check of the current session.
#[utoipa::path(post, path = "/v1/sessions/current/recovery", tag = "sessions", request_body = Code, responses(
    (status = 200, body = SessionView),
    (status = 401, description = "wrong or used code, or no valid session", body = Problem),
))]
pub(crate) async fn check_recovery_code(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Json(body): Json<Code>,
) -> Response {
    let result = state.identity.check_recovery_code(instance.id, &token, &body.code).await;
    ok_or_problem(result, |session| Json(SessionView::from(session)).into_response())
}

/// Secrets in a response must not be cached.
fn no_store() -> [(axum::http::header::HeaderName, axum::http::HeaderValue); 1] {
    [(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"))]
}
