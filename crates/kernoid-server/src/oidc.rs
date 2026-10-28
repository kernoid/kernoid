// SPDX-License-Identifier: AGPL-3.0-or-later
//! OpenID Connect over HTTP, at the paths ZITADEL uses: discovery, JWKS, authorize, token, userinfo – and the two
//! routes the login UI needs to finish an auth request with its session (`/v1/auth-requests/{id}`). The protocol
//! endpoints answer in OAuth's error format (`{"error", "error_description"}`), the `/v1` routes with problem details.

use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kernoid_oidc::{
    AuthRequestInfo, AuthorizeRequest, Authorized, EndSession, EndSessionRequest, OidcError, TokenRequest, discovery,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{AppState, CurrentInstance, Problem, sessions};

/// `/v1` errors as problem details.
pub(crate) fn problem(error: OidcError) -> Response {
    let status = match error {
        OidcError::Identity(error) => return sessions::problem(error),
        OidcError::AuthRequestNotFound => StatusCode::NOT_FOUND,
        OidcError::AccessDenied(_) => StatusCode::FORBIDDEN,
        OidcError::InvalidToken => StatusCode::UNAUTHORIZED,
        OidcError::MfaRequired => {
            // The login UI asks for a second factor – or has one set up – and finishes again.
            let mut problem = Problem::new(StatusCode::UNAUTHORIZED).detail(error.to_string());
            problem.kind = "urn:kernoid:problem:mfa-required".into();
            return problem.into_response();
        }
        OidcError::ConsentRequired => {
            // The login UI shows what the application asks for and finishes again with the person's consent.
            let mut problem = Problem::new(StatusCode::FORBIDDEN).detail(error.to_string());
            problem.kind = "urn:kernoid:problem:consent-required".into();
            return problem.into_response();
        }
        OidcError::LoginRequired => {
            // The login UI recognises this by its type and logs the person in again.
            let mut problem = Problem::new(StatusCode::UNAUTHORIZED).detail(error.to_string());
            problem.kind = "urn:kernoid:problem:login-required".into();
            return problem.into_response();
        }
        OidcError::Internal(ref message) => {
            tracing::error!(%message, "oidc");
            return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
        }
        _ => StatusCode::BAD_REQUEST,
    };
    Problem::new(status).detail(error.to_string()).into_response()
}

/// Protocol errors in OAuth's format (RFC 6749, 5.2).
fn oauth_error(error: OidcError) -> Response {
    let (status, code) = match &error {
        OidcError::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
        OidcError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
        OidcError::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        OidcError::InvalidScope => (StatusCode::BAD_REQUEST, "invalid_scope"),
        OidcError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
        OidcError::Internal(message) => {
            tracing::error!(%message, "oidc");
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => (StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let description = match &error {
        OidcError::Internal(_) => "try again later".to_owned(),
        error => error.to_string(),
    };
    let mut response =
        (status, no_store(), Json(json!({ "error": code, "error_description": description }))).into_response();
    match code {
        "invalid_client" => {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"kernoid\""));
        }
        "invalid_token" => {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer error=\"invalid_token\""));
        }
        _ => {}
    }
    response
}

/// Tokens must not be cached anywhere (RFC 6749, 5.1).
fn no_store() -> [(header::HeaderName, HeaderValue); 2] {
    [
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (header::PRAGMA, HeaderValue::from_static("no-cache")),
    ]
}

pub(crate) async fn configuration(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
) -> Response {
    Json(discovery(&state.oidc.issuer(&instance.primary_domain))).into_response()
}

pub(crate) async fn keys(State(state): State<AppState>, CurrentInstance(instance): CurrentInstance) -> Response {
    match state.oidc.jwks(instance.id).await {
        Ok(jwks) => Json(jwks).into_response(),
        Err(error) => oauth_error(error),
    }
}

/// Starts a login: checks the client and sends the browser to the login UI – or, if the request is faulty, back to
/// the client. A wrong client or redirect URI is shown here and never redirected to.
pub(crate) async fn authorize(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Query(request): Query<AuthorizeRequest>,
) -> Response {
    match state.oidc.authorize(&instance, &request).await {
        Ok(Authorized::Login { url, .. } | Authorized::Error { url }) => Redirect::to(&url).into_response(),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// The client of a token or revocation request: from an HTTP Basic header or from the form – not both.
fn client_credentials(
    headers: &HeaderMap,
    form_id: Option<String>,
    form_secret: Option<String>,
) -> Result<(Option<String>, Option<String>), Box<Response>> {
    match basic_credentials(headers) {
        Some(_) if form_secret.is_some() => {
            Err(Box::new(oauth_error(OidcError::InvalidRequest("use one way of client authentication".into()))))
        }
        Some((id, _)) if form_id.as_ref().is_some_and(|form_id| *form_id != id) => {
            Err(Box::new(oauth_error(OidcError::InvalidClient)))
        }
        Some((id, secret)) => Ok((Some(id), Some(secret))),
        None => Ok((form_id, form_secret)),
    }
}

/// `client_id:client_secret` of an HTTP Basic header, each form-urlencoded (RFC 6749, 2.3.1).
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let unescape =
        |value: &str| url::form_urlencoded::parse(format!("v={value}").as_bytes()).next().map(|(_, v)| v.into_owned());
    Some((unescape(id)?, unescape(secret)?))
}

pub(crate) async fn token(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let (client_id, client_secret) = match client_credentials(&headers, form.client_id, form.client_secret) {
        Ok(credentials) => credentials,
        Err(response) => return *response,
    };
    let request = TokenRequest {
        grant_type: form.grant_type,
        code: form.code,
        redirect_uri: form.redirect_uri,
        code_verifier: form.code_verifier,
        refresh_token: form.refresh_token,
        scope: form.scope,
        client_id,
        client_secret,
    };
    match state.oidc.token(&instance, &request).await {
        Ok(tokens) => (no_store(), Json(tokens)).into_response(),
        Err(error) => oauth_error(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeForm {
    token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// Token revocation (RFC 7009): `200` whether or not the token was known.
pub(crate) async fn revoke(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    let (client_id, client_secret) = match client_credentials(&headers, form.client_id, form.client_secret) {
        Ok(credentials) => credentials,
        Err(response) => return *response,
    };
    let Some(client_id) = client_id else { return oauth_error(OidcError::InvalidClient) };
    match state.oidc.revoke(&instance, &client_id, client_secret.as_deref(), &form.token).await {
        Ok(()) => (StatusCode::OK, no_store()).into_response(),
        Err(error) => oauth_error(error),
    }
}

/// RP-initiated logout: ends the session named in `id_token_hint` and sends the browser back to a registered
/// `post_logout_redirect_uri` – or, without one, says it is done. Accepts the query (GET) or a form (POST).
pub(crate) async fn end_session_get(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Query(request): Query<EndSessionRequest>,
) -> Response {
    end_session(&state, &instance, &request).await
}

pub(crate) async fn end_session_post(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Form(request): Form<EndSessionRequest>,
) -> Response {
    end_session(&state, &instance, &request).await
}

async fn end_session(
    state: &AppState,
    instance: &kernoid_identity::InstanceInfo,
    request: &EndSessionRequest,
) -> Response {
    match state.oidc.end_session(instance, request).await {
        Ok(EndSession { redirect, frontchannel }) if !frontchannel.is_empty() => {
            frontchannel_page(redirect.as_deref(), &frontchannel)
        }
        Ok(EndSession { redirect: Some(url), .. }) => Redirect::to(&url).into_response(),
        Ok(EndSession { redirect: None, .. }) => Json(json!({ "logged_out": true })).into_response(),
        Err(error) => problem(error),
    }
}

/// Front-channel logout (Front-Channel Logout 1.0, 3): a page that loads each application's logout URI in an
/// invisible frame, then goes on to the redirect URI. No script: the frames load on their own, a refresh moves on.
fn frontchannel_page(redirect: Option<&str>, uris: &[String]) -> Response {
    let escape =
        |value: &str| value.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");
    let origins: Vec<String> =
        uris.iter().filter_map(|uri| url::Url::parse(uri).ok()).map(|url| url.origin().ascii_serialization()).collect();
    let frames: String = uris
        .iter()
        .map(|uri| format!("<iframe src=\"{}\" width=\"0\" height=\"0\" hidden></iframe>", escape(uri)))
        .collect();
    let (refresh, next) = match redirect {
        Some(url) => (
            format!("<meta http-equiv=\"refresh\" content=\"2;url={}\">", escape(url)),
            format!("<p><a href=\"{}\">Continue</a></p>", escape(url)),
        ),
        None => (String::new(), String::new()),
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Logged out</title>{refresh}</head>\
         <body><p>You are logged out.</p>{next}{frames}</body></html>"
    );
    let policy = format!("default-src 'none'; frame-src {}; frame-ancestors 'none'", origins.join(" "));
    let mut response = (no_store(), axum::response::Html(body)).into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

#[derive(Debug, Deserialize)]
pub(crate) struct IntrospectForm {
    token: String,
    /// A hint only; kernoid looks at access tokens first, then refresh tokens.
    #[allow(dead_code, reason = "accepted as RFC 7662 allows, not needed to find the token")]
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// Token introspection (RFC 7662) for resource servers – confidential clients of the same project.
pub(crate) async fn introspect(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Response {
    let (client_id, client_secret) = match client_credentials(&headers, form.client_id, form.client_secret) {
        Ok(credentials) => credentials,
        Err(response) => return *response,
    };
    let Some(client_id) = client_id else { return oauth_error(OidcError::InvalidClient) };
    match state.oidc.introspect(&instance, &client_id, client_secret.as_deref(), &form.token).await {
        Ok(answer) => (no_store(), Json(answer)).into_response(),
        Err(error) => oauth_error(error),
    }
}

pub(crate) async fn userinfo(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    headers: HeaderMap,
) -> Response {
    let Some(token) = sessions::bearer(&headers) else { return oauth_error(OidcError::InvalidToken) };
    match state.oidc.userinfo(&instance, &token).await {
        Ok(claims) => (no_store(), Json(claims)).into_response(),
        Err(error) => oauth_error(error),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AuthRequestView {
    id: String,
    /// The name of the application asking.
    application: String,
    scopes: Vec<String>,
    /// `none`, `login`, `consent`, `select_account` – what the login UI must respect.
    prompt: Vec<String>,
    /// The session may be at most this many seconds old.
    max_age: Option<i32>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<AuthRequestInfo> for AuthRequestView {
    fn from(info: AuthRequestInfo) -> Self {
        Self {
            id: info.id,
            application: info.application,
            scopes: info.scopes,
            prompt: info.prompt,
            max_age: info.max_age,
            expires_at: info.expires_at,
        }
    }
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct Finish {
    /// The person agreed to what the application asks for (after `urn:kernoid:problem:consent-required`).
    #[serde(default)]
    consent: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct Finished {
    /// Where to send the browser: the application's redirect URI with the code.
    callback_url: String,
}

/// A pending auth request – for the login UI to show who is asking.
#[utoipa::path(get, path = "/v1/auth-requests/{id}", tag = "login", params(("id" = String, Path)), responses(
    (status = 200, body = AuthRequestView),
    (status = 404, description = "unknown, expired or already finished", body = Problem),
))]
pub(crate) async fn auth_request(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(id): Path<String>,
) -> Response {
    match state.oidc.auth_request(&instance, &id).await {
        Ok(info) => Json(AuthRequestView::from(info)).into_response(),
        Err(error) => problem(error),
    }
}

/// Finishes an auth request with the session of the bearer token; answers with the URL to send the browser to. If
/// the application needs consent, the answer is `403` with type `urn:kernoid:problem:consent-required`: show what it
/// asks for, and finish again with `{"consent": true}`.
#[utoipa::path(post, path = "/v1/auth-requests/{id}", tag = "login", params(("id" = String, Path)),
    request_body(content = Option<Finish>), responses(
    (status = 200, body = Finished),
    (status = 401, description = "no valid session", body = Problem),
    (status = 403, description = "the account may not use this application, or consent is needed", body = Problem),
    (status = 404, description = "unknown, expired or already finished", body = Problem),
))]
pub(crate) async fn finish(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Path(id): Path<String>,
    body: Option<Json<Finish>>,
) -> Response {
    let consent = body.is_some_and(|Json(body)| body.consent);
    match state.oidc.finish(&instance, &id, &token, consent).await {
        Ok(callback_url) => Json(Finished { callback_url }).into_response(),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Decline {
    /// `login_required`, `consent_required`, `interaction_required`, `account_selection_required` or `access_denied`.
    error: String,
}

/// Ends an auth request without a login – no session for `prompt=none`, or the person declined; answers with the
/// URL that tells the application.
#[utoipa::path(post, path = "/v1/auth-requests/{id}/decline", tag = "login", params(("id" = String, Path)),
    request_body = Decline, responses(
    (status = 200, body = Finished),
    (status = 400, description = "unknown error code", body = Problem),
    (status = 404, description = "unknown, expired or already finished", body = Problem),
))]
pub(crate) async fn decline(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(id): Path<String>,
    Json(body): Json<Decline>,
) -> Response {
    match state.oidc.fail(&instance, &id, &body.error).await {
        Ok(callback_url) => Json(Finished { callback_url }).into_response(),
        Err(error) => problem(error),
    }
}
