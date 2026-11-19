// SPDX-License-Identifier: AGPL-3.0-or-later
//! For programs on axum: the routes of the login (`/auth/login`, `/auth/callback`, `/auth/logout`,
//! `/auth/backchannel-logout`) and the extractor [`Authenticated`], which gives a handler who is logged in – from the
//! session cookie of the program's web app, or from an access token its apps send as `Authorization: Bearer`.
//!
//! The session cookie is HttpOnly and `SameSite=Lax`; requests that change something and carry it must also carry the
//! header `kernoid-csrf` and come from the program's origin, as kernoid's own web app does (RFC 0001, 7.2).

use std::sync::Arc;

use axum::{
    Form, Json, Router,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use jiff::SignedDuration;
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::{
    relying::{AuthError, Pending, Principal, RelyingParty, random},
    sessions::{SESSION_LIFETIME, Session, Sessions},
};

/// The header a request with the session cookie must carry when it changes something.
pub const CSRF_HEADER: &str = "kernoid-csrf";

/// The login of a program: its relying party and where its sessions are kept. Put it into the router's state.
#[derive(Debug, Clone)]
pub struct Auth {
    relying: RelyingParty,
    sessions: Arc<dyn Sessions>,
    /// The program's origin, from `redirect_uri`.
    origin: String,
    /// Cookies with `Secure` and the `__Host-` prefix – whenever the program is reached over HTTPS.
    secure: bool,
    lifetime: SignedDuration,
}

impl Auth {
    pub fn new(relying: RelyingParty, sessions: Arc<dyn Sessions>) -> Self {
        let redirect = Url::parse(&relying.settings().redirect_uri).expect("RelyingParty::new checked redirect_uri");
        Self {
            origin: redirect.origin().ascii_serialization(),
            secure: redirect.scheme() == "https",
            relying,
            sessions,
            lifetime: SESSION_LIFETIME,
        }
    }

    /// How long a session lasts (8 hours unless set).
    pub fn with_lifetime(mut self, lifetime: SignedDuration) -> Self {
        self.lifetime = lifetime;
        self
    }

    pub fn relying_party(&self) -> &RelyingParty {
        &self.relying
    }

    fn cookie_name(&self) -> &'static str {
        if self.secure { "__Host-kernoid-auth" } else { "kernoid-auth" }
    }

    fn pending_name(&self) -> &'static str {
        if self.secure { "__Host-kernoid-auth-login" } else { "kernoid-auth-login" }
    }

    fn cookie(&self, name: &str, value: &str, max_age: i64) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"))
            .expect("cookie values are base64url")
    }

    /// The routes below `/auth/`, for any router whose state gives an [`Auth`].
    pub fn routes<S>() -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Auth: FromRef<S>,
    {
        Router::new()
            .route("/auth/login", get(login))
            .route("/auth/callback", get(callback))
            .route("/auth/logout", post(logout))
            .route("/auth/backchannel-logout", post(backchannel_logout))
    }

    /// Who is behind a request: an access token, or the session cookie (with the check against cross-site requests).
    #[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
    pub async fn principal(&self, method: &Method, headers: &HeaderMap) -> Result<Principal, Response> {
        if let Some(token) = bearer(headers) {
            return self.relying.verify_access_token(&token).await.map_err(|error| {
                tracing::debug!(%error, "access token refused");
                unauthorized("the access token is not valid")
            });
        }
        let Some(id) = cookie(headers, self.cookie_name()) else { return Err(unauthorized("not logged in")) };
        let Some(session) = self.sessions.get(&id).await else { return Err(unauthorized("the session has ended")) };
        if !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) && !self.same_origin(headers) {
            return Err(problem(
                StatusCode::FORBIDDEN,
                "a request with the session cookie needs the header kernoid-csrf",
            ));
        }
        Ok(session.principal)
    }

    fn same_origin(&self, headers: &HeaderMap) -> bool {
        let origin = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok());
        headers.contains_key(CSRF_HEADER) && origin.is_none_or(|origin| origin == self.origin)
    }
}

/// Who is logged in; a handler that takes it answers `401` to anyone else.
#[derive(Debug, Clone)]
pub struct Authenticated(pub Principal);

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
    Auth: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let auth = Auth::from_ref(state);
        auth.principal(&parts.method, &parts.headers).await.map(Self)
    }
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    #[serde(default)]
    next: Option<String>,
}

async fn login(State(auth): State<Auth>, Query(query): Query<LoginQuery>) -> Response {
    match auth.relying.start(query.next.as_deref().unwrap_or("/")).await {
        Ok(start) => {
            let mut response = Redirect::to(&start.url).into_response();
            let pending = auth.cookie(auth.pending_name(), &start.pending.encode(), 600);
            response.headers_mut().append(header::SET_COOKIE, pending);
            response
        }
        Err(error) => failed(&error),
    }
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

async fn callback(State(auth): State<Auth>, headers: HeaderMap, Query(query): Query<CallbackQuery>) -> Response {
    let Some(pending) = cookie(&headers, auth.pending_name()).and_then(|value| Pending::decode(&value)) else {
        return problem(StatusCode::BAD_REQUEST, "no login was started in this browser");
    };
    let result = match (query.code, query.state, query.error) {
        (_, _, Some(error)) => Err(AuthError::Denied(error)),
        (Some(code), Some(state), None) => auth.relying.finish(&pending, &code, &state).await,
        _ => Err(AuthError::State),
    };
    let login = match result {
        Ok(login) => login,
        Err(error) => return failed(&error),
    };
    let id = match random() {
        Ok(id) => id,
        Err(error) => return failed(&error),
    };
    auth.sessions.put(&id, Session::new(login, auth.lifetime)).await;
    let mut response = Redirect::to(&pending.next).into_response();
    let lifetime = auth.lifetime.as_secs();
    response.headers_mut().append(header::SET_COOKIE, auth.cookie(auth.cookie_name(), &id, lifetime));
    response.headers_mut().append(header::SET_COOKIE, auth.cookie(auth.pending_name(), "", 0));
    response
}

/// Ends the program's session; answers where to go to end the provider's login too (`{"next": …}`), if it can.
async fn logout(State(auth): State<Auth>, headers: HeaderMap) -> Response {
    if !auth.same_origin(&headers) {
        return problem(StatusCode::FORBIDDEN, "logging out needs the header kernoid-csrf");
    }
    let mut hint = None;
    if let Some(id) = cookie(&headers, auth.cookie_name()) {
        hint = auth.sessions.get(&id).await.map(|session| session.id_token);
        auth.sessions.remove(&id).await;
    }
    let next = auth.relying.logout_url(hint.as_deref(), None).await.ok().flatten();
    let mut response = Json(json!({ "next": next })).into_response();
    response.headers_mut().append(header::SET_COOKIE, auth.cookie(auth.cookie_name(), "", 0));
    response
}

#[derive(Debug, Deserialize)]
struct LogoutForm {
    logout_token: String,
}

/// The provider ends logins (OpenID Connect Back-Channel Logout 1.0, 2.8).
async fn backchannel_logout(State(auth): State<Auth>, Form(form): Form<LogoutForm>) -> Response {
    let mut response = match auth.relying.verify_logout_token(&form.logout_token).await {
        Ok(logout) => {
            let ended = auth.sessions.remove_logins(logout.subject.as_deref(), logout.session.as_deref()).await;
            tracing::info!(ended, "back-channel logout");
            StatusCode::OK.into_response()
        }
        Err(error) => {
            tracing::info!(%error, "logout token refused");
            (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_request" }))).into_response()
        }
    };
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim().to_owned())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
}

fn problem(status: StatusCode, detail: &str) -> Response {
    let body = json!({ "type": "about:blank", "title": status.canonical_reason(), "status": status.as_u16(),
        "detail": detail });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
    response
}

fn unauthorized(detail: &str) -> Response {
    problem(StatusCode::UNAUTHORIZED, detail)
}

fn failed(error: &AuthError) -> Response {
    match error {
        AuthError::State | AuthError::Denied(_) | AuthError::Token(_) => {
            tracing::info!(%error, "login refused");
            problem(StatusCode::BAD_REQUEST, &error.to_string())
        }
        AuthError::Provider(_) | AuthError::Settings(_) => {
            tracing::warn!(%error, "login failed");
            problem(StatusCode::BAD_GATEWAY, "the identity provider cannot be used")
        }
    }
}
