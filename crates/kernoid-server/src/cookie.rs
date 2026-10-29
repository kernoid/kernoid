// SPDX-License-Identifier: AGPL-3.0-or-later
//! The session in an HttpOnly cookie, for browsers (RFC 0001, 7.6): no script of the page can read the token.
//!
//! - A login asked for with `"cookie": true` sets `__Host-kernoid-session` (`kernoid-session` without HTTPS):
//!   `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, as long as the session – and leaves the token out of the answer.
//!   Logins without it answer with the token, for clients that send it as `Authorization: Bearer` (the CLI, scripts,
//!   apps, login UIs on another site).
//! - A request authenticates with the bearer token if it has one, else with the cookie.
//! - **Cross-site request forgery:** a request that changes something (anything but `GET`, `HEAD`, `OPTIONS`) and
//!   authenticates with the cookie must carry the header `kernoid-csrf` – which a page of another origin cannot send
//!   without the CORS preflight kernoid refuses it – and an `Origin` of the instance: one of its domains, or its own
//!   login UI. `SameSite=Lax` keeps the cookie from other sites' requests on top of that.

use axum::{
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::{IdentityError, InstanceInfo};

use crate::{AppState, Problem, sessions};

const SECURE_NAME: &str = "__Host-kernoid-session";
const PLAIN_NAME: &str = "kernoid-session";
/// The header a cookie-authenticated change must carry.
pub const CSRF_HEADER: &str = "kernoid-csrf";

/// Whether the installation is reached over HTTPS – then the cookie is `Secure` and `__Host-` bound.
fn secure(state: &AppState) -> bool {
    state.oidc.issuer("").starts_with("https:")
}

fn name(state: &AppState) -> &'static str {
    if secure(state) { SECURE_NAME } else { PLAIN_NAME }
}

/// `Set-Cookie` for a new session.
pub(crate) fn set(state: &AppState, token: &str, expires_at: DateTime<Utc>) -> HeaderValue {
    let seconds = (expires_at - Utc::now()).num_seconds().max(0);
    let secure = if secure(state) { "; Secure" } else { "" };
    let cookie = format!("{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={seconds}{secure}", name(state));
    HeaderValue::from_str(&cookie).expect("a session token is a header value")
}

/// `Set-Cookie` that removes the session cookie.
pub(crate) fn clear(state: &AppState) -> HeaderValue {
    let secure = if secure(state) { "; Secure" } else { "" };
    let cookie = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}", name(state));
    HeaderValue::from_str(&cookie).expect("a cookie header value")
}

/// Whether the request carries the session cookie.
pub(crate) fn present(headers: &HeaderMap) -> bool {
    from_cookie(headers).is_some()
}

/// The session token in the request's cookies, if any.
fn from_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SECURE_NAME || *name == PLAIN_NAME)
        .map(|(_, token)| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}

fn forged() -> Response {
    let mut problem = Problem::new(StatusCode::FORBIDDEN).detail(format!(
        "a change with the session cookie needs the {CSRF_HEADER} header and an Origin of this instance"
    ));
    problem.kind = "urn:kernoid:problem:csrf".into();
    problem.into_response()
}

/// Whether `origin` (the `Origin` header) belongs to the instance: one of its domains, or its own login UI.
fn own_origin(origin: &str, instance: &InstanceInfo, secure: bool) -> bool {
    let Ok(origin) = url::Url::parse(origin) else { return false };
    let Some(host) = origin.host_str() else { return false };
    if instance
        .login_ui
        .as_deref()
        .and_then(|ui| url::Url::parse(ui).ok())
        .is_some_and(|ui| ui.origin() == origin.origin())
    {
        return true;
    }
    let scheme_fits = origin.scheme() == "https" || !secure;
    scheme_fits && instance.domains.iter().any(|domain| domain.eq_ignore_ascii_case(host))
}

/// Whether a request that authenticates with the cookie comes from a page of the instance: WebSockets carry the
/// cookie without any header a page could be kept from sending, so their `Origin` decides (RFC 6455, 10.2).
pub(crate) fn from_own_page(state: &AppState, headers: &HeaderMap, instance: &InstanceInfo) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok())
        .is_some_and(|origin| own_origin(origin, instance, secure(state)))
}

/// The session token of a request: the bearer token, or the cookie – for a change only with the CSRF header and an
/// `Origin` of the instance.
#[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
pub(crate) fn session_token(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    instance: Option<&InstanceInfo>,
) -> Result<String, Response> {
    if let Some(token) = sessions::bearer(headers) {
        return Ok(token);
    }
    let token = from_cookie(headers).ok_or_else(|| sessions::problem(IdentityError::InvalidSession))?;
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(token);
    }
    let marked = headers.get(CSRF_HEADER).is_some();
    let origin = headers.get(header::ORIGIN).and_then(|origin| origin.to_str().ok());
    let from_here = match (origin, instance) {
        (Some(origin), Some(instance)) => own_origin(origin, instance, secure(state)),
        _ => false,
    };
    if marked && from_here { Ok(token) } else { Err(forged()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_cookie_is_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("theme=dark; __Host-kernoid-session=ks1.a.b; x=1"));
        assert_eq!(from_cookie(&headers).as_deref(), Some("ks1.a.b"));
        headers.insert(header::COOKIE, HeaderValue::from_static("kernoid-session-other=nope"));
        assert_eq!(from_cookie(&headers), None);
    }

    #[test]
    fn origins_of_the_instance() {
        let instance = InstanceInfo {
            id: uuid::Uuid::nil(),
            name: "Firma".into(),
            primary_domain: "login.firma.de".into(),
            login_ui: Some("https://anmeldung.firma.de/login".into()),
            passkey_rp_id: "login.firma.de".into(),
            domains: vec!["login.firma.de".into(), "sso.firma.de".into()],
        };
        assert!(own_origin("https://login.firma.de", &instance, true));
        assert!(own_origin("https://sso.firma.de", &instance, true));
        assert!(own_origin("https://anmeldung.firma.de", &instance, true));
        assert!(!own_origin("http://login.firma.de", &instance, true), "not over plain HTTP");
        assert!(!own_origin("https://evil.example", &instance, true));
        assert!(!own_origin("null", &instance, true));
    }
}
