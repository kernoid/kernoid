// SPDX-License-Identifier: AGPL-3.0-or-later
//! The login UI (`web/login`, MIT): static files served at `/login` from `http.login_ui`. kernoid sends browsers here
//! to answer OpenID Connect auth requests (`/login?authRequest=…`); `/login/account` is the account page. The web app
//! (`web/app`, MIT) is served the same way at `/app` from `http.web_app`. Every response carries a strict
//! Content-Security-Policy – scripts and styles only from this origin, nothing inline – and may not be framed, so
//! that no other site can overlay the login form.

use std::path::Path;

use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use tower_http::services::{ServeDir, ServeFile};

use crate::Problem;

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
     connect-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
/// The web app also shows files: images, audio and video from this origin's downloads, PDFs in a frame of it.
const APP_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
     media-src 'self'; frame-src 'self'; connect-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; \
     frame-ancestors 'none'";

/// The routes below `/login`: the files, or a problem if the UI is not installed.
pub(crate) fn routes(directory: &Path) -> Router {
    files(directory, "the login UI", "http.login_ui", CONTENT_SECURITY_POLICY)
}

/// The routes below `/app`: the web app's files, or a problem if it is not installed.
pub(crate) fn app_routes(directory: &Path) -> Router {
    files(directory, "the web app", "http.web_app", APP_CONTENT_SECURITY_POLICY)
}

fn files(directory: &Path, what: &'static str, setting: &'static str, policy: &'static str) -> Router {
    let index = directory.join("index.html");
    if !index.is_file() {
        tracing::warn!(path = %directory.display(), "no {what} there ({setting}); it answers 404");
        return Router::new().fallback(move || async move {
            Problem::new(StatusCode::NOT_FOUND).detail(format!("{what} is not installed")).into_response()
        });
    }
    // Paths that are not files – /login/account, /app/… – get the page itself, which finds its way from the URL.
    let files = ServeDir::new(directory).append_index_html_on_directories(true).fallback(ServeFile::new(index));
    Router::new()
        .fallback_service(files)
        .layer(middleware::from_fn(move |request, next| headers(policy, request, next)))
}

async fn headers(policy: &'static str, request: Request, next: Next) -> Response {
    // Built files carry a hash in their name and never change; everything else is checked every time.
    let immutable = request.uri().path().starts_with("/assets/");
    let mut response = next.run(request).await;
    let set = |response: &mut Response, name: HeaderName, value: &'static str| {
        response.headers_mut().insert(name, HeaderValue::from_static(value));
    };
    set(&mut response, header::CONTENT_SECURITY_POLICY, policy);
    set(&mut response, header::X_FRAME_OPTIONS, "DENY");
    set(&mut response, header::REFERRER_POLICY, "no-referrer");
    set(&mut response, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(
        &mut response,
        header::CACHE_CONTROL,
        if immutable { "public, max-age=31536000, immutable" } else { "no-cache" },
    );
    response
}
