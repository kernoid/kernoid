// SPDX-License-Identifier: AGPL-3.0-or-later
//! The login UI (`web/login`, MIT), built into the binary and served at `/login`. kernoid sends browsers here to
//! answer OpenID Connect auth requests (`/login?authRequest=…`); `/login/account` is the account page. The web app
//! (`web/app`, MIT) is served the same way at `/app`. For development, `http.login_ui` and `http.web_app` may name a
//! directory with a build to serve instead. Every response carries a strict Content-Security-Policy – scripts and
//! styles only from this origin, nothing inline – and may not be framed, so that no other site can overlay the login
//! form.

use std::{borrow::Cow, path::Path};

use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use tower_http::services::{ServeDir, ServeFile};

use crate::Problem;

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
     font-src 'self'; connect-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
/// The web app also shows files: images, audio and video from this origin's downloads, PDFs in a frame of it. It runs
/// the end-to-end library as WebAssembly (`'wasm-unsafe-eval'` compiles WebAssembly only, no JavaScript) and shows
/// what it decrypted as images and media from `blob:` URLs – never in a frame, where a decrypted page would run as
/// this origin.
const APP_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
     img-src 'self' data: blob:; font-src 'self'; media-src 'self' blob:; frame-src 'self'; connect-src 'self'; \
     manifest-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// The login UI, built by `pnpm build` in `web/`; a build of kernoid without it answers 404 at `/login`.
#[derive(rust_embed::Embed)]
#[folder = "../../web/login/dist"]
#[allow_missing = true]
struct LoginUi;

/// The web app, built the same way.
#[derive(rust_embed::Embed)]
#[folder = "../../web/app/dist"]
#[allow_missing = true]
struct WebApp;

/// The routes below `/login`.
pub(crate) fn routes(directory: Option<&Path>) -> Router {
    match directory {
        Some(directory) => files(directory, "the login UI", "http.login_ui", CONTENT_SECURITY_POLICY),
        None => embedded::<LoginUi>("the login UI", CONTENT_SECURITY_POLICY),
    }
}

/// The routes below `/app`.
pub(crate) fn app_routes(directory: Option<&Path>) -> Router {
    match directory {
        Some(directory) => files(directory, "the web app", "http.web_app", APP_CONTENT_SECURITY_POLICY),
        None => embedded::<WebApp>("the web app", APP_CONTENT_SECURITY_POLICY),
    }
}

fn not_installed(what: &'static str) -> Router {
    Router::new().fallback(move || async move {
        Problem::new(StatusCode::NOT_FOUND).detail(format!("{what} is not installed")).into_response()
    })
}

/// The files built into the binary; paths that are not files – /login/account, /app/… – get the page itself, which
/// finds its way from the URL.
fn embedded<Files: rust_embed::Embed>(what: &'static str, policy: &'static str) -> Router {
    if Files::get("index.html").is_none() {
        tracing::warn!("this build of kernoid has no {what}; it answers 404");
        return not_installed(what);
    }
    let serve = |uri: Uri| async move {
        let path = uri.path().trim_start_matches('/');
        let path = if path.is_empty() || path.ends_with('/') {
            Cow::Owned(format!("{path}index.html"))
        } else {
            Cow::Borrowed(path)
        };
        let Some(file) = Files::get(&path).or_else(|| Files::get("index.html")) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        ([(header::CONTENT_TYPE, file.metadata.mimetype().to_owned())], file.data).into_response()
    };
    Router::new().fallback(serve).layer(middleware::from_fn(move |request, next| headers(policy, request, next)))
}

/// A build in a directory (development).
fn files(directory: &Path, what: &'static str, setting: &'static str, policy: &'static str) -> Router {
    let index = directory.join("index.html");
    if !index.is_file() {
        tracing::warn!(path = %directory.display(), "no {what} there ({setting}); it answers 404");
        return not_installed(what);
    }
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

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;

    use super::*;

    /// A build as `pnpm build` leaves it: an index page and one asset.
    #[derive(rust_embed::Embed)]
    #[folder = "src/testdata/login-ui"]
    struct Fixture;

    #[tokio::test]
    async fn an_embedded_build_is_served_with_strict_headers() {
        let app = embedded::<Fixture>("the login UI", CONTENT_SECURITY_POLICY);
        for path in ["/", "/index.html", "/account", "/idp"] {
            let response = app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
            assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], CONTENT_SECURITY_POLICY);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert!(String::from_utf8_lossy(&body).contains("<title>login</title>"), "{path}");
        }
        let asset = app.oneshot(Request::get("/assets/app-1234.js").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(asset.headers()[header::CONTENT_TYPE], "text/javascript");
        assert_eq!(asset.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        assert_eq!(asset.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }
}
