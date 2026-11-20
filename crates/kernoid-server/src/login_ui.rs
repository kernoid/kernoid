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

/// The builds made into the binary by `build.rs`: the login UI and the web app from `pnpm build` in `web/` (empty in
/// a build of kernoid without them, which answers 404 at `/login` and `/app`), and the tests' fixture.
mod builds {
    include!(concat!(env!("OUT_DIR"), "/builds.rs"));
}

/// The files of a build, by their path.
#[derive(Debug, Clone, Copy)]
struct Build(&'static [(&'static str, &'static [u8])]);

impl Build {
    fn get(self, path: &str) -> Option<&'static [u8]> {
        self.0.binary_search_by(|(name, _)| (*name).cmp(path)).ok().map(|index| self.0[index].1)
    }
}

/// The routes below `/login`.
pub(crate) fn routes(directory: Option<&Path>) -> Router {
    match directory {
        Some(directory) => files(directory, "the login UI", "http.login_ui", CONTENT_SECURITY_POLICY),
        None => embedded(Build(builds::LOGIN_UI), "the login UI", CONTENT_SECURITY_POLICY),
    }
}

/// The routes below `/app`.
pub(crate) fn app_routes(directory: Option<&Path>) -> Router {
    match directory {
        Some(directory) => files(directory, "the web app", "http.web_app", APP_CONTENT_SECURITY_POLICY),
        None => embedded(Build(builds::WEB_APP), "the web app", APP_CONTENT_SECURITY_POLICY),
    }
}

fn not_installed(what: &'static str) -> Router {
    Router::new().fallback(move || async move {
        Problem::new(StatusCode::NOT_FOUND).detail(format!("{what} is not installed")).into_response()
    })
}

/// The files built into the binary; paths that are not files – /login/account, /app/… – get the page itself, which
/// finds its way from the URL.
fn embedded(files: Build, what: &'static str, policy: &'static str) -> Router {
    if files.get("index.html").is_none() {
        tracing::warn!("this build of kernoid has no {what}; it answers 404");
        return not_installed(what);
    }
    let serve = move |uri: Uri| async move {
        let path = uri.path().trim_start_matches('/');
        let path = if path.is_empty() || path.ends_with('/') {
            Cow::Owned(format!("{path}index.html"))
        } else {
            Cow::Borrowed(path)
        };
        let (path, data) = match files.get(&path) {
            Some(data) => (path.as_ref(), data),
            None => match files.get("index.html") {
                Some(data) => ("index.html", data),
                None => return StatusCode::NOT_FOUND.into_response(),
            },
        };
        ([(header::CONTENT_TYPE, content_type(path))], data).into_response()
    };
    Router::new().fallback(serve).layer(middleware::from_fn(move |request, next| headers(policy, request, next)))
}

/// The media type of a built file, by its extension – the kinds a build of the web apps holds.
fn content_type(path: &str) -> &'static str {
    let extension = path.rsplit_once('.').map(|(_, extension)| extension.to_ascii_lowercase()).unwrap_or_default();
    match extension.as_str() {
        "html" | "htm" => "text/html",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
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

    #[tokio::test]
    async fn an_embedded_build_is_served_with_strict_headers() {
        // A build as `pnpm build` leaves it: an index page and one asset (`src/testdata/login-ui`).
        let app = embedded(Build(builds::FIXTURE), "the login UI", CONTENT_SECURITY_POLICY);
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

    #[test]
    fn files_are_found_by_their_path_and_typed_by_their_extension() {
        let fixture = Build(builds::FIXTURE);
        assert!(fixture.get("index.html").is_some());
        assert!(fixture.get("assets/app-1234.js").is_some());
        assert!(fixture.get("assets").is_none());
        assert!(builds::FIXTURE.windows(2).all(|pair| pair[0].0 < pair[1].0), "sorted for the search");
        assert_eq!(content_type("assets/x.WOFF2"), "font/woff2");
        assert_eq!(content_type("manifest.webmanifest"), "application/manifest+json");
        assert_eq!(content_type("LICENSE"), "application/octet-stream");
    }
}
