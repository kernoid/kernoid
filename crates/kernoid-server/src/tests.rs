// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http, Tls};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::Value;
use tower::ServiceExt;

use super::*;

/// A state whose database cannot be reached.
fn state() -> AppState {
    let db = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .unwrap();
    let keys = Arc::new(TenantKeys::new(db.clone(), Key::random().unwrap()));
    let identity = kernoid_identity::Identity::new(kernoid_events::EventStore::new(db.clone()));
    let oidc = kernoid_oidc::Oidc::new(
        kernoid_events::EventStore::new(db.clone()),
        kernoid_store::MainKeys::new(Key::random().unwrap(), Vec::new()),
        "https",
    );
    AppState::new(db, BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity, oidc)
}

fn app() -> Router {
    router(state(), Router::new(), &Http::default())
}

async fn send(request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, String::from_utf8(body.to_vec()).unwrap())
}

async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    send(Request::get(path).body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn live_without_database() {
    let (status, _, body) = get("/healthz").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"));
}

#[tokio::test]
async fn not_ready_without_database() {
    let (status, _, body) = get("/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"database":"failed","blob":"ok"}"#);
}

#[tokio::test]
async fn every_response_has_a_request_id() {
    let (_, headers, _) = get("/version").await;
    let id = headers.get("x-request-id").unwrap().to_str().unwrap();
    assert_eq!(id.len(), 36, "a UUID: {id}");
}

#[tokio::test]
async fn unknown_paths_are_problems() {
    let (status, headers, body) = get("/nothing/here").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["content-type"], "application/problem+json");
    let problem: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(problem, serde_json::json!({ "type": "about:blank", "title": "Not Found", "status": 404 }));
}

#[tokio::test]
async fn bodies_are_limited() {
    let big = || vec![b'x'; BODY_LIMIT + 1];
    // Announced as too large: refused before it is read.
    let announced = Request::post("/graphql")
        .header("content-type", "application/json")
        .header("content-length", BODY_LIMIT + 1)
        .body(Body::from(big()))
        .unwrap();
    assert_eq!(send(announced).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // Not announced: reading stops at the limit and the request fails.
    let streamed =
        Request::post("/graphql").header("content-type", "application/json").body(Body::from(big())).unwrap();
    assert!(send(streamed).await.0.is_client_error());
}

#[tokio::test]
async fn openapi_describes_the_rest_api() {
    let (status, _, body) = get("/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    let openapi: Value = serde_json::from_str(&body).unwrap();
    assert!(openapi["openapi"].as_str().unwrap().starts_with("3."));
    for path in ["/healthz", "/readyz", "/version"] {
        assert!(openapi["paths"][path].is_object(), "{path}");
    }
}

#[tokio::test]
async fn graphql_answers_and_refuses_deep_queries() {
    let query = |q: &str| {
        Request::post("/graphql")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "query": q }).to_string()))
            .unwrap()
    };
    let (status, _, body) = send(query("{ version { name version } }")).await;
    assert_eq!(status, StatusCode::OK);
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["data"]["version"]["name"], "kernoid");

    let deep = format!(
        "{{ __schema {{ types {{ fields {{ type {{ {}name{} }} }} }} }} }}",
        "ofType { ".repeat(14),
        " }".repeat(14)
    );
    let (_, _, body) = send(query(&deep)).await;
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert!(answer["errors"][0]["message"].as_str().unwrap().contains("too deep"), "{body}");
}

/// A self-signed certificate for localhost, written to a temporary directory.
fn certificate() -> (tempdir::Dir, rustls_pki_types::CertificateDer<'static>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let dir = tempdir::Dir::new();
    std::fs::write(dir.path("cert.pem"), issued.cert.pem()).unwrap();
    std::fs::write(dir.path("key.pem"), issued.signing_key.serialize_pem()).unwrap();
    (dir, issued.cert.der().clone())
}

mod tempdir {
    /// A directory removed when dropped.
    pub struct Dir(std::path::PathBuf);

    impl Dir {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!("kernoid-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        pub fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

#[tokio::test]
async fn serves_https_and_shuts_down() {
    let (dir, der) = certificate();
    let http = Http {
        listen: free_port(),
        tls: Some(Tls { certificate: dir.path("cert.pem"), key: dir.path("key.pem") }),
        ..Http::default()
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn({
        let http = http.clone();
        async move {
            serve(&http, router(state(), Router::new(), &http), async {
                let _ = stopped.await;
            })
            .await
        }
    });

    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates({
            let mut roots = rustls::RootCertStore::empty();
            roots.add(der).unwrap();
            roots
        })
        .with_no_client_auth();
    let client = reqwest::Client::builder().tls_backend_preconfigured(tls).build().unwrap();
    let url = format!("https://localhost:{}/version", http.listen.port());
    let mut answer = None;
    for _ in 0..50 {
        match client.get(&url).send().await {
            Ok(response) => {
                answer = Some(response);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let answer = answer.expect("the server answers over TLS");
    assert_eq!(answer.status(), 200);
    assert!(answer.headers().contains_key("x-request-id"));

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

/// A login UI build in a directory of its own: an index page and one asset.
fn login_ui() -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("kernoid-login-ui-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(directory.join("assets")).unwrap();
    std::fs::write(directory.join("index.html"), "<!doctype html><title>login</title>").unwrap();
    std::fs::write(directory.join("assets/app-1234.js"), "console.log(1)").unwrap();
    directory
}

#[tokio::test]
async fn the_login_ui_is_served_with_strict_headers() {
    let directory = login_ui();
    let app = router(state(), Router::new(), &Http { login_ui: Some(directory.clone()), ..Http::default() });
    for path in ["/login", "/login/", "/login?authRequest=ar1.x", "/login/account"] {
        let response = app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let headers = response.headers();
        let policy = headers["content-security-policy"].to_str().unwrap();
        assert!(policy.contains("script-src 'self'") && policy.contains("frame-ancestors 'none'"), "{policy}");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["cache-control"], "no-cache");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("<title>login</title>"), "{path}");
    }
    let asset = app.oneshot(Request::get("/login/assets/app-1234.js").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(asset.headers()["cache-control"], "public, max-age=31536000, immutable");
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn a_missing_login_ui_is_a_problem() {
    let nowhere = std::env::temp_dir().join(format!("kernoid-no-login-ui-{}", uuid::Uuid::new_v4()));
    let app = router(state(), Router::new(), &Http { login_ui: Some(nowhere), ..Http::default() });
    let response = app.oneshot(Request::get("/login/account").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("the login UI is not installed"));
}

#[tokio::test]
async fn browser_called_protocol_endpoints_allow_cross_origin_requests() {
    let preflight = Request::options("/oauth/v2/token")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send(preflight).await;
    assert_eq!(headers["access-control-allow-origin"], "*");
    // The administration API is not meant for other origins.
    let preflight = Request::options("/v1/groups")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send(preflight).await;
    assert!(headers.get("access-control-allow-origin").is_none());
}
