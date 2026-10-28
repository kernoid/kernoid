// SPDX-License-Identifier: AGPL-3.0-or-later
//! The session API over REST and GraphQL, against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity, session::FAILURES_PER_NAME};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

/// An instance at HOST with the account alice@firma.de.
async fn app(pool: &PgPool) -> Router {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();
    identity.set_password(alice, PASSWORD, "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let oidc = kernoid_oidc::Oidc::new(
        EventStore::new(pool.clone()),
        kernoid_store::MainKeys::new(Key::random().unwrap(), Vec::new()),
        "https",
    );
    let state = AppState::new(pool.clone(), BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity, oidc);
    router(state, Router::new(), &Http::default())
}

struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Value,
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    Answer { status: parts.status, headers: parts.headers, body }
}

fn login(address: &str, password: &str) -> Request<Body> {
    Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .header("user-agent", "kernoid-test")
        .body(Body::from(json!({ "address": address, "password": password }).to_string()))
        .unwrap()
}

fn with_token(method: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri("/v1/sessions/current")
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn rest_login_session_logout(pool: PgPool) {
    let app = app(&pool).await;
    let created = send(&app, login("Alice@firma.de", PASSWORD)).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["account"]["address"], "alice@firma.de");
    let token = created.body["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("ks1."));
    let device = created.body["device_token"].as_str().unwrap().to_owned();
    assert!(device.starts_with("kdt1."));
    // Sent along with the next login, it comes back unchanged.
    let again = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "address": "alice@firma.de", "password": PASSWORD, "device_token": device }).to_string(),
        ))
        .unwrap();
    assert_eq!(send(&app, again).await.body["device_token"], device.as_str());

    let current = send(&app, with_token("GET", &token)).await;
    assert_eq!(current.status, StatusCode::OK);
    assert_eq!(current.body["id"], created.body["id"]);
    assert_eq!(current.body["checks"], json!(["password"]));
    assert!(current.body.get("token").is_none(), "the token is shown only once");

    // Logging out answers where to go next – nowhere, for a session that did not come from a SAML provider.
    let again = send(&app, login("alice@firma.de", PASSWORD)).await.body["token"].as_str().unwrap().to_owned();
    let out = Request::post("/v1/sessions/current/logout")
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {again}"))
        .body(Body::empty())
        .unwrap();
    let out = send(&app, out).await;
    assert_eq!((out.status, &out.body), (StatusCode::OK, &json!({ "redirect": null })));
    assert_eq!(send(&app, with_token("GET", &again)).await.status, StatusCode::UNAUTHORIZED);

    assert_eq!(send(&app, with_token("DELETE", &token)).await.status, StatusCode::NO_CONTENT);
    let gone = send(&app, with_token("GET", &token)).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
    assert_eq!(gone.headers[header::WWW_AUTHENTICATE], "Bearer");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn rest_refusals(pool: PgPool) {
    let app = app(&pool).await;
    let wrong = send(&app, login("alice@firma.de", "wrong password!!")).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.headers["content-type"], "application/problem+json");
    assert_eq!(wrong.body["detail"], "the address or the password is wrong");
    assert_eq!(send(&app, login("nobody@firma.de", PASSWORD)).await.body, wrong.body, "unknown looks the same");

    let no_token = Request::get("/v1/sessions/current").header("host", HOST).body(Body::empty()).unwrap();
    assert_eq!(send(&app, no_token).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, with_token("GET", "ks1.nonsense")).await.status, StatusCode::UNAUTHORIZED);

    // Another host – no instance, no login.
    let elsewhere = Request::post("/v1/sessions")
        .header("host", "elsewhere.example")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
        .unwrap();
    assert_eq!(send(&app, elsewhere).await.status, StatusCode::NOT_FOUND);

    for _ in 1..FAILURES_PER_NAME {
        send(&app, login("alice@firma.de", "wrong password!!")).await;
    }
    let throttled = send(&app, login("alice@firma.de", PASSWORD)).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = throttled.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert!((1..=900).contains(&retry), "{retry}");
}

async fn graphql(app: &Router, query: &str, token: Option<&str>) -> Value {
    let mut request = Request::post("/graphql").header("host", HOST).header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    send(app, request.body(Body::from(json!({ "query": query }).to_string())).unwrap()).await.body
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn graphql_login_session_logout(pool: PgPool) {
    let app = app(&pool).await;
    let created = graphql(
        &app,
        &format!(r#"mutation {{ createSession(address: "alice@firma.de", password: "{PASSWORD}") {{ token account {{ address }} }} }}"#),
        None,
    )
    .await;
    assert_eq!(created["data"]["createSession"]["account"]["address"], "alice@firma.de");
    let token = created["data"]["createSession"]["token"].as_str().unwrap().to_owned();

    let session = graphql(&app, "{ session { checks account { displayName } } }", Some(&token)).await;
    assert_eq!(session["data"]["session"], json!({ "checks": ["password"], "account": { "displayName": "Alice" } }));

    let ended = graphql(&app, "mutation { terminateSession }", Some(&token)).await;
    assert_eq!(ended["data"]["terminateSession"], true);
    let gone = graphql(&app, "{ session { checks } }", Some(&token)).await;
    assert_eq!(gone["errors"][0]["extensions"]["code"], "UNAUTHENTICATED");

    let wrong = graphql(
        &app,
        r#"mutation { createSession(address: "alice@firma.de", password: "wrong password!!") { token } }"#,
        None,
    )
    .await;
    assert_eq!(wrong["errors"][0]["extensions"]["code"], "UNAUTHENTICATED");
    for _ in 1..FAILURES_PER_NAME {
        graphql(
            &app,
            r#"mutation { createSession(address: "alice@firma.de", password: "wrong password!!") { token } }"#,
            None,
        )
        .await;
    }
    let throttled = graphql(
        &app,
        &format!(r#"mutation {{ createSession(address: "alice@firma.de", password: "{PASSWORD}") {{ token }} }}"#),
        None,
    )
    .await;
    assert_eq!(throttled["errors"][0]["extensions"]["code"], "TOO_MANY_ATTEMPTS");
    assert!(throttled["errors"][0]["extensions"]["retryAfter"].as_u64().unwrap() >= 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn openapi_lists_the_session_routes(pool: PgPool) {
    let app = app(&pool).await;
    let openapi = send(&app, Request::get("/openapi.json").body(Body::empty()).unwrap()).await.body;
    assert!(openapi["paths"]["/v1/sessions"]["post"].is_object());
    assert!(openapi["paths"]["/v1/sessions/current"]["get"].is_object());
    assert!(openapi["paths"]["/v1/sessions/current"]["delete"].is_object());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn browsers_keep_the_session_in_an_httponly_cookie(pool: PgPool) {
    let app = app(&pool).await;
    let login = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD, "cookie": true }).to_string()))
        .unwrap();
    let created = send(&app, login).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert!(created.body.get("token").is_none(), "no token for scripts to read");
    let set = created.headers[header::SET_COOKIE].to_str().unwrap().to_owned();
    assert!(set.starts_with("__Host-kernoid-session=ks1."), "{set}");
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age="] {
        assert!(set.contains(attribute), "{attribute} in {set}");
    }
    let cookie = set.split(';').next().unwrap().to_owned();
    let with_cookie = |method: &str, path: &str| {
        Request::builder().method(method).uri(path).header("host", HOST).header(header::COOKIE, cookie.clone())
    };

    // Reading works with the cookie alone.
    let current = send(&app, with_cookie("GET", "/v1/sessions/current").body(Body::empty()).unwrap()).await;
    assert_eq!(current.status, StatusCode::OK);
    // A change needs the CSRF header and an Origin of the instance.
    let rename = |request: axum::http::request::Builder| {
        request
            .header("content-type", "application/json")
            .body(Body::from(json!({ "display_name": "Alice A." }).to_string()))
            .unwrap()
    };
    let forged = send(
        &app,
        rename(
            with_cookie("PATCH", "/v1/account")
                .header(header::ORIGIN, "https://evil.example")
                .header("kernoid-csrf", "1"),
        ),
    )
    .await;
    assert_eq!(
        (forged.status, forged.body["type"].as_str()),
        (StatusCode::FORBIDDEN, Some("urn:kernoid:problem:csrf"))
    );
    let unmarked =
        send(&app, rename(with_cookie("PATCH", "/v1/account").header(header::ORIGIN, "https://login.firma.de"))).await;
    assert_eq!(unmarked.status, StatusCode::FORBIDDEN);
    let no_origin = send(&app, rename(with_cookie("PATCH", "/v1/account").header("kernoid-csrf", "1"))).await;
    assert_eq!(no_origin.status, StatusCode::FORBIDDEN);
    let genuine = send(
        &app,
        rename(
            with_cookie("PATCH", "/v1/account")
                .header(header::ORIGIN, "https://login.firma.de")
                .header("kernoid-csrf", "1"),
        ),
    )
    .await;
    assert_eq!(genuine.status, StatusCode::NO_CONTENT);
    // GraphQL is a POST: the same rule.
    let graphql = |origin: &str| {
        with_cookie("POST", "/graphql")
            .header(header::ORIGIN, origin)
            .header("kernoid-csrf", "1")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "query": "{ session { account { displayName } } }" }).to_string()))
            .unwrap()
    };
    assert_eq!(send(&app, graphql("https://evil.example")).await.status, StatusCode::FORBIDDEN);
    let answer = send(&app, graphql("https://login.firma.de")).await;
    assert_eq!(answer.body["data"]["session"]["account"]["displayName"], "Alice A.", "{}", answer.body);

    // Logging out ends the session and removes the cookie.
    let out = send(
        &app,
        with_cookie("POST", "/v1/sessions/current/logout")
            .header(header::ORIGIN, "https://login.firma.de")
            .header("kernoid-csrf", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(out.status, StatusCode::OK);
    assert!(out.headers[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
    let gone = send(&app, with_cookie("GET", "/v1/sessions/current").body(Body::empty()).unwrap()).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
}
