// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP over HTTP: logging in, the session, the API, the push stream; set `DATABASE_URL` as for the other crates'
//! tests.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::Engine;
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

/// An instance at HOST with the account alice@firma.de; its app password.
async fn app(pool: &PgPool) -> (Router, String) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();
    identity.set_password(alice, PASSWORD, "test").await.unwrap();
    let (_, app_password) = identity.add_app_password(alice, "Mail", "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let blobs = BlobStore::from_config(&Blob::Memory, keys).unwrap();
    let oidc = kernoid_oidc::Oidc::new(
        EventStore::new(pool.clone()),
        kernoid_store::MainKeys::new(Key::random().unwrap(), Vec::new()),
        "https",
    );
    let mail = kernoid_mail::Mail::new(pool.clone(), blobs.clone(), kernoid_mail::Limits::default());
    let jmap = kernoid_jmap::Jmap::new(mail, 1_000_000, chrono::Duration::days(5));
    let state = AppState::new(pool.clone(), blobs, identity, oidc).with_jmap(jmap, kernoid_mail::MailEvents::default());
    (router(state, Router::new(), &Http::default()), app_password)
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}")))
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, String::from_utf8_lossy(&bytes).into_owned())
}

fn get(uri: &str, authorization: Option<&str>) -> Request<Body> {
    let mut request = Request::get(uri).header("host", HOST);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    request.body(Body::empty()).unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_programs_log_in_and_talk_jmap(pool: PgPool) {
    let (app, app_password) = app(&pool).await;

    let (status, headers, _) = send(&app, get("/.well-known/jmap", None)).await;
    assert_eq!(
        (status, headers.get(header::LOCATION).unwrap().to_str().unwrap()),
        (StatusCode::PERMANENT_REDIRECT, "/jmap/session")
    );

    let (status, headers, _) = send(&app, get("/jmap/session", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap().starts_with("Basic"));
    let (status, _, _) = send(&app, get("/jmap/session", Some(&basic("alice@firma.de", "wrong")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An app password, or – without a second factor – the password.
    let (status, _, body) = send(&app, get("/jmap/session", Some(&basic("alice@firma.de", &app_password)))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session["username"], "alice@firma.de");
    assert_eq!(session["apiUrl"], format!("https://{HOST}/jmap/api"));
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_owned();

    // A kernoid session works too.
    let login = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
        .unwrap();
    let (_, _, body) = send(&app, login).await;
    let token = serde_json::from_str::<Value>(&body).unwrap()["token"].as_str().unwrap().to_owned();
    let request = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Mailbox/query", { "accountId": account, "filter": { "role": "inbox" } }, "0"]],
    });
    let api = Request::post("/jmap/api")
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(request.to_string()))
        .unwrap();
    let (status, _, body) = send(&app, api).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["methodResponses"][0][0], "Mailbox/query");
    assert_eq!(response["methodResponses"][0][1]["ids"].as_array().unwrap().len(), 1);

    // Problem details for a broken request.
    let broken = Request::post("/jmap/api")
        .header("host", HOST)
        .header(header::AUTHORIZATION, basic("alice@firma.de", &app_password))
        .body(Body::from("{"))
        .unwrap();
    let (status, _, body) = send(&app, broken).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("urn:ietf:params:jmap:error:notJSON"));

    // Upload, then download.
    let upload = Request::post(format!("/jmap/upload/{account}/"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, basic("alice@firma.de", &app_password))
        .header("content-type", "text/plain")
        .body(Body::from("hello"))
        .unwrap();
    let (status, _, body) = send(&app, upload).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let blob = serde_json::from_str::<Value>(&body).unwrap()["blobId"].as_str().unwrap().to_owned();
    let (status, headers, body) = send(
        &app,
        get(&format!("/jmap/download/{account}/{blob}/hello.txt"), Some(&basic("alice@firma.de", &app_password))),
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello"));
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/plain");

    // The push stream: the current state, then it closes as asked.
    let (status, headers, body) = send(
        &app,
        get("/jmap/eventsource?types=*&closeafter=state&ping=0", Some(&basic("alice@firma.de", &app_password))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/event-stream"));
    assert!(body.contains("event: state") && body.contains("\"@type\":\"StateChange\""), "{body}");
    assert!(body.contains(&account));
}
