// SPDX-License-Identifier: AGPL-3.0-or-later
//! Finding the instance by host, against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{DomainName, Identity};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

async fn app(pool: &PgPool) -> (Router, uuid::Uuid) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let id = identity.add_instance("Example", &DomainName::parse("login.example.org").unwrap(), "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let oidc = kernoid_oidc::Oidc::new(
        EventStore::new(pool.clone()),
        kernoid_store::MainKeys::new(Key::random().unwrap(), Vec::new()),
        "https",
    );
    let state = AppState::new(pool.clone(), BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity, oidc);
    (router(state, Router::new(), &Http::default()), id)
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn rest_finds_the_instance_by_host(pool: PgPool) {
    let (app, id) = app(&pool).await;
    let request = Request::get("/v1/instance").header("host", "Login.Example.org:443").body(Body::empty()).unwrap();
    let (status, body) = send(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "id": id.to_string(), "name": "Example", "primary_domain": "login.example.org" }));

    let unknown = Request::get("/v1/instance").header("host", "elsewhere.example").body(Body::empty()).unwrap();
    let (status, body) = send(app.clone(), unknown).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["detail"], "no instance is reached under this host");

    // A forwarded host from a peer that is not a trusted proxy does not count.
    let forged = Request::get("/v1/instance")
        .header("host", "elsewhere.example")
        .header("x-forwarded-host", "login.example.org")
        .header("forwarded", "host=login.example.org")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(app, forged).await.0, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn graphql_finds_the_instance_by_host(pool: PgPool) {
    let (app, id) = app(&pool).await;
    let query = |host: &str| {
        Request::post("/graphql")
            .header("host", host)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "query": "{ instance { id name primaryDomain } }" }).to_string()))
            .unwrap()
    };
    let (status, body) = send(app.clone(), query("login.example.org")).await;
    assert_eq!(status, StatusCode::OK);
    let expected = json!({ "id": id.to_string(), "name": "Example", "primaryDomain": "login.example.org" });
    assert_eq!(body["data"]["instance"], expected);
    let (_, body) = send(app, query("elsewhere.example")).await;
    assert_eq!(body["data"]["instance"], Value::Null);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn openapi_lists_the_instance_route(pool: PgPool) {
    let (app, _) = app(&pool).await;
    let (_, openapi) = send(app, Request::get("/openapi.json").body(Body::empty()).unwrap()).await;
    assert!(openapi["paths"]["/v1/instance"]["get"].is_object());
}
