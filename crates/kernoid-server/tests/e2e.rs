// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end encryption at the HTTP edge (RFC 0006): the tenant's policy and recovery key over REST and GraphQL, and
//! the Web Key Directory serving the accounts' keys by both methods. Against PostgreSQL; set `DATABASE_URL` as for the
//! other crates' tests.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_e2e::{Kind, SecretKey};
use kernoid_events::EventStore;
use kernoid_identity::{
    Address, DomainName, Identity,
    openpgp::{KeyCopy, wkd_hash},
    role::{Principal, Role},
};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

/// Alice administers the tenant Firma; Bob has a key.
async fn setup(pool: &PgPool) -> (Router, Identity, Uuid) {
    let events = EventStore::new(pool.clone());
    let main = MainKeys::new(Key::random().unwrap(), Vec::new());
    let identity = Identity::with_secrets(events.clone(), main.clone());
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();
    identity.set_password(alice, PASSWORD, "test").await.unwrap();
    identity
        .grant_role(tenant, Principal::Account(alice), &Role::parse("tenant_admin").unwrap(), "test")
        .await
        .unwrap();
    let bob = identity.add_account(tenant, &Address::parse("bob@firma.de").unwrap(), "Bob", "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let blobs = BlobStore::from_config(&Blob::Memory, keys).unwrap();
    let oidc = kernoid_oidc::Oidc::new(events, main, "https");
    let mail = kernoid_mail::Mail::new(pool.clone(), blobs.clone(), kernoid_mail::Limits::default());
    let jmap = kernoid_jmap::Jmap::new(mail, 1_000_000, chrono::Duration::days(5));
    let state =
        AppState::new(pool.clone(), blobs, identity.clone(), oidc).with_jmap(jmap, kernoid_mail::MailEvents::default());
    (router(state, Router::new(), &Http::default()), identity, bob)
}

async fn answer(app: &Router, request: Request<Body>) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let kind = response.headers().get(header::CONTENT_TYPE).map(|v| v.to_str().unwrap().to_owned());
    (status, kind, response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

async fn token(app: &Router) -> String {
    let request = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
        .unwrap();
    let (_, _, body) = answer(app, request).await;
    serde_json::from_slice::<Value>(&body).unwrap()["token"].as_str().unwrap().to_owned()
}

async fn api(app: &Router, token: &str, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let (status, _, body) = answer(app, request).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn wkd(app: &Router, host: &str, path: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    answer(app, Request::get(path).header("host", host).body(Body::empty()).unwrap()).await
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_tenant_sets_its_policy_and_recovery_key(pool: PgPool) {
    let (app, _, _) = setup(&pool).await;
    let token = token(&app).await;
    let (status, policy) = api(&app, &token, "GET", "/v1/tenant/e2e", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        policy,
        json!({ "mail": "allowed", "vaults": "allowed", "collections": "allowed", "recovery": false, "recovery_key": null })
    );

    let recovering = json!({ "mail": "required", "vaults": "allowed", "collections": "forbidden", "recovery": true });
    let (status, _) = api(&app, &token, "PUT", "/v1/tenant/e2e", Some(recovering.clone())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "recovery needs the key first");
    let recovery = SecretKey::generate(Kind::Pqc, &["recovery@firma.de"]).unwrap();
    let body = json!({ "public_key": STANDARD.encode(recovery.public().to_bytes().unwrap()) });
    let (status, set) = api(&app, &token, "PUT", "/v1/tenant/e2e/recovery-key", Some(body)).await;
    assert_eq!((status, set["fingerprint"].as_str()), (StatusCode::OK, Some(recovery.fingerprint().as_str())));
    let (status, _) =
        api(&app, &token, "PUT", "/v1/tenant/e2e/recovery-key", Some(json!({ "public_key": "%%" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = api(&app, &token, "PUT", "/v1/tenant/e2e", Some(recovering)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let query = json!({ "query": "{ tenantEndToEndPolicy { mail collections recovery recoveryKeyFingerprint } }" });
    let (_, graphql) = api(&app, &token, "POST", "/graphql", Some(query)).await;
    assert_eq!(
        graphql["data"]["tenantEndToEndPolicy"],
        json!({ "mail": "required", "collections": "forbidden", "recovery": true, "recoveryKeyFingerprint": recovery.fingerprint() })
    );
    let mutation = json!({ "query": r#"mutation { setTenantEndToEndPolicy(mail: "sometimes", vaults: "allowed", collections: "allowed", recovery: false) }"# });
    let (_, graphql) = api(&app, &token, "POST", "/graphql", Some(mutation)).await;
    assert!(graphql["errors"].is_array(), "{graphql}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_web_key_directory_serves_keys_in_use(pool: PgPool) {
    let (app, identity, bob) = setup(&pool).await;
    let key = SecretKey::generate(Kind::Compatible, &["bob@firma.de"]).unwrap().public().to_bytes().unwrap();
    let copy = KeyCopy { label: "recovery".into(), protected: b"protected".to_vec(), salt: None };
    identity.add_openpgp_key(bob, &key, vec![copy], "test").await.unwrap();
    let hash = wkd_hash("bob");

    let (status, kind, body) = wkd(&app, "firma.de", &format!("/.well-known/openpgpkey/hu/{hash}?l=bob")).await;
    assert_eq!((status, kind.as_deref()), (StatusCode::OK, Some("application/octet-stream")));
    assert_eq!(body, key);
    let (status, _, body) =
        wkd(&app, "openpgpkey.firma.de", &format!("/.well-known/openpgpkey/firma.de/hu/{hash}")).await;
    assert_eq!((status, body == key), (StatusCode::OK, true), "advanced, without l=");
    assert_eq!(wkd(&app, "firma.de", "/.well-known/openpgpkey/policy").await.0, StatusCode::OK);
    assert_eq!(wkd(&app, "openpgpkey.firma.de", "/.well-known/openpgpkey/firma.de/policy").await.0, StatusCode::OK);

    // The same 404 for an address without a key, a wrong l=, another host, and the wrong method's path.
    for (host, path) in [
        ("firma.de", format!("/.well-known/openpgpkey/hu/{}?l=alice", wkd_hash("alice"))),
        ("firma.de", format!("/.well-known/openpgpkey/hu/{hash}?l=alice")),
        ("elsewhere.example", format!("/.well-known/openpgpkey/hu/{hash}?l=bob")),
        ("firma.de", format!("/.well-known/openpgpkey/firma.de/hu/{hash}")),
        ("openpgpkey.firma.de", format!("/.well-known/openpgpkey/elsewhere.example/hu/{hash}")),
        ("elsewhere.example", "/.well-known/openpgpkey/policy".to_owned()),
    ] {
        assert_eq!(wkd(&app, host, &path).await.0, StatusCode::NOT_FOUND, "{host}{path}");
    }
}
