// SPDX-License-Identifier: AGPL-3.0-or-later
//! TOTP and passkeys over HTTP, against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use std::sync::Arc;

use aws_lc_rs::hmac;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity};
use kernoid_oidc::Oidc;
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};
use webauthn_rs_proto::AllowCredentials;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

async fn app(pool: &PgPool) -> (Router, uuid::Uuid) {
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
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let oidc = Oidc::new(events, main, "https");
    let state = AppState::new(pool.clone(), BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity, oidc);
    (router(state, Router::new(), &Http::default()), alice)
}

async fn call(app: &Router, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path).header("host", HOST);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => request.header("content-type", "application/json").body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    };
    let response = app.clone().oneshot(request.unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn login(app: &Router) -> String {
    let (_, body) =
        call(app, "POST", "/v1/sessions", None, Some(json!({ "address": "alice@firma.de", "password": PASSWORD })))
            .await;
    body["token"].as_str().unwrap().to_owned()
}

fn totp(secret: &str, offset: i64) -> String {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut key) = (0u32, 0, Vec::new());
    for c in secret.chars() {
        buffer = (buffer << 5) | ALPHABET.find(c).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key.push((buffer >> bits) as u8);
        }
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 30;
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key),
        &((now as i64 + offset) as u64).to_be_bytes(),
    );
    let mac = mac.as_ref();
    let at = usize::from(mac[19] & 0x0f);
    format!("{:06}", u32::from_be_bytes([mac[at] & 0x7f, mac[at + 1], mac[at + 2], mac[at + 3]]) % 1_000_000)
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn totp_over_http(pool: PgPool) {
    let (app, _) = app(&pool).await;
    let token = login(&app).await;
    let (status, setup) = call(&app, "POST", "/v1/account/totp", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let secret = setup["secret"].as_str().unwrap();
    assert!(setup["uri"].as_str().unwrap().starts_with("otpauth://totp/Firma%3Aalice%40firma.de?"));

    let (status, _) =
        call(&app, "POST", "/v1/account/totp/confirm", Some(&token), Some(json!({ "code": "000000" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) =
        call(&app, "POST", "/v1/account/totp/confirm", Some(&token), Some(json!({ "code": totp(secret, 0) }))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A new login checks the second factor.
    let second = login(&app).await;
    let (status, session) =
        call(&app, "POST", "/v1/sessions/current/totp", Some(&second), Some(json!({ "code": totp(secret, 1) }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["checks"], json!(["password", "totp"]));

    // Changing how one logs in needs a recent session.
    sqlx::query!("UPDATE sessions SET created_at = now() - interval '20 minutes'").execute(&pool).await.unwrap();
    let (status, problem) = call(&app, "DELETE", "/v1/account/totp", Some(&second), None).await;
    assert_eq!(
        (status, problem["type"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("urn:kernoid:problem:login-required"))
    );
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn passkeys_over_http(pool: PgPool) {
    let (app, alice) = app(&pool).await;
    let token = login(&app).await;
    let origin: url::Url = "https://login.firma.de".parse().unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let (status, start) = call(&app, "POST", "/v1/account/passkeys/start", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let options: CreationChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    assert_eq!(options.public_key.rp.id, HOST, "the instance is the relying party");
    let credential = authenticator.do_registration(origin.clone(), options).unwrap();
    let credential_id = credential.raw_id.to_vec();
    let answer = json!({ "challenge_id": start["challenge_id"], "name": "Laptop", "credential": credential });
    let (status, created) = call(&app, "POST", "/v1/account/passkeys/finish", Some(&token), Some(answer)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, list) = call(&app, "GET", "/v1/account/passkeys", Some(&token), None).await;
    assert_eq!(list[0]["name"], "Laptop");
    assert_eq!(list[0]["id"], created["id"]);

    // Logging in with the passkey alone.
    let (_, start) = call(&app, "POST", "/v1/sessions/passkey/start", None, None).await;
    let mut options: RequestChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    assert!(options.public_key.allow_credentials.is_empty());
    options.public_key.allow_credentials =
        vec![AllowCredentials { type_: "public-key".into(), id: credential_id.into(), transports: None }];
    let mut assertion = authenticator.do_authentication(origin, options).unwrap();
    assertion.response.user_handle = Some(alice.as_bytes().to_vec().into());
    let answer = json!({ "challenge_id": start["challenge_id"], "credential": assertion });
    let (status, session) = call(&app, "POST", "/v1/sessions/passkey/finish", None, Some(answer.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, current) = call(&app, "GET", "/v1/sessions/current", Some(session["token"].as_str().unwrap()), None).await;
    assert_eq!(current["checks"], json!(["passkey"]));
    // The same answer again: the challenge is gone.
    assert_eq!(call(&app, "POST", "/v1/sessions/passkey/finish", None, Some(answer)).await.0, StatusCode::UNAUTHORIZED);

    let id = created["id"].as_str().unwrap();
    assert_eq!(
        call(&app, "DELETE", &format!("/v1/account/passkeys/{id}"), Some(&token), None).await.0,
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn openapi_lists_the_mfa_routes(pool: PgPool) {
    let (app, _) = app(&pool).await;
    let (_, openapi) = call(&app, "GET", "/openapi.json", None, None).await;
    for path in
        ["/v1/account/totp", "/v1/account/passkeys/start", "/v1/sessions/passkey/finish", "/v1/sessions/current/totp"]
    {
        assert!(openapi["paths"][path].is_object(), "{path}");
    }
}
