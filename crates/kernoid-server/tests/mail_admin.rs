// SPDX-License-Identifier: AGPL-3.0-or-later
//! The administration of mail over REST and GraphQL (RFC 0002, 12.3), against PostgreSQL; set `DATABASE_URL` as for
//! the other crates' tests.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{
    Address, DomainName, Identity,
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

/// Alice administers the tenant Firma, Bob is an ordinary account of it.
async fn setup(pool: &PgPool) -> (Router, Uuid, Uuid) {
    let events = EventStore::new(pool.clone());
    let main = MainKeys::new(Key::random().unwrap(), Vec::new());
    let identity = Identity::with_secrets(events.clone(), main.clone());
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let mut accounts = Vec::new();
    for address in ["alice@firma.de", "bob@firma.de"] {
        let account = identity.add_account(tenant, &Address::parse(address).unwrap(), address, "test").await.unwrap();
        identity.set_password(account, PASSWORD, "test").await.unwrap();
        accounts.push(account);
    }
    identity
        .grant_role(tenant, Principal::Account(accounts[0]), &Role::parse("tenant_admin").unwrap(), "test")
        .await
        .unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let blobs = BlobStore::from_config(&Blob::Memory, keys).unwrap();
    let oidc = kernoid_oidc::Oidc::new(events, main, "https");
    let mail = kernoid_mail::Mail::new(pool.clone(), blobs.clone(), kernoid_mail::Limits::default());
    let jmap = kernoid_jmap::Jmap::new(mail, 1_000_000, chrono::Duration::days(5));
    let state = AppState::new(pool.clone(), blobs, identity, oidc).with_jmap(jmap, kernoid_mail::MailEvents::default());
    (router(state, Router::new(), &Http::default()), accounts[0], accounts[1])
}

struct Call<'a> {
    app: &'a Router,
    token: String,
}

impl Call<'_> {
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        let request = match body {
            Some(body) => request.header("content-type", "application/json").body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        };
        self.answer(request.unwrap()).await
    }

    async fn answer(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn status(&self, method: &str, path: &str, body: Option<Value>) -> u16 {
        self.send(method, path, body).await.0.as_u16()
    }

    async fn graphql(&self, query: &str) -> Value {
        let (status, body) = self.send("POST", "/graphql", Some(json!({ "query": query }))).await;
        assert_eq!(status, StatusCode::OK);
        body
    }
}

async fn login<'a>(app: &'a Router, address: &str) -> Call<'a> {
    let request = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": address, "password": PASSWORD }).to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let session: Value = serde_json::from_slice(&bytes).unwrap();
    Call { app, token: session["token"].as_str().unwrap().to_owned() }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_is_administered_and_shared(pool: PgPool) {
    let (app, _alice_id, bob_id) = setup(&pool).await;
    let alice = login(&app, "alice@firma.de").await;
    let bob = login(&app, "bob@firma.de").await;

    // Shared mailboxes are accounts nobody logs in as.
    let shared = json!({ "address": "info@firma.de", "display_name": "Info" });
    assert_eq!(bob.status("POST", "/v1/shared-mailboxes", Some(shared.clone())).await, 403);
    let (status, created) = alice.send("POST", "/v1/shared-mailboxes", Some(shared)).await;
    assert_eq!(status, StatusCode::CREATED);
    let info = created["id"].as_str().unwrap().to_owned();
    let (_, accounts) = alice.send("GET", "/v1/accounts", None).await;
    assert!(accounts.as_array().unwrap().iter().any(|a| a["address"] == "info@firma.de" && a["shared"] == true));
    let password = json!({ "password": "a password for nobody at all" });
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{info}/password"), Some(password)).await, 400);

    // Quotas: the tenant's default, then the account's own.
    assert_eq!(alice.status("PUT", "/v1/tenant/mail-quota", Some(json!({ "bytes": 1_000_000 }))).await, 204);
    assert_eq!(alice.send("GET", "/v1/tenant/mail-quota", None).await.1["bytes"], 1_000_000);
    let (_, overview) = alice.send("GET", &format!("/v1/accounts/{info}/mail"), None).await;
    assert_eq!(
        (overview["shared"].as_bool(), overview["quota"].as_u64(), overview["effective_quota"].as_u64()),
        (Some(true), None, Some(1_000_000))
    );
    assert_eq!(overview["mailboxes"].as_array().unwrap().len(), 6);
    assert_eq!(
        alice.status("PUT", &format!("/v1/accounts/{info}/mail/quota"), Some(json!({ "bytes": 5000 }))).await,
        204
    );
    assert_eq!(alice.send("GET", &format!("/v1/accounts/{info}/mail"), None).await.1["effective_quota"], 5000);

    // Importing a message; Sieve scripts.
    let import = Request::post(format!("/v1/accounts/{info}/mail/import"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", alice.token))
        .header("content-type", "message/rfc822")
        .body(Body::from("From: x@remote.example\r\nSubject: Hi\r\n\r\nHello\r\n"))
        .unwrap();
    assert_eq!(alice.answer(import).await.0, StatusCode::CREATED);
    let (_, overview) = alice.send("GET", &format!("/v1/accounts/{info}/mail"), None).await;
    let inbox = overview["mailboxes"].as_array().unwrap().iter().find(|m| m["role"] == "inbox").unwrap().clone();
    assert_eq!(inbox["total_emails"], 1);
    let script = json!({ "content": "require \"fileinto\";\r\nkeep;\r\n", "activate": true });
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{info}/mail/sieve/filter"), Some(script)).await, 204);
    assert_eq!(alice.send("GET", &format!("/v1/accounts/{info}/mail/sieve"), None).await.1[0]["active"], true);
    let bad = json!({ "content": "this is not sieve" });
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{info}/mail/sieve/bad"), Some(bad)).await, 400);
    assert_eq!(
        alice.status("PUT", &format!("/v1/accounts/{info}/mail/sieve-active"), Some(json!({ "name": null }))).await,
        204
    );
    assert_eq!(alice.status("DELETE", &format!("/v1/accounts/{info}/mail/sieve/filter"), None).await, 204);

    // Access: Bob may read and send as info@.
    let grant = json!({ "grantee_kind": "account", "grantee_id": bob_id, "rights": "lrs", "send_as": true });
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{info}/mail/access"), Some(grant)).await, 204);
    let wrong = json!({ "grantee_kind": "account", "grantee_id": bob_id, "rights": "lz" });
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{info}/mail/access"), Some(wrong)).await, 400);
    let (_, grants) = alice.send("GET", &format!("/v1/accounts/{info}/mail/access"), None).await;
    assert_eq!((grants[0]["grantee_name"].as_str(), grants[0]["rights"].as_str()), (Some("bob@firma.de"), Some("lrs")));
    let (_, shared) = bob.send("GET", "/v1/account/mail/shared", None).await;
    assert_eq!((shared[0]["address"].as_str(), shared[0]["send_as"].as_bool()), (Some("info@firma.de"), Some(true)));

    // Bob shares his own inbox with Alice, then stops.
    let own = json!({ "grantee": "alice@firma.de", "rights": "lr" });
    assert_eq!(bob.status("PUT", "/v1/account/mail/access", Some(own)).await, 204);
    assert_eq!(bob.send("GET", "/v1/account/mail/access", None).await.1.as_array().unwrap().len(), 1);
    assert_eq!(bob.status("DELETE", "/v1/account/mail/access?grantee=alice%40firma.de", None).await, 204);

    // The queue is the instance's: a tenant administrator does not see it.
    assert_eq!(alice.status("GET", "/v1/instance/mail-queue", None).await, 403);

    // GraphQL: the same.
    let body = alice.graphql(&format!(r#"{{ accountMail(account: "{info}") {{ shared effectiveQuota }} mailAccess(account: "{info}") {{ granteeName sendAs }} }}"#)).await;
    assert_eq!(body["data"]["accountMail"], json!({ "shared": true, "effectiveQuota": 5000 }), "{body}");
    assert_eq!(body["data"]["mailAccess"][0]["sendAs"], true);
    let body = alice
        .graphql(&format!(
            r#"mutation {{ removeMailAccess(account: "{info}", granteeKind: "account", granteeId: "{bob_id}") }}"#
        ))
        .await;
    assert_eq!(body["data"]["removeMailAccess"], true, "{body}");
    assert_eq!(bob.graphql("{ sharedMail { address } }").await["data"]["sharedMail"], json!([]));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn retention_and_mbox(pool: PgPool) {
    let (app, alice_id, _) = setup(&pool).await;
    let alice = login(&app, "alice@firma.de").await;
    let bob = login(&app, "bob@firma.de").await;

    let retention = json!({ "trash_days": 30, "junk_days": 7 });
    assert_eq!(bob.status("PUT", "/v1/tenant/mail-retention", Some(retention.clone())).await, 403);
    assert_eq!(alice.status("PUT", "/v1/tenant/mail-retention", Some(retention.clone())).await, 204);
    assert_eq!(alice.send("GET", "/v1/tenant/mail-retention", None).await.1, retention);
    assert_eq!(alice.status("PUT", "/v1/tenant/mail-retention", Some(json!({ "trash_days": 0 }))).await, 400);

    // An mbox in, the same out – with the keywords.
    let mbox = "From x@remote.example Sat Oct 24 10:00:00 2026\nStatus: RO\nX-Keywords: work\nFrom: x@remote.example\nSubject: One\n\n>From the start\n\n\
                From y@remote.example Sat Oct 24 11:00:00 2026\nFrom: y@remote.example\nSubject: Two\n\nSecond\n\n";
    let import = Request::post(format!("/v1/accounts/{alice_id}/mail/mailboxes/archive/mbox"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", alice.token))
        .header("content-type", "application/mbox")
        .body(Body::from(mbox))
        .unwrap();
    let (status, done) = alice.answer(import).await;
    assert_eq!((status, done), (StatusCode::OK, json!({ "imported": 2, "failed": 0 })));
    let export = Request::get(format!("/v1/accounts/{alice_id}/mail/mailboxes/archive/mbox"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", alice.token))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(export).await.unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/mbox");
    let text = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(
        text.starts_with("From x@remote.example Sat Oct 24 10:00:00 2026\nStatus: RO\nX-Keywords: work\n"),
        "{text}"
    );
    assert!(
        text.contains("\n>From the start\n")
            && text.contains("\nFrom y@remote.example Sat Oct 24 11:00:00 2026\nStatus: O\n"),
        "{text}"
    );
    assert_eq!(alice.status("GET", &format!("/v1/accounts/{alice_id}/mail/mailboxes/nowhere/mbox"), None).await, 404);

    // GraphQL: the same.
    let body = alice
        .graphql(&format!(
            r#"{{ mailRetention {{ trashDays junkDays }} exportMailbox(account: "{alice_id}", mailbox: "archive") }}"#
        ))
        .await;
    assert_eq!(body["data"]["mailRetention"], json!({ "trashDays": 30, "junkDays": 7 }), "{body}");
    assert!(body["data"]["exportMailbox"].as_str().unwrap().contains("Subject: Two"));
}
