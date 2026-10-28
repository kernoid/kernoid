// SPDX-License-Identifier: AGPL-3.0-or-later
//! Provisioning with SCIM 2.0 as a directory like Entra ID does it, against PostgreSQL; set `DATABASE_URL` as for the
//! other tests.

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
use kernoid_oidc::Oidc;
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const HOST: &str = "login.firma.de";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

struct Setup {
    app: Router,
    identity: Identity,
    tenant: Uuid,
    alice: Uuid,
    token: String,
}

async fn setup(pool: &PgPool) -> Setup {
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
    identity
        .grant_role(tenant, Principal::Account(alice), &Role::parse("tenant_admin").unwrap(), "test")
        .await
        .unwrap();
    let (_, token) = identity.add_scim_token(tenant, "Entra ID", "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let oidc = Oidc::new(events, main, "https");
    let state =
        AppState::new(pool.clone(), BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity.clone(), oidc);
    Setup { app: router(state, Router::new(), &Http::default()), identity, tenant, alice, token }
}

async fn scim(s: &Setup, method: &str, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("/scim/v2{path}"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let request = match body {
        Some(body) => request.header("content-type", "application/scim+json").body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    };
    let response = s.app.clone().oneshot(request.unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_directory_provisions_users_and_groups(pool: PgPool) {
    let s = setup(&pool).await;
    let t = s.token.as_str();

    assert_eq!(scim(&s, "GET", "/Users", "kscim1.wrong", None).await.0, StatusCode::UNAUTHORIZED);
    let (_, config) = scim(&s, "GET", "/ServiceProviderConfig", t, None).await;
    assert_eq!(config["patch"]["supported"], true);

    // Entra ID looks for the user first, then creates it.
    let filter = "/Users?filter=userName%20eq%20%22carol%40firma.de%22";
    let (_, found) = scim(&s, "GET", filter, t, None).await;
    assert_eq!(found["totalResults"], 0);
    let carol = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "carol@firma.de",
        "externalId": "carol-guid",
        "active": true,
        "name": { "givenName": "Carol", "familyName": "Lee" },
        "emails": [{ "value": "carol@firma.de", "primary": true }, { "value": "c.lee@firma.de" }, { "value": "carol@gmail.com" }],
    });
    let (status, created) = scim(&s, "POST", "/Users", t, Some(carol.clone())).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let carol_id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["displayName"], "Carol Lee");
    // Addresses on the tenant's domains become aliases; others are left out.
    assert_eq!(created["emails"].as_array().unwrap().len(), 2);
    assert_eq!(scim(&s, "POST", "/Users", t, Some(carol)).await.0, StatusCode::CONFLICT);
    let (_, found) = scim(&s, "GET", "/Users?filter=externalId%20eq%20%22carol-guid%22", t, None).await;
    assert_eq!(found["Resources"][0]["userName"], "carol@firma.de");

    // Entra ID's PATCH: capitalised ops, booleans as strings.
    let patch = json!({ "schemas": [PATCH], "Operations": [
        { "op": "Replace", "path": "displayName", "value": "Carol L." },
        { "op": "Replace", "path": "active", "value": "False" },
    ]});
    let (status, patched) = scim(&s, "PATCH", &format!("/Users/{carol_id}"), t, Some(patch)).await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!((patched["displayName"].as_str(), patched["active"].as_bool()), (Some("Carol L."), Some(false)));
    let patch = json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "value": { "active": true, "userName": "c.lee@firma.de" } }] });
    let (_, patched) = scim(&s, "PATCH", &format!("/Users/{carol_id}"), t, Some(patch)).await;
    assert_eq!((patched["userName"].as_str(), patched["active"].as_bool()), (Some("c.lee@firma.de"), Some(true)));

    // Groups with members.
    let group = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Sales",
                        "externalId": "sales-guid", "members": [{ "value": carol_id }] });
    let (status, created) = scim(&s, "POST", "/Groups", t, Some(group)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sales = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["members"][0]["value"], carol_id);
    let remove = json!({ "schemas": [PATCH], "Operations": [{ "op": "Remove", "path": format!("members[value eq \"{carol_id}\"]") }] });
    let (_, patched) = scim(&s, "PATCH", &format!("/Groups/{sales}"), t, Some(remove)).await;
    assert_eq!(patched["members"], json!([]));
    let add = json!({ "schemas": [PATCH], "Operations": [{ "op": "Add", "path": "members", "value": [{ "value": carol_id }] }] });
    let (_, patched) = scim(&s, "PATCH", &format!("/Groups/{sales}"), t, Some(add)).await;
    assert_eq!(patched["members"].as_array().unwrap().len(), 1);
    let (_, list) = scim(&s, "GET", "/Groups?excludedAttributes=members", t, None).await;
    assert!(list["Resources"][0].get("members").is_none());

    // DELETE deactivates and ends sessions; the account stays.
    assert_eq!(scim(&s, "DELETE", &format!("/Users/{carol_id}"), t, None).await.0, StatusCode::NO_CONTENT);
    let (_, gone) = scim(&s, "GET", &format!("/Users/{carol_id}"), t, None).await;
    assert_eq!(gone["active"], false);

    // Events name the token.
    let creators = sqlx::query_scalar!("SELECT DISTINCT creator FROM events WHERE event_type = 'account.added'")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(creators.iter().any(|creator| creator.starts_with("scim:")), "{creators:?}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_directory_cannot_take_over_administration(pool: PgPool) {
    let s = setup(&pool).await;
    let t = s.token.as_str();
    // Alice is the tenant's administrator: SCIM may not deactivate her.
    let (status, problem) = scim(&s, "DELETE", &format!("/Users/{}", s.alice), t, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    // Nor change the members of a group that holds roles.
    let admins = s.identity.add_group(s.tenant, "Admins", "test").await.unwrap();
    s.identity.grant_role(s.tenant, Principal::Group(admins), &Role::parse("auditor").unwrap(), "test").await.unwrap();
    let carol = json!({ "userName": "carol@firma.de", "displayName": "Carol" });
    let (_, created) = scim(&s, "POST", "/Users", t, Some(carol)).await;
    let add = json!({ "schemas": [PATCH], "Operations": [{ "op": "add", "path": "members", "value": [{ "value": created["id"] }] }] });
    assert_eq!(scim(&s, "PATCH", &format!("/Groups/{admins}"), t, Some(add)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(scim(&s, "DELETE", &format!("/Groups/{admins}"), t, None).await.0, StatusCode::CONFLICT);
    // An address on a domain of others is refused.
    let foreign = json!({ "userName": "eve@other.de" });
    assert_eq!(scim(&s, "POST", "/Users", t, Some(foreign)).await.0, StatusCode::BAD_REQUEST);
    // A revoked token is refused.
    let id = s.identity.scim_tokens(s.tenant).await.unwrap()[0].id;
    s.identity.remove_scim_token(s.tenant, id, "test").await.unwrap();
    assert_eq!(scim(&s, "GET", "/Users", t, None).await.0, StatusCode::UNAUTHORIZED);
}

/// Like `scim`, with `If-Match`; returns the ETag too.
async fn scim_if(
    s: &Setup,
    method: &str,
    path: &str,
    if_match: &str,
    body: Option<Value>,
) -> (StatusCode, Option<String>, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("/scim/v2{path}"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", s.token))
        .header(header::IF_MATCH, if_match)
        .header("content-type", "application/scim+json")
        .body(Body::from(body.map(|body| body.to_string()).unwrap_or_default()))
        .unwrap();
    let response = s.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let etag = response.headers().get(header::ETAG).map(|value| value.to_str().unwrap().to_owned());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, etag, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn bulk_sorting_versions_and_passwords(pool: PgPool) {
    let s = setup(&pool).await;
    let t = s.token.as_str();
    let (_, config) = scim(&s, "GET", "/ServiceProviderConfig", t, None).await;
    assert_eq!(
        (config["bulk"]["supported"].as_bool(), config["etag"]["supported"].as_bool()),
        (Some(true), Some(true))
    );

    // Bulk: two users and a group of them, the group referring to the users by bulkId.
    let user = |name: &str| json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": format!("{name}@firma.de"), "displayName": name });
    let bulk = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations": [
            { "method": "POST", "path": "/Users", "bulkId": "z", "data": user("zoe") },
            { "method": "POST", "path": "/Users", "bulkId": "d", "data": user("dan") },
            { "method": "POST", "path": "/Groups", "bulkId": "g", "data": {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Team",
                "members": [{ "value": "bulkId:z" }, { "value": "bulkId:d" }] } },
            { "method": "POST", "path": "/Groups", "data": {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Later",
                "members": [{ "value": "bulkId:unknown" }] } },
            { "method": "DELETE", "path": "/Users/not-an-id" },
        ],
    });
    let (status, answer) = scim(&s, "POST", "/Bulk", t, Some(bulk)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let results = answer["Operations"].as_array().unwrap();
    let statuses: Vec<&str> = results.iter().map(|result| result["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["201", "201", "201", "409", "404"]);
    assert!(results[0]["location"].as_str().unwrap().contains("/scim/v2/Users/"));
    assert!(results[0]["version"].as_str().unwrap().starts_with("W/\""));
    let group = results[2]["location"].as_str().unwrap().rsplit('/').next().unwrap().to_owned();
    let (_, team) = scim(&s, "GET", &format!("/Groups/{group}"), t, None).await;
    assert_eq!(team["members"].as_array().unwrap().len(), 2);
    // failOnErrors stops early.
    let failing = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "failOnErrors": 1,
        "Operations": [{ "method": "DELETE", "path": "/Users/x" }, { "method": "POST", "path": "/Users", "data": user("eve") }] });
    let (_, answer) = scim(&s, "POST", "/Bulk", t, Some(failing)).await;
    assert_eq!(answer["Operations"].as_array().unwrap().len(), 1);

    // Sorting.
    let (_, sorted) = scim(&s, "GET", "/Users?sortBy=userName&sortOrder=descending", t, None).await;
    let names: Vec<&str> =
        sorted["Resources"].as_array().unwrap().iter().map(|u| u["userName"].as_str().unwrap()).collect();
    assert_eq!(names, ["zoe@firma.de", "dan@firma.de", "alice@firma.de"]);
    let (_, sorted) = scim(&s, "GET", "/Users?sortBy=displayName", t, None).await;
    assert_eq!(sorted["Resources"][0]["displayName"], "Alice");
    assert_eq!(scim(&s, "GET", "/Users?sortBy=title", t, None).await.0, StatusCode::BAD_REQUEST);

    // Versions: a change with an old ETag is refused; with the current one it passes, and the version moves on.
    let zoe = results[0]["location"].as_str().unwrap().rsplit('/').next().unwrap().to_owned();
    let (_, meta) = scim(&s, "GET", &format!("/Users/{zoe}"), t, None).await;
    let version = meta["meta"]["version"].as_str().unwrap().to_owned();
    assert!(meta["meta"]["created"].is_string() && meta["meta"]["lastModified"].is_string());
    let rename = |name: &str| json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "displayName", "value": name }] });
    let (status, etag, _) = scim_if(&s, "PATCH", &format!("/Users/{zoe}"), &version, Some(rename("Zoë"))).await;
    assert_eq!(status, StatusCode::OK);
    let etag = etag.unwrap();
    assert_ne!(etag, version);
    let (status, _, _) = scim_if(&s, "PATCH", &format!("/Users/{zoe}"), &version, Some(rename("Zoey"))).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    let (status, _, _) = scim_if(&s, "PATCH", &format!("/Users/{zoe}"), "*", Some(rename("Zoey"))).await;
    assert_eq!(status, StatusCode::OK);

    // Passwords: set for accounts SCIM may manage – never shown, never for an administrator.
    let password = json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "password", "value": "a long scim password" }] });
    let (status, answer) = scim(&s, "PATCH", &format!("/Users/{zoe}"), t, Some(password.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.get("password").is_none());
    s.identity
        .create_session(
            s.identity.account(zoe.parse().unwrap()).await.unwrap().instance,
            "zoe@firma.de",
            "a long scim password",
            None,
            &Default::default(),
        )
        .await
        .unwrap();
    let (status, _) = scim(&s, "PATCH", &format!("/Users/{}", s.alice), t, Some(password)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
