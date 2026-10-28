// SPDX-License-Identifier: AGPL-3.0-or-later
//! The administration API over REST and GraphQL, against PostgreSQL; set `DATABASE_URL` as for the other crates'
//! tests.

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
use kernoid_oidc::{Oidc, application::Kind};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

struct Setup {
    app: Router,
    instance: Uuid,
    tenant: Uuid,
    other: Uuid,
    alice: Uuid,
    bob: Uuid,
    foreign_application: Uuid,
}

/// Alice administers the tenant Firma, Bob is an ordinary account of it; the tenant Other has an application and an
/// account, dave@other.de.
async fn setup(pool: &PgPool) -> Setup {
    let events = EventStore::new(pool.clone());
    let main = MainKeys::new(Key::random().unwrap(), Vec::new());
    let identity = Identity::with_secrets(events.clone(), main.clone());
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let mut tenants = Vec::new();
    for (name, mail) in [("Firma", "firma.de"), ("Other", "other.de")] {
        let tenant = identity.add_tenant(instance, name, "test").await.unwrap();
        identity.add_tenant_domain(instance, tenant, &domain(mail), "test").await.unwrap();
        identity.trust_tenant_domain(instance, tenant, &domain(mail), "test").await.unwrap();
        tenants.push(tenant);
    }
    let mut accounts = Vec::new();
    for (tenant, address) in
        [(tenants[0], "alice@firma.de"), (tenants[0], "bob@firma.de"), (tenants[1], "dave@other.de")]
    {
        let account = identity.add_account(tenant, &Address::parse(address).unwrap(), address, "test").await.unwrap();
        identity.set_password(account, PASSWORD, "test").await.unwrap();
        accounts.push(account);
    }
    let admin = Role::parse("tenant_admin").unwrap();
    identity.grant_role(tenants[0], Principal::Account(accounts[0]), &admin, "test").await.unwrap();
    let oidc = Oidc::new(events, main, "https");
    let project = identity.add_project(tenants[1], "Theirs", "test").await.unwrap();
    let callback = ["https://app.other.de/callback".to_owned()];
    let (foreign_application, _) =
        oidc.add_application(tenants[1], project, "Theirs", Kind::Confidential, &callback, &[], "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let state = AppState::new(pool.clone(), BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity, oidc)
        .with_modules(&["jitsi"]);
    Setup {
        app: router(state, Router::new(), &Http::default()),
        instance,
        tenant: tenants[0],
        other: tenants[1],
        alice: accounts[0],
        bob: accounts[1],
        foreign_application,
    }
}

/// Requests with a session token and, optionally, the tenant to act on.
struct Call<'a> {
    app: &'a Router,
    token: Option<&'a str>,
    tenant: Option<String>,
}

impl<'a> Call<'a> {
    fn new(app: &'a Router, token: &'a str) -> Self {
        Self { app, token: Some(token), tenant: None }
    }

    fn anonymous(app: &'a Router) -> Self {
        Self { app, token: None, tenant: None }
    }

    fn for_tenant(mut self, tenant: impl ToString) -> Self {
        self.tenant = Some(tenant.to_string());
        self
    }

    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path).header("host", HOST);
        if let Some(token) = self.token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(tenant) = &self.tenant {
            request = request.header("kernoid-tenant", tenant);
        }
        let request = match body {
            Some(body) => request.header("content-type", "application/json").body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        };
        let response = self.app.clone().oneshot(request.unwrap()).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.send("GET", path, None).await
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

async fn login(app: &Router, address: &str) -> String {
    let body = json!({ "address": address, "password": PASSWORD });
    let (_, session) = Call::anonymous(app).send("POST", "/v1/sessions", Some(body)).await;
    session["token"].as_str().unwrap().to_owned()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn tenants_are_administered_over_rest(pool: PgPool) {
    let s = setup(&pool).await;
    let alice_token = login(&s.app, "alice@firma.de").await;
    let bob_token = login(&s.app, "bob@firma.de").await;
    let (alice, bob) = (Call::new(&s.app, &alice_token), Call::new(&s.app, &bob_token));

    assert_eq!(Call::anonymous(&s.app).status("GET", "/v1/tenant", None).await, 401);
    let (status, problem) = bob.get("/v1/tenant").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["detail"], "this needs the permission directory.read");

    // The tenant: name, modules, domains.
    assert_eq!(alice.status("PATCH", "/v1/tenant", Some(json!({ "name": "Firma GmbH" }))).await, 204);
    assert_eq!(alice.status("PUT", "/v1/tenant/modules/jitsi", Some(json!({ "enabled": true }))).await, 204);
    assert_eq!(alice.status("PUT", "/v1/tenant/modules/nope", Some(json!({ "enabled": true }))).await, 400);
    let (status, claimed) = alice.send("POST", "/v1/tenant/domains", Some(json!({ "domain": "firma.example" }))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(claimed["record"]["name"], "_kernoid-challenge.firma.example");
    // No DNS resolver here; marking a domain verified without DNS is for instance administrators.
    assert_eq!(alice.status("POST", "/v1/tenant/domains/firma.example/verify", None).await, 400);
    let trust = Some(json!({ "trust": true }));
    assert_eq!(alice.status("POST", "/v1/tenant/domains/firma.example/verify", trust).await, 403);
    let (_, tenant) = alice.get("/v1/tenant").await;
    assert_eq!(tenant["name"], "Firma GmbH");
    assert_eq!(tenant["modules"], json!(["jitsi"]));
    assert_eq!(tenant["domains"].as_array().unwrap().len(), 2);
    assert_eq!(alice.status("DELETE", "/v1/tenant/domains/firma.example", None).await, 204);

    // Accounts.
    let new = json!({ "address": "carol@firma.de", "display_name": "Carol", "password": PASSWORD });
    let (status, created) = alice.send("POST", "/v1/accounts", Some(new)).await;
    assert_eq!(status, StatusCode::CREATED);
    let carol = created["id"].as_str().unwrap().to_owned();
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{carol}/aliases/c@firma.de"), None).await, 204);
    let change = json!({ "display_name": "Carol C.", "primary_address": "c@firma.de" });
    assert_eq!(alice.status("PATCH", &format!("/v1/accounts/{carol}"), Some(change)).await, 204);
    let (_, account) = alice.get(&format!("/v1/accounts/{carol}")).await;
    assert_eq!((account["address"].as_str(), account["display_name"].as_str()), (Some("c@firma.de"), Some("Carol C.")));
    let (_, accounts) = alice.get("/v1/accounts").await;
    assert_eq!(accounts.as_array().unwrap().len(), 3);
    let carol_token = login(&s.app, "c@firma.de").await;
    let (_, sessions) = alice.get(&format!("/v1/accounts/{carol}/sessions")).await;
    assert_eq!(sessions.as_array().unwrap().len(), 1);
    let password = Some(json!({ "password": "another long password" }));
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{carol}/password"), password).await, 204);
    // Setting the password ended Carol's sessions.
    assert_eq!(Call::new(&s.app, &carol_token).status("GET", "/v1/sessions/current", None).await, 401);
    assert_eq!(alice.status("DELETE", &format!("/v1/accounts/{carol}/second-factors"), None).await, 204);
    assert_eq!(alice.status("GET", &format!("/v1/accounts/{}", Uuid::now_v7()), None).await, 404);

    // Groups and roles: Bob becomes a user manager through a group.
    let (_, team) = alice.send("POST", "/v1/groups", Some(json!({ "name": "Team" }))).await;
    let team = team["id"].as_str().unwrap().to_owned();
    assert_eq!(alice.status("PUT", &format!("/v1/groups/{team}/members/{}", s.bob), None).await, 204);
    assert_eq!(alice.status("PUT", &format!("/v1/roles/user_manager/group/{team}"), None).await, 204);
    let (_, permissions) = bob.get("/v1/tenant/permissions").await;
    assert_eq!(
        permissions["permissions"],
        json!(["directory.read", "accounts.manage", "groups.manage", "authorizations.manage"])
    );
    // Bob may not take over Alice: she holds permissions he does not.
    let password = Some(json!({ "password": "taken over, perhaps?" }));
    let (status, problem) = bob.send("PUT", &format!("/v1/accounts/{}/password", s.alice), password).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    let deactivate = Some(json!({ "active": false }));
    assert_eq!(bob.status("PATCH", &format!("/v1/accounts/{}", s.alice), deactivate).await, 403);
    // Nor widen his rights through roles or the group's members.
    assert_eq!(bob.status("PUT", &format!("/v1/roles/tenant_admin/account/{}", s.bob), None).await, 403);
    assert_eq!(bob.status("PUT", &format!("/v1/groups/{team}/members/{}", s.alice), None).await, 403);

    // A role of the tenant's own.
    let definition = Some(json!({ "permissions": ["directory.read", "projects.manage"] }));
    assert_eq!(alice.status("PUT", "/v1/roles/project_lead", definition).await, 204);
    let builtin = Some(json!({ "permissions": ["directory.read"] }));
    assert_eq!(alice.status("PUT", "/v1/roles/auditor", builtin).await, 400);
    let instance_permission = Some(json!({ "permissions": ["tenants.manage"] }));
    assert_eq!(alice.status("PUT", "/v1/roles/sneaky", instance_permission).await, 400);
    assert_eq!(alice.status("PUT", &format!("/v1/roles/project_lead/account/{}", s.bob), None).await, 204);
    let (_, roles) = alice.get("/v1/roles").await;
    let own: Vec<_> = roles["roles"].as_array().unwrap().iter().filter(|role| role["builtin"] == false).collect();
    assert_eq!(own.len(), 1);
    assert_eq!(own[0]["permissions"], json!(["directory.read", "projects.manage"]));
    let (_, permissions) = bob.get("/v1/tenant/permissions").await;
    assert!(permissions["permissions"].as_array().unwrap().contains(&json!("projects.manage")));
    assert_eq!(alice.status("DELETE", "/v1/roles/project_lead", None).await, 400);
    assert_eq!(alice.status("DELETE", &format!("/v1/roles/project_lead/account/{}", s.bob), None).await, 204);
    assert_eq!(alice.status("DELETE", "/v1/roles/project_lead", None).await, 204);

    // The last tenant admin stays; a group with roles too.
    assert_eq!(alice.status("DELETE", &format!("/v1/roles/tenant_admin/account/{}", s.alice), None).await, 400);
    assert_eq!(alice.status("DELETE", &format!("/v1/groups/{team}"), None).await, 400);

    // Instance administration needs instance roles; other tenants stay hidden.
    assert_eq!(alice.status("GET", "/v1/instance/tenants", None).await, 403);
    let other = Call::new(&s.app, &alice_token).for_tenant(s.other);
    assert_eq!(other.status("GET", "/v1/tenant", None).await, 404);
    assert_eq!(Call::new(&s.app, &alice_token).for_tenant("not-an-id").status("GET", "/v1/tenant", None).await, 404);

    let (_, openapi) = Call::anonymous(&s.app).get("/openapi.json").await;
    for path in [
        "/v1/tenant/domains/{domain}/verify",
        "/v1/accounts/{id}/password",
        "/v1/roles/{role}",
        "/v1/projects/{id}/authorizations/{role}/{kind}/{principal}",
        "/v1/applications/{id}/secret",
        "/v1/instance/signing-keys/{kid}/activate",
        "/v1/account/password",
    ] {
        assert!(openapi["paths"][path].is_object(), "{path}");
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_second_factor_with_a_grace_period(pool: PgPool) {
    let s = setup(&pool).await;
    let token = login(&s.app, "alice@firma.de").await;
    let alice = Call::new(&s.app, &token);
    let policy = Some(json!({ "mfa_required": true, "mfa_grace_days": 30 }));
    let (status, tenant) = alice.send("PUT", "/v1/tenant/policy", policy).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!((tenant["mfa_required"].as_bool(), tenant["mfa_grace_days"].as_u64()), (Some(true), Some(30)));
    // Without a second factor yet, alice may go on – and is told until when.
    let (status, factors) = alice.get("/v1/account/factors").await;
    assert_eq!((status, factors["required"].as_bool()), (StatusCode::OK, Some(true)));
    assert!(factors["setup_due"].is_string());
    assert_eq!(alice.status("GET", "/v1/tenant", None).await, 200);
    let bad = Some(json!({ "mfa_required": true, "mfa_grace_days": 400 }));
    assert_eq!(alice.status("PUT", "/v1/tenant/policy", bad).await, 400);
    // Without a grace period, administration needs the second factor.
    let none = Some(json!({ "mfa_required": true, "mfa_grace_days": 0 }));
    assert_eq!(alice.status("PUT", "/v1/tenant/policy", none).await, 200);
    assert_eq!(alice.status("GET", "/v1/tenant", None).await, 401);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn projects_and_applications(pool: PgPool) {
    let s = setup(&pool).await;
    let token = login(&s.app, "alice@firma.de").await;
    let alice = Call::new(&s.app, &token);

    let (status, created) = alice.send("POST", "/v1/projects", Some(json!({ "name": "Portal" }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let project = created["id"].as_str().unwrap().to_owned();
    let role = Some(json!({ "display_name": "Editor", "group": "Content" }));
    assert_eq!(alice.status("PUT", &format!("/v1/projects/{project}/roles/editor"), role).await, 204);
    let role = Some(json!({ "display_name": "Bad" }));
    assert_eq!(alice.status("PUT", &format!("/v1/projects/{project}/roles/has%20space"), role).await, 400);
    let settings = Some(json!({ "role_assertion": true, "role_check": true }));
    assert_eq!(alice.status("PATCH", &format!("/v1/projects/{project}"), settings).await, 204);
    let (_, view) = alice.get(&format!("/v1/projects/{project}")).await;
    assert_eq!((view["role_assertion"].as_bool(), view["role_check"].as_bool()), (Some(true), Some(true)));
    assert_eq!(view["roles"], json!([{ "key": "editor", "display_name": "Editor", "group": "Content" }]));

    let grant = format!("/v1/projects/{project}/authorizations/editor/account/{}", s.bob);
    assert_eq!(alice.status("PUT", &grant, None).await, 204);
    let missing = format!("/v1/projects/{project}/authorizations/admin/account/{}", s.bob);
    assert_eq!(alice.status("PUT", &missing, None).await, 404);
    let (_, holders) = alice.get(&format!("/v1/projects/{project}/authorizations")).await;
    assert_eq!(
        holders,
        json!([{ "role": "editor", "tenant": s.tenant.to_string(), "principal_kind": "account",
                    "principal_id": s.bob.to_string() }])
    );
    assert_eq!(alice.status("DELETE", &format!("/v1/projects/{project}/roles/editor"), None).await, 400);

    // Applications live in projects.
    let new = json!({
        "project": project,
        "name": "Portal",
        "kind": "confidential",
        "redirect_uris": ["https://portal.firma.de/callback"],
    });
    let (status, created) = alice.send("POST", "/v1/applications", Some(new)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(created["client_secret"].as_str().unwrap().starts_with("kcs1."));
    let application = created["id"].as_str().unwrap().to_owned();
    let change = json!({ "name": "Portal 2", "post_logout_redirect_uris": ["https://portal.firma.de/"] });
    assert_eq!(alice.status("PATCH", &format!("/v1/applications/{application}"), Some(change)).await, 204);
    let (status, secret) = alice.send("POST", &format!("/v1/applications/{application}/secret"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(secret["client_secret"].as_str().unwrap().starts_with("kcs1."));
    let policy = Some(json!({ "mfa_required": true }));
    let (_, view) = alice.send("PUT", &format!("/v1/applications/{application}/policy"), policy.clone()).await;
    assert_eq!((view["name"].as_str(), view["mfa_required"].as_bool()), (Some("Portal 2"), Some(true)));
    assert_eq!(view["project"], json!(project));
    let foreign = format!("/v1/applications/{}/policy", s.foreign_application);
    assert_eq!(alice.status("PUT", &foreign, policy).await, 404);
    assert_eq!(alice.status("DELETE", &format!("/v1/projects/{project}"), None).await, 400);
    let (_, applications) = alice.get("/v1/applications").await;
    assert_eq!(applications.as_array().unwrap().len(), 1);

    // Options: token format, offline access, consent, logout notifications.
    assert_eq!(view["options"]["access_token_format"], "opaque");
    let options = json!({ "access_token_format": "jwt", "offline_access": true,
                          "frontchannel_logout_uri": "https://portal.firma.de/logout" });
    let (status, view) = alice.send("PUT", &format!("/v1/applications/{application}/options"), Some(options)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        view["options"],
        json!({ "access_token_format": "jwt", "offline_access": true, "consent_required": false,
                "backchannel_logout_uri": null, "frontchannel_logout_uri": "https://portal.firma.de/logout" })
    );
    let private = json!({ "backchannel_logout_uri": "https://10.0.0.1/logout" });
    assert_eq!(alice.status("PUT", &format!("/v1/applications/{application}/options"), Some(private)).await, 400);
    let bad = json!({ "access_token_format": "paseto" });
    assert_eq!(alice.status("PUT", &format!("/v1/applications/{application}/options"), Some(bad)).await, 400);

    // Consents of an account: none yet.
    let (status, consents) = alice.get(&format!("/v1/accounts/{}/consents", s.bob)).await;
    assert_eq!((status, consents), (StatusCode::OK, json!([])));
    let path = format!("/v1/accounts/{}/consents/{application}", s.bob);
    assert_eq!(alice.status("DELETE", &path, None).await, 404);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn instance_administrators(pool: PgPool) {
    let s = setup(&pool).await;
    let identity = Identity::new(EventStore::new(pool.clone()));
    let admin = Role::parse("instance_admin").unwrap();
    identity.grant_instance_role(s.instance, Principal::Account(s.bob), &admin, "test").await.unwrap();
    let token = login(&s.app, "bob@firma.de").await;
    let bob = Call::new(&s.app, &token);

    let (_, details) = bob.get("/v1/instance/details").await;
    assert_eq!(details["domains"], json!([HOST]));
    let (_, tenants) = bob.get("/v1/instance/tenants").await;
    assert_eq!(tenants.as_array().unwrap().len(), 2);
    let (status, created) = bob.send("POST", "/v1/instance/tenants", Some(json!({ "name": "Third" }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let third = created["id"].as_str().unwrap().to_owned();
    let change = Some(json!({ "name": "Third Ltd", "active": false }));
    assert_eq!(bob.status("PATCH", &format!("/v1/instance/tenants/{third}"), change).await, 204);
    let own = Some(json!({ "active": false }));
    assert_eq!(bob.status("PATCH", &format!("/v1/instance/tenants/{}", s.tenant), own).await, 400);

    // Acting on another tenant through the header.
    let other = Call::new(&s.app, &token).for_tenant(s.other);
    let (status, tenant) = other.get("/v1/tenant").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tenant["name"], "Other");
    let (_, accounts) = other.get("/v1/accounts").await;
    assert_eq!(accounts[0]["address"], "dave@other.de");
    let (_, created) = other.send("POST", "/v1/tenant/domains", Some(json!({ "domain": "other.example" }))).await;
    assert_eq!(created["domain"], "other.example");
    let trust = Some(json!({ "trust": true }));
    assert_eq!(other.status("POST", "/v1/tenant/domains/other.example/verify", trust).await, 204);

    // Instance roles, domains and signing keys.
    let (_, roles) = bob.get("/v1/instance/roles").await;
    assert_eq!(roles["assignments"].as_array().unwrap().len(), 1);
    let path = format!("/v1/instance/roles/instance_auditor/account/{}", s.alice);
    assert_eq!(bob.status("PUT", &path, None).await, 204);
    let path = format!("/v1/instance/roles/instance_admin/account/{}", s.bob);
    assert_eq!(bob.status("DELETE", &path, None).await, 400);
    assert_eq!(bob.status("PUT", "/v1/instance/domains/sso.firma.de", None).await, 204);
    assert_eq!(bob.status("DELETE", &format!("/v1/instance/domains/{HOST}"), None).await, 400);
    assert_eq!(bob.status("PATCH", "/v1/instance", Some(json!({ "name": "Firma SSO" }))).await, 204);
    let (status, key) = bob.send("POST", "/v1/instance/signing-keys", None).await;
    assert_eq!(status, StatusCode::CREATED);
    let kid = key["kid"].as_str().unwrap();
    assert_eq!(bob.status("POST", &format!("/v1/instance/signing-keys/{kid}/activate"), None).await, 204);
    let (_, keys) = bob.get("/v1/instance/signing-keys").await;
    assert_eq!(keys[0]["state"], "active");

    // A login UI of the instance's own.
    let ui = Some(json!({ "url": "https://anmeldung.firma.de/" }));
    assert_eq!(bob.status("PUT", "/v1/instance/login-ui", ui).await, 204);
    let (_, details) = bob.get("/v1/instance/details").await;
    assert_eq!(details["login_ui_url"], "https://anmeldung.firma.de/");
    let bad = Some(json!({ "url": "http://anmeldung.firma.de/" }));
    assert_eq!(bob.status("PUT", "/v1/instance/login-ui", bad).await, 400);
    assert_eq!(bob.status("PUT", "/v1/instance/login-ui", Some(json!({ "url": null }))).await, 204);

    // Passkeys stay bound to their RP ID; another needs a domain of the instance under it.
    assert_eq!(details["passkey_rp_id"], HOST);
    assert_eq!(bob.status("PUT", "/v1/instance/passkey-rp-id", Some(json!({ "rp_id": "example.com" }))).await, 400);
    let (_, related) = Call::anonymous(&s.app).get("/.well-known/webauthn").await;
    assert_eq!(related["origins"][0], format!("https://{HOST}"));

    // Instance roles of the instance's own.
    let helpdesk = Some(json!({ "permissions": ["instance.read", "directory.read"] }));
    assert_eq!(bob.status("PUT", "/v1/instance/roles/helpdesk", helpdesk).await, 204);
    assert_eq!(
        bob.status("PUT", "/v1/instance/roles/instance_admin", Some(json!({ "permissions": ["instance.read"] }))).await,
        400
    );
    let path = format!("/v1/instance/roles/helpdesk/account/{}", s.alice);
    assert_eq!(bob.status("PUT", &path, None).await, 204);
    let (_, roles) = bob.get("/v1/instance/roles").await;
    let own = roles["roles"].as_array().unwrap().iter().find(|role| role["name"] == "helpdesk").unwrap().clone();
    assert_eq!(
        own,
        json!({ "name": "helpdesk", "permissions": ["instance.read"],
                            "tenant_permissions": ["directory.read"], "builtin": false })
    );
    assert_eq!(bob.status("DELETE", "/v1/instance/roles/helpdesk", None).await, 400);
    assert_eq!(bob.status("DELETE", &path, None).await, 204);
    assert_eq!(bob.status("DELETE", "/v1/instance/roles/helpdesk", None).await, 204);

    // The auditor reads, changes nothing – also in other tenants.
    let auditor_token = login(&s.app, "alice@firma.de").await;
    let auditor = Call::new(&s.app, &auditor_token).for_tenant(s.other);
    assert_eq!(auditor.status("GET", "/v1/accounts", None).await, 200);
    assert_eq!(auditor.status("POST", "/v1/groups", Some(json!({ "name": "X" }))).await, 403);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn own_account(pool: PgPool) {
    let s = setup(&pool).await;
    let first = login(&s.app, "bob@firma.de").await;
    let second = login(&s.app, "bob@firma.de").await;
    let bob = Call::new(&s.app, &first);

    let (_, sessions) = bob.get("/v1/sessions").await;
    assert_eq!(sessions.as_array().unwrap().len(), 2);
    assert_eq!(bob.status("PATCH", "/v1/account", Some(json!({ "display_name": "Bob B." }))).await, 204);
    let wrong = json!({ "current_password": "wrong", "new_password": "a new long password" });
    assert_eq!(bob.status("PUT", "/v1/account/password", Some(wrong)).await, 401);
    let right = json!({ "current_password": PASSWORD, "new_password": "a new long password" });
    assert_eq!(bob.status("PUT", "/v1/account/password", Some(right)).await, 204);
    // The other session ended, this one goes on.
    assert_eq!(Call::new(&s.app, &second).status("GET", "/v1/sessions/current", None).await, 401);
    let (_, current) = bob.get("/v1/sessions/current").await;
    assert_eq!(current["account"]["display_name"], "Bob B.");
    let id = current["id"].as_str().unwrap().to_owned();
    assert_eq!(bob.status("DELETE", &format!("/v1/sessions/{}", Uuid::now_v7()), None).await, 404);
    assert_eq!(bob.status("DELETE", &format!("/v1/sessions/{id}"), None).await, 204);
    assert_eq!(bob.status("GET", "/v1/sessions/current", None).await, 401);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn graphql_administration(pool: PgPool) {
    let s = setup(&pool).await;
    let alice_token = login(&s.app, "alice@firma.de").await;
    let bob_token = login(&s.app, "bob@firma.de").await;
    let (alice, bob) = (Call::new(&s.app, &alice_token), Call::new(&s.app, &bob_token));

    let body = bob.graphql("{ tenant { name } }").await;
    assert_eq!(body["errors"][0]["extensions"]["code"], "FORBIDDEN");

    let body = alice.graphql(r#"mutation { addGroup(name: "Team") addProject(name: "Portal") }"#).await;
    let team = body["data"]["addGroup"].as_str().unwrap().to_owned();
    let project = body["data"]["addProject"].as_str().unwrap().to_owned();
    let mutation = format!(
        r#"mutation {{
            addGroupMember(group: "{team}", account: "{bob}")
            defineRole(name: "reader", permissions: ["directory.read"])
            grantRole(role: "reader", principalKind: "group", principalId: "{team}")
            setProjectRole(project: "{project}", key: "viewer", displayName: "Viewer")
            grantProjectRole(project: "{project}", role: "viewer", principalKind: "group", principalId: "{team}")
            updateProject(id: "{project}", roleCheck: true) {{ roleCheck roles {{ key }} }}
        }}"#,
        bob = s.bob
    );
    let body = alice.graphql(&mutation).await;
    assert_eq!(body["errors"], Value::Null, "{body}");
    assert_eq!(body["data"]["updateProject"], json!({ "roleCheck": true, "roles": [{ "key": "viewer" }] }));

    let body = bob.graphql("{ permissions { permissions } groups { name } roles { roles { name builtin } } }").await;
    assert_eq!(body["data"]["permissions"]["permissions"], json!(["directory.read"]));
    assert_eq!(body["data"]["groups"], json!([{ "name": "Team" }]));
    assert_eq!(body["data"]["roles"]["roles"].as_array().unwrap().len(), 5);

    let mutation = format!(
        r#"mutation {{ addApplication(project: "{project}", name: "Portal", kind: "public",
            redirectUris: ["https://portal.firma.de/callback"]) {{ id clientSecret }} }}"#
    );
    let body = alice.graphql(&mutation).await;
    assert_eq!(body["data"]["addApplication"]["clientSecret"], Value::Null);
    let application = body["data"]["addApplication"]["id"].as_str().unwrap().to_owned();
    let mutation = format!(r#"mutation {{ updateApplication(id: "{application}", active: false) {{ active }} }}"#);
    assert_eq!(alice.graphql(&mutation).await["data"]["updateApplication"]["active"], false);
    let mutation = format!(
        r#"mutation {{ setApplicationPolicy(id: "{}", mfaRequired: true) {{ mfaRequired }} }}"#,
        s.foreign_application
    );
    assert_eq!(alice.graphql(&mutation).await["errors"][0]["extensions"]["code"], "NOT_FOUND");

    let mutation = format!(
        r#"mutation {{ revokeRole(role: "tenant_admin", principalKind: "account", principalId: "{}") }}"#,
        s.alice
    );
    assert_eq!(alice.graphql(&mutation).await["errors"][0]["extensions"]["code"], "BAD_REQUEST");
    let body = bob.graphql("{ mySessions { id } }").await;
    assert_eq!(body["data"]["mySessions"].as_array().unwrap().len(), 1);
    assert_eq!(alice.graphql("{ tenants { name } }").await["errors"][0]["extensions"]["code"], "FORBIDDEN");
    let other = Call::new(&s.app, &alice_token).for_tenant(s.other);
    assert_eq!(other.graphql("{ accounts { address } }").await["errors"][0]["extensions"]["code"], "NOT_FOUND");

    let body = alice.graphql("mutation { setTenantPolicy(mfaRequired: true) { mfaRequired } }").await;
    assert_eq!(body["data"]["setTenantPolicy"]["mfaRequired"], true);
    let body = alice.graphql("{ tenant { name } }").await;
    assert_eq!(body["errors"][0]["extensions"]["code"], "MFA_REQUIRED");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn projects_are_granted_to_other_tenants(pool: PgPool) {
    let s = setup(&pool).await;
    let identity = Identity::new(EventStore::new(pool.clone()));
    let dave = identity.account_by_address(&Address::parse("dave@other.de").unwrap()).await.unwrap().unwrap();
    let admin = Role::parse("tenant_admin").unwrap();
    identity.grant_role(s.other, Principal::Account(dave.id), &admin, "test").await.unwrap();
    let alice_token = login(&s.app, "alice@firma.de").await;
    let dave_token = login(&s.app, "dave@other.de").await;
    let (alice, dave_call) = (Call::new(&s.app, &alice_token), Call::new(&s.app, &dave_token));

    let (_, created) = alice.send("POST", "/v1/projects", Some(json!({ "name": "Portal" }))).await;
    let project = created["id"].as_str().unwrap().to_owned();
    for key in ["editor", "admin"] {
        let role = Some(json!({ "display_name": key }));
        assert_eq!(alice.status("PUT", &format!("/v1/projects/{project}/roles/{key}"), role).await, 204);
    }
    // Granted by a verified mail domain of the other tenant.
    let roles = Some(json!({ "roles": ["editor"] }));
    assert_eq!(alice.status("PUT", &format!("/v1/projects/{project}/grants/other.de"), roles).await, 204);
    let unknown = Some(json!({ "roles": ["editor"] }));
    assert_eq!(alice.status("PUT", &format!("/v1/projects/{project}/grants/nowhere.de"), unknown).await, 404);
    let (_, grants) = alice.get(&format!("/v1/projects/{project}/grants")).await;
    assert_eq!(grants[0]["tenant_name"], "Other");

    // The other tenant sees the grant and gives the granted role to its own account – no other role.
    let (_, granted) = dave_call.get("/v1/granted-projects").await;
    assert_eq!(granted[0]["roles"], json!(["editor"]));
    let path = format!("/v1/projects/{project}/authorizations/editor/account/{}", dave.id);
    assert_eq!(dave_call.status("PUT", &path, None).await, 204);
    let path = format!("/v1/projects/{project}/authorizations/admin/account/{}", dave.id);
    assert_eq!(dave_call.status("PUT", &path, None).await, 404);
    // Nor may it change the project itself.
    assert_eq!(
        dave_call.status("PATCH", &format!("/v1/projects/{project}"), Some(json!({ "name": "Mine" }))).await,
        404
    );
    let alice_grant = format!("/v1/projects/{project}/authorizations/editor/account/{}", s.alice);
    assert_eq!(alice.status("PUT", &alice_grant, None).await, 204);
    let (_, own) = dave_call.get(&format!("/v1/projects/{project}/authorizations")).await;
    assert_eq!(own.as_array().unwrap().len(), 1);
    let (_, all) = alice.get(&format!("/v1/projects/{project}/authorizations")).await;
    assert_eq!(all.as_array().unwrap().len(), 2);

    // The grant stays while its roles are held there.
    assert_eq!(alice.status("DELETE", &format!("/v1/projects/{project}/grants/{}", s.other), None).await, 400);
    let body = dave_call.graphql("{ grantedProjects { projectName roles } }").await;
    assert_eq!(body["data"]["grantedProjects"], json!([{ "projectName": "Portal", "roles": ["editor"] }]));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn identity_providers_are_administered(pool: PgPool) {
    let s = setup(&pool).await;
    let token = login(&s.app, "alice@firma.de").await;
    let alice = Call::new(&s.app, &token);
    let new = json!({
        "name": "Firma SSO",
        "issuer": "https://sso.firma.de/realms/firma",
        "client_id": "kernoid",
        "client_secret": "s3cret",
        "scopes": ["email", "profile"],
        "domains": ["firma.de"],
        "auto_create": true,
    });
    let (status, created) = alice.send("POST", "/v1/identity-providers", Some(new)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let idp = created["id"].as_str().unwrap().to_owned();
    let (_, view) = alice.get(&format!("/v1/identity-providers/{idp}")).await;
    assert_eq!(view["redirect_uri"], "https://login.firma.de/idp/callback");
    assert_eq!(view["scopes"], json!(["openid", "email", "profile"]));
    assert_eq!(view["has_secret"], true);
    assert!(view.get("client_secret").is_none());

    // Logins of firma.de go there; other domains, and switched-off providers, do not.
    let anonymous = Call::anonymous(&s.app);
    let (_, options) = anonymous.get("/v1/login-options?address=bob%40firma.de").await;
    assert_eq!(options["identity_provider"]["name"], "Firma SSO");
    let (_, options) = anonymous.get("/v1/login-options?address=dave%40other.de").await;
    assert_eq!(options["identity_provider"], Value::Null);
    assert_eq!(
        alice.status("PATCH", &format!("/v1/identity-providers/{idp}"), Some(json!({ "active": false }))).await,
        204
    );
    let (_, options) = anonymous.get("/v1/login-options?address=bob%40firma.de").await;
    assert_eq!(options["identity_provider"], Value::Null);

    assert_eq!((view["instance_wide"].as_bool(), view["sync_profile"].as_bool()), (Some(false), Some(false)));
    // A provider for the whole instance needs instance.manage – a tenant administrator has none.
    let wide = json!({ "name": "All", "issuer": "https://sso.firma.de/all", "client_id": "k", "instance_wide": true });
    assert_eq!(alice.status("POST", "/v1/identity-providers", Some(wide)).await, 403);

    // Settings are checked: plain HTTP and domains of others are refused.
    let bad = json!({ "name": "X", "issuer": "http://sso.firma.de", "client_id": "k" });
    assert_eq!(alice.status("POST", "/v1/identity-providers", Some(bad)).await, 400);
    let bad = json!({ "name": "X", "issuer": "https://sso.other.de", "client_id": "k", "domains": ["other.de"] });
    assert_eq!(alice.status("POST", "/v1/identity-providers", Some(bad)).await, 400);
    // Others may not see or change it.
    let bob_token = login(&s.app, "bob@firma.de").await;
    assert_eq!(Call::new(&s.app, &bob_token).status("GET", "/v1/identity-providers", None).await, 403);

    let body = alice.graphql("{ identityProviders { name redirectUri active } }").await;
    assert_eq!(body["data"]["identityProviders"][0]["active"], false);
    assert_eq!(alice.status("DELETE", &format!("/v1/identity-providers/{idp}/secret"), None).await, 204);
    assert_eq!(alice.status("DELETE", &format!("/v1/identity-providers/{idp}"), None).await, 204);

    // The callback with an unknown state goes back to the login UI with an error.
    let response = s
        .app
        .clone()
        .oneshot(Request::get("/idp/callback?state=forged&code=x").header("host", HOST).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("https://login.firma.de/login/idp#error="), "{location}");
    // A one-time code that does not exist gets no session.
    let exchange = Some(json!({ "login": format!("{}.nothing", Uuid::now_v7()) }));
    assert_eq!(anonymous.status("POST", "/v1/idp-logins/session", exchange).await, 401);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn saml_endpoints_answer(pool: PgPool) {
    let s = setup(&pool).await;
    let request = Request::get("/idp/saml/metadata").header("host", HOST).body(Body::empty()).unwrap();
    let response = s.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/samlmetadata+xml");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let metadata = String::from_utf8(body.to_vec()).unwrap();
    assert!(metadata.contains(r#"entityID="https://login.firma.de/idp/saml""#), "{metadata}");
    assert!(metadata.contains(r#"Location="https://login.firma.de/idp/saml/acs""#));

    // A Response for no login under way goes back to the login UI with an error.
    let request = Request::post("/idp/saml/acs")
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("SAMLResponse=PHg%2B&RelayState=forged"))
        .unwrap();
    let response = s.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response.headers()["location"].to_str().unwrap().starts_with("https://login.firma.de/login/idp#error="));
}
