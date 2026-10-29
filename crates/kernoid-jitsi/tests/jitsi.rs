// SPDX-License-Identifier: AGPL-3.0-or-later
//! The routes of the module jitsi against PostgreSQL; set `DATABASE_URL` as for the other crates' tests. Who is
//! logged in comes from a header here, in place of the core's sessions.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header, request::Parts},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::future::BoxFuture;
use kernoid_events::EventStore;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_jitsi::JitsiModule;
use kernoid_module::{Caller, Context, Module, Sessions};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WHO: &str = "operator";

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

/// Logged in as the account a header names.
#[derive(Debug, Default)]
struct FakeSessions(Mutex<HashMap<String, Caller>>);

impl Sessions for FakeSessions {
    fn caller<'a>(&'a self, request: &'a Parts) -> BoxFuture<'a, Option<Caller>> {
        let name = request.headers.get("x-test-login").and_then(|value| value.to_str().ok()).map(str::to_owned);
        Box::pin(async move { self.0.lock().unwrap().get(&name?).cloned() })
    }
}

struct Setup {
    identity: Identity,
    sessions: Arc<FakeSessions>,
    router: Router,
    instance: Uuid,
}

async fn setup(pool: PgPool, guests: bool) -> Setup {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let sessions = Arc::new(FakeSessions::default());
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let config: toml::Table = toml::from_str(&format!(
        "url = \"https://meet.example.org\"\napp_id = \"kernoid\"\napp_secret = \"{}\"\nguests = {guests}",
        "s".repeat(32)
    ))
    .unwrap();
    let context = Context {
        db: pool.clone(),
        events: EventStore::new(pool.clone()),
        blobs: BlobStore::new(Arc::new(InMemory::new()), keys),
        sessions: Some(sessions.clone()),
        config,
    };
    let router = Router::new().nest("/modules/jitsi", JitsiModule.routes(&context).unwrap());
    Setup { identity, sessions, router, instance }
}

impl Setup {
    /// A tenant with the domain `<domain>`, and the account `<local>@<domain>`, logged in as `<local>`.
    async fn tenant(&self, domain: &str, uses: bool) -> Uuid {
        let tenant = self.identity.add_tenant(self.instance, domain, WHO).await.unwrap();
        let name = DomainName::parse(domain).unwrap();
        let token = self.identity.add_tenant_domain(self.instance, tenant, &name, WHO).await.unwrap();
        let dns = FakeDns::default();
        dns.0
            .lock()
            .unwrap()
            .insert(format!("{CHALLENGE_LABEL}.{domain}"), vec![format!("kernoid-verification={token}")]);
        self.identity.verify_tenant_domain(self.instance, tenant, &name, &dns, WHO).await.unwrap();
        if uses {
            self.identity.set_tenant_module(self.instance, tenant, "jitsi", true, &["jitsi"], WHO).await.unwrap();
        }
        tenant
    }

    async fn log_in(&self, tenant: Uuid, local: &str, domain: &str) {
        let address = format!("{local}@{domain}");
        let account = self.identity.add_account(tenant, &Address::parse(&address).unwrap(), local, WHO).await.unwrap();
        let caller = Caller {
            account,
            tenant,
            instance: self.instance,
            display_name: local.to_owned(),
            address,
            base: "https://login.firma.example".into(),
        };
        self.sessions.0.lock().unwrap().insert(local.to_owned(), caller);
    }

    async fn request(&self, method: &str, path: &str, login: Option<&str>) -> (StatusCode, Option<String>, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(login) = login {
            request = request.header("x-test-login", login);
        }
        let response = self.router.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
        let status = response.status();
        let location = response.headers().get(header::LOCATION).map(|value| value.to_str().unwrap().to_owned());
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, location, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

fn claims(location: &str) -> Value {
    let token = location.split_once("?jwt=").unwrap().1;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn meetings_are_made_and_joined_with_tokens(pool: PgPool) {
    let setup = setup(pool, false).await;
    let firma = setup.tenant("firma.example", true).await;
    let other = setup.tenant("other.example", false).await;
    setup.log_in(firma, "alice", "firma.example").await;
    setup.log_in(firma, "bob", "firma.example").await;
    setup.log_in(other, "carol", "other.example").await;

    // Only where the tenant uses it.
    assert_eq!(setup.request("GET", "/modules/jitsi/status", Some("alice")).await.2["enabled"], true);
    assert_eq!(setup.request("GET", "/modules/jitsi/status", Some("carol")).await.2["enabled"], false);
    assert_eq!(setup.request("GET", "/modules/jitsi/status", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(setup.request("POST", "/modules/jitsi/meetings", Some("carol")).await.0, StatusCode::FORBIDDEN);
    assert_eq!(setup.request("POST", "/modules/jitsi/meetings", None).await.0, StatusCode::UNAUTHORIZED);

    let (status, _, meeting) = setup.request("POST", "/modules/jitsi/meetings", Some("alice")).await;
    assert_eq!(status, StatusCode::CREATED);
    let room = meeting["room"].as_str().unwrap().to_owned();
    assert_eq!(meeting["url"], format!("https://login.firma.example/modules/jitsi/join/{room}"));
    let join = format!("/modules/jitsi/join/{room}");

    // The owner as moderator, others of the instance as participants – each with a token for this room only.
    let (status, location, _) = setup.request("GET", &join, Some("alice")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.unwrap();
    assert!(location.starts_with(&format!("https://meet.example.org/{room}?jwt=")), "{location}");
    let alice = claims(&location);
    assert_eq!((alice["room"].as_str(), alice["sub"].as_str()), (Some(room.as_str()), Some("meet.example.org")));
    assert_eq!(alice["context"]["user"]["moderator"], "true");
    for participant in ["bob", "carol"] {
        let location = setup.request("GET", &join, Some(participant)).await.1.unwrap();
        assert_eq!(claims(&location)["context"]["user"]["moderator"], "false", "{participant}");
    }

    // Without a session: the login, which comes back here.
    let (status, location, _) = setup.request("GET", &join, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.unwrap(), format!("/login/account?next=%2Fmodules%2Fjitsi%2Fjoin%2F{room}"));
    assert_eq!(
        setup.request("GET", "/modules/jitsi/join/000000000000000000000000", Some("alice")).await.0,
        StatusCode::NOT_FOUND
    );

    // A tenant that stops using it: its meetings are gone.
    setup.identity.set_tenant_module(setup.instance, firma, "jitsi", false, &[], WHO).await.unwrap();
    assert_eq!(setup.request("GET", &join, Some("alice")).await.0, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn guests_join_without_a_token_where_jitsi_lets_them(pool: PgPool) {
    let setup = setup(pool, true).await;
    let firma = setup.tenant("firma.example", true).await;
    setup.log_in(firma, "alice", "firma.example").await;
    let room =
        setup.request("POST", "/modules/jitsi/meetings", Some("alice")).await.2["room"].as_str().unwrap().to_owned();
    let (status, location, _) = setup.request("GET", &format!("/modules/jitsi/join/{room}"), None).await;
    assert_eq!(
        (status, location.as_deref()),
        (StatusCode::SEE_OTHER, Some(format!("https://meet.example.org/{room}").as_str()))
    );
}
