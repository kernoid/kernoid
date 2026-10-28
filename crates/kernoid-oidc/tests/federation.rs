// SPDX-License-Identifier: AGPL-3.0-or-later
//! Logging in with an external identity provider, against PostgreSQL and a fake provider on 127.0.0.1 that signs
//! RS256 ID tokens and checks PKCE; set `DATABASE_URL` as for the other tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair, KeySize},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use axum::{Form, Json, Router, extract::State, routing::get, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity, InstanceInfo, session::ClientMeta};
use kernoid_oidc::{Oidc, federation::IdpSettings};
use kernoid_store::{MainKeys, crypto::Key};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// The fake provider: what the test lets it answer.
#[derive(Default)]
struct Provider {
    issuer: String,
    /// From the authorization request: the PKCE challenge and the nonce to put into the ID token.
    challenge: String,
    nonce: String,
    /// The claims besides iss, aud, exp, iat, nonce.
    claims: Value,
}

type Shared = Arc<(Mutex<Provider>, KeyPair)>;

fn jwk(key: &KeyPair) -> Value {
    let public = key.public_key();
    json!({ "kty": "RSA", "kid": "fake-1", "alg": "RS256", "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
            "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()) })
}

async fn discovery(State(shared): State<Shared>) -> Json<Value> {
    let issuer = shared.0.lock().unwrap().issuer.clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/keys"),
    }))
}

async fn keys(State(shared): State<Shared>) -> Json<Value> {
    Json(json!({ "keys": [jwk(&shared.1)] }))
}

async fn token(
    State(shared): State<Shared>,
    Form(form): Form<HashMap<String, String>>,
) -> (axum::http::StatusCode, Json<Value>) {
    let provider = shared.0.lock().unwrap();
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != provider.challenge
        || form.get("client_secret").map(String::as_str) != Some("s3cret")
    {
        return (axum::http::StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })));
    }
    let now = chrono::Utc::now().timestamp();
    let mut claims =
        json!({ "iss": provider.issuer, "aud": "kernoid", "exp": now + 300, "iat": now, "nonce": provider.nonce });
    for (key, value) in provider.claims.as_object().unwrap() {
        claims[key] = value.clone();
    }
    let part = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
    let input = format!("{}.{}", part(&json!({ "alg": "RS256", "kid": "fake-1" })), part(&claims));
    let mut signature = vec![0; shared.1.public_modulus_len()];
    shared.1.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut signature).unwrap();
    let id_token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
    (axum::http::StatusCode::OK, Json(json!({ "access_token": "x", "token_type": "Bearer", "id_token": id_token })))
}

async fn provider() -> Shared {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let shared: Shared = Arc::new((
        Mutex::new(Provider { issuer, ..Provider::default() }),
        KeyPair::generate(KeySize::Rsa2048).unwrap(),
    ));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/keys", get(keys))
        .route("/token", post(token))
        .with_state(shared.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    shared
}

struct Setup {
    oidc: Oidc,
    identity: Identity,
    instance: InstanceInfo,
    tenant: Uuid,
    shared: Shared,
}

async fn setup(pool: &PgPool) -> Setup {
    let events = EventStore::new(pool.clone());
    let identity = Identity::new(events.clone());
    let oidc =
        Oidc::new(events, MainKeys::new(Key::random().unwrap(), Vec::new()), "https").allow_private_networks(true);
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let id = identity.add_instance("Firma", &domain("login.firma.de"), "test").await.unwrap();
    let tenant = identity.add_tenant(id, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    let instance = identity.instance_by_host("login.firma.de").await.unwrap().unwrap();
    Setup { oidc, identity, instance, tenant, shared: provider().await }
}

fn settings(issuer: &str, auto_create: bool, auto_link: bool) -> IdpSettings {
    IdpSettings {
        name: "Firma SSO".into(),
        issuer: issuer.into(),
        client_id: "kernoid".into(),
        scopes: vec!["email".into(), "profile".into()],
        domains: vec!["firma.de".into()],
        auto_create,
        auto_link,
        sync_profile: false,
        register: false,
        saml: None,
    }
}

/// Starts a login, lets the fake provider answer with `claims`, and returns the login UI's fragment.
async fn login(s: &Setup, idp: Uuid, claims: Value) -> HashMap<String, String> {
    let url = s.oidc.start_idp_login(&s.instance, idp, None, Some("bob@firma.de")).await.unwrap();
    let url = url::Url::parse(&url).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["redirect_uri"], "https://login.firma.de/idp/callback");
    assert_eq!(query["scope"], "openid email profile");
    assert_eq!(query["login_hint"], "bob@firma.de");
    {
        let mut provider = s.shared.0.lock().unwrap();
        provider.challenge = query["code_challenge"].clone();
        provider.nonce = query["nonce"].clone();
        provider.claims = claims;
    }
    let back = s.oidc.idp_callback(&s.instance, Some(&query["state"]), Some("the-code"), None).await;
    let (page, fragment) = back.split_once('#').unwrap();
    assert_eq!(page, "https://login.firma.de/login/idp");
    url::form_urlencoded::parse(fragment.as_bytes()).into_owned().collect()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_first_login_creates_the_account_and_later_ones_find_it(pool: PgPool) {
    let s = setup(&pool).await;
    let issuer = s.shared.0.lock().unwrap().issuer.clone();
    let idp =
        s.oidc.add_identity_provider(s.tenant, &settings(&issuer, true, false), Some("s3cret"), "test").await.unwrap();

    let found = s.oidc.login_options(s.instance.id, "bob@firma.de").await.unwrap().unwrap();
    assert_eq!((found.id, found.name.as_str()), (idp, "Firma SSO"));
    assert!(s.oidc.login_options(s.instance.id, "bob@elsewhere.de").await.unwrap().is_none());

    let claims = json!({ "sub": "ext-bob", "email": "bob@firma.de", "email_verified": true, "name": "Bob", "amr": ["pwd", "mfa"] });
    let answer = login(&s, idp, claims.clone()).await;
    let handoff = answer.get("login").expect("a one-time code").clone();
    let result = s.oidc.exchange_idp_login(s.instance.id, &handoff, None, &ClientMeta::default()).await.unwrap();
    assert_eq!(result.session.account.address, "bob@firma.de");
    assert_eq!(result.session.account.display_name, "Bob");
    let session = s.identity.session(s.instance.id, &result.session.token).await.unwrap();
    assert_eq!(session.checks, ["idp", "idp_mfa"]);
    assert!(kernoid_identity::session::is_multi_factor(&session.checks));
    // The one-time code works once.
    assert!(s.oidc.exchange_idp_login(s.instance.id, &handoff, None, &ClientMeta::default()).await.is_err());

    // The next login finds the linked account, even with another address at the provider.
    let mut changed = claims;
    changed["email"] = json!("robert@firma.de");
    changed["amr"] = json!(["pwd"]);
    let answer = login(&s, idp, changed).await;
    let again = s.oidc.exchange_idp_login(s.instance.id, &answer["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(again.session.account.id, result.session.account.id);
    let checks = s.identity.session(s.instance.id, &again.session.token).await.unwrap().checks;
    assert_eq!(checks, ["idp"]);

    let links = s.identity.account_links(result.session.account.id).await.unwrap();
    assert_eq!((links[0].idp, links[0].subject.as_str()), (idp, "ext-bob"));
    // A provider with linked accounts stays.
    assert!(s.oidc.remove_identity_provider(s.tenant, idp, "test").await.is_err());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn without_creating_or_linking_unknown_people_are_refused(pool: PgPool) {
    let s = setup(&pool).await;
    let issuer = s.shared.0.lock().unwrap().issuer.clone();
    let idp =
        s.oidc.add_identity_provider(s.tenant, &settings(&issuer, false, true), Some("s3cret"), "test").await.unwrap();
    let alice =
        s.identity.add_account(s.tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();

    // Nobody with that address: refused, not created.
    let answer = login(&s, idp, json!({ "sub": "ext-bob", "email": "bob@firma.de", "email_verified": true })).await;
    assert!(answer["error"].contains("no kernoid account"), "{answer:?}");
    // An address the provider does not vouch for is not linked.
    let answer =
        login(&s, idp, json!({ "sub": "ext-alice", "email": "alice@firma.de", "email_verified": false })).await;
    assert!(answer.contains_key("error"));
    // A verified one is.
    let answer = login(&s, idp, json!({ "sub": "ext-alice", "email": "alice@firma.de", "email_verified": true })).await;
    let result =
        s.oidc.exchange_idp_login(s.instance.id, &answer["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(result.session.account.id, alice);

    // An ID token for another nonce is refused.
    let url = s.oidc.start_idp_login(&s.instance, idp, None, None).await.unwrap();
    let query: HashMap<String, String> = url::Url::parse(&url).unwrap().query_pairs().into_owned().collect();
    {
        let mut provider = s.shared.0.lock().unwrap();
        provider.challenge = query["code_challenge"].clone();
        provider.nonce = "another".into();
        provider.claims = json!({ "sub": "ext-alice" });
    }
    let back = s.oidc.idp_callback(&s.instance, Some(&query["state"]), Some("c"), None).await;
    assert!(back.contains("error="), "{back}");
    // An unknown state, and a provider that said no.
    assert!(s.oidc.idp_callback(&s.instance, Some("forged"), Some("c"), None).await.contains("expired"));
    let url = s.oidc.start_idp_login(&s.instance, idp, None, None).await.unwrap();
    let query: HashMap<String, String> = url::Url::parse(&url).unwrap().query_pairs().into_owned().collect();
    let back = s.oidc.idp_callback(&s.instance, Some(&query["state"]), None, Some("access_denied")).await;
    assert!(back.contains("cancelled"), "{back}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn providers_are_checked_when_they_are_set_up(pool: PgPool) {
    let s = setup(&pool).await;
    let issuer = s.shared.0.lock().unwrap().issuer.clone();
    let mut wrong = settings(&issuer, false, false);
    wrong.domains = vec!["other.de".into()];
    assert!(s.oidc.add_identity_provider(s.tenant, &wrong, None, "test").await.is_err());
    let idp = s.oidc.add_identity_provider(s.tenant, &settings(&issuer, false, false), None, "test").await.unwrap();
    // One provider per domain.
    assert!(s.oidc.add_identity_provider(s.tenant, &settings(&issuer, false, false), None, "test").await.is_err());
    s.oidc.check_identity_provider(s.tenant, idp).await.unwrap();
    let info = s.oidc.identity_provider(idp).await.unwrap();
    assert_eq!(info.settings.scopes, ["openid", "email", "profile"]);
    assert!(!info.has_secret);
    s.oidc.set_identity_provider_secret(s.tenant, idp, Some("s3cret"), "test").await.unwrap();
    assert!(s.oidc.identity_provider(idp).await.unwrap().has_secret);
    s.oidc.set_identity_provider_active(s.tenant, idp, false, "test").await.unwrap();
    assert!(s.oidc.login_options(s.instance.id, "bob@firma.de").await.unwrap().is_none());

    // Without allowing private networks, kernoid refuses such an issuer outright.
    let strict = Oidc::new(EventStore::new(pool.clone()), MainKeys::new(Key::random().unwrap(), Vec::new()), "https");
    assert!(strict.add_identity_provider(s.tenant, &settings(&issuer, false, false), None, "test").await.is_err());
    s.oidc.remove_identity_provider(s.tenant, idp, "test").await.unwrap();

    // The secret never enters an event.
    let leaked = sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM events WHERE payload::text LIKE '%s3cret%'"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(leaked, 0);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn profiles_follow_the_provider_when_asked(pool: PgPool) {
    let s = setup(&pool).await;
    let issuer = s.shared.0.lock().unwrap().issuer.clone();
    let idp = s
        .oidc
        .add_identity_provider(
            s.tenant,
            &IdpSettings { sync_profile: true, ..settings(&issuer, true, false) },
            Some("s3cret"),
            "test",
        )
        .await
        .unwrap();
    let claims = json!({ "sub": "ext-bob", "email": "bob@firma.de", "email_verified": true, "name": "Bob" });
    let answer = login(&s, idp, claims.clone()).await;
    let first = s.oidc.exchange_idp_login(s.instance.id, &answer["login"], None, &ClientMeta::default()).await.unwrap();
    let mut renamed = claims;
    renamed["name"] = json!("Robert Builder");
    let answer = login(&s, idp, renamed).await;
    let again = s.oidc.exchange_idp_login(s.instance.id, &answer["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(again.session.account.id, first.session.account.id);
    assert_eq!(s.identity.account(first.session.account.id).await.unwrap().display_name, "Robert Builder");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_provider_of_the_instance_serves_every_tenant(pool: PgPool) {
    let s = setup(&pool).await;
    let issuer = s.shared.0.lock().unwrap().issuer.clone();
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let other = s.identity.add_tenant(s.instance.id, "Other", "test").await.unwrap();
    s.identity.add_tenant_domain(s.instance.id, other, &domain("other.de"), "test").await.unwrap();
    s.identity.trust_tenant_domain(s.instance.id, other, &domain("other.de"), "test").await.unwrap();
    let both = IdpSettings { domains: vec!["firma.de".into(), "other.de".into()], ..settings(&issuer, true, false) };
    // A tenant cannot route another tenant's domain.
    assert!(s.oidc.add_identity_provider(s.tenant, &both, Some("s3cret"), "test").await.is_err());
    let owner = kernoid_oidc::federation::IdpOwner::Instance(s.instance.id);
    let idp = s.oidc.add_identity_provider(owner, &both, Some("s3cret"), "test").await.unwrap();
    let info = s.oidc.identity_provider(idp).await.unwrap();
    assert_eq!((info.tenant, info.instance), (None, s.instance.id));
    // Both tenants see it; a tenant's own provider can no longer take one of its domains.
    assert_eq!(s.oidc.identity_providers(other).await.unwrap().len(), 1);
    assert!(
        s.oidc.add_identity_provider(s.tenant, &settings(&issuer, true, false), Some("s3cret"), "test").await.is_err()
    );
    assert_eq!(s.oidc.login_options(s.instance.id, "carol@other.de").await.unwrap().unwrap().id, idp);

    // An account is created in the tenant of the address's domain.
    let claims = json!({ "sub": "ext-carol", "email": "carol@other.de", "email_verified": true, "name": "Carol" });
    let answer = login(&s, idp, claims).await;
    let carol = s.oidc.exchange_idp_login(s.instance.id, &answer["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(carol.session.account.tenant, other);
    let claims = json!({ "sub": "ext-bob", "email": "bob@firma.de", "email_verified": true, "name": "Bob" });
    let answer = login(&s, idp, claims).await;
    let bob = s.oidc.exchange_idp_login(s.instance.id, &answer["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(bob.session.account.tenant, s.tenant);
    // Changed by the instance only.
    assert!(s.oidc.set_identity_provider_active(s.tenant, idp, false, "test").await.is_err());
    s.oidc.set_identity_provider_active(owner, idp, false, "test").await.unwrap();
}

/// Lets the fake provider answer a login started at `url` with `claims`; returns the login UI's fragment.
async fn answer(s: &Setup, url: &str, claims: Value) -> HashMap<String, String> {
    let url = url::Url::parse(url).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    {
        let mut provider = s.shared.0.lock().unwrap();
        provider.challenge = query["code_challenge"].clone();
        provider.nonce = query["nonce"].clone();
        provider.claims = claims;
    }
    let back = s.oidc.idp_callback(&s.instance, Some(&query["state"]), Some("the-code"), None).await;
    let (_, fragment) = back.split_once('#').unwrap();
    url::form_urlencoded::parse(fragment.as_bytes()).into_owned().collect()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn sign_in_with_a_provider_registers_proposes_linking_and_links(pool: PgPool) {
    let s = setup(&pool).await;
    let issuer = s.shared.0.lock().unwrap().issuer.clone();
    // A "Sign in with …" provider: no domains, open for registration.
    let open =
        IdpSettings { name: "Google".into(), domains: vec![], register: true, ..settings(&issuer, false, false) };
    let idp = s.oidc.add_identity_provider(s.tenant, &open, Some("s3cret"), "test").await.unwrap();
    assert_eq!(s.oidc.open_providers(s.instance.id).await.unwrap()[0].name, "Google");
    let max = s
        .identity
        .add_account(s.tenant, &Address::parse("max.mustermann@firma.de").unwrap(), "Max", "test")
        .await
        .unwrap();
    s.identity.set_password(max, "a long password of max", "test").await.unwrap();
    let start = || s.oidc.start_idp_login(&s.instance, idp, None, None);

    // Closed for registration: an unknown person is refused.
    let claims = json!({ "sub": "g-erika", "email": "erika@gmail.com", "email_verified": true, "name": "Erika" });
    let refused = answer(&s, &start().await.unwrap(), claims.clone()).await;
    assert!(refused.contains_key("error"), "{refused:?}");
    s.identity.set_registration(s.tenant, true, &[], "test").await.unwrap();
    let new = answer(&s, &start().await.unwrap(), claims).await;
    let erika = s.oidc.exchange_idp_login(s.instance.id, &new["login"], None, &ClientMeta::default()).await.unwrap();
    let account = s.identity.account(erika.session.account.id).await.unwrap();
    assert!(!account.native && account.address == "erika@gmail.com");
    assert!(s.identity.services(account.id).await.unwrap().is_empty(), "a login, no mailbox");

    // Max's verified address: linking is proposed, never done unasked.
    let claims = json!({ "sub": "g-max", "email": "max.mustermann@firma.de", "email_verified": true, "name": "Max" });
    let proposal = answer(&s, &start().await.unwrap(), claims.clone()).await;
    let handoff = proposal.get("link").expect("a proposal").clone();
    assert!(s.oidc.exchange_idp_login(s.instance.id, &handoff, None, &ClientMeta::default()).await.is_err());
    let shown = s.oidc.link_proposal(s.instance.id, &handoff).await.unwrap();
    assert_eq!(
        (shown.email.as_str(), shown.provider.as_str(), shown.may_register),
        ("max.mustermann@firma.de", "Google", true)
    );
    // Only Max, logged in, links it.
    assert!(s.oidc.confirm_link(s.instance.id, &handoff, &erika.session.token).await.is_err());
    let logged_in = s
        .identity
        .create_session(
            s.instance.id,
            "max.mustermann@firma.de",
            "a long password of max",
            None,
            &ClientMeta::default(),
        )
        .await
        .unwrap();
    s.oidc.confirm_link(s.instance.id, &handoff, &logged_in.token).await.unwrap();
    assert!(s.oidc.confirm_link(s.instance.id, &handoff, &logged_in.token).await.is_err(), "once only");
    let again = answer(&s, &start().await.unwrap(), claims).await;
    let session =
        s.oidc.exchange_idp_login(s.instance.id, &again["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(session.session.account.id, max);

    // Or a separate account instead – without the address, which stays Max's.
    let other = json!({ "sub": "g-max-private", "email": "max.mustermann@firma.de", "email_verified": true, "name": "Max privat" });
    let proposal = answer(&s, &start().await.unwrap(), other).await;
    let separate =
        s.oidc.register_instead(s.instance.id, &proposal["link"], None, &ClientMeta::default()).await.unwrap();
    assert_ne!(separate.session.account.id, max);
    assert_eq!(s.identity.account(separate.session.account.id).await.unwrap().display_name, "Max privat");

    // From the account page: Erika links another login at the provider to her account.
    let url = s.oidc.start_idp_link(&s.instance, &erika.session.token, idp).await.unwrap();
    let linked =
        answer(&s, &url, json!({ "sub": "g-erika-work", "email": "erika@work.example", "email_verified": true })).await;
    let session =
        s.oidc.exchange_idp_login(s.instance.id, &linked["login"], None, &ClientMeta::default()).await.unwrap();
    assert_eq!(session.session.account.id, erika.session.account.id);
    // A login linked to someone else is not moved.
    let url = s.oidc.start_idp_link(&s.instance, &erika.session.token, idp).await.unwrap();
    let taken = answer(&s, &url, json!({ "sub": "g-max", "email": "x@gmail.com", "email_verified": true })).await;
    assert!(taken.contains_key("error"), "{taken:?}");
}
