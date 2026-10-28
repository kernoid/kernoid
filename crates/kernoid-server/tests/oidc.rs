// SPDX-License-Identifier: AGPL-3.0-or-later
//! OpenID Connect over HTTP, against PostgreSQL; set `DATABASE_URL` as for the other crates' tests. Walks the flow as
//! browser, login UI and application see it.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity};
use kernoid_oidc::{Oidc, application::Kind};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";
const CALLBACK: &str = "https://app.firma.de/callback";
const LOGGED_OUT: &str = "https://app.firma.de/bye";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Setup {
    app: Router,
    client_id: String,
    secret: String,
}

async fn setup(pool: &PgPool) -> Setup {
    let events = EventStore::new(pool.clone());
    let identity = Identity::new(events.clone());
    let main = Key::random().unwrap();
    let oidc = Oidc::new(events, MainKeys::new(main.clone(), Vec::new()), "https");
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();
    identity.set_password(alice, PASSWORD, "test").await.unwrap();
    let project = identity.add_project(tenant, "Project", "test").await.unwrap();
    let (client, secret) = oidc
        .add_application(tenant, project, "App", Kind::Confidential, &[CALLBACK.into()], &[LOGGED_OUT.into()], "test")
        .await
        .unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), main));
    let state = AppState::new(pool.clone(), BlobStore::from_config(&Blob::Memory, keys).unwrap(), identity, oidc);
    Setup {
        app: router(state, Router::new(), &Http::default()),
        client_id: client.to_string(),
        secret: secret.unwrap(),
    }
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
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Answer { status: parts.status, headers: parts.headers, body }
}

fn get(path: &str) -> axum::http::request::Builder {
    Request::get(path).header("host", HOST)
}

fn query(url: &str) -> std::collections::HashMap<String, String> {
    url::Url::parse(url).unwrap().query_pairs().into_owned().collect()
}

fn authorize_path(client_id: &str, redirect: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect)
        .append_pair("scope", "openid email")
        .append_pair("state", "af0ifjsldkj")
        .append_pair("nonce", "n-0S6")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("/oauth/v2/authorize?{params}")
}

/// Browser and login UI: authorize, log in, finish; returns the code.
async fn code(setup: &Setup) -> String {
    let started = send(&setup.app, get(&authorize_path(&setup.client_id, CALLBACK)).body(Body::empty()).unwrap()).await;
    assert_eq!(started.status, StatusCode::SEE_OTHER);
    let login = started.headers[header::LOCATION].to_str().unwrap().to_owned();
    assert!(login.starts_with("https://login.firma.de/login?authRequest="), "{login}");
    let auth_request = query(&login)["authRequest"].clone();

    let info = send(&setup.app, get(&format!("/v1/auth-requests/{auth_request}")).body(Body::empty()).unwrap()).await;
    assert_eq!((info.status, &info.body["application"]), (StatusCode::OK, &json!("App")));

    let session = send(
        &setup.app,
        Request::post("/v1/sessions")
            .header("host", HOST)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
            .unwrap(),
    )
    .await;
    let token = session.body["token"].as_str().unwrap();
    let finished = send(
        &setup.app,
        Request::post(format!("/v1/auth-requests/{auth_request}"))
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(finished.status, StatusCode::OK);
    let callback = finished.body["callback_url"].as_str().unwrap();
    let params = query(callback);
    assert_eq!((params["state"].as_str(), params["iss"].as_str()), ("af0ifjsldkj", "https://login.firma.de"));
    params["code"].clone()
}

fn token_request(setup: &Setup, code: &str, secret: &str) -> Request<Body> {
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", CALLBACK)
        .append_pair("code_verifier", VERIFIER)
        .finish();
    Request::post("/oauth/v2/token")
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {}", STANDARD.encode(format!("{}:{secret}", setup.client_id))))
        .body(Body::from(form))
        .unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn discovery_and_keys(pool: PgPool) {
    let setup = setup(&pool).await;
    let configuration = send(&setup.app, get("/.well-known/openid-configuration").body(Body::empty()).unwrap()).await;
    assert_eq!(configuration.status, StatusCode::OK);
    assert_eq!(configuration.body["issuer"], "https://login.firma.de");
    assert_eq!(configuration.body["token_endpoint"], "https://login.firma.de/oauth/v2/token");
    assert_eq!(configuration.body["code_challenge_methods_supported"], json!(["S256"]));
    // The issuer comes from the instance, not from the request.
    let via_alias =
        Request::get("/.well-known/openid-configuration").header("host", "LOGIN.firma.de").body(Body::empty()).unwrap();
    assert_eq!(send(&setup.app, via_alias).await.body["issuer"], "https://login.firma.de");
    let elsewhere =
        Request::get("/.well-known/openid-configuration").header("host", "evil.example").body(Body::empty()).unwrap();
    assert_eq!(send(&setup.app, elsewhere).await.status, StatusCode::NOT_FOUND);

    let keys = send(&setup.app, get("/oauth/v2/keys").body(Body::empty()).unwrap()).await;
    assert_eq!(keys.body, json!({ "keys": [] }), "no key before the first login");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_whole_flow_over_http(pool: PgPool) {
    let setup = setup(&pool).await;
    let code = code(&setup).await;
    let tokens = send(&setup.app, token_request(&setup, &code, &setup.secret)).await;
    assert_eq!(tokens.status, StatusCode::OK);
    assert_eq!(tokens.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(tokens.body["token_type"], "Bearer");
    let id_token = tokens.body["id_token"].as_str().unwrap();
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(id_token.split('.').next().unwrap()).unwrap()).unwrap();
    let keys = send(&setup.app, get("/oauth/v2/keys").body(Body::empty()).unwrap()).await;
    assert_eq!(keys.body["keys"][0]["kid"], header["kid"]);

    let access = tokens.body["access_token"].as_str().unwrap();
    let userinfo = send(
        &setup.app,
        get("/oidc/v1/userinfo").header(header::AUTHORIZATION, format!("Bearer {access}")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(userinfo.status, StatusCode::OK);
    assert_eq!(userinfo.body["email"], "alice@firma.de");
    assert!(userinfo.body.get("name").is_none(), "profile was not asked for");

    // The code is used up.
    let again = send(&setup.app, token_request(&setup, &code, &setup.secret)).await;
    assert_eq!((again.status, again.body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_grant")));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn protocol_errors(pool: PgPool) {
    let setup = setup(&pool).await;
    // A wrong redirect URI is shown, never followed.
    let wrong = send(
        &setup.app,
        get(&authorize_path(&setup.client_id, "https://evil.example/cb")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert!(wrong.headers.get(header::LOCATION).is_none());
    assert_eq!(wrong.headers["content-type"], "application/problem+json");

    let code = code(&setup).await;
    let bad_secret = send(&setup.app, token_request(&setup, &code, "kcs1.wrong")).await;
    assert_eq!(
        (bad_secret.status, bad_secret.body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid_client"))
    );
    assert_eq!(bad_secret.headers[header::WWW_AUTHENTICATE], "Basic realm=\"kernoid\"");

    let no_token = send(&setup.app, get("/oidc/v1/userinfo").body(Body::empty()).unwrap()).await;
    assert_eq!(no_token.status, StatusCode::UNAUTHORIZED);
    assert_eq!(no_token.headers[header::WWW_AUTHENTICATE], "Bearer error=\"invalid_token\"");

    let unknown = send(&setup.app, get("/v1/auth-requests/ar1.unknown").body(Body::empty()).unwrap()).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn graphql_finishes_auth_requests(pool: PgPool) {
    let setup = setup(&pool).await;
    let started = send(&setup.app, get(&authorize_path(&setup.client_id, CALLBACK)).body(Body::empty()).unwrap()).await;
    let auth_request = query(started.headers[header::LOCATION].to_str().unwrap())["authRequest"].clone();
    let graphql = |query: String, token: Option<String>| {
        let mut request = Request::post("/graphql").header("host", HOST).header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request.body(Body::from(json!({ "query": query }).to_string())).unwrap()
    };
    let login =
        format!(r#"mutation {{ createSession(address: "alice@firma.de", password: "{PASSWORD}") {{ token }} }}"#);
    let token = send(&setup.app, graphql(login, None)).await.body["data"]["createSession"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let info =
        send(&setup.app, graphql(format!(r#"{{ authRequest(id: "{auth_request}") {{ application scopes }} }}"#), None))
            .await;
    assert_eq!(info.body["data"]["authRequest"], json!({ "application": "App", "scopes": ["openid", "email"] }));
    let finished = send(
        &setup.app,
        graphql(format!(r#"mutation {{ finishAuthRequest(id: "{auth_request}") }}"#), Some(token.clone())),
    )
    .await;
    assert!(finished.body["data"]["finishAuthRequest"].as_str().unwrap().starts_with(CALLBACK));
    let again =
        send(&setup.app, graphql(format!(r#"mutation {{ finishAuthRequest(id: "{auth_request}") }}"#), Some(token)))
            .await;
    assert_eq!(again.body["errors"][0]["extensions"]["code"], "NOT_FOUND");
}

fn form_post(path: &str, setup: &Setup, pairs: &[(&str, &str)]) -> Request<Body> {
    let form = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
    Request::post(path)
        .header("host", HOST)
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{}:{}", setup.client_id, setup.secret))),
        )
        .body(Body::from(form))
        .unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn refresh_revoke_and_logout_over_http(pool: PgPool) {
    let setup = setup(&pool).await;
    let configuration = send(&setup.app, get("/.well-known/openid-configuration").body(Body::empty()).unwrap()).await;
    assert_eq!(configuration.body["end_session_endpoint"], "https://login.firma.de/oidc/v1/end_session");
    assert_eq!(configuration.body["grant_types_supported"], json!(["authorization_code", "refresh_token"]));

    let code = code(&setup).await;
    let tokens = send(&setup.app, token_request(&setup, &code, &setup.secret)).await.body;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let refreshed = send(
        &setup.app,
        form_post("/oauth/v2/token", &setup, &[("grant_type", "refresh_token"), ("refresh_token", refresh)]),
    )
    .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    let next = refreshed.body["refresh_token"].as_str().unwrap().to_owned();
    let wider = send(
        &setup.app,
        form_post(
            "/oauth/v2/token",
            &setup,
            &[("grant_type", "refresh_token"), ("refresh_token", &next), ("scope", "openid profile")],
        ),
    )
    .await;
    assert_eq!(wider.body["error"], "invalid_scope");

    // Revocation answers 200 also for tokens it does not know.
    let revoked = send(&setup.app, form_post("/oauth/v2/revoke", &setup, &[("token", "krt1.unknown")])).await;
    assert_eq!(revoked.status, StatusCode::OK);

    // Logout with the ID token: back to the registered URI, the session and its tokens end.
    let id_token = refreshed.body["id_token"].as_str().unwrap();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", id_token)
        .append_pair("post_logout_redirect_uri", LOGGED_OUT)
        .append_pair("state", "s1")
        .finish();
    let out = send(&setup.app, get(&format!("/oidc/v1/end_session?{query}")).body(Body::empty()).unwrap()).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert_eq!(out.headers[header::LOCATION], "https://app.firma.de/bye?state=s1");
    let after = send(
        &setup.app,
        form_post("/oauth/v2/token", &setup, &[("grant_type", "refresh_token"), ("refresh_token", &next)]),
    )
    .await;
    assert_eq!(after.body["error"], "invalid_grant");

    // An unregistered redirect is not followed.
    let evil = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &setup.client_id)
        .append_pair("post_logout_redirect_uri", "https://evil.example/")
        .finish();
    let refused = send(&setup.app, get(&format!("/oidc/v1/end_session?{evil}")).body(Body::empty()).unwrap()).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.headers.get(header::LOCATION).is_none());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_login_ui_sees_prompt_and_can_decline(pool: PgPool) {
    let setup = setup(&pool).await;
    let path = format!("{}&prompt=none", authorize_path(&setup.client_id, CALLBACK));
    let started = send(&setup.app, get(&path).body(Body::empty()).unwrap()).await;
    let auth_request = query(started.headers[header::LOCATION].to_str().unwrap())["authRequest"].clone();
    let info = send(&setup.app, get(&format!("/v1/auth-requests/{auth_request}")).body(Body::empty()).unwrap()).await;
    assert_eq!(info.body["prompt"], json!(["none"]));

    let declined = send(
        &setup.app,
        Request::post(format!("/v1/auth-requests/{auth_request}/decline"))
            .header("host", HOST)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "error": "login_required" }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(declined.status, StatusCode::OK);
    let params = query(declined.body["callback_url"].as_str().unwrap());
    assert_eq!((params["error"].as_str(), params["state"].as_str()), ("login_required", "af0ifjsldkj"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_required_second_factor_is_a_problem_the_login_ui_recognises(pool: PgPool) {
    let setup = setup(&pool).await;
    let oidc = Oidc::new(EventStore::new(pool.clone()), MainKeys::new(Key::random().unwrap(), Vec::new()), "https");
    oidc.set_application_mfa_required(setup.client_id.parse().unwrap(), true, "test").await.unwrap();

    let started = send(&setup.app, get(&authorize_path(&setup.client_id, CALLBACK)).body(Body::empty()).unwrap()).await;
    let auth_request = query(started.headers[header::LOCATION].to_str().unwrap())["authRequest"].clone();
    let session = send(
        &setup.app,
        Request::post("/v1/sessions")
            .header("host", HOST)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
            .unwrap(),
    )
    .await;
    let token = session.body["token"].as_str().unwrap();
    let finish = || {
        Request::post(format!("/v1/auth-requests/{auth_request}"))
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let refused = send(&setup.app, finish()).await;
    assert_eq!(
        (refused.status, refused.body["type"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("urn:kernoid:problem:mfa-required"))
    );

    // The UI asks for a recovery code (the account has no other factor yet), then finishes.
    let codes = send(
        &setup.app,
        Request::post("/v1/account/recovery-codes")
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(codes.headers[header::CACHE_CONTROL], "no-store");
    let code = codes.body["codes"][0].as_str().unwrap();
    let checked = send(
        &setup.app,
        Request::post("/v1/sessions/current/recovery")
            .header("host", HOST)
            .header("content-type", "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(json!({ "code": code }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(checked.body["checks"], json!(["password", "recovery"]));
    assert_eq!(send(&setup.app, finish()).await.status, StatusCode::OK);
}

/// Authorize and log in as the login UI does; returns the auth request and the session token.
async fn started_login(setup: &Setup, scope: &str) -> (String, String) {
    let path = authorize_path(&setup.client_id, CALLBACK).replace("scope=openid+email", &format!("scope={scope}"));
    let started = send(&setup.app, get(&path).body(Body::empty()).unwrap()).await;
    let auth_request = query(started.headers[header::LOCATION].to_str().unwrap())["authRequest"].clone();
    let session = send(
        &setup.app,
        Request::post("/v1/sessions")
            .header("host", HOST)
            .header("content-type", "application/json")
            .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
            .unwrap(),
    )
    .await;
    (auth_request, session.body["token"].as_str().unwrap().to_owned())
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn consent_introspection_and_frontchannel_logout_over_http(pool: PgPool) {
    let setup = setup(&pool).await;
    let oidc = Oidc::new(EventStore::new(pool.clone()), MainKeys::new(Key::random().unwrap(), Vec::new()), "https");
    let options = kernoid_oidc::application::AppOptions {
        offline_access: true,
        frontchannel_logout_uri: Some("https://app.firma.de/fc-logout".into()),
        ..Default::default()
    };
    oidc.set_application_options(setup.client_id.parse().unwrap(), &options, "test").await.unwrap();
    let configuration = send(&setup.app, get("/.well-known/openid-configuration").body(Body::empty()).unwrap()).await;
    assert_eq!(configuration.body["introspection_endpoint"], "https://login.firma.de/oauth/v2/introspect");
    assert_eq!(configuration.body["backchannel_logout_supported"], true);

    let (auth_request, token) = started_login(&setup, "openid+offline_access").await;
    let finish = |body: Option<Value>| {
        let request = Request::post(format!("/v1/auth-requests/{auth_request}"))
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        match body {
            Some(body) => request.header("content-type", "application/json").body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap()
    };
    let refused = send(&setup.app, finish(None)).await;
    assert_eq!(
        (refused.status, refused.body["type"].as_str()),
        (StatusCode::FORBIDDEN, Some("urn:kernoid:problem:consent-required"))
    );
    let finished = send(&setup.app, finish(Some(json!({ "consent": true })))).await;
    assert_eq!(finished.status, StatusCode::OK);
    let code = query(finished.body["callback_url"].as_str().unwrap())["code"].clone();
    let tokens = send(&setup.app, token_request(&setup, &code, &setup.secret)).await.body;
    assert_eq!(tokens["scope"], "openid offline_access");

    // The account sees its consent.
    let bearer = |request: axum::http::request::Builder| {
        request.header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
    };
    let consents = send(&setup.app, bearer(get("/v1/account/consents"))).await;
    assert_eq!(consents.body[0]["application"], setup.client_id.as_str());
    assert_eq!(consents.body[0]["scopes"], json!(["openid", "offline_access"]));

    // Introspection by the application itself (a confidential client).
    let access = tokens["access_token"].as_str().unwrap();
    let answer = send(&setup.app, form_post("/oauth/v2/introspect", &setup, &[("token", access)])).await;
    assert_eq!((answer.status, &answer.body["active"]), (StatusCode::OK, &json!(true)));
    assert_eq!(answer.headers[header::CACHE_CONTROL], "no-store");

    // Logout: a page with a frame for the application's front-channel URI, then on to the redirect.
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", tokens["id_token"].as_str().unwrap())
        .append_pair("post_logout_redirect_uri", LOGGED_OUT)
        .finish();
    let response = setup
        .app
        .clone()
        .oneshot(get(&format!("/oidc/v1/end_session?{query}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_owned();
    assert_eq!(policy, "default-src 'none'; frame-src https://app.firma.de; frame-ancestors 'none'");
    let page = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(page.contains("<iframe src=\"https://app.firma.de/fc-logout?iss=https%3A%2F%2Flogin.firma.de&amp;sid="));
    assert!(page.contains("content=\"2;url=https://app.firma.de/bye\""), "{page}");

    // Offline access outlives the logout, until the account withdraws its consent.
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let refreshed = send(
        &setup.app,
        form_post("/oauth/v2/token", &setup, &[("grant_type", "refresh_token"), ("refresh_token", refresh)]),
    )
    .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    let (auth_request, token) = started_login(&setup, "openid").await;
    let _ = auth_request;
    let withdrawn = send(
        &setup.app,
        Request::delete(format!("/v1/account/consents/{}", setup.client_id))
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(withdrawn.status, StatusCode::NO_CONTENT);
    let next = refreshed.body["refresh_token"].as_str().unwrap();
    let after = send(
        &setup.app,
        form_post("/oauth/v2/token", &setup, &[("grant_type", "refresh_token"), ("refresh_token", next)]),
    )
    .await;
    assert_eq!(after.body["error"], "invalid_grant");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_instances_own_login_ui_may_call_the_api(pool: PgPool) {
    let setup = setup(&pool).await;
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance = identity.instance_by_host(HOST).await.unwrap().unwrap();
    let preflight = |origin: &str| {
        Request::options("/v1/sessions")
            .header("host", HOST)
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .unwrap()
    };
    // Without a login UI of its own, no origin may.
    let answer = send(&setup.app, preflight("https://anmeldung.firma.de")).await;
    assert!(answer.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    identity.set_login_ui(instance.id, Some("https://anmeldung.firma.de/login"), "test").await.unwrap();
    let answer = send(&setup.app, preflight("https://anmeldung.firma.de")).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    assert_eq!(answer.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://anmeldung.firma.de");
    assert!(answer.headers[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str().unwrap().contains("authorization"));
    // With the session cookie, on the same site – and the CSRF header.
    assert_eq!(answer.headers[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
    assert!(answer.headers[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str().unwrap().contains("kernoid-csrf"));
    let other = send(&setup.app, preflight("https://evil.example")).await;
    assert!(other.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    // The real request carries the header, too; authorize sends the browser to the login UI.
    let session = send(
        &setup.app,
        Request::post("/v1/sessions")
            .header("host", HOST)
            .header(header::ORIGIN, "https://anmeldung.firma.de")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(session.status, StatusCode::CREATED);
    assert_eq!(session.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://anmeldung.firma.de");
    let started = send(&setup.app, get(&authorize_path(&setup.client_id, CALLBACK)).body(Body::empty()).unwrap()).await;
    let location = started.headers[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with("https://anmeldung.firma.de/login?authRequest="), "{location}");
}
