// SPDX-License-Identifier: AGPL-3.0-or-later
//! The whole login of a program against a provider in the test: discovery, PKCE, the ID token, the session cookie and
//! its protection against cross-site requests, access tokens, and back-channel logout.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair, KeySize},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use axum::{
    Form, Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kernoid_auth::{
    relying::{RelyingParty, Settings},
    sessions::MemorySessions,
    web::{Auth, Authenticated},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const CLIENT: &str = "music";

/// A provider: it signs with one RSA key and hands out tokens for the codes the test registers.
#[derive(Clone)]
struct Provider {
    issuer: String,
    key: Arc<KeyPair>,
    /// code → (PKCE challenge, nonce)
    codes: Arc<Mutex<HashMap<String, (String, String)>>>,
}

impl Provider {
    fn sign(&self, typ: &str, claims: &Value) -> String {
        let header = json!({ "alg": "RS256", "kid": "k1", "typ": typ });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        let mut signature = vec![0; self.key.public_modulus_len()];
        self.key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut signature).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn claims(&self) -> Value {
        let now = jiff::Timestamp::now().as_second();
        json!({ "iss": self.issuer, "sub": "account-1", "aud": CLIENT, "iat": now, "exp": now + 300, "sid": "login-1",
            "name": "Ada", "urn:kernoid:tenant": "tenant-1",
            "urn:kernoid:project:roles": { "librarian": { "tenant-1": "School" } } })
    }

    fn access_token(&self) -> String {
        self.sign("at+jwt", &self.claims())
    }
}

async fn discovery(State(provider): State<Provider>) -> Json<Value> {
    let issuer = &provider.issuer;
    Json(json!({ "issuer": issuer, "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"), "jwks_uri": format!("{issuer}/keys"),
        "end_session_endpoint": format!("{issuer}/logout") }))
}

async fn keys(State(provider): State<Provider>) -> Json<Value> {
    let public = provider.key.public_key();
    Json(json!({ "keys": [{ "kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
        "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()) }] }))
}

async fn token(
    State(provider): State<Provider>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let Some((challenge, nonce)) = provider.codes.lock().unwrap().remove(&form["code"]) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })));
    };
    if URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())) != challenge {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })));
    }
    let mut claims = provider.claims();
    claims["nonce"] = json!(nonce);
    let id_token = provider.sign("JWT", &claims);
    (
        StatusCode::OK,
        Json(json!({ "id_token": id_token, "access_token": provider.access_token(), "token_type": "Bearer" })),
    )
}

async fn provider() -> Provider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let provider =
        Provider { issuer, key: Arc::new(KeyPair::generate(KeySize::Rsa2048).unwrap()), codes: Default::default() };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/keys", get(keys))
        .route("/token", post(token))
        .with_state(provider.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    provider
}

fn program(provider: &Provider) -> Router {
    let settings = Settings {
        issuer: provider.issuer.clone(),
        client_id: CLIENT.into(),
        client_secret: Some("secret".into()),
        redirect_uri: "http://music.test/auth/callback".into(),
        scopes: vec!["profile".into(), "urn:kernoid:project:roles".into()],
        roles_claim: None,
        allow_private: true,
    };
    let auth = Auth::new(RelyingParty::new(settings).unwrap(), Arc::new(MemorySessions::new()));
    Router::new()
        .route(
            "/me",
            get(|Authenticated(who): Authenticated| async move {
                let librarian = who.has_role("librarian");
                format!("{} {} {librarian}", who.subject, who.tenant.unwrap_or_default())
            })
            .post(|Authenticated(who): Authenticated| async move { who.subject }),
        )
        .merge(Auth::routes())
        .with_state(auth)
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    (parts.status, parts.headers, String::from_utf8(body.to_vec()).unwrap())
}

fn cookie(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|value| value.split(';').next())
        .unwrap()
        .to_owned()
}

fn query(url: &str, name: &str) -> String {
    url::Url::parse(url).unwrap().query_pairs().find(|(key, _)| key == name).unwrap().1.into_owned()
}

#[tokio::test]
async fn a_program_logs_in_keeps_a_session_and_ends_it() {
    let provider = provider().await;
    let app = program(&provider);

    // The login begins: to the provider, with PKCE, and a cookie for the way back.
    let (status, headers, _) = send(&app, Request::get("/auth/login?next=/library").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers[header::LOCATION].to_str().unwrap().to_owned();
    assert!(location.starts_with(&format!("{}/authorize?", provider.issuer)));
    assert_eq!(query(&location, "code_challenge_method"), "S256");
    assert_eq!(query(&location, "scope"), "openid profile urn:kernoid:project:roles");
    let pending = cookie(&headers, "kernoid-auth-login");
    let state = query(&location, "state");
    provider.codes.lock().unwrap().insert("c1".into(), (query(&location, "code_challenge"), query(&location, "nonce")));

    // A callback with another state is refused.
    let wrong = Request::get("/auth/callback?code=c1&state=other").header(header::COOKIE, &pending).body(Body::empty());
    assert_eq!(send(&app, wrong.unwrap()).await.0, StatusCode::BAD_REQUEST);
    // So is one without the cookie of the browser that began.
    let foreign = Request::get(format!("/auth/callback?code=c1&state={state}")).body(Body::empty()).unwrap();
    assert_eq!(send(&app, foreign).await.0, StatusCode::BAD_REQUEST);

    // The way back: the code exchanged, the ID token checked, a session.
    let back = Request::get(format!("/auth/callback?code=c1&state={state}")).header(header::COOKIE, &pending);
    let (status, headers, body) = send(&app, back.body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(headers[header::LOCATION], "/library");
    let session = cookie(&headers, "kernoid-auth");

    let me = || Request::get("/me").header(header::COOKIE, &session).body(Body::empty()).unwrap();
    assert_eq!(send(&app, me()).await.2, "account-1 tenant-1 true");
    // Changing something with the cookie needs the CSRF header, from the program's origin.
    let post = |csrf: bool, origin: &str| {
        let mut request = Request::post("/me").header(header::COOKIE, &session).header(header::ORIGIN, origin);
        if csrf {
            request = request.header("kernoid-csrf", "1");
        }
        request.body(Body::empty()).unwrap()
    };
    assert_eq!(send(&app, post(false, "http://music.test")).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, post(true, "https://evil.test")).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, post(true, "http://music.test")).await.0, StatusCode::OK);

    // The apps send access tokens.
    let bearer = |token: &str| {
        Request::get("/me").header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
    };
    assert_eq!(send(&app, bearer(&provider.access_token())).await.0, StatusCode::OK);
    let mut foreign = provider.claims();
    foreign["aud"] = json!("another-app");
    assert_eq!(send(&app, bearer(&provider.sign("at+jwt", &foreign))).await.0, StatusCode::UNAUTHORIZED);
    // An ID token is no access token.
    assert_eq!(send(&app, bearer(&provider.sign("JWT", &provider.claims()))).await.0, StatusCode::UNAUTHORIZED);

    // The provider ends the login: the session goes with it.
    let now = jiff::Timestamp::now().as_second();
    let logout = provider.sign(
        "logout+jwt",
        &json!({ "iss": provider.issuer, "aud": CLIENT, "iat": now, "jti": "j1", "sid": "login-1",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }),
    );
    let request = Request::post("/auth/backchannel-logout")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("logout_token={logout}")))
        .unwrap();
    assert_eq!(send(&app, request).await.0, StatusCode::OK);
    assert_eq!(send(&app, me()).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logging_out_ends_the_session_and_names_the_provider() {
    let provider = provider().await;
    let app = program(&provider);
    let (_, headers, _) = send(&app, Request::get("/auth/login").body(Body::empty()).unwrap()).await;
    let location = headers[header::LOCATION].to_str().unwrap().to_owned();
    let pending = cookie(&headers, "kernoid-auth-login");
    provider.codes.lock().unwrap().insert("c2".into(), (query(&location, "code_challenge"), query(&location, "nonce")));
    let back = Request::get(format!("/auth/callback?code=c2&state={}", query(&location, "state")))
        .header(header::COOKIE, &pending)
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send(&app, back).await;
    let session = cookie(&headers, "kernoid-auth");

    let out = |csrf: bool| {
        let mut request = Request::post("/auth/logout").header(header::COOKIE, &session);
        if csrf {
            request = request.header("kernoid-csrf", "1");
        }
        request.body(Body::empty()).unwrap()
    };
    assert_eq!(send(&app, out(false)).await.0, StatusCode::FORBIDDEN);
    let (status, _, body) = send(&app, out(true)).await;
    assert_eq!(status, StatusCode::OK);
    let next: Value = serde_json::from_str(&body).unwrap();
    assert!(
        next["next"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}/logout?client_id=music&id_token_hint=", provider.issuer))
    );
    let me = Request::get("/me").header(header::COOKIE, &session).body(Body::empty()).unwrap();
    assert_eq!(send(&app, me).await.0, StatusCode::UNAUTHORIZED);
}
