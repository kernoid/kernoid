// SPDX-License-Identifier: AGPL-3.0-or-later
//! The authorization code flow against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity, InstanceInfo, role::Principal, session::ClientMeta};
use kernoid_oidc::{
    AuthorizeRequest, Authorized, EndSessionRequest, Oidc, OidcError, ROLES_CLAIM, ROLES_SCOPE, TokenRequest,
    application::{AppOptions, Kind, TokenFormat},
    keys::KeyState,
};
use kernoid_store::{MainKeys, crypto::Key};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CALLBACK: &str = "https://app.firma.de/callback";
const LOGGED_OUT: &str = "https://app.firma.de/logged-out";

struct Setup {
    oidc: Oidc,
    identity: Identity,
    instance: InstanceInfo,
    tenant: Uuid,
    project: Uuid,
    /// A confidential application and its secret.
    app: Uuid,
    secret: String,
    /// A session of alice@firma.de.
    session: String,
}

fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

async fn setup(pool: &PgPool, main: Key) -> Setup {
    let events = EventStore::new(pool.clone());
    let identity = Identity::new(events.clone());
    let oidc = Oidc::new(events, MainKeys::new(main, Vec::new()), "https");
    let id = identity.add_instance("Firma", &domain("login.firma.de"), "test").await.unwrap();
    let tenant = identity.add_tenant(id, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();
    identity.set_password(alice, PASSWORD, "test").await.unwrap();
    let session = identity.create_session(id, "alice@firma.de", PASSWORD, None, &ClientMeta::default()).await.unwrap();
    let project = identity.add_project(tenant, "Project", "test").await.unwrap();
    let (app, secret) = oidc
        .add_application(
            tenant,
            project,
            "App",
            Kind::Confidential,
            &[CALLBACK.to_owned()],
            &[LOGGED_OUT.to_owned()],
            "test",
        )
        .await
        .unwrap();
    let instance = identity.instance_by_host("login.firma.de").await.unwrap().unwrap();
    Setup { oidc, identity, instance, tenant, project, app, secret: secret.unwrap(), session: session.token }
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

fn authorize_request(client: Uuid, scope: &str) -> AuthorizeRequest {
    AuthorizeRequest {
        response_type: Some("code".into()),
        client_id: Some(client.to_string()),
        redirect_uri: Some(CALLBACK.into()),
        scope: Some(scope.into()),
        state: Some("xyz".into()),
        nonce: Some("n-0S6_WzA2Mj".into()),
        code_challenge: Some(challenge()),
        code_challenge_method: Some("S256".into()),
        prompt: None,
        max_age: None,
    }
}

fn query(url: &str) -> std::collections::HashMap<String, String> {
    url::Url::parse(url).unwrap().query_pairs().into_owned().collect()
}

/// Runs authorize and finish; returns the code.
async fn code(setup: &Setup, scope: &str) -> String {
    let Authorized::Login { auth_request, url } =
        setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, scope)).await.unwrap()
    else {
        panic!("expected a login")
    };
    assert_eq!(url, format!("https://login.firma.de/login?authRequest={auth_request}"));
    let callback = setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await.unwrap();
    assert!(callback.starts_with(CALLBACK));
    let params = query(&callback);
    assert_eq!(params["state"], "xyz");
    assert_eq!(params["iss"], "https://login.firma.de");
    params["code"].clone()
}

fn token_request(setup: &Setup, code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: Some("authorization_code".into()),
        code: Some(code.into()),
        redirect_uri: Some(CALLBACK.into()),
        code_verifier: Some(VERIFIER.into()),
        client_id: Some(setup.app.to_string()),
        client_secret: Some(setup.secret.clone()),
        ..TokenRequest::default()
    }
}

/// Checks the ID token's signature against the JWKS, as a client would; returns header and claims.
async fn verify(setup: &Setup, id_token: &str) -> (Value, Value) {
    let parts: Vec<&str> = id_token.split('.').collect();
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    let jwks = setup.oidc.jwks(setup.instance.id).await.unwrap();
    let jwk = jwks["keys"].as_array().unwrap().iter().find(|key| key["kid"] == header["kid"]).expect("kid in the JWKS");
    let decode = |field: &str| URL_SAFE_NO_PAD.decode(jwk[field].as_str().unwrap()).unwrap();
    let public = RsaPublicKeyComponents { n: decode("n"), e: decode("e") };
    let message = format!("{}.{}", parts[0], parts[1]);
    public.verify(&RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    (header, claims)
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn code_flow_from_authorize_to_userinfo(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let code = code(&setup, "openid profile email").await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    assert_eq!((tokens.token_type, tokens.expires_in, tokens.scope.as_str()), ("Bearer", 3600, "openid profile email"));

    let (header, claims) = verify(&setup, &tokens.id_token).await;
    assert_eq!(header["alg"], "RS256");
    let alice = setup.identity.account_by_address(&Address::parse("alice@firma.de").unwrap()).await.unwrap().unwrap();
    assert_eq!(claims["iss"], "https://login.firma.de");
    assert_eq!(claims["sub"], alice.id.to_string());
    assert_eq!(claims["aud"], setup.app.to_string());
    assert_eq!(claims["nonce"], "n-0S6_WzA2Mj");
    assert_eq!(claims["amr"], json!(["pwd"]));
    assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());

    let info = setup.oidc.userinfo(&setup.instance, &tokens.access_token).await.unwrap();
    assert_eq!(
        Value::Object(info),
        json!({ "sub": alice.id.to_string(), "name": "Alice", "preferred_username": "alice@firma.de",
                "email": "alice@firma.de", "email_verified": true })
    );

    // Logging out ends what the session handed out.
    setup.identity.terminate_session(setup.instance.id, &setup.session).await.unwrap();
    assert!(matches!(setup.oidc.userinfo(&setup.instance, &tokens.access_token).await, Err(OidcError::InvalidToken)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn scopes_limit_the_claims(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let code = code(&setup, "openid unknown-scope").await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    let info = setup.oidc.userinfo(&setup.instance, &tokens.access_token).await.unwrap();
    assert_eq!(info.keys().collect::<Vec<_>>(), ["sub"]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn authorize_checks_the_client_before_redirecting(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let mut unknown = authorize_request(Uuid::now_v7(), "openid");
    assert!(matches!(setup.oidc.authorize(&setup.instance, &unknown).await, Err(OidcError::InvalidClient)));
    unknown.client_id = Some("not a uuid".into());
    assert!(matches!(setup.oidc.authorize(&setup.instance, &unknown).await, Err(OidcError::InvalidClient)));
    for wrong in
        ["https://evil.example/callback", "https://app.firma.de/callback/", "https://app.firma.de/callback?x=1"]
    {
        let request = AuthorizeRequest { redirect_uri: Some(wrong.into()), ..authorize_request(setup.app, "openid") };
        assert!(
            matches!(setup.oidc.authorize(&setup.instance, &request).await, Err(OidcError::InvalidRedirectUri)),
            "{wrong}"
        );
    }

    // Once client and redirect URI are known good, errors go back to the client.
    let cases = [
        (AuthorizeRequest { code_challenge: None, ..authorize_request(setup.app, "openid") }, "invalid_request"),
        (
            AuthorizeRequest { code_challenge_method: Some("plain".into()), ..authorize_request(setup.app, "openid") },
            "invalid_request",
        ),
        (authorize_request(setup.app, "profile"), "invalid_scope"),
        (
            AuthorizeRequest { response_type: Some("token".into()), ..authorize_request(setup.app, "openid") },
            "unsupported_response_type",
        ),
    ];
    for (request, expected) in cases {
        let Authorized::Error { url } = setup.oidc.authorize(&setup.instance, &request).await.unwrap() else {
            panic!("expected an error redirect")
        };
        let params = query(&url);
        assert!(url.starts_with(CALLBACK));
        assert_eq!(
            (params["error"].as_str(), params["state"].as_str(), params["iss"].as_str()),
            (expected, "xyz", "https://login.firma.de")
        );
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_code_works_once_and_a_second_try_revokes(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let code = code(&setup, "openid").await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    setup.oidc.userinfo(&setup.instance, &tokens.access_token).await.unwrap();
    assert!(matches!(
        setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await,
        Err(OidcError::InvalidGrant(_))
    ));
    assert!(matches!(setup.oidc.userinfo(&setup.instance, &tokens.access_token).await, Err(OidcError::InvalidToken)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn token_requests_are_checked(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let code = code(&setup, "openid").await;
    let good = token_request(&setup, &code);
    let wrong_verifier = TokenRequest { code_verifier: Some("a".repeat(43)), ..good.clone() };
    let wrong_redirect = TokenRequest { redirect_uri: Some("https://app.firma.de/other".into()), ..good.clone() };
    let no_verifier = TokenRequest { code_verifier: None, ..good.clone() };
    let wrong_secret = TokenRequest { client_secret: Some("kcs1.wrong".into()), ..good.clone() };
    let no_secret = TokenRequest { client_secret: None, ..good.clone() };
    let wrong_grant = TokenRequest { grant_type: Some("password".into()), ..good.clone() };
    assert!(matches!(setup.oidc.token(&setup.instance, &wrong_verifier).await, Err(OidcError::InvalidGrant(_))));
    assert!(matches!(setup.oidc.token(&setup.instance, &wrong_redirect).await, Err(OidcError::InvalidGrant(_))));
    assert!(matches!(setup.oidc.token(&setup.instance, &no_verifier).await, Err(OidcError::InvalidRequest(_))));
    assert!(matches!(setup.oidc.token(&setup.instance, &wrong_secret).await, Err(OidcError::InvalidClient)));
    assert!(matches!(setup.oidc.token(&setup.instance, &no_secret).await, Err(OidcError::InvalidClient)));
    assert!(matches!(setup.oidc.token(&setup.instance, &wrong_grant).await, Err(OidcError::UnsupportedGrantType)));
    // The failed attempts did not use the code up – but a code is not an open door: the right request still works once.
    setup.oidc.token(&setup.instance, &good).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn public_clients_use_pkce_alone(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let (public, secret) = setup
        .oidc
        .add_application(
            setup.tenant,
            setup.project,
            "SPA",
            Kind::Public,
            &["http://localhost:5173/callback".into()],
            &[],
            "test",
        )
        .await
        .unwrap();
    assert_eq!(secret, None);
    let request = AuthorizeRequest {
        redirect_uri: Some("http://localhost:5173/callback".into()),
        ..authorize_request(public, "openid")
    };
    let Authorized::Login { auth_request, .. } = setup.oidc.authorize(&setup.instance, &request).await.unwrap() else {
        panic!()
    };
    let code =
        query(&setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await.unwrap())["code"].clone();
    let token = TokenRequest {
        redirect_uri: Some("http://localhost:5173/callback".into()),
        client_id: Some(public.to_string()),
        client_secret: Some("anything".into()),
        ..token_request(&setup, &code)
    };
    assert!(matches!(setup.oidc.token(&setup.instance, &token).await, Err(OidcError::InvalidClient)));
    setup.oidc.token(&setup.instance, &TokenRequest { client_secret: None, ..token }).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn applications_serve_their_own_tenant(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    // An account of another tenant in the same instance.
    let other = setup.identity.add_tenant(setup.instance.id, "Other", "test").await.unwrap();
    setup.identity.add_tenant_domain(setup.instance.id, other, &domain("other.de"), "test").await.unwrap();
    setup.identity.trust_tenant_domain(setup.instance.id, other, &domain("other.de"), "test").await.unwrap();
    let bob = setup.identity.add_account(other, &Address::parse("bob@other.de").unwrap(), "Bob", "test").await.unwrap();
    setup.identity.set_password(bob, PASSWORD, "test").await.unwrap();
    let bobs = setup
        .identity
        .create_session(setup.instance.id, "bob@other.de", PASSWORD, None, &ClientMeta::default())
        .await
        .unwrap();

    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, "openid")).await.unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &auth_request, &bobs.token, false).await,
        Err(OidcError::AccessDenied(_))
    ));

    let scope = format!("openid urn:kernoid:tenant:id:{other}");
    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, &scope)).await.unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await,
        Err(OidcError::AccessDenied(_))
    ));
    // An auth request is used up once finished; a second finish fails.
    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, "openid")).await.unwrap()
    else {
        panic!()
    };
    setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await.unwrap();
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await,
        Err(OidcError::AuthRequestNotFound)
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn signing_keys_rotate(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let first = setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let (first_header, _) = verify(&setup, &first.id_token).await;
    let keys = setup.oidc.signing_keys(setup.instance.id).await.unwrap();
    assert_eq!(keys.len(), 1, "created at the first login");
    assert_eq!(keys[0].state, KeyState::Active);

    let next = setup.oidc.add_signing_key(setup.instance.id, "test").await.unwrap();
    assert_eq!(
        setup.oidc.jwks(setup.instance.id).await.unwrap()["keys"].as_array().unwrap().len(),
        2,
        "published before it signs"
    );
    let still = setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    assert_eq!(verify(&setup, &still.id_token).await.0["kid"], first_header["kid"]);

    setup.oidc.activate_signing_key(setup.instance.id, &next, "test").await.unwrap();
    let rotated =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    assert_eq!(verify(&setup, &rotated.id_token).await.0["kid"], next.as_str());
    // The old key stays published, so the first token still verifies.
    verify(&setup, &first.id_token).await;

    let old = first_header["kid"].as_str().unwrap();
    assert!(matches!(
        setup.oidc.remove_signing_key(setup.instance.id, &next, "test").await,
        Err(OidcError::InvalidRequest(_))
    ));
    assert!(matches!(
        setup.oidc.remove_signing_key(setup.instance.id, old, "test").await,
        Err(OidcError::InvalidRequest(_))
    ));
    sqlx::query!("UPDATE signing_keys SET state_since = now() - interval '2 hours' WHERE kid = $1", old)
        .execute(&pool)
        .await
        .unwrap();
    setup.oidc.remove_signing_key(setup.instance.id, old, "test").await.unwrap();
    assert_eq!(setup.oidc.jwks(setup.instance.id).await.unwrap()["keys"].as_array().unwrap().len(), 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn no_secret_ever_enters_an_event(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let code = code(&setup, "openid").await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    let new_secret = setup.oidc.new_client_secret(setup.app, "test").await.unwrap();
    let payloads: Vec<String> =
        sqlx::query_scalar!("SELECT payload::text AS \"p!\" FROM events").fetch_all(&pool).await.unwrap();
    for secret in [&setup.secret, &new_secret, &code, &tokens.access_token, &setup.session] {
        assert!(payloads.iter().all(|payload| !payload.contains(secret.as_str())), "{secret}");
    }
    assert!(payloads.iter().all(|payload| !payload.contains("PRIVATE") && !payload.contains("\"d\"")));
    // The old secret no longer works, the new one does.
    let code = self::code(&setup, "openid").await;
    assert!(matches!(
        setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await,
        Err(OidcError::InvalidClient)
    ));
    setup
        .oidc
        .token(&setup.instance, &TokenRequest { client_secret: Some(new_secret), ..token_request(&setup, &code) })
        .await
        .unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn signing_keys_follow_a_new_main_key(pool: PgPool) {
    let old = Key::random().unwrap();
    let setup = setup(&pool, old.clone()).await;
    let first = setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();

    let events = EventStore::new(pool.clone());
    let new = Key::random().unwrap();
    let rotated = Oidc::new(events.clone(), MainKeys::new(new.clone(), vec![old]), "https");
    assert_eq!(rotated.rewrap_signing_keys().await.unwrap(), 1);
    let only_new = Oidc::new(events, MainKeys::new(new, Vec::new()), "https");
    let code = code(&setup, "openid").await;
    let again = only_new.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    assert_eq!(verify(&setup, &again.id_token).await.0["kid"], verify(&setup, &first.id_token).await.0["kid"]);
}

fn refresh_request(setup: &Setup, refresh_token: &str) -> TokenRequest {
    TokenRequest {
        grant_type: Some("refresh_token".into()),
        refresh_token: Some(refresh_token.into()),
        client_id: Some(setup.app.to_string()),
        client_secret: Some(setup.secret.clone()),
        ..TokenRequest::default()
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn refresh_tokens_rotate(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let first =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid email").await)).await.unwrap();
    let refresh = first.refresh_token.clone().expect("a refresh token");
    assert!(refresh.starts_with("krt1."));

    let second = setup.oidc.token(&setup.instance, &refresh_request(&setup, &refresh)).await.unwrap();
    let next = second.refresh_token.clone().unwrap();
    assert_ne!(next, refresh, "every refresh hands out the next token");
    let (_, claims) = verify(&setup, &second.id_token).await;
    assert!(claims.get("nonce").is_none(), "no nonce on refresh");
    setup.oidc.userinfo(&setup.instance, &second.access_token).await.unwrap();

    // Fewer scopes are fine, more are not.
    let narrower = TokenRequest { scope: Some("openid".into()), ..refresh_request(&setup, &next) };
    let third = setup.oidc.token(&setup.instance, &narrower).await.unwrap();
    assert_eq!(third.scope, "openid");
    let wider = TokenRequest {
        scope: Some("openid email profile".into()),
        ..refresh_request(&setup, third.refresh_token.as_ref().unwrap())
    };
    assert!(matches!(setup.oidc.token(&setup.instance, &wider).await, Err(OidcError::InvalidScope)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_reused_refresh_token_revokes_the_login(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let first = setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let stolen = first.refresh_token.clone().unwrap();
    let legitimate = setup.oidc.token(&setup.instance, &refresh_request(&setup, &stolen)).await.unwrap();

    // The copy comes back: everything of this login is revoked – the attacker's and the legitimate client's tokens.
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, &stolen)).await,
        Err(OidcError::InvalidGrant(_))
    ));
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, legitimate.refresh_token.as_ref().unwrap())).await,
        Err(OidcError::InvalidGrant(_))
    ));
    for access in [&first.access_token, &legitimate.access_token] {
        assert!(matches!(setup.oidc.userinfo(&setup.instance, access).await, Err(OidcError::InvalidToken)));
    }
    // Another login of the same session is not affected.
    let other = setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    setup.oidc.token(&setup.instance, &refresh_request(&setup, other.refresh_token.as_ref().unwrap())).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn refresh_tokens_end_with_the_session_and_belong_to_their_client(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let refresh = tokens.refresh_token.unwrap();
    let (other, other_secret) = setup
        .oidc
        .add_application(setup.tenant, setup.project, "Other", Kind::Confidential, &[CALLBACK.into()], &[], "test")
        .await
        .unwrap();
    let foreign = TokenRequest {
        client_id: Some(other.to_string()),
        client_secret: other_secret,
        ..refresh_request(&setup, &refresh)
    };
    assert!(matches!(setup.oidc.token(&setup.instance, &foreign).await, Err(OidcError::InvalidGrant(_))));

    let expires: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar!("SELECT expires_at FROM refresh_tokens LIMIT 1").fetch_one(&pool).await.unwrap();
    let session_expires: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar!("SELECT expires_at FROM sessions LIMIT 1").fetch_one(&pool).await.unwrap();
    assert_eq!(expires, session_expires, "a refresh token lives as long as its session");

    setup.identity.terminate_session(setup.instance.id, &setup.session).await.unwrap();
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, &refresh)).await,
        Err(OidcError::InvalidGrant(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn revocation(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let client = setup.app.to_string();
    // Unknown tokens and wrong credentials.
    setup.oidc.revoke(&setup.instance, &client, Some(&setup.secret), "krt1.unknown").await.unwrap();
    assert!(matches!(
        setup.oidc.revoke(&setup.instance, &client, Some("kcs1.wrong"), tokens.refresh_token.as_ref().unwrap()).await,
        Err(OidcError::InvalidClient)
    ));
    // Revoking the refresh token ends the whole login.
    setup
        .oidc
        .revoke(&setup.instance, &client, Some(&setup.secret), tokens.refresh_token.as_ref().unwrap())
        .await
        .unwrap();
    assert!(matches!(setup.oidc.userinfo(&setup.instance, &tokens.access_token).await, Err(OidcError::InvalidToken)));
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, tokens.refresh_token.as_ref().unwrap())).await,
        Err(OidcError::InvalidGrant(_))
    ));
    // An access token alone.
    let again = setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    setup.oidc.revoke(&setup.instance, &client, Some(&setup.secret), &again.access_token).await.unwrap();
    assert!(matches!(setup.oidc.userinfo(&setup.instance, &again.access_token).await, Err(OidcError::InvalidToken)));
    setup.oidc.token(&setup.instance, &refresh_request(&setup, again.refresh_token.as_ref().unwrap())).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn prompt_and_max_age(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let started = |prompt: Option<&str>, max_age: Option<&str>| AuthorizeRequest {
        prompt: prompt.map(str::to_owned),
        max_age: max_age.map(str::to_owned),
        ..authorize_request(setup.app, "openid")
    };
    for (prompt, max_age, error) in [
        (Some("none login"), None, "prompt=none cannot be combined"),
        (Some("bogus"), None, "unknown prompt value"),
        (None, Some("-1"), "max_age is a number of seconds"),
        (None, Some("soon"), "max_age is a number of seconds"),
    ] {
        let Authorized::Error { url } = setup.oidc.authorize(&setup.instance, &started(prompt, max_age)).await.unwrap()
        else {
            panic!("expected an error for {prompt:?} {max_age:?}")
        };
        assert_eq!(query(&url)["error_description"], error);
    }

    // The session was created before this request: prompt=login asks for a fresh one.
    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &started(Some("login"), None)).await.unwrap()
    else {
        panic!()
    };
    let info = setup.oidc.auth_request(&setup.instance, &auth_request).await.unwrap();
    assert_eq!(info.prompt, ["login"]);
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await,
        Err(OidcError::LoginRequired)
    ));
    let fresh = setup
        .identity
        .create_session(
            setup.instance.id,
            "alice@firma.de",
            PASSWORD,
            None,
            &kernoid_identity::session::ClientMeta::default(),
        )
        .await
        .unwrap();
    setup.oidc.finish(&setup.instance, &auth_request, &fresh.token, false).await.unwrap();

    // max_age=0 cannot be met by any session older than the request; a generous one can.
    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &started(None, Some("0"))).await.unwrap()
    else {
        panic!()
    };
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(setup.oidc.auth_request(&setup.instance, &auth_request).await.unwrap().max_age, Some(0));
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &auth_request, &fresh.token, false).await,
        Err(OidcError::LoginRequired)
    ));
    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &started(None, Some("3600"))).await.unwrap()
    else {
        panic!()
    };
    setup.oidc.finish(&setup.instance, &auth_request, &fresh.token, false).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_login_ui_can_decline(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let request = AuthorizeRequest { prompt: Some("none".into()), ..authorize_request(setup.app, "openid") };
    let Authorized::Login { auth_request, .. } = setup.oidc.authorize(&setup.instance, &request).await.unwrap() else {
        panic!()
    };
    assert!(matches!(
        setup.oidc.fail(&setup.instance, &auth_request, "made_up").await,
        Err(OidcError::InvalidRequest(_))
    ));
    let url = setup.oidc.fail(&setup.instance, &auth_request, "login_required").await.unwrap();
    let params = query(&url);
    assert!(url.starts_with(CALLBACK));
    assert_eq!((params["error"].as_str(), params["state"].as_str()), ("login_required", "xyz"));
    // Ended: neither finishing nor failing again works.
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await,
        Err(OidcError::AuthRequestNotFound)
    ));
    assert!(matches!(
        setup.oidc.fail(&setup.instance, &auth_request, "access_denied").await,
        Err(OidcError::AuthRequestNotFound)
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn logout_at_the_request_of_the_application(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let logout = |hint: Option<&str>, uri: Option<&str>| EndSessionRequest {
        id_token_hint: hint.map(str::to_owned),
        post_logout_redirect_uri: uri.map(str::to_owned),
        state: Some("bye".into()),
        ..EndSessionRequest::default()
    };

    // Unregistered redirect: refused, and the session lives on.
    assert!(matches!(
        setup.oidc.end_session(&setup.instance, &logout(Some(&tokens.id_token), Some("https://evil.example/"))).await,
        Err(OidcError::InvalidRequest(_))
    ));
    setup.identity.session(setup.instance.id, &setup.session).await.unwrap();
    // A forged hint is refused.
    let forged = format!("{}x", tokens.id_token);
    assert!(matches!(
        setup.oidc.end_session(&setup.instance, &logout(Some(&forged), None)).await,
        Err(OidcError::InvalidRequest(_))
    ));
    // A redirect without knowing the client is refused.
    assert!(matches!(
        setup.oidc.end_session(&setup.instance, &logout(None, Some(LOGGED_OUT))).await,
        Err(OidcError::InvalidRequest(_))
    ));

    let back =
        setup.oidc.end_session(&setup.instance, &logout(Some(&tokens.id_token), Some(LOGGED_OUT))).await.unwrap();
    assert_eq!(back.redirect.as_deref(), Some("https://app.firma.de/logged-out?state=bye"));
    assert!(setup.identity.session(setup.instance.id, &setup.session).await.is_err(), "the session has ended");
    assert!(matches!(setup.oidc.userinfo(&setup.instance, &tokens.access_token).await, Err(OidcError::InvalidToken)));
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, tokens.refresh_token.as_ref().unwrap())).await,
        Err(OidcError::InvalidGrant(_))
    ));
    // Logging out again – the token is old now – is harmless.
    assert_eq!(
        setup.oidc.end_session(&setup.instance, &logout(Some(&tokens.id_token), None)).await.unwrap(),
        kernoid_oidc::EndSession::default()
    );
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_second_factor_can_be_required(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let started = || async {
        let Authorized::Login { auth_request, .. } =
            setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, "openid")).await.unwrap()
        else {
            panic!()
        };
        auth_request
    };

    // The application requires it: a password alone is not enough.
    setup.oidc.set_application_mfa_required(setup.app, true, "test").await.unwrap();
    let request = started().await;
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &request, &setup.session, false).await,
        Err(OidcError::MfaRequired)
    ));
    // A recovery code – a one-time password – is a second factor; the same request finishes now.
    let codes = setup.identity.generate_recovery_codes(setup.instance.id, &setup.session).await.unwrap();
    setup.identity.check_recovery_code(setup.instance.id, &setup.session, &codes[0]).await.unwrap();
    let callback = setup.oidc.finish(&setup.instance, &request, &setup.session, false).await.unwrap();
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &query(&callback)["code"])).await.unwrap();
    let (_, claims) = verify(&setup, &tokens.id_token).await;
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));

    // The tenant requires it: another password-only session is refused, also for other applications.
    setup.oidc.set_application_mfa_required(setup.app, false, "test").await.unwrap();
    setup.identity.set_tenant_mfa_required(setup.instance.id, setup.tenant, true, "test").await.unwrap();
    let weak = setup
        .identity
        .create_session(
            setup.instance.id,
            "alice@firma.de",
            PASSWORD,
            None,
            &kernoid_identity::session::ClientMeta::default(),
        )
        .await
        .unwrap();
    let request = started().await;
    assert!(matches!(
        setup.oidc.finish(&setup.instance, &request, &weak.token, false).await,
        Err(OidcError::MfaRequired)
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_requirement_switched_on_later_stops_refreshing(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let refreshed = setup
        .oidc
        .token(&setup.instance, &refresh_request(&setup, tokens.refresh_token.as_ref().unwrap()))
        .await
        .unwrap();
    setup.identity.set_tenant_mfa_required(setup.instance.id, setup.tenant, true, "test").await.unwrap();
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, refreshed.refresh_token.as_ref().unwrap())).await,
        Err(OidcError::InvalidGrant(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn project_roles_decide_and_go_into_tokens(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let alice = setup.identity.account_by_address(&Address::parse("alice@firma.de").unwrap()).await.unwrap().unwrap();
    let (tenant, project) = (setup.tenant, setup.project);
    setup.identity.set_project_role(tenant, project, "editor", "Editor", None, "test").await.unwrap();

    // Without settings, roles stay out of tokens – unless the scope asks for them.
    let first = code(&setup, "openid").await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &first)).await.unwrap();
    assert_eq!(verify(&setup, &tokens.id_token).await.1[ROLES_CLAIM], Value::Null);
    let second = code(&setup, &format!("openid {ROLES_SCOPE}")).await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &second)).await.unwrap();
    assert_eq!(verify(&setup, &tokens.id_token).await.1[ROLES_CLAIM], json!({}));

    // With role_check, an account without a role in the project may not log in, nor refresh.
    let refresh = tokens.refresh_token.unwrap();
    setup.identity.set_project_settings(tenant, project, true, true, "test").await.unwrap();
    let Authorized::Login { auth_request, .. } =
        setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, "openid")).await.unwrap()
    else {
        panic!("expected a login")
    };
    let refused = setup.oidc.finish(&setup.instance, &auth_request, &setup.session, false).await;
    assert!(matches!(refused, Err(OidcError::AccessDenied(_))), "{refused:?}");
    let refused = setup.oidc.token(&setup.instance, &refresh_request(&setup, &refresh)).await;
    assert!(matches!(refused, Err(OidcError::InvalidGrant(_))), "{refused:?}");

    // A role through a group lets the account in; role_assertion puts it into the ID token and userinfo.
    let group = setup.identity.add_group(tenant, "Editors", "test").await.unwrap();
    setup.identity.add_group_member(tenant, group, alice.id, "test").await.unwrap();
    setup.identity.grant_project_role(tenant, project, Principal::Group(group), "editor", "test").await.unwrap();
    let first = code(&setup, "openid").await;
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &first)).await.unwrap();
    let expected = json!({ "editor": { tenant.to_string(): "Firma" } });
    assert_eq!(verify(&setup, &tokens.id_token).await.1[ROLES_CLAIM], expected);
    let info = setup.oidc.userinfo(&setup.instance, &tokens.access_token).await.unwrap();
    assert_eq!(info[ROLES_CLAIM], expected);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn granted_projects_let_other_tenants_in(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let (instance, owner, project) = (setup.instance.id, setup.tenant, setup.project);
    let other = setup.identity.add_tenant(instance, "Other", "test").await.unwrap();
    setup.identity.add_tenant_domain(instance, other, &domain("other.de"), "test").await.unwrap();
    setup.identity.trust_tenant_domain(instance, other, &domain("other.de"), "test").await.unwrap();
    let bob = setup.identity.add_account(other, &Address::parse("bob@other.de").unwrap(), "Bob", "test").await.unwrap();
    setup.identity.set_password(bob, PASSWORD, "test").await.unwrap();
    let bobs = setup.identity.create_session(instance, "bob@other.de", PASSWORD, None, &ClientMeta::default()).await;
    let bobs = bobs.unwrap().token;
    let login = |session: String| {
        let setup = &setup;
        async move {
            let Authorized::Login { auth_request, .. } =
                setup.oidc.authorize(&setup.instance, &authorize_request(setup.app, "openid")).await.unwrap()
            else {
                panic!("expected a login")
            };
            setup.oidc.finish(&setup.instance, &auth_request, &session, false).await
        }
    };
    for (key, name) in [("editor", "Editor"), ("admin", "Admin")] {
        setup.identity.set_project_role(owner, project, key, name, None, "test").await.unwrap();
    }
    setup.identity.set_project_settings(owner, project, true, true, "test").await.unwrap();

    // Not granted: Bob's tenant may neither use the project nor give its roles.
    assert!(matches!(login(bobs.clone()).await, Err(OidcError::AccessDenied(_))));
    let refused = setup.identity.grant_project_role(other, project, Principal::Account(bob), "editor", "test").await;
    assert!(matches!(refused, Err(kernoid_identity::IdentityError::NotFound(_))));

    // Granted with editor only: the other tenant gives that role, not more.
    let editor = std::collections::BTreeSet::from(["editor".to_owned()]);
    setup.identity.grant_project(owner, project, other, &editor, "test").await.unwrap();
    assert!(matches!(login(bobs.clone()).await, Err(OidcError::AccessDenied(_))), "role_check: no role yet");
    let refused = setup.identity.grant_project_role(other, project, Principal::Account(bob), "admin", "test").await;
    assert!(matches!(refused, Err(kernoid_identity::IdentityError::NotFound(_))));
    setup.identity.grant_project_role(other, project, Principal::Account(bob), "editor", "test").await.unwrap();
    let callback = login(bobs.clone()).await.unwrap();
    let code = query(&callback)["code"].clone();
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    let expected = json!({ "editor": { other.to_string(): "Other" } });
    assert_eq!(verify(&setup, &tokens.id_token).await.1[ROLES_CLAIM], expected);

    // The owner sees every tenant's authorizations, the other tenant its own.
    assert_eq!(setup.identity.project_authorizations(project, None).await.unwrap().len(), 1);
    assert_eq!(setup.identity.project_authorizations(project, Some(owner)).await.unwrap().len(), 0);
    // A grant goes only once its roles are no longer held there; the same for taking a role out of it.
    let none: std::collections::BTreeSet<String> = ["admin".to_owned()].into();
    assert!(setup.identity.grant_project(owner, project, other, &none, "test").await.is_err());
    assert!(setup.identity.revoke_project_grant(owner, project, other, "test").await.is_err());
    assert!(setup.identity.remove_project_role(owner, project, "editor", "test").await.is_err());
    setup.identity.revoke_project_role(other, project, Principal::Account(bob), "editor", "test").await.unwrap();
    setup.identity.revoke_project_grant(owner, project, other, "test").await.unwrap();
    assert!(matches!(login(bobs).await, Err(OidcError::AccessDenied(_))));
}

/// Runs authorize for `scope` (and `prompt`), then finish with or without consent.
async fn finish_with(setup: &Setup, scope: &str, prompt: Option<&str>, consent: bool) -> Result<String, OidcError> {
    let mut request = authorize_request(setup.app, scope);
    request.prompt = prompt.map(str::to_owned);
    let Authorized::Login { auth_request, .. } = setup.oidc.authorize(&setup.instance, &request).await.unwrap() else {
        panic!("expected a login")
    };
    setup.oidc.finish(&setup.instance, &auth_request, &setup.session, consent).await
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn offline_access_needs_consent_and_outlives_the_session(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let alice = setup.identity.session(setup.instance.id, &setup.session).await.unwrap().account.id;

    // An application that may not ask for it: the scope is dropped, no consent asked.
    let code = query(&finish_with(&setup, "openid offline_access", None, false).await.unwrap())["code"].clone();
    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    assert_eq!(tokens.scope, "openid");

    let allowed = AppOptions { offline_access: true, ..AppOptions::default() };
    setup.oidc.set_application_options(setup.app, &allowed, "test").await.unwrap();
    assert!(matches!(finish_with(&setup, "openid offline_access", None, false).await, Err(OidcError::ConsentRequired)));
    let code = query(&finish_with(&setup, "openid offline_access", None, true).await.unwrap())["code"].clone();
    let consents = setup.identity.consents(alice).await.unwrap();
    assert_eq!((consents.len(), consents[0].scopes.clone()), (1, vec!["openid".into(), "offline_access".into()]));
    // Agreed once, asked no more – unless the application asks with prompt=consent.
    finish_with(&setup, "openid offline_access", None, false).await.unwrap();
    assert!(matches!(finish_with(&setup, "openid", Some("consent"), false).await, Err(OidcError::ConsentRequired)));

    let tokens = setup.oidc.token(&setup.instance, &token_request(&setup, &code)).await.unwrap();
    assert_eq!(tokens.scope, "openid offline_access");
    let session = setup.identity.session(setup.instance.id, &setup.session).await.unwrap().id;
    setup.identity.terminate_session_by_id(setup.instance.id, session, "test").await.unwrap();
    // The session is gone; the offline grant is not.
    let refreshed = setup
        .oidc
        .token(&setup.instance, &refresh_request(&setup, tokens.refresh_token.as_ref().unwrap()))
        .await
        .unwrap();
    setup.oidc.userinfo(&setup.instance, &refreshed.access_token).await.unwrap();
    let (_, claims) = verify(&setup, &refreshed.id_token).await;
    assert_eq!(claims["sub"], alice.to_string());

    // Withdrawing the consent ends it, and the tokens.
    setup.oidc.revoke_consent(alice, setup.app, "test").await.unwrap();
    assert!(setup.identity.consents(alice).await.unwrap().is_empty());
    assert!(matches!(
        setup.oidc.userinfo(&setup.instance, &refreshed.access_token).await,
        Err(OidcError::InvalidToken)
    ));
    assert!(matches!(
        setup.oidc.token(&setup.instance, &refresh_request(&setup, refreshed.refresh_token.as_ref().unwrap())).await,
        Err(OidcError::InvalidGrant(_))
    ));
    assert!(matches!(setup.oidc.revoke_consent(alice, setup.app, "test").await, Err(OidcError::Identity(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_application_may_require_consent(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let required = AppOptions { consent_required: true, ..AppOptions::default() };
    setup.oidc.set_application_options(setup.app, &required, "test").await.unwrap();
    assert_eq!(setup.oidc.application(setup.app).await.unwrap().options, required);
    assert!(matches!(finish_with(&setup, "openid email", None, false).await, Err(OidcError::ConsentRequired)));
    finish_with(&setup, "openid email", None, true).await.unwrap();
    finish_with(&setup, "openid email", None, false).await.unwrap();
    // More than was agreed to: asked again, and the consent grows.
    assert!(matches!(finish_with(&setup, "openid email profile", None, false).await, Err(OidcError::ConsentRequired)));
    finish_with(&setup, "openid email profile", None, true).await.unwrap();
    let alice = setup.identity.session(setup.instance.id, &setup.session).await.unwrap().account.id;
    assert_eq!(setup.identity.consent(alice, setup.app).await.unwrap().unwrap(), ["openid", "email", "profile"]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn access_tokens_as_jwt(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let jwt = AppOptions { access_token_format: TokenFormat::Jwt, ..AppOptions::default() };
    setup.oidc.set_application_options(setup.app, &jwt, "test").await.unwrap();
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid email").await)).await.unwrap();
    let (header, claims) = verify(&setup, &tokens.access_token).await;
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(claims["aud"], setup.app.to_string());
    assert_eq!(claims["client_id"], setup.app.to_string());
    assert_eq!(claims["iss"], "https://login.firma.de");
    assert_eq!(claims["scope"], "openid email");
    assert!(claims["jti"].is_string() && claims["sid"].is_string());
    // Kernoid knows it, too: userinfo and revocation work as for opaque tokens.
    let info = setup.oidc.userinfo(&setup.instance, &tokens.access_token).await.unwrap();
    assert_eq!(info["email"], "alice@firma.de");
    setup
        .oidc
        .revoke(&setup.instance, &setup.app.to_string(), Some(&setup.secret), &tokens.access_token)
        .await
        .unwrap();
    assert!(matches!(setup.oidc.userinfo(&setup.instance, &tokens.access_token).await, Err(OidcError::InvalidToken)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn introspection_for_resource_servers(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid profile").await)).await.unwrap();
    // An API of the same project, as a confidential client.
    let (api, api_secret) = setup
        .oidc
        .add_application(setup.tenant, setup.project, "API", Kind::Confidential, &[], &[], "test")
        .await
        .unwrap();
    let api_secret = api_secret.unwrap();
    let answer = setup
        .oidc
        .introspect(&setup.instance, &api.to_string(), Some(&api_secret), &tokens.access_token)
        .await
        .unwrap();
    assert_eq!(answer["active"], true);
    assert_eq!(answer["client_id"], setup.app.to_string());
    assert_eq!(answer["scope"], "openid profile");
    assert_eq!(answer["username"], "alice@firma.de");
    assert_eq!(answer["token_type"], "Bearer");
    let refresh = tokens.refresh_token.as_ref().unwrap();
    let answer = setup.oidc.introspect(&setup.instance, &api.to_string(), Some(&api_secret), refresh).await.unwrap();
    assert_eq!((answer["active"].clone(), answer["token_type"].clone()), (json!(true), json!("refresh_token")));
    let unknown = setup.oidc.introspect(&setup.instance, &api.to_string(), Some(&api_secret), "kat1.nope").await;
    assert_eq!(unknown.unwrap(), json!({ "active": false }));

    // Another project's client learns nothing; a public client may not ask; a wrong secret is refused.
    let other_project = setup.identity.add_project(setup.tenant, "Other", "test").await.unwrap();
    let (other, other_secret) = setup
        .oidc
        .add_application(setup.tenant, other_project, "Other", Kind::Confidential, &[], &[], "test")
        .await
        .unwrap();
    let answer = setup
        .oidc
        .introspect(&setup.instance, &other.to_string(), other_secret.as_deref(), &tokens.access_token)
        .await
        .unwrap();
    assert_eq!(answer, json!({ "active": false }));
    let (public, _) = setup
        .oidc
        .add_application(setup.tenant, setup.project, "SPA", Kind::Public, &[CALLBACK.to_owned()], &[], "test")
        .await
        .unwrap();
    assert!(matches!(
        setup.oidc.introspect(&setup.instance, &public.to_string(), None, &tokens.access_token).await,
        Err(OidcError::InvalidClient)
    ));
    assert!(matches!(
        setup.oidc.introspect(&setup.instance, &api.to_string(), Some("wrong"), &tokens.access_token).await,
        Err(OidcError::InvalidClient)
    ));

    // Revoked: inactive.
    setup
        .oidc
        .revoke(&setup.instance, &setup.app.to_string(), Some(&setup.secret), &tokens.access_token)
        .await
        .unwrap();
    let answer = setup
        .oidc
        .introspect(&setup.instance, &api.to_string(), Some(&api_secret), &tokens.access_token)
        .await
        .unwrap();
    assert_eq!(answer, json!({ "active": false }));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn applications_learn_of_logouts(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    // An application listening for logout tokens, at a local address (allowed for this test).
    let received: std::sync::Arc<std::sync::Mutex<Vec<String>>> = std::sync::Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route(
            "/logout",
            axum::routing::post(
                |axum::extract::State(received): axum::extract::State<
                    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
                >,
                 axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| async move {
                    received.lock().unwrap().push(form["logout_token"].clone());
                },
            ),
        )
        .with_state(received.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let oidc = setup.oidc.clone().allow_private_networks(true);
    let notified = AppOptions {
        backchannel_logout_uri: Some(format!("http://{address}/logout")),
        frontchannel_logout_uri: Some("https://app.firma.de/frontchannel-logout".into()),
        ..AppOptions::default()
    };
    assert!(
        matches!(
            setup.oidc.set_application_options(setup.app, &notified, "test").await,
            Err(OidcError::InvalidRequest(_))
        ),
        "a private address needs outbound.allow_private_networks"
    );
    oidc.set_application_options(setup.app, &notified, "test").await.unwrap();

    let tokens = oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let (_, id_claims) = verify(&setup, &tokens.id_token).await;
    let request = EndSessionRequest { id_token_hint: Some(tokens.id_token.clone()), ..EndSessionRequest::default() };
    let ended = oidc.end_session(&setup.instance, &request).await.unwrap();
    let sid = id_claims["sid"].as_str().unwrap();
    assert_eq!(
        ended.frontchannel,
        [format!("https://app.firma.de/frontchannel-logout?iss=https%3A%2F%2Flogin.firma.de&sid={sid}")]
    );

    let done = oidc.deliver_logout_notifications().await.unwrap();
    assert_eq!((done.queued, done.delivered, done.failed), (1, 1, 0));
    let tokens_received = received.lock().unwrap().clone();
    assert_eq!(tokens_received.len(), 1);
    let (header, claims) = verify(&setup, &tokens_received[0]).await;
    assert_eq!(header["typ"], "logout+jwt");
    assert_eq!(claims["sid"], sid);
    assert_eq!(claims["sub"], id_claims["sub"]);
    assert_eq!(claims["aud"], setup.app.to_string());
    assert!(claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
    assert!(claims.get("nonce").is_none());
    // Told once.
    assert_eq!(oidc.deliver_logout_notifications().await.unwrap().queued, 0);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn failed_logout_notifications_are_tried_again_later(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let oidc = setup.oidc.clone().allow_private_networks(true);
    // Nobody listens there.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let notified =
        AppOptions { backchannel_logout_uri: Some(format!("http://{address}/logout")), ..AppOptions::default() };
    oidc.set_application_options(setup.app, &notified, "test").await.unwrap();
    code(&setup, "openid").await;
    setup.identity.terminate_session(setup.instance.id, &setup.session).await.unwrap();
    let done = oidc.deliver_logout_notifications().await.unwrap();
    assert_eq!((done.queued, done.delivered, done.failed), (1, 0, 1));
    // Not due again yet.
    assert_eq!(oidc.deliver_logout_notifications().await.unwrap(), Default::default());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn signing_keys_rotate_on_their_own(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    let zero = std::time::Duration::ZERO;
    let week = std::time::Duration::from_secs(7 * 24 * 60 * 60);
    // Without an active key there is nothing to rotate; the first token makes one.
    assert_eq!(setup.oidc.rotate_signing_keys(zero, zero, week).await.unwrap(), Default::default());
    setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let first = setup.oidc.signing_keys(setup.instance.id).await.unwrap();
    assert_eq!(first.len(), 1);
    // Not due: nothing happens.
    assert_eq!(setup.oidc.rotate_signing_keys(week, zero, week).await.unwrap(), Default::default());
    // Due: a successor is published first …
    assert_eq!(setup.oidc.rotate_signing_keys(zero, week, week).await.unwrap().added, 1);
    let keys = setup.oidc.signing_keys(setup.instance.id).await.unwrap();
    assert_eq!(keys.iter().map(|key| key.state).collect::<Vec<_>>(), [KeyState::Active, KeyState::Initial]);
    assert_eq!(setup.oidc.rotate_signing_keys(zero, week, week).await.unwrap(), Default::default());
    // … and signs once it has been published long enough.
    assert_eq!(setup.oidc.rotate_signing_keys(zero, zero, week).await.unwrap().activated, 1);
    let keys = setup.oidc.signing_keys(setup.instance.id).await.unwrap();
    assert_eq!(keys.iter().map(|key| key.state).collect::<Vec<_>>(), [KeyState::Inactive, KeyState::Active]);
    let tokens =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let (header, _) = verify(&setup, &tokens.id_token).await;
    assert_eq!(header["kid"], keys[1].kid);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_instance_may_have_its_own_login_ui(pool: PgPool) {
    let setup = setup(&pool, Key::random().unwrap()).await;
    for bad in ["http://login.example/", "https://login.example/?x=1", "https://login.example/#a", "not a url"] {
        assert!(setup.identity.set_login_ui(setup.instance.id, Some(bad), "test").await.is_err(), "{bad}");
    }
    setup.identity.set_login_ui(setup.instance.id, Some("https://anmeldung.firma.de/login/"), "test").await.unwrap();
    let instance = setup.identity.instance_by_host("login.firma.de").await.unwrap().unwrap();
    assert_eq!(instance.login_ui.as_deref(), Some("https://anmeldung.firma.de/login/"));
    let Authorized::Login { auth_request, url } =
        setup.oidc.authorize(&instance, &authorize_request(setup.app, "openid")).await.unwrap()
    else {
        panic!("expected a login")
    };
    assert_eq!(url, format!("https://anmeldung.firma.de/login?authRequest={auth_request}"));
    setup.identity.set_login_ui(setup.instance.id, None, "test").await.unwrap();
    let instance = setup.identity.instance_by_host("login.firma.de").await.unwrap().unwrap();
    assert_eq!(instance.login_ui, None);
}

/// Mail programs log in over IMAP and SMTP with an access token that has the scope `mail` (OAUTHBEARER, XOAUTH2).
#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn access_tokens_with_the_mail_scope_log_mail_programs_in(pool: PgPool) {
    use kernoid_identity::services::Service;

    let setup = setup(&pool, Key::random().unwrap()).await;
    let alice = setup.identity.session(setup.instance.id, &setup.session).await.unwrap().account.id;
    let without =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid").await)).await.unwrap();
    let with =
        setup.oidc.token(&setup.instance, &token_request(&setup, &code(&setup, "openid mail").await)).await.unwrap();

    // Without the service mail, no mail login; then with the scope only, and for the token's own account only.
    setup.identity.revoke_service(alice, Service::Mail, "test").await.unwrap();
    assert!(setup.identity.token_login(&with.access_token, None).await.is_err());
    setup.identity.grant_service(alice, Service::Mail, "test").await.unwrap();
    assert_eq!(setup.identity.token_login(&with.access_token, Some("alice@firma.de")).await.unwrap().id, alice);
    assert_eq!(setup.identity.token_login(&with.access_token, None).await.unwrap().id, alice);
    assert!(matches!(
        setup.identity.token_login(&without.access_token, None).await,
        Err(kernoid_identity::IdentityError::InvalidCredentials)
    ));
    assert!(matches!(
        setup.identity.token_login(&with.access_token, Some("bob@firma.de")).await,
        Err(kernoid_identity::IdentityError::InvalidCredentials)
    ));
    // A revoked token no longer does.
    setup.oidc.revoke(&setup.instance, &setup.app.to_string(), Some(&setup.secret), &with.access_token).await.unwrap();
    assert!(setup.identity.token_login(&with.access_token, None).await.is_err());
}
