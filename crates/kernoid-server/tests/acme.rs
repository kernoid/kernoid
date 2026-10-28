// SPDX-License-Identifier: AGPL-3.0-or-later
//! ACME certificates as the `api` processes use them: served by SNI from PostgreSQL, the CA's HTTP-01 challenges
//! answered from PostgreSQL, everything else on the HTTP port sent to HTTPS. Ordering against a CA is tested by hand
//! with Pebble (see `docs/operations.md`).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kernoid_config::Http;
use kernoid_events::EventStore;
use kernoid_identity::{DomainName, Identity};
use kernoid_server::acme::{Certificates, http_router, status};
use kernoid_store::{MainKeys, crypto::Key};
use sqlx::PgPool;
use tower::ServiceExt;

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn stored_certificates_are_served_by_name(pool: PgPool) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    identity.add_instance("Firma", &DomainName::parse("login.firma.de").unwrap(), "test").await.unwrap();
    let main = MainKeys::new(Key::random().unwrap(), Vec::new());

    // What the worker stores after an order: the chain, the key sealed with the main key.
    let issued = rcgen::generate_simple_self_signed(vec!["login.firma.de".to_owned()]).unwrap();
    let sealed = main.seal_secret(b"kernoid/tls-key/v1/login.firma.de", &issued.signing_key.serialize_der()).unwrap();
    sqlx::query!(
        "INSERT INTO tls_certificates (domain, chain_pem, key_sealed, not_after)
         VALUES ('login.firma.de', $1, $2, now() + interval '60 days')",
        issued.cert.pem(),
        sealed,
    )
    .execute(&pool)
    .await
    .unwrap();
    let certificates = Arc::new(Certificates::new(pool.clone(), main, None));
    assert_eq!(certificates.refresh().await.unwrap(), 1);
    assert_eq!(certificates.refresh().await.unwrap(), 0, "only what changed is loaded again");
    let states = status(&pool).await.unwrap();
    assert_eq!((states[0].domain.as_str(), states[0].not_after.is_some()), ("login.firma.de", true));

    let http = Http { listen: free_port(), ..Http::default() };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn({
        let http = http.clone();
        let app = axum::Router::new().route("/hello", axum::routing::get(|| async { "hello" }));
        async move {
            kernoid_server::serve_with(
                &http,
                app,
                async {
                    let _ = stopped.await;
                },
                Some(certificates),
            )
            .await
        }
    });
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates({
            let mut roots = rustls::RootCertStore::empty();
            roots.add(issued.cert.der().clone()).unwrap();
            roots
        })
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .resolve("login.firma.de", http.listen)
        .resolve("other.firma.de", http.listen)
        .build()
        .unwrap();
    let mut answer = None;
    for _ in 0..50 {
        match client.get(format!("https://login.firma.de:{}/hello", http.listen.port())).send().await {
            Ok(response) => {
                answer = Some(response);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    assert_eq!(answer.expect("served over TLS").text().await.unwrap(), "hello");
    // A name without a certificate gets none.
    assert!(client.get(format!("https://other.firma.de:{}/hello", http.listen.port())).send().await.is_err());
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap().unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn challenges_are_answered_and_the_rest_goes_to_https(pool: PgPool) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    identity.add_instance("Firma", &DomainName::parse("login.firma.de").unwrap(), "test").await.unwrap();
    sqlx::query!(
        "INSERT INTO acme_challenges (token, key_authorization, expires_at)
         VALUES ('tok-1', 'tok-1.thumbprint', now() + interval '1 hour')"
    )
    .execute(&pool)
    .await
    .unwrap();
    let app = http_router(pool.clone(), identity);
    let get = |path: &str, host: &str| Request::get(path).header(header::HOST, host).body(Body::empty()).unwrap();

    let answer = app.clone().oneshot(get("/.well-known/acme-challenge/tok-1", "login.firma.de")).await.unwrap();
    assert_eq!(answer.status(), StatusCode::OK);
    assert_eq!(answer.into_body().collect().await.unwrap().to_bytes(), "tok-1.thumbprint");
    let unknown = app.clone().oneshot(get("/.well-known/acme-challenge/nope", "login.firma.de")).await.unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let moved = app.clone().oneshot(get("/login/account?x=1", "login.firma.de:80")).await.unwrap();
    assert_eq!(moved.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(moved.headers()[header::LOCATION], "https://login.firma.de/login/account?x=1");
    // No redirects for names that are not an instance's.
    let elsewhere = app.oneshot(get("/", "evil.example")).await.unwrap();
    assert_eq!(elsewhere.status(), StatusCode::NOT_FOUND);
}
