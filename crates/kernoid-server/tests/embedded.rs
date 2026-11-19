// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's identity built into a program (RFC 0009, 3): in a schema of its own beside the program's tables, its
//! routes merged with the program's, and `Session` in the program's handlers. Against PostgreSQL, set `DATABASE_URL` as
//! for the other tests; the database is the test's own, without kernoid's migrations – the program migrates.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use http_body_util::BodyExt;
use kernoid_config::Config;
use kernoid_identity::{Address, DomainName};
use kernoid_server::embedded::{Embedded, Session};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use tower::ServiceExt;

const HOST: &str = "music.example.org";

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[sqlx::test(migrations = false)]
async fn a_program_builds_in_identity_in_a_schema_of_its_own(pool: PgPool) {
    let admin = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let name = pool.connect_options().get_database().unwrap().to_owned();
    let url = format!("{}/{name}", admin.rsplit_once('/').unwrap().0);
    // The program's own table, and kernoid's schema beside it.
    sqlx::query!("CREATE TABLE scores (id int PRIMARY KEY)").execute(&pool).await.unwrap();
    sqlx::query!("CREATE SCHEMA kernoid").execute(&pool).await.unwrap();
    let config = Config::from_sources(
        &format!(
            r#"
            [services]
            mail = false
            calendars = false
            files = false
            [database]
            url = "{url}"
            schema = "kernoid"
            [blob]
            kind = "database"
            [encryption]
            main_key = "{}"
            "#,
            "11".repeat(32)
        ),
        [],
    )
    .unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let kernoid = Embedded::start(config, shutdown.clone()).await.unwrap();

    // An instance, a tenant and an account, as the program's setup would make them.
    let identity = &kernoid.state().identity;
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Music", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "School", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("school.example"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("school.example"), "test").await.unwrap();
    let ada =
        identity.add_account(tenant, &Address::parse("ada@school.example").unwrap(), "Ada", "test").await.unwrap();
    identity.set_password(ada, "correct horse battery staple", "test").await.unwrap();

    let program = Router::new()
        .route("/music/me", get(|session: Session| async move { session.account.display_name }))
        .with_state(kernoid.state().clone());
    let app = kernoid.router(program);

    // kernoid's routes: only identity's.
    let request = |method: &str, path: &str| Request::builder().method(method).uri(path).header("host", HOST);
    let (status, body) = send(&app, request("GET", "/v1/services").body(Body::empty()).unwrap()).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, r#"{"mail":false,"calendars":false,"files":false,"relay":false}"#)
    );
    assert_eq!(send(&app, request("GET", "/jmap/session").body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);

    // The program's route: nobody without a login, Ada with hers.
    assert_eq!(send(&app, request("GET", "/music/me").body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    let login = request("POST", "/v1/sessions")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "address": "ada@school.example", "password": "correct horse battery staple" }).to_string(),
        ))
        .unwrap();
    let (status, body) = send(&app, login).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = serde_json::from_str::<Value>(&body).unwrap()["token"].as_str().unwrap().to_owned();
    let me = request("GET", "/music/me").header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty());
    assert_eq!(send(&app, me.unwrap()).await, (StatusCode::OK, "Ada".to_owned()));

    // kernoid's tables are in its schema, the program's in public.
    let mut program = PgConnection::connect(&url).await.unwrap();
    let kernoid_tables: i64 =
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM pg_tables WHERE schemaname = 'kernoid'"#)
            .fetch_one(&mut program)
            .await
            .unwrap();
    let public_tables: Vec<String> =
        sqlx::query_scalar!(r#"SELECT tablename AS "name!" FROM pg_tables WHERE schemaname = 'public'"#)
            .fetch_all(&mut program)
            .await
            .unwrap();
    assert!(kernoid_tables > 50, "{kernoid_tables}");
    assert_eq!(public_tables, ["scores"]);

    shutdown.cancel();
}
