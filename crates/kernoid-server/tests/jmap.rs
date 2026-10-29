// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP over HTTP: logging in, the session, the API, the push stream; set `DATABASE_URL` as for the other crates'
//! tests.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::Engine;
use http_body_util::BodyExt;
use kernoid_config::{Blob, Http};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

/// An instance at HOST with the account alice@firma.de; its app password.
async fn app(pool: &PgPool) -> (Router, String) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", "test").await.unwrap();
    identity.set_password(alice, PASSWORD, "test").await.unwrap();
    let (_, app_password) = identity.add_app_password(alice, "Mail", "test").await.unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let blobs = BlobStore::from_config(&Blob::Memory, keys).unwrap();
    let oidc = kernoid_oidc::Oidc::new(
        EventStore::new(pool.clone()),
        kernoid_store::MainKeys::new(Key::random().unwrap(), Vec::new()),
        "https",
    );
    let mail = kernoid_mail::Mail::new(pool.clone(), blobs.clone(), kernoid_mail::Limits::default());
    let jmap = kernoid_jmap::Jmap::new(mail, 1_000_000, chrono::Duration::days(5));
    // Changes reach the push streams as in the server: through PostgreSQL's notifications.
    let events = kernoid_mail::MailEvents::default();
    tokio::spawn(events.clone().listen(pool.clone(), tokio_util::sync::CancellationToken::new()));
    // Listening starts in the background: wait until a notification comes through, so that no change is missed.
    let mut heard = events.subscribe();
    let probe = uuid::Uuid::nil().to_string();
    loop {
        sqlx::query!("SELECT pg_notify('kernoid_mail', $1)", probe).execute(pool).await.unwrap();
        if tokio::time::timeout(std::time::Duration::from_millis(200), heard.recv()).await.is_ok() {
            break;
        }
    }
    let state = AppState::new(pool.clone(), blobs, identity, oidc).with_jmap(jmap, events);
    (router(state, Router::new(), &Http::default()), app_password)
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}")))
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, String::from_utf8_lossy(&bytes).into_owned())
}

fn get(uri: &str, authorization: Option<&str>) -> Request<Body> {
    let mut request = Request::get(uri).header("host", HOST);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    request.body(Body::empty()).unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_programs_log_in_and_talk_jmap(pool: PgPool) {
    let (app, app_password) = app(&pool).await;

    let (status, headers, _) = send(&app, get("/.well-known/jmap", None)).await;
    assert_eq!(
        (status, headers.get(header::LOCATION).unwrap().to_str().unwrap()),
        (StatusCode::PERMANENT_REDIRECT, "/jmap/session")
    );

    let (status, headers, _) = send(&app, get("/jmap/session", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap().starts_with("Basic"));
    let (status, _, _) = send(&app, get("/jmap/session", Some(&basic("alice@firma.de", "wrong")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An app password, or – without a second factor – the password.
    let (status, _, body) = send(&app, get("/jmap/session", Some(&basic("alice@firma.de", &app_password)))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session["username"], "alice@firma.de");
    assert_eq!(session["apiUrl"], format!("https://{HOST}/jmap/api"));
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_owned();

    // A kernoid session works too.
    let login = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": "alice@firma.de", "password": PASSWORD }).to_string()))
        .unwrap();
    let (_, _, body) = send(&app, login).await;
    let token = serde_json::from_str::<Value>(&body).unwrap()["token"].as_str().unwrap().to_owned();
    let request = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Mailbox/query", { "accountId": account, "filter": { "role": "inbox" } }, "0"]],
    });
    let api = Request::post("/jmap/api")
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(request.to_string()))
        .unwrap();
    let (status, _, body) = send(&app, api).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["methodResponses"][0][0], "Mailbox/query");
    assert_eq!(response["methodResponses"][0][1]["ids"].as_array().unwrap().len(), 1);

    // Problem details for a broken request.
    let broken = Request::post("/jmap/api")
        .header("host", HOST)
        .header(header::AUTHORIZATION, basic("alice@firma.de", &app_password))
        .body(Body::from("{"))
        .unwrap();
    let (status, _, body) = send(&app, broken).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("urn:ietf:params:jmap:error:notJSON"));

    // Upload, then download.
    let upload = Request::post(format!("/jmap/upload/{account}/"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, basic("alice@firma.de", &app_password))
        .header("content-type", "text/plain")
        .body(Body::from("hello"))
        .unwrap();
    let (status, _, body) = send(&app, upload).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let blob = serde_json::from_str::<Value>(&body).unwrap()["blobId"].as_str().unwrap().to_owned();
    let (status, headers, body) = send(
        &app,
        get(&format!("/jmap/download/{account}/{blob}/hello.txt"), Some(&basic("alice@firma.de", &app_password))),
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello"));
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/plain");

    // The push stream: the current state, then it closes as asked.
    let (status, headers, body) = send(
        &app,
        get("/jmap/eventsource?types=*&closeafter=state&ping=0", Some(&basic("alice@firma.de", &app_password))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/event-stream"));
    assert!(body.contains("event: state") && body.contains("\"@type\":\"StateChange\""), "{body}");
    assert!(body.contains(&account));
}

/// JMAP over WebSocket (RFC 8887): a request and its response, then push after WebSocketPushEnable.
#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn requests_and_push_over_a_websocket(pool: PgPool) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    let (app, app_password) = app(&pool).await;
    let (_, _, body) = send(&app, get("/jmap/session", Some(&basic("alice@firma.de", &app_password)))).await;
    let session: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session["capabilities"]["urn:ietf:params:jmap:websocket"]["url"], "wss://login.firma.de/jmap/ws");
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_owned();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });

    // With the cookie but from another site: refused.
    let mut foreign = format!("ws://{address}/jmap/ws").into_client_request().unwrap();
    foreign.headers_mut().insert("host", HOST.parse().unwrap());
    foreign.headers_mut().insert("cookie", "__Host-kernoid-session=ks1.nonsense".parse().unwrap());
    foreign.headers_mut().insert("origin", "https://evil.example".parse().unwrap());
    foreign.headers_mut().insert("sec-websocket-protocol", "jmap".parse().unwrap());
    assert!(tokio_tungstenite::connect_async(foreign).await.is_err());

    let mut request = format!("ws://{address}/jmap/ws").into_client_request().unwrap();
    request.headers_mut().insert("host", HOST.parse().unwrap());
    request.headers_mut().insert("authorization", basic("alice@firma.de", &app_password).parse().unwrap());
    request.headers_mut().insert("sec-websocket-protocol", "jmap".parse().unwrap());
    let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], "jmap");

    let call = json!({
        "@type": "Request", "id": "r1",
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Mailbox/get", { "accountId": account, "properties": ["name", "role"] }, "a"]],
    });
    socket.send(Message::Text(call.to_string().into())).await.unwrap();
    let answer = read(&mut socket).await;
    assert_eq!((answer["@type"].as_str(), answer["requestId"].as_str()), (Some("Response"), Some("r1")));
    assert_eq!(answer["methodResponses"][0][0], "Mailbox/get");

    socket.send(Message::Text(json!({ "@type": "WebSocketPushEnable" }).to_string().into())).await.unwrap();
    let first = read(&mut socket).await;
    assert_eq!(first["@type"], "StateChange");
    let create = json!({
        "@type": "Request", "id": "r2",
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Mailbox/set", { "accountId": account, "create": { "n": { "name": "Projects" } } }, "b"]],
    });
    socket.send(Message::Text(create.to_string().into())).await.unwrap();
    // The response and the push come in either order.
    let (a, b) = (read(&mut socket).await, read(&mut socket).await);
    let types: Vec<&str> = [&a, &b].iter().map(|message| message["@type"].as_str().unwrap()).collect();
    assert!(types.contains(&"Response") && types.contains(&"StateChange"), "{a} {b}");

    socket.send(Message::Text("not json".into())).await.unwrap();
    assert_eq!(read(&mut socket).await["@type"], "RequestError");
}

async fn read<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await.unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = message.unwrap().unwrap() {
            return serde_json::from_str(text.as_str()).unwrap();
        }
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_email_is_viewed_as_laid_out_in_a_sandbox(pool: PgPool) {
    let (app, app_password) = app(&pool).await;
    let auth = basic("alice@firma.de", &app_password);
    let (_, _, body) = send(&app, get("/jmap/session", Some(&auth))).await;
    let account = serde_json::from_str::<Value>(&body).unwrap()["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .unwrap()
        .to_owned();
    let raw = "From: news@example.org\r\nTo: alice@firma.de\r\nSubject: News\r\nMIME-Version: 1.0\r\n\
        Content-Type: multipart/related; boundary=b\r\n\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
        <style>p{color:red}</style><p>Hi <img src=\"cid:logo@x\"></p><script>alert(1)</script>\r\n\
        --b\r\nContent-Type: image/png\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--b--\r\n";
    let upload = Request::post(format!("/jmap/upload/{account}/"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, &auth)
        .header("content-type", "message/rfc822")
        .body(Body::from(raw))
        .unwrap();
    let (_, _, body) = send(&app, upload).await;
    let blob = serde_json::from_str::<Value>(&body).unwrap()["blobId"].as_str().unwrap().to_owned();
    let using = json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]);
    let query = json!({ "using": using,
        "methodCalls": [["Mailbox/query", { "accountId": account, "filter": { "role": "inbox" } }, "m"]] });
    let api = |body: Value| {
        Request::post("/jmap/api")
            .header("host", HOST)
            .header(header::AUTHORIZATION, &auth)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let (_, _, body) = send(&app, api(query)).await;
    let inbox = serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["ids"][0].clone();
    let import = json!({ "using": using, "methodCalls": [["Email/import", { "accountId": account,
        "emails": { "e": { "blobId": blob, "mailboxIds": { inbox.as_str().unwrap(): true } } } }, "i"]] });
    let (_, _, body) = send(&app, api(import)).await;
    let imported: Value = serde_json::from_str(&body).unwrap();
    let email =
        imported["methodResponses"][0][1]["created"]["e"]["id"].as_str().unwrap_or_else(|| panic!("{body}")).to_owned();
    let get_email = json!({ "using": using, "methodCalls": [["Email/get", { "accountId": account, "ids": [email],
        "properties": ["htmlBody"] }, "g"]] });
    let (_, _, body) = send(&app, api(get_email)).await;
    let part =
        serde_json::from_str::<Value>(&body).unwrap()["methodResponses"][0][1]["list"][0]["htmlBody"][0]["blobId"]
            .as_str()
            .unwrap()
            .to_owned();

    let (status, headers, page) = send(&app, get(&format!("/jmap/view/{account}/{part}"), Some(&auth))).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let policy = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    for directive in
        ["sandbox allow-popups", "default-src 'none'", "img-src data:", "form-action 'none'", "frame-ancestors 'self'"]
    {
        assert!(policy.contains(directive), "{directive} in {policy}");
    }
    assert!(!policy.contains("allow-scripts") && !policy.contains("allow-same-origin"), "{policy}");
    assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(
        page.contains("<style>p{color:red}</style>") && page.contains("src=\"data:image/png;base64,iVBORw0KGgo=\""),
        "{page}"
    );

    // Only a reader of the email; only an HTML part.
    let (status, _, _) = send(&app, get(&format!("/jmap/view/{account}/{part}"), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let image = part.rsplit_once('-').map(|(email, _)| format!("{email}-2")).unwrap();
    let (status, _, _) = send(&app, get(&format!("/jmap/view/{account}/{image}"), Some(&auth))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
