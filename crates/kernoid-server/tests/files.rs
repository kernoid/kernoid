// SPDX-License-Identifier: AGPL-3.0-or-later
//! Files over HTTP (RFC 0005): their administration over REST and GraphQL, JMAP for an account with files, and direct
//! writes; against PostgreSQL – set `DATABASE_URL` as for the other crates' tests.

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
    services::Service,
};
use kernoid_server::{AppState, router};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const HOST: &str = "login.firma.de";
const PASSWORD: &str = "correct horse battery staple";

/// Alice administers the tenant Firma, Bob is an ordinary account of it; both have files.
async fn setup(pool: &PgPool) -> (Router, Uuid, Uuid) {
    let (app, alice, bob, _) = setup_with_mail(pool).await;
    (app, alice, bob)
}

/// The same, with the mail store – for what the worker does.
async fn setup_with_mail(pool: &PgPool) -> (Router, Uuid, Uuid, kernoid_mail::Mail) {
    let events = EventStore::new(pool.clone());
    let main = MainKeys::new(Key::random().unwrap(), Vec::new());
    let identity = Identity::with_secrets(events.clone(), main.clone());
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let instance = identity.add_instance("Firma", &domain(HOST), "test").await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain("firma.de"), "test").await.unwrap();
    let mut accounts = Vec::new();
    for address in ["alice@firma.de", "bob@firma.de"] {
        let account = identity.add_account(tenant, &Address::parse(address).unwrap(), address, "test").await.unwrap();
        identity.set_password(account, PASSWORD, "test").await.unwrap();
        identity.grant_service(account, Service::Files, "test").await.unwrap();
        accounts.push(account);
    }
    identity
        .grant_role(tenant, Principal::Account(accounts[0]), &Role::parse("tenant_admin").unwrap(), "test")
        .await
        .unwrap();
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let blobs = BlobStore::from_config(&Blob::Memory, keys).unwrap();
    let oidc = kernoid_oidc::Oidc::new(events, main, "https");
    let mail = kernoid_mail::Mail::new(pool.clone(), blobs.clone(), kernoid_mail::Limits::default());
    let files = kernoid_files::Files::new(pool.clone(), blobs.clone(), kernoid_files::Limits::default());
    let jmap = kernoid_jmap::Jmap::new(mail.clone(), 1_000_000, chrono::Duration::days(5))
        .with_files(files)
        .with_identity(Identity::new(EventStore::new(pool.clone())));
    let state = AppState::new(pool.clone(), blobs, identity, oidc).with_jmap(jmap, kernoid_mail::MailEvents::default());
    (router(state, Router::new(), &Http::default()), accounts[0], accounts[1], mail)
}

struct Call<'a> {
    app: &'a Router,
    token: String,
}

impl Call<'_> {
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        let request = match body {
            Some(body) => request.header("content-type", "application/json").body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        };
        self.answer(request.unwrap()).await
    }

    async fn answer(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
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

async fn login<'a>(app: &'a Router, address: &str) -> Call<'a> {
    let request = Request::post("/v1/sessions")
        .header("host", HOST)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "address": address, "password": PASSWORD }).to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let session: Value = serde_json::from_slice(&bytes).unwrap();
    Call { app, token: session["token"].as_str().unwrap().to_owned() }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn files_are_counted_administered_and_written(pool: PgPool) {
    let (app, _alice_id, bob_id) = setup(&pool).await;
    let alice = login(&app, "alice@firma.de").await;
    let bob = login(&app, "bob@firma.de").await;

    // Bob makes a file through JMAP: an upload, then a node that takes it.
    let upload = Request::post(format!("/jmap/upload/{bob_id}/"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", bob.token))
        .header("content-type", "text/plain")
        .body(Body::from("hello"))
        .unwrap();
    let (status, uploaded) = bob.answer(upload).await;
    assert_eq!(status, StatusCode::CREATED);
    let request = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:filenode"],
        "methodCalls": [["FileNode/set", { "accountId": bob_id.to_string(), "create": { "f": {
            "@type": "File", "parentId": null, "name": "hello.txt", "blobId": uploaded["blobId"],
        } } }, "c"]],
    });
    let (status, answer) = bob.send("POST", "/jmap/api", Some(request)).await;
    assert_eq!(status, StatusCode::OK);
    let node = answer["methodResponses"][0][1]["created"]["f"]["id"].as_str().unwrap().to_owned();

    // A direct write replaces its content.
    let write = |token: &str, body: &'static str| {
        Request::put(format!("/jmap/files/{bob_id}/{node}"))
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from(body))
            .unwrap()
    };
    let (status, written) = bob.answer(write(&bob.token, "hello, world")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!((written["size"].as_u64(), written["mediaType"].as_str()), (Some(12), Some("text/plain")));
    // Not Alice's to write, administrator or not.
    assert_eq!(alice.answer(write(&alice.token, "mine")).await.0, StatusCode::NOT_FOUND);

    // Quotas: the tenant's default, then the account's own; Bob may not.
    assert_eq!(bob.status("PUT", "/v1/tenant/files-quota", Some(json!({ "bytes": 100 }))).await, 403);
    assert_eq!(alice.status("PUT", "/v1/tenant/files-quota", Some(json!({ "bytes": 1_000_000 }))).await, 204);
    assert_eq!(alice.send("GET", "/v1/tenant/files-quota", None).await.1["bytes"], 1_000_000);
    let (_, overview) = alice.send("GET", &format!("/v1/accounts/{bob_id}/files"), None).await;
    // The first content is kept as a version and counts as well.
    assert_eq!(
        (overview["used_bytes"].as_u64(), overview["quota"].as_u64(), overview["effective_quota"].as_u64()),
        (Some(17), None, Some(1_000_000))
    );
    let quota = Some(json!({ "bytes": 20 }));
    assert_eq!(alice.status("PUT", &format!("/v1/accounts/{bob_id}/files/quota"), quota).await, 204);
    let (status, _) = bob.answer(write(&bob.token, "more than twenty bytes, surely")).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);

    // The same through GraphQL.
    let answer = alice.graphql(&format!("{{ accountFiles(account: \"{bob_id}\") {{ usedBytes quota }} }}")).await;
    assert_eq!(answer["data"]["accountFiles"], json!({ "usedBytes": 17, "quota": 20 }));
    let answer = alice.graphql("mutation { setTenantFilesQuota(bytes: null) }").await;
    assert_eq!(answer["data"]["setTenantFilesQuota"], true);
    assert_eq!(alice.graphql("{ tenantFilesQuota }").await["data"]["tenantFilesQuota"], Value::Null);
    let answer = bob.graphql(&format!("mutation {{ setFilesQuota(account: \"{bob_id}\", bytes: null) }}")).await;
    assert_eq!(answer["errors"][0]["extensions"]["code"], "FORBIDDEN");
}

/// A request with HTTP Basic, as file managers send them.
fn dav(method: &str, path: &str, user: &str, headers: &[(&str, &str)], body: impl Into<Body>) -> Request<Body> {
    use base64::Engine;
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{PASSWORD}"));
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Basic {credentials}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(body.into()).unwrap()
}

async fn text(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMapCopy, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&bytes).into_owned())
}

type HeaderMapCopy = axum::http::HeaderMap;

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn drives_are_administered_and_reached_over_webdav(pool: PgPool) {
    let (app, alice_id, bob_id) = setup(&pool).await;
    let alice = login(&app, "alice@firma.de").await;

    // Alice, an administrator, makes a drive and gives Bob and herself every right on it.
    let (status, created) = alice.send("POST", "/v1/drives", Some(json!({ "name": "falkOSS" }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let drive = created["id"].as_str().unwrap().to_owned();
    assert_eq!(alice.send("GET", "/v1/drives", None).await.1[0]["name"], "falkOSS");
    for member in [alice_id, bob_id] {
        let grant = json!({ "grantee_kind": "account", "grantee_id": member.to_string(), "rights": "randws" });
        assert_eq!(alice.status("PUT", &format!("/v1/accounts/{drive}/files/access"), Some(grant)).await, 204);
    }
    assert_eq!(
        alice.send("GET", &format!("/v1/accounts/{drive}/files/access"), None).await.1.as_array().unwrap().len(),
        2
    );

    // Bob's file manager: the top lists his own store and the drive.
    let (status, _, body) = text(&app, dav("PROPFIND", "/webdav/", "bob@firma.de", &[("depth", "1")], "")).await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(body.contains("/webdav/bob@firma.de/") && body.contains("/webdav/falkOSS/"), "{body}");
    assert_eq!(text(&app, dav("OPTIONS", "/webdav/", "bob@firma.de", &[], "")).await.1["dav"], "1, 2");

    // A folder and a file, written and read back, also in part.
    assert_eq!(text(&app, dav("MKCOL", "/webdav/falkOSS/Board", "bob@firma.de", &[], "")).await.0, StatusCode::CREATED);
    let put = dav(
        "PUT",
        "/webdav/falkOSS/Board/minutes.txt",
        "bob@firma.de",
        &[("content-type", "text/plain")],
        "hello, board",
    );
    assert_eq!(text(&app, put).await.0, StatusCode::CREATED);
    let (status, headers, body) =
        text(&app, dav("GET", "/webdav/falkOSS/Board/minutes.txt", "alice@firma.de", &[], "")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello, board"));
    assert_eq!(headers[header::CONTENT_TYPE], "text/plain");
    // Content is never run as a page of the instance's origin.
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().starts_with("sandbox;"));
    let range = dav("GET", "/webdav/falkOSS/Board/minutes.txt", "alice@firma.de", &[("range", "bytes=7-")], "");
    let (status, headers, body) = text(&app, range).await;
    assert_eq!((status, body.as_str()), (StatusCode::PARTIAL_CONTENT, "board"));
    assert_eq!(headers[header::CONTENT_RANGE], "bytes 7-11/12");
    let (_, _, listing) =
        text(&app, dav("PROPFIND", "/webdav/falkOSS/Board/", "alice@firma.de", &[("depth", "1")], "")).await;
    assert!(
        listing.contains("minutes.txt") && listing.contains("<D:getcontentlength>12</D:getcontentlength>"),
        "{listing}"
    );

    // Locks keep the other member out until they go.
    let lockinfo = r#"<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#;
    let (status, headers, body) = text(
        &app,
        dav("LOCK", "/webdav/falkOSS/Board/minutes.txt", "bob@firma.de", &[("timeout", "Second-60")], lockinfo),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = headers["lock-token"].to_str().unwrap().to_owned();
    let blocked = dav("PUT", "/webdav/falkOSS/Board/minutes.txt", "alice@firma.de", &[], "mine");
    assert_eq!(text(&app, blocked).await.0, StatusCode::LOCKED);
    let condition = format!("({token})");
    let allowed = dav("PUT", "/webdav/falkOSS/Board/minutes.txt", "bob@firma.de", &[("if", &condition)], "v2");
    assert_eq!(text(&app, allowed).await.0, StatusCode::NO_CONTENT);
    let unlock = dav("UNLOCK", "/webdav/falkOSS/Board/minutes.txt", "bob@firma.de", &[("lock-token", &token)], "");
    assert_eq!(text(&app, unlock).await.0, StatusCode::NO_CONTENT);

    // Moving, copying, deleting.
    let destination = format!("http://{HOST}/webdav/falkOSS/minutes.txt");
    let moved =
        dav("MOVE", "/webdav/falkOSS/Board/minutes.txt", "alice@firma.de", &[("destination", &destination)], "");
    assert_eq!(text(&app, moved).await.0, StatusCode::CREATED);
    let copy = format!("http://{HOST}/webdav/falkOSS/Board/copy.txt");
    let copied = dav("COPY", "/webdav/falkOSS/minutes.txt", "alice@firma.de", &[("destination", &copy)], "");
    assert_eq!(text(&app, copied).await.0, StatusCode::CREATED);
    let (_, _, body) = text(&app, dav("GET", "/webdav/falkOSS/Board/copy.txt", "bob@firma.de", &[], "")).await;
    assert_eq!(body, "v2");
    assert_eq!(
        text(&app, dav("DELETE", "/webdav/falkOSS/Board/", "bob@firma.de", &[], "")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        text(&app, dav("GET", "/webdav/falkOSS/Board/copy.txt", "bob@firma.de", &[], "")).await.0,
        StatusCode::NOT_FOUND
    );

    // Between stores: Bob copies a file of his own into the drive, and moves it back under another name.
    let put = dav("PUT", "/webdav/bob@firma.de/mine.txt", "bob@firma.de", &[("content-type", "text/plain")], "mine");
    assert_eq!(text(&app, put).await.0, StatusCode::CREATED);
    let into_drive = format!("http://{HOST}/webdav/falkOSS/mine.txt");
    let copied = dav("COPY", "/webdav/bob@firma.de/mine.txt", "bob@firma.de", &[("destination", &into_drive)], "");
    assert_eq!(text(&app, copied).await.0, StatusCode::CREATED);
    assert_eq!(text(&app, dav("GET", "/webdav/falkOSS/mine.txt", "alice@firma.de", &[], "")).await.2, "mine");
    let back = format!("http://{HOST}/webdav/bob@firma.de/back.txt");
    let moved = dav("MOVE", "/webdav/falkOSS/mine.txt", "bob@firma.de", &[("destination", &back)], "");
    assert_eq!(text(&app, moved).await.0, StatusCode::CREATED);
    assert_eq!(
        text(&app, dav("GET", "/webdav/falkOSS/mine.txt", "bob@firma.de", &[], "")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(text(&app, dav("GET", "/webdav/bob@firma.de/back.txt", "bob@firma.de", &[], "")).await.2, "mine");
    // Alice does not reach Bob's store: she cannot put anything there.
    let to_bob = format!("http://{HOST}/webdav/bob@firma.de/hers.txt");
    let refused = dav("COPY", "/webdav/falkOSS/minutes.txt", "alice@firma.de", &[("destination", &to_bob)], "");
    assert_eq!(text(&app, refused).await.0, StatusCode::BAD_GATEWAY);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn links_open_files_to_anyone_who_has_them(pool: PgPool) {
    let (app, _alice_id, bob_id) = setup(&pool).await;
    let bob = login(&app, "bob@firma.de").await;
    let anyone = Call { app: &app, token: String::new() };
    let using =
        json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:filenode", "https://kernoid.dev/jmap/file-links"]);
    let jmap = |calls: Value| json!({ "using": using, "methodCalls": calls });

    // Bob has a directory with a file, and a file beside it.
    let mut blobs = Vec::new();
    for text in ["shared text", "secret text"] {
        let upload = Request::post(format!("/jmap/upload/{bob_id}/"))
            .header("host", HOST)
            .header(header::AUTHORIZATION, format!("Bearer {}", bob.token))
            .header("content-type", "text/plain")
            .body(Body::from(text))
            .unwrap();
        blobs.push(bob.answer(upload).await.1["blobId"].clone());
    }
    let account = bob_id.to_string();
    let (_, answer) = bob
        .send(
            "POST",
            "/jmap/api",
            Some(jmap(json!([["FileNode/set", { "accountId": account, "create": {
            "d": { "@type": "Directory", "parentId": null, "name": "Shared" },
            "a": { "@type": "File", "parentId": "#d", "name": "a täxt.txt", "blobId": blobs[0] },
            "s": { "@type": "File", "parentId": null, "name": "secret.txt", "blobId": blobs[1] },
        } }, "c"]]))),
        )
        .await;
    let created = &answer["methodResponses"][0][1]["created"];
    let (directory, file, secret) =
        (created["d"]["id"].clone(), created["a"]["id"].clone(), created["s"]["id"].clone());

    // Two links to the directory: one open, one with a password.
    let (_, answer) = bob
        .send(
            "POST",
            "/jmap/api",
            Some(jmap(json!([["FileLink/set", { "accountId": account, "create": {
            "open": { "nodeId": directory },
            "locked": { "nodeId": directory, "password": "a long link password", "expires": "2099-01-01T00:00:00Z" },
            "past": { "nodeId": directory, "expires": "2001-01-01T00:00:00Z" },
        } }, "c"]]))),
        )
        .await;
    let set = &answer["methodResponses"][0][1];
    assert_eq!(set["notCreated"]["past"]["type"], "invalidProperties", "{set}");
    let open = set["created"]["open"]["token"].as_str().unwrap().to_owned();
    let locked = set["created"]["locked"]["token"].as_str().unwrap().to_owned();
    let open_id = set["created"]["open"]["id"].clone();

    // Anyone with the open link sees the directory, lists it, downloads what is in it – nothing else.
    let (status, link) = anyone.send("GET", &format!("/v1/links/{open}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link["node"]["name"], "Shared");
    let (_, listed) = anyone.send("GET", &format!("/v1/links/{open}/nodes"), None).await;
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(listed[0]["name"], "a täxt.txt");
    let download = |token: &str, node: &Value, access: &str| {
        Request::get(format!("/v1/links/{token}/download/{}?access={access}", node.as_str().unwrap()))
            .header("host", HOST)
            .body(Body::empty())
            .unwrap()
    };
    let (status, headers, body) = text(&app, download(&open, &file, "")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "shared text"));
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned();
    assert!(header("content-disposition").contains("filename*=UTF-8''a%20t%C3%A4xt.txt"), "{headers:?}");
    assert_eq!(header("x-content-type-options"), "nosniff");
    assert_eq!(text(&app, download(&open, &secret, "")).await.0, StatusCode::NOT_FOUND);
    let outside = format!("/v1/links/{open}/nodes?parent={}", secret.as_str().unwrap());
    assert_eq!(anyone.status("GET", &outside, None).await, 404);
    assert_eq!(anyone.status("GET", "/v1/links/not-a-token", None).await, 404);

    // The other needs its password; a wrong one is refused.
    let (status, needs) = anyone.send("GET", &format!("/v1/links/{locked}"), None).await;
    assert_eq!((status, needs["passwordRequired"].clone()), (StatusCode::UNAUTHORIZED, json!(true)));
    let unlock = |password: &str| json!({ "password": password });
    assert_eq!(anyone.status("POST", &format!("/v1/links/{locked}/unlock"), Some(unlock("wrong"))).await, 401);
    let (status, unlocked) =
        anyone.send("POST", &format!("/v1/links/{locked}/unlock"), Some(unlock("a long link password"))).await;
    assert_eq!(status, StatusCode::OK);
    let access = unlocked["access"].as_str().unwrap();
    assert_eq!(anyone.status("GET", &format!("/v1/links/{locked}?access={access}"), None).await, 200);
    assert_eq!(text(&app, download(&locked, &file, access)).await.2, "shared text");
    // The open link has no password to unlock.
    assert_eq!(anyone.status("POST", &format!("/v1/links/{open}/unlock"), Some(unlock("x"))).await, 404);

    // Bob lists his links – without tokens – and removes one; it stops working.
    let (_, answer) =
        bob.send("POST", "/jmap/api", Some(jmap(json!([["FileLink/get", { "accountId": account }, "g"]])))).await;
    let list = answer["methodResponses"][0][1]["list"].as_array().unwrap().clone();
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|link| link.get("token").is_none()));
    assert!(list.iter().any(|link| link["hasPassword"] == json!(true) && link["expires"] == "2099-01-01T00:00:00Z"));
    let (_, answer) = bob
        .send(
            "POST",
            "/jmap/api",
            Some(jmap(json!([["FileLink/set", { "accountId": account, "destroy": [open_id] }, "d"]]))),
        )
        .await;
    assert_eq!(answer["methodResponses"][0][1]["destroyed"].as_array().unwrap().len(), 1);
    assert_eq!(anyone.status("GET", &format!("/v1/links/{open}"), None).await, 404);

    // Alice may not make links to Bob's files: she reaches none of them.
    let alice = login(&app, "alice@firma.de").await;
    let (_, answer) = alice
        .send(
            "POST",
            "/jmap/api",
            Some(jmap(json!([["FileLink/set", { "accountId": account, "create": {
            "x": { "nodeId": directory },
        } }, "c"]]))),
        )
        .await;
    assert_eq!(answer["methodResponses"][0][0], "error", "{answer}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn links_let_people_add_files(pool: PgPool) {
    let (app, _alice_id, bob_id, mail) = setup_with_mail(&pool).await;
    let bob = login(&app, "bob@firma.de").await;
    let anyone = Call { app: &app, token: String::new() };
    let using =
        json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:filenode", "https://kernoid.dev/jmap/file-links"]);
    let jmap = |calls: Value| json!({ "using": using, "methodCalls": calls });
    let account = bob_id.to_string();
    let upload = Request::post(format!("/jmap/upload/{bob_id}/"))
        .header("host", HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", bob.token))
        .body(Body::from("bob's"))
        .unwrap();
    let blob = bob.answer(upload).await.1["blobId"].clone();
    let (_, answer) = bob
        .send(
            "POST",
            "/jmap/api",
            Some(jmap(json!([["FileNode/set", { "accountId": account, "create": {
            "d": { "@type": "Directory", "parentId": null, "name": "Submissions" },
            "f": { "@type": "File", "parentId": "#d", "name": "rules.txt", "blobId": blob },
        } }, "c"]]))),
        )
        .await;
    let created = &answer["methodResponses"][0][1]["created"];
    let (directory, file) = (created["d"]["id"].clone(), created["f"]["id"].clone());

    // A drop box (adds, does not read), a link that does both, one that reads; adding is for directories, and a link
    // does something.
    let (_, answer) = bob
        .send(
            "POST",
            "/jmap/api",
            Some(jmap(json!([["FileLink/set", { "accountId": account, "create": {
            "drop": { "nodeId": directory, "mayRead": false, "mayAdd": true },
            "both": { "nodeId": directory, "mayAdd": true },
            "read": { "nodeId": directory },
            "file": { "nodeId": file, "mayAdd": true },
            "nothing": { "nodeId": directory, "mayRead": false },
        } }, "c"]]))),
        )
        .await;
    let set = &answer["methodResponses"][0][1];
    assert_eq!(set["notCreated"]["file"]["type"], "invalidProperties", "{set}");
    assert_eq!(set["notCreated"]["nothing"]["type"], "invalidProperties", "{set}");
    let token = |name: &str| set["created"][name]["token"].as_str().unwrap().to_owned();
    let (drop, both, read) = (token("drop"), token("both"), token("read"));

    // The drop box shows its directory's name, not what is in it.
    let (status, link) = anyone.send("GET", &format!("/v1/links/{drop}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (link["node"]["name"].clone(), link["mayRead"].clone(), link["mayAdd"].clone()),
        (json!("Submissions"), json!(false), json!(true))
    );
    assert_eq!(anyone.status("GET", &format!("/v1/links/{drop}/nodes"), None).await, 404);
    let download = format!("/v1/links/{drop}/download/{}", file.as_str().unwrap());
    assert_eq!(anyone.status("GET", &download, None).await, 404);

    // Files go in; a name taken gets a number, nothing is replaced.
    let add = |token: &str, query: &str, content: &'static str| {
        Request::post(format!("/v1/links/{token}/files?{query}"))
            .header("host", HOST)
            .header("content-type", "text/plain")
            .body(Body::from(content))
            .unwrap()
    };
    let (status, added) = anyone.answer(add(&drop, "name=report.txt", "first")).await;
    assert_eq!((status, added["name"].clone()), (StatusCode::CREATED, json!("report.txt")), "{added}");
    let (status, added) = anyone.answer(add(&drop, "name=report.txt", "second")).await;
    assert_eq!((status, added["name"].clone()), (StatusCode::CREATED, json!("report (2).txt")), "{added}");
    let (status, added) = anyone.answer(add(&drop, "name=rules.txt", "not bob's")).await;
    assert_eq!((status, added["name"].clone()), (StatusCode::CREATED, json!("rules (2).txt")), "{added}");
    assert_eq!(anyone.answer(add(&drop, "name=a%2Fb", "x")).await.0, StatusCode::BAD_REQUEST);
    // Not below what it names, not through a link that only reads, not into a file.
    assert_eq!(anyone.answer(add(&read, "name=x.txt", "x")).await.0, StatusCode::FORBIDDEN);
    let into_file = format!("name=x.txt&parent={}", file.as_str().unwrap());
    assert_eq!(anyone.answer(add(&both, &into_file, "x")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(anyone.answer(add(&drop, &into_file, "x")).await.0, StatusCode::NOT_FOUND);

    // The link that reads too shows what came in; Bob's file is as it was.
    let (_, listed) = anyone.send("GET", &format!("/v1/links/{both}/nodes"), None).await;
    let names: Vec<&str> = listed.as_array().unwrap().iter().filter_map(|node| node["name"].as_str()).collect();
    assert_eq!(names, ["report (2).txt", "report.txt", "rules (2).txt", "rules.txt"]);
    let rules = Request::get(format!("/v1/links/{both}/download/{}", file.as_str().unwrap()))
        .header("host", HOST)
        .body(Body::empty())
        .unwrap();
    assert_eq!(text(&app, rules).await.2, "bob's");

    // Bob's links say what they do.
    let (_, answer) =
        bob.send("POST", "/jmap/api", Some(jmap(json!([["FileLink/get", { "accountId": account }, "g"]])))).await;
    let list = answer["methodResponses"][0][1]["list"].as_array().unwrap().clone();
    let mut rights: Vec<(bool, bool)> =
        list.iter().map(|link| (link["mayRead"].as_bool().unwrap(), link["mayAdd"].as_bool().unwrap())).collect();
    rights.sort();
    assert_eq!(rights, [(false, true), (true, false), (true, true)]);

    // The worker tells Bob – who made the links – in one email what came in, once the links are quiet.
    let identity = Identity::new(EventStore::new(pool.clone()));
    let notify = |quiet| {
        let (identity, mail) = (identity.clone(), mail.clone());
        async move { kernoid_server::file_links::notify_arrivals(&identity, &mail, None, quiet).await.unwrap() }
    };
    assert_eq!(notify(std::time::Duration::from_secs(3600)).await, 0, "not quiet long enough");
    assert_eq!(notify(std::time::Duration::ZERO).await, 1);
    assert_eq!(notify(std::time::Duration::ZERO).await, 0, "told once");
    let inbox = mail.mailboxes(bob_id).await.unwrap().into_iter().find(|mailbox| mailbox.name == "Inbox").unwrap();
    let entries = mail.mailbox_entries(bob_id, inbox.id).await.unwrap();
    let ids: Vec<Uuid> = entries.iter().map(|entry| entry.email).collect();
    let emails = mail.emails(bob_id, &ids).await.unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].subject.as_deref(), Some("Files added to \"Submissions\""));
}
