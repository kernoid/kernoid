// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay against PostgreSQL (set `DATABASE_URL` as for the other crates): members sync envelopes through it,
//! strangers are refused, spaces are founded only by accounts – or by anyone on an open relay –, each program's spaces
//! stay apart, large envelopes go to object storage, and a tenant's spaces can be removed. The cases of aktujo's relay
//! (aktujo 0.4.1), taken over with it.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Extensions, HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt;
use kernoid_base::{SpaceId, from_root, to_root};
use kernoid_crypt::{
    Domain, Envelope, EnvelopeContent, Invitation, JoinRequest, Member, MemberKeys, MemberList, MemberRecord, Rights,
    SpaceKey, request_signature,
};
use kernoid_log::{Clock, Event};
use kernoid_relay::{BoxFuture, Founder, Founders, Relay, router};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const D: Domain = Domain::KERNOID;
/// The token the test's accounts found spaces with.
const TOKEN: &str = "a-valid-session";

/// Accounts: the token `TOKEN` is the account given.
#[derive(Debug)]
struct Accounts(Founder);

impl Founders for Accounts {
    fn founder<'a>(&'a self, _: &'a Extensions, headers: &'a HeaderMap) -> BoxFuture<'a, Option<Founder>> {
        let valid = headers.get(kernoid_relay::FOUNDER_HEADER).is_some_and(|value| value == TOKEN);
        Box::pin(async move { valid.then_some(self.0) })
    }
}

struct Setup {
    app: Router,
    relay: Relay,
    founder: Founder,
}

/// A tenant with an account, and the relay for kernoid's and aktujo's spaces.
async fn setup(pool: &PgPool, open: bool) -> Setup {
    let (instance, tenant, account) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    sqlx::query!("INSERT INTO instances (id, name) VALUES ($1, 'Test')", instance).execute(pool).await.unwrap();
    sqlx::query!("INSERT INTO tenants (id, instance_id, name) VALUES ($1, $2, 'Firma')", tenant, instance)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query!(
        "INSERT INTO accounts (id, tenant_id, display_name, primary_address) VALUES ($1, $2, 'Ada', 'ada@firma.test')",
        account,
        tenant
    )
    .execute(pool)
    .await
    .unwrap();
    let founder = Founder { tenant, account };
    let blobs = BlobStore::in_memory(Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap())));
    let relay = Relay::new(
        pool.clone(),
        blobs,
        &["kernoid".to_owned(), "aktujo".to_owned()],
        open.then_some(tenant),
        Arc::new(Accounts(founder)),
    );
    Setup { app: router(relay.clone()), relay, founder }
}

impl Setup {
    async fn send(
        &self,
        method: &str,
        path: &str,
        keys: Option<&MemberKeys>,
        founder: bool,
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(keys) = keys {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            request = request.header("authorization", request_signature(keys, method, path, now));
        }
        if founder {
            request = request.header(kernoid_relay::FOUNDER_HEADER, TOKEN);
        }
        let response = self.app.clone().oneshot(request.body(Body::from(body)).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }
}

fn space() -> SpaceId {
    "0192f1e4-0000-7000-8000-0000000000c1".parse().unwrap()
}

fn device(keys: &MemberKeys, name: &str) -> Member {
    Member::device(keys, name.parse().unwrap(), None, Rights::Manage)
}

fn founded(laptop: &MemberKeys) -> (MemberRecord, SpaceKey) {
    MemberRecord::found(&space(), laptop, vec![device(laptop, "laptop")])
}

fn path(scheme: &str, what: &str) -> String {
    format!("/relay/{scheme}/v1/spaces/{}/{what}", space())
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn members_sync_envelopes_through_the_relay(pool: PgPool) {
    let relay = setup(&pool, false).await;
    let (laptop, phone) = (MemberKeys::generate(D), MemberKeys::generate(D));
    let (members, envelopes) = (path("kernoid", "members"), path("kernoid", "envelopes"));

    // A space not founded yet has no records; founding it needs an account here.
    let (status, records) = relay.send("GET", &format!("{members}?after=-1"), None, false, vec![]).await;
    assert_eq!((status, records), (StatusCode::OK, Value::Array(vec![])));
    let (first, key) = founded(&laptop);
    assert_eq!(relay.send("POST", &members, None, false, to_root(&first).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(relay.send("POST", &members, None, true, to_root(&first).unwrap()).await.0, StatusCode::CREATED);
    assert_eq!(relay.send("POST", &members, None, true, to_root(&first).unwrap()).await.0, StatusCode::CONFLICT);

    let mut list = MemberList::new(D, space());
    list.apply(first.clone()).unwrap();
    let second = list.add(&laptop, &key, vec![device(&phone, "phone")]);
    let body = to_root(&second).unwrap();
    assert_eq!(relay.send("POST", &members, None, false, body.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(relay.send("POST", &members, Some(&laptop), false, body).await.0, StatusCode::CREATED);
    assert_eq!(
        relay.send("POST", &members, Some(&laptop), false, to_root(&first).unwrap()).await.0,
        StatusCode::CONFLICT
    );

    let mut clock = Clock::new("laptop".parse().unwrap());
    let event = Event::new(clock.now(1), 1, None, &serde_json::json!({"kind": "space_founded"})).unwrap();
    let envelope = Envelope::seal_event(&space(), 0, &key, &laptop, &event);
    let body = to_root(&envelope).unwrap();
    assert_eq!(relay.send("POST", &envelopes, Some(&laptop), false, body.clone()).await.0, StatusCode::CREATED);
    assert_eq!(relay.send("POST", &envelopes, Some(&laptop), false, body).await.0, StatusCode::OK);

    // The phone reads the member list (open), its keys, and the envelope.
    let (status, records) = relay.send("GET", &format!("{members}?after=-1"), None, false, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let records: Vec<MemberRecord> =
        records.as_array().unwrap().iter().map(|r| from_root(r.to_string().as_bytes()).unwrap()).collect();
    let list = MemberList::from_records(D, space(), &records).unwrap();
    let keys = list.keys(&phone).unwrap();
    let (status, page) = relay.send("GET", &format!("{envelopes}?after=0"), Some(&phone), false, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["more"], false);
    let received: Envelope = from_root(page["envelopes"][0]["envelope"].to_string().as_bytes()).unwrap();
    assert_eq!(Event::read(&received.open_event(&keys, &list).unwrap()).unwrap(), event);

    // The space is the founder's tenant's.
    let spaces = relay.relay.spaces(relay.founder.tenant).await.unwrap();
    assert_eq!(spaces.len(), 1);
    assert_eq!((spaces[0].domain.as_str(), spaces[0].founder), ("kernoid", Some(relay.founder.account)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn strangers_and_other_programs_are_refused(pool: PgPool) {
    let relay = setup(&pool, true).await;
    let (laptop, stranger) = (MemberKeys::generate(D), MemberKeys::generate(D));
    let (first, key) = founded(&laptop);
    // An open relay: founding needs no account.
    assert_eq!(
        relay.send("POST", &path("kernoid", "members"), None, false, to_root(&first).unwrap()).await.0,
        StatusCode::CREATED
    );
    let envelopes = path("kernoid", "envelopes");
    let (status, _) = relay.send("GET", &format!("{envelopes}?after=0"), Some(&stranger), false, vec![]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let forged = Envelope::seal(&space(), 0, &key, &stranger, EnvelopeContent::Original, b"x");
    let (status, _) = relay.send("POST", &envelopes, Some(&stranger), false, to_root(&forged).unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = relay.send("GET", "/relay/kernoid/v1/spaces/not-a-space/members", None, false, vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The space is kernoid's: under aktujo's domain it is not there, and a domain not allowed is unknown.
    let (status, _) =
        relay.send("GET", &format!("{}?after=0", path("aktujo", "envelopes")), Some(&laptop), false, vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = relay.send("GET", &format!("{}?after=-1", path("spezado", "members")), None, false, vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn requests_to_join_wait_for_a_manager(pool: PgPool) {
    let relay = setup(&pool, false).await;
    let (laptop, phone) = (MemberKeys::generate(D), MemberKeys::generate(D));
    let requests = path("kernoid", "requests");
    let invitation = Invitation::new("https://relay.example/relay/kernoid", space());
    let request = to_root(&invitation.request(device(&phone, "phone"))).unwrap();
    assert_eq!(relay.send("POST", &requests, None, false, request.clone()).await.0, StatusCode::NOT_FOUND);
    let (first, _) = founded(&laptop);
    relay.send("POST", &path("kernoid", "members"), None, true, to_root(&first).unwrap()).await;
    assert_eq!(relay.send("POST", &requests, None, false, request).await.0, StatusCode::CREATED);
    assert_eq!(relay.send("GET", &requests, Some(&phone), false, vec![]).await.0, StatusCode::FORBIDDEN);
    let (status, waiting) = relay.send("GET", &requests, Some(&laptop), false, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let waiting: JoinRequest = from_root(waiting[0].to_string().as_bytes()).unwrap();
    assert!(invitation.proves(&waiting));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn large_envelopes_go_to_object_storage_and_leave_with_their_space(pool: PgPool) {
    let relay = setup(&pool, false).await;
    let laptop = MemberKeys::generate(D);
    let (first, key) = founded(&laptop);
    relay.send("POST", &path("kernoid", "members"), None, true, to_root(&first).unwrap()).await;
    let original = vec![7u8; 200 * 1024];
    let envelope = Envelope::seal(&space(), 0, &key, &laptop, EnvelopeContent::Original, &original);
    let envelopes = path("kernoid", "envelopes");
    assert_eq!(
        relay.send("POST", &envelopes, Some(&laptop), false, to_root(&envelope).unwrap()).await.0,
        StatusCode::CREATED
    );
    let stored =
        sqlx::query!("SELECT canonical IS NULL AS outside, blob FROM relay_envelopes").fetch_one(&pool).await.unwrap();
    assert_eq!(stored.outside, Some(true));
    let pending = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM blob_garbage"#).fetch_one(&pool).await.unwrap();
    assert_eq!(pending, 0, "the object is kept once its row committed");
    let (status, page) = relay.send("GET", &format!("{envelopes}?after=0"), Some(&laptop), false, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let received: Envelope = from_root(page["envelopes"][0]["envelope"].to_string().as_bytes()).unwrap();
    assert_eq!(received, envelope);
    assert!(relay.relay.spaces(relay.founder.tenant).await.unwrap()[0].bytes > 200 * 1024);

    // A quota the tenant's spaces exceed refuses what comes next.
    sqlx::query!("UPDATE tenants SET relay_quota = 1000 WHERE id = $1", relay.founder.tenant)
        .execute(&pool)
        .await
        .unwrap();
    let more = Envelope::seal(&space(), 0, &key, &laptop, EnvelopeContent::Original, b"one more");
    let (status, _) = relay.send("POST", &envelopes, Some(&laptop), false, to_root(&more).unwrap()).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(relay.relay.used(relay.founder.tenant).await.unwrap() > 200 * 1024);

    // Removed by its tenant – not by another –, its object becomes garbage.
    assert!(!relay.relay.remove_space(Uuid::now_v7(), space().as_str()).await.unwrap());
    assert!(relay.relay.remove_space(relay.founder.tenant, space().as_str()).await.unwrap());
    let garbage = sqlx::query_scalar!(r#"SELECT key AS "key!" FROM blob_garbage"#).fetch_all(&pool).await.unwrap();
    assert_eq!(garbage, [stored.blob.unwrap()]);
    let (status, _) = relay.send("GET", &format!("{envelopes}?after=0"), Some(&laptop), false, vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
