// SPDX-License-Identifier: AGPL-3.0-or-later
//! Protocol 2 of the relay against PostgreSQL (set `DATABASE_URL` as for the other crates): a roster, streams read and
//! written only with their tokens, links sealed into a person's stream, generations, originals, removal at once.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Extensions, HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt;
use kernoid_base::{Bytes, Sha256Hash, SpaceId, to_root};
use kernoid_crypt::{
    Domain,
    pq::HybridKeys,
    stream::{
        Device, LinkBody, Permission, RosterRecord, StreamId, StreamKey, StreamRecord, Token, Writer, found,
        person_key, request_signature, token_hash,
    },
};
use kernoid_log::{Clock, Event};
use kernoid_relay::{BoxFuture, Founder, Founders, READ_HEADER, Relay, WRITE_HEADER, router};
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const D: Domain = Domain::KERNOID;
const TOKEN: &str = "a-valid-session";

#[derive(Debug)]
struct Accounts(Founder);

impl Founders for Accounts {
    fn founder<'a>(&'a self, _: &'a Extensions, headers: &'a HeaderMap) -> BoxFuture<'a, Option<Founder>> {
        let valid = headers.get(kernoid_relay::FOUNDER_HEADER).is_some_and(|value| value == TOKEN);
        Box::pin(async move { valid.then_some(self.0) })
    }
}

async fn setup(pool: &PgPool) -> Router {
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
    let blobs = BlobStore::in_memory(Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap())));
    let relay =
        Relay::new(pool.clone(), blobs, &["kernoid".to_owned()], None, Arc::new(Accounts(Founder { tenant, account })));
    router(relay)
}

#[derive(Default)]
struct Call<'a> {
    keys: Option<&'a HybridKeys>,
    founder: bool,
    read: Option<String>,
    write: Option<String>,
}

async fn send(app: &Router, method: &str, path: &str, call: Call<'_>, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(keys) = call.keys {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        request = request.header("authorization", request_signature(D, keys, method, path, now));
    }
    if call.founder {
        request = request.header(kernoid_relay::FOUNDER_HEADER, TOKEN);
    }
    if let Some(token) = call.read {
        request = request.header(READ_HEADER, token);
    }
    if let Some(token) = call.write {
        request = request.header(WRITE_HEADER, token);
    }
    let response = app.clone().oneshot(request.body(Body::from(body)).unwrap()).await.unwrap();
    let status = response.status();
    (status, response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

fn space() -> SpaceId {
    "0192f1e4-0000-7000-8000-0000000000d2".parse().unwrap()
}

fn path(what: &str) -> String {
    format!("/relay/kernoid/v2/spaces/{}/{what}", space())
}

fn tokens(key: &StreamKey, stream: &StreamId, generation: u32, inbox: bool) -> Vec<u8> {
    let hash = |which| Bytes(token_hash(&key.token(D, which, stream, generation)).0.to_vec());
    serde_json::to_vec(
        &json!({ "generation": generation, "read": hash(Token::Read), "write": hash(Token::Write), "inbox": inbox }),
    )
    .unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn streams_are_read_and_written_with_their_tokens(pool: PgPool) {
    let app = setup(&pool).await;
    let phone = HybridKeys::generate(D);
    let founding = found(D, &space(), &phone, "alice-phone".parse().unwrap(), None, None).unwrap();
    let roster_path = path("roster");
    let body = to_root(&founding.record).unwrap();
    assert_eq!(send(&app, "POST", &roster_path, Call::default(), body.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(&app, "POST", &roster_path, Call { founder: true, ..Call::default() }, body.clone()).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        send(&app, "POST", &roster_path, Call { founder: true, ..Call::default() }, body).await.0,
        StatusCode::CONFLICT
    );
    // Protocol 1 does not see the space.
    let v1 = format!("/relay/kernoid/v1/spaces/{}/envelopes", space());
    assert_eq!(send(&app, "GET", &v1, Call::default(), vec![]).await.0, StatusCode::NOT_FOUND);

    // The space stream: made with its token hashes, written with the write token, read with the read token.
    let stream = &founding.space_stream;
    let key = &founding.space_key;
    let stream_path = path(&format!("streams/{stream}"));
    let me = || Call { keys: Some(&phone), ..Call::default() };
    assert_eq!(
        send(&app, "PUT", &stream_path, Call::default(), tokens(key, stream, 0, false)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(send(&app, "PUT", &stream_path, me(), tokens(key, stream, 0, false)).await.0, StatusCode::CREATED);
    assert_eq!(send(&app, "PUT", &stream_path, me(), tokens(key, stream, 0, false)).await.0, StatusCode::CONFLICT);

    let writer = Writer { domain: D, space: &space(), keys: &phone, at: 0 };
    let mut clock = Clock::new("alice-phone".parse().unwrap());
    let event = Event::new(clock.now(1_800_000_000_000), 1, None, &json!({"kind": "hello"})).unwrap();
    let record = StreamRecord::event(&writer, stream, 0, key, &event);
    let records_path = path(&format!("streams/{stream}/records"));
    let write = key.token_text(D, Token::Write, stream, 0);
    let read = key.token_text(D, Token::Read, stream, 0);
    let with = |read: Option<&str>, write: Option<&str>| Call {
        keys: Some(&phone),
        read: read.map(str::to_owned),
        write: write.map(str::to_owned),
        ..Call::default()
    };
    let body = to_root(&record).unwrap();
    assert_eq!(send(&app, "POST", &records_path, me(), body.clone()).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, "POST", &records_path, with(None, Some(&read)), body.clone()).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, "POST", &records_path, with(None, Some(&write)), body.clone()).await.0, StatusCode::CREATED);
    assert_eq!(send(&app, "POST", &records_path, with(None, Some(&write)), body).await.0, StatusCode::OK);
    let list = format!("{records_path}?after=0");
    assert_eq!(send(&app, "GET", &list, me(), vec![]).await.0, StatusCode::FORBIDDEN);
    let (status, answer) = send(&app, "GET", &list, with(Some(&read), None), vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&answer)["records"][0]["record"]["id"], json!(record.id));

    // A new generation needs the write token of the last one; a reader of generation 0 sees that it came, no more.
    let next = StreamKey::generate();
    let generations = path(&format!("streams/{stream}/generations"));
    assert_eq!(
        send(&app, "POST", &generations, with(None, Some(&read)), tokens(&next, stream, 1, false)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, "POST", &generations, with(None, Some(&write)), tokens(&next, stream, 1, false)).await.0,
        StatusCode::CREATED
    );
    let new_write = next.token_text(D, Token::Write, stream, 1);
    let new_read = next.token_text(D, Token::Read, stream, 1);
    let generation = StreamRecord::generation(&writer, stream, 1, &next, key);
    let event = Event::new(clock.now(1_800_000_000_001), 2, None, &json!({"kind": "later"})).unwrap();
    let later = StreamRecord::event(&writer, stream, 1, &next, &event);
    for record in [&generation, &later] {
        assert_eq!(
            send(&app, "POST", &records_path, with(None, Some(&new_write)), to_root(record).unwrap()).await.0,
            StatusCode::CREATED
        );
    }
    let old = json(&send(&app, "GET", &list, with(Some(&read), None), vec![]).await.1);
    assert_eq!(old["records"].as_array().unwrap().len(), 2, "{old}");
    let new = json(&send(&app, "GET", &list, with(Some(&new_read), None), vec![]).await.1);
    assert_eq!(new["records"].as_array().unwrap().len(), 3);

    // Following several streams at once.
    let follow = serde_json::to_vec(&json!([{ "stream": stream, "after": 1, "read": new_read },
        { "stream": StreamId::generate(), "after": 0, "read": new_read }]))
    .unwrap();
    let answer = json(&send(&app, "POST", &path("follow"), me(), follow).await.1);
    assert_eq!(answer["streams"][stream.as_str()]["records"].as_array().unwrap().len(), 2, "{answer}");

    // Originals by their hash, read with a read token.
    let sealed = next.seal_original(D, stream, &vec![7u8; 100_000]);
    let hash = Sha256Hash::of(&sealed);
    let original = path(&format!("streams/{stream}/originals/{hash}"));
    assert_eq!(
        send(&app, "PUT", &original, with(None, Some(&new_write)), b"other".to_vec()).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(&app, "PUT", &original, with(None, Some(&new_write)), sealed.clone()).await.0, StatusCode::CREATED);
    let (status, bytes) = send(&app, "GET", &original, with(Some(&read), None), vec![]).await;
    assert_eq!((status, bytes == sealed), (StatusCode::OK, true));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_removed_device_gets_nothing_and_sealed_links_need_no_token(pool: PgPool) {
    let app = setup(&pool).await;
    let phone = HybridKeys::generate(D);
    let founding = found(D, &space(), &phone, "alice-phone".parse().unwrap(), None, None).unwrap();
    let mut roster = kernoid_crypt::stream::Roster::new(D, space());
    roster.apply(founding.record.clone()).unwrap();
    let roster_path = path("roster");
    send(&app, "POST", &roster_path, Call { founder: true, ..Call::default() }, to_root(&founding.record).unwrap())
        .await;

    // Alice's laptop joins her person.
    let laptop = HybridKeys::generate(D);
    let laptop_device =
        Device::new(&laptop, founding.person.clone(), "alice-laptop".parse().unwrap(), None).with(&[Permission::Write]);
    let seals = person_key(D, &space(), &founding.person, 0, &founding.person_seed, None, &[&laptop_device]).unwrap();
    let record = roster
        .next(RosterRecord {
            add_devices: vec![laptop_device.clone()],
            person_keys: vec![seals],
            ..RosterRecord::blank(&space())
        })
        .sign(&laptop);
    // The laptop is no device yet: it cannot sign the request.
    let call = |keys| Call { keys: Some(keys), ..Call::default() };
    assert_eq!(
        send(&app, "POST", &roster_path, call(&laptop), to_root(&record).unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let record = roster
        .next(RosterRecord {
            add_devices: vec![laptop_device.clone()],
            person_keys: record.person_keys.clone(),
            ..RosterRecord::blank(&space())
        })
        .sign(&phone);
    assert_eq!(send(&app, "POST", &roster_path, call(&phone), to_root(&record).unwrap()).await.0, StatusCode::CREATED);
    roster.apply(record).unwrap();

    // Alice's person stream is an inbox: the laptop seals a link to her into it without the stream's write token.
    let person_stream = StreamId::generate();
    let stream_key = StreamKey::of_person(D, &founding.person, &founding.person_seed);
    let stream_path = path(&format!("streams/{person_stream}"));
    assert_eq!(
        send(&app, "PUT", &stream_path, call(&phone), tokens(&stream_key, &person_stream, 0, true)).await.0,
        StatusCode::CREATED
    );
    let writer = Writer { domain: D, space: &space(), keys: &laptop, at: 1 };
    let body = LinkBody { stream: StreamId::generate(), generation: 0, key: Bytes(vec![1; 32]) };
    let alice = roster.person_key(&founding.person).unwrap().clone();
    let sealed = StreamRecord::sealed_link(&writer, &person_stream, &alice, &body).unwrap();
    let records_path = path(&format!("streams/{person_stream}/records"));
    assert_eq!(
        send(&app, "POST", &records_path, call(&laptop), to_root(&sealed).unwrap()).await.0,
        StatusCode::CREATED
    );
    // An event needs the token there too.
    let event = StreamRecord::link(&writer, &person_stream, 0, &stream_key, &body);
    assert_eq!(
        send(&app, "POST", &records_path, call(&laptop), to_root(&event).unwrap()).await.0,
        StatusCode::FORBIDDEN
    );

    // The laptop is removed: at once it reads nothing, with any token.
    let new_seed = kernoid_base::random::<32>();
    let phone_device = roster.device(&phone.verifying().id()).unwrap().clone();
    let rotated =
        person_key(D, &space(), &founding.person, 1, &new_seed, Some(&founding.person_seed), &[&phone_device]).unwrap();
    let removal = roster
        .next(RosterRecord {
            remove_devices: vec![laptop_device.id],
            person_keys: vec![rotated],
            ..RosterRecord::blank(&space())
        })
        .sign(&phone);
    assert_eq!(send(&app, "POST", &roster_path, call(&phone), to_root(&removal).unwrap()).await.0, StatusCode::CREATED);
    let read = stream_key.token_text(D, Token::Read, &person_stream, 0);
    let list = format!("{records_path}?after=0");
    let laptop_call = Call { keys: Some(&laptop), read: Some(read.clone()), ..Call::default() };
    assert_eq!(send(&app, "GET", &list, laptop_call, vec![]).await.0, StatusCode::UNAUTHORIZED);
    let phone_call = Call { keys: Some(&phone), read: Some(read), ..Call::default() };
    assert_eq!(send(&app, "GET", &list, phone_call, vec![]).await.0, StatusCode::OK);

    // Purging a stream needs `purge` and its write token.
    let write = stream_key.token_text(D, Token::Write, &person_stream, 0);
    let purge = Call { keys: Some(&phone), write: Some(write), ..Call::default() };
    assert_eq!(send(&app, "DELETE", &stream_path, purge, vec![]).await.0, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, "GET", &list, call(&phone), vec![]).await.0, StatusCode::FORBIDDEN);
}
