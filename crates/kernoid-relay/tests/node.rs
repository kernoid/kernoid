// SPDX-License-Identifier: AGPL-3.0-or-later
//! A server as a node of a space against kernoid's relay, both on PostgreSQL (set `DATABASE_URL` as for the other
//! crates): it founds a space, a second node joins as a person of its own, each reads what the other wrote; the node
//! comes back from the database alone, nothing opens under another key, and no event is stored readable.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap};
use kernoid_base::SpaceId;
use kernoid_crypt::{Domain, stream::StreamId};
use kernoid_relay::node::Node;
use kernoid_relay::{BoxFuture, Founder, Founders, Relay, router};
use kernoid_spaces::streams::Streams;
use kernoid_store::{BlobStore, TenantKeys, crypto::Key};
use serde_json::json;
use sqlx::PgPool;
use tokio::runtime::Handle;
use uuid::Uuid;

const D: Domain = Domain::KERNOID;
const TOKEN: &str = "a-valid-session";
const SERVER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[derive(Debug)]
struct Accounts(Founder);

impl Founders for Accounts {
    fn founder<'a>(&'a self, _: &'a Extensions, headers: &'a HeaderMap) -> BoxFuture<'a, Option<Founder>> {
        let valid = headers.get(kernoid_relay::FOUNDER_HEADER).is_some_and(|value| value == TOKEN);
        Box::pin(async move { valid.then_some(self.0) })
    }
}

/// kernoid's relay on a port of its own, with an account that may found spaces; its URL.
async fn relay(pool: &PgPool) -> String {
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/relay/kernoid", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(relay)).await.unwrap() });
    url
}

fn node(pool: &PgPool, runtime: &Handle, name: &str, key: &str) -> Streams<Node> {
    let node = Node::new(pool.clone(), name, Key::from_hex(key).unwrap(), runtime.clone()).unwrap();
    Streams::open(D, name.parse().unwrap(), node)
}

fn titles(streams: &Streams<Node>, space: &SpaceId, stream: &StreamId) -> Vec<String> {
    let log = streams.log(space, stream).unwrap();
    log.ordered().iter().filter_map(|(_, e)| e.members.get("title")?.as_str().map(str::to_owned)).collect()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_server_is_one_more_node_of_a_space(pool: PgPool) {
    let url = relay(&pool).await;
    let runtime = Handle::current();
    let nodes = pool.clone();
    let (space, stream) = tokio::task::spawn_blocking(move || {
        let mut server = node(&nodes, &runtime, "server", SERVER_KEY);
        let (space, _code) = server.found(&url, Some(TOKEN), Some("Server"), Some("Acme")).unwrap();
        let stream = server.space_stream(&space).unwrap();
        server.write(&space, &stream, &json!({"kind": "note", "title": "Welcome"})).unwrap();

        // A second node – a device, here kept in PostgreSQL too: the server's build has no SQLite.
        let mut laptop = node(&nodes, &runtime, "laptop", OTHER_KEY);
        let invitation = server.invite(&space, true).unwrap();
        laptop.join(&invitation, Some("Laptop"), Some("Ada")).unwrap();
        assert_eq!(server.sync(&space).unwrap().added.len(), 1);
        laptop.sync(&space).unwrap();
        assert_eq!(titles(&laptop, &space, &stream), ["Welcome"]);
        laptop.write(&space, &stream, &json!({"kind": "note", "title": "From Ada"})).unwrap();
        server.sync(&space).unwrap();
        assert_eq!(titles(&server, &space, &stream), ["Welcome", "From Ada"]);
        drop(server);

        // The server again, from the database alone: its seed, keys and events are there.
        let mut again = node(&nodes, &runtime, "server", SERVER_KEY);
        assert_eq!(again.spaces().unwrap(), std::slice::from_ref(&space));
        assert_eq!(titles(&again, &space, &stream), ["Welcome", "From Ada"]);
        again.write(&space, &stream, &json!({"kind": "note", "title": "Later"})).unwrap();
        laptop.sync(&space).unwrap();
        assert_eq!(titles(&laptop, &space, &stream), ["Welcome", "From Ada", "Later"]);

        // Under another key, the node's secrets do not open.
        let wrong = node(&nodes, &runtime, "server", OTHER_KEY);
        assert!(wrong.log(&space, &stream).is_err());
        assert!(wrong.person(&space).is_err());
        (space, stream)
    })
    .await
    .unwrap();

    // Nothing of the events, the keys or the state is stored readable.
    for table in ["node_stream_events", "node_spaces", "node_stream_keys"] {
        let rows: Vec<Vec<u8>> = match table {
            "node_stream_events" => {
                sqlx::query_scalar!("SELECT canonical FROM node_stream_events").fetch_all(&pool).await.unwrap()
            }
            "node_spaces" => sqlx::query_scalar!("SELECT state FROM node_spaces").fetch_all(&pool).await.unwrap(),
            _ => sqlx::query_scalar!("SELECT key FROM node_stream_keys").fetch_all(&pool).await.unwrap(),
        };
        assert!(!rows.is_empty(), "{table}");
        for row in rows {
            for plain in [&b"Welcome"[..], b"From Ada", b"seed", space.as_str().as_bytes(), stream.as_str().as_bytes()]
            {
                assert!(
                    !row.windows(plain.len()).any(|w| w == plain),
                    "{table} holds {:?}",
                    String::from_utf8_lossy(plain)
                );
            }
        }
    }
}
