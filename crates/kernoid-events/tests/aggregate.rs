// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed aggregates against PostgreSQL; set `DATABASE_URL` as for tests/postgres.rs.

use std::sync::atomic::{AtomicUsize, Ordering};

use kernoid_events::{
    AggregateId, Error, EventStore, Expected, NewEvent,
    aggregate::{Aggregate, CommandError, DomainEvent},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
enum CounterEvent {
    #[serde(rename = "counter.added")]
    Added { by: i64 },
    #[serde(rename = "counter.closed")]
    Closed,
}

impl DomainEvent for CounterEvent {
    fn revision(event_type: &str) -> i16 {
        // counter.added changed its payload once: revision 1 had { "amount": n }.
        if event_type == "counter.added" { 2 } else { 1 }
    }

    fn upcast(event_type: &str, revision: i16, payload: Value) -> Result<Value, String> {
        match (event_type, revision) {
            ("counter.added", 1) => Ok(json!({ "by": payload["amount"] })),
            _ => Err(format!("no upcast for {event_type} {revision}")),
        }
    }
}

#[derive(Debug, Default)]
struct Counter {
    total: i64,
    closed: bool,
}

impl Aggregate for Counter {
    const TYPE: &'static str = "counter";
    type Event = CounterEvent;

    fn apply(&mut self, event: CounterEvent) {
        match event {
            CounterEvent::Added { by } => self.total += by,
            CounterEvent::Closed => self.closed = true,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Refusal {
    Closed,
}

fn add(by: i64) -> impl Fn(&Counter) -> Result<Vec<CounterEvent>, Refusal> {
    move |counter| if counter.closed { Err(Refusal::Closed) } else { Ok(vec![CounterEvent::Added { by }]) }
}

const INSTANCE: Uuid = Uuid::from_u128(1);
const OWNER: Uuid = Uuid::from_u128(100);

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn commands_fold_and_refuse(pool: PgPool) {
    let store = EventStore::new(pool);
    store.execute(INSTANCE, OWNER, "c1", "test", add(2)).await.unwrap();
    store.execute(INSTANCE, OWNER, "c1", "test", add(3)).await.unwrap();
    store
        .execute(INSTANCE, OWNER, "c1", "test", |_: &Counter| Ok::<_, Refusal>(vec![CounterEvent::Closed]))
        .await
        .unwrap();

    let loaded = store.load::<Counter>(INSTANCE, "c1").await.unwrap();
    assert_eq!((loaded.state.total, loaded.state.closed, loaded.sequence), (5, true, 3));
    assert!(matches!(
        store.execute(INSTANCE, OWNER, "c1", "test", add(1)).await,
        Err(CommandError::Refused(Refusal::Closed))
    ));
    assert_eq!(store.load::<Counter>(INSTANCE, "c1").await.unwrap().sequence, 3);

    // Stored as event type and bare payload, with the current revision; unit variants have a null payload.
    let stored = store.events(&AggregateId::new(INSTANCE, "counter", "c1")).await.unwrap();
    assert_eq!((stored[0].event_type.as_str(), stored[0].revision), ("counter.added", 2));
    assert_eq!(stored[0].payload, json!({ "by": 2 }));
    assert_eq!((stored[2].event_type.as_str(), &stored[2].payload), ("counter.closed", &Value::Null));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn old_revisions_are_upcast_and_newer_ones_refused(pool: PgPool) {
    let store = EventStore::new(pool);
    let id = AggregateId::new(INSTANCE, "counter", "c1");
    let old = NewEvent {
        event_type: "counter.added".into(),
        revision: 1,
        payload: json!({ "amount": 7 }),
        creator: "t".into(),
    };
    store.append(&id, OWNER, Expected::New, &[old]).await.unwrap();
    assert_eq!(store.load::<Counter>(INSTANCE, "c1").await.unwrap().state.total, 7);

    let future = NewEvent { event_type: "counter.added".into(), revision: 3, payload: json!({}), creator: "t".into() };
    store.append(&id, OWNER, Expected::Any, &[future]).await.unwrap();
    assert!(matches!(store.load::<Counter>(INSTANCE, "c1").await, Err(Error::Decode { revision: 3, .. })));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn concurrent_commands_are_decided_again(pool: PgPool) {
    let store = EventStore::new(pool);
    let commands = (0..3).map(|_| {
        let store = store.clone();
        tokio::spawn(async move { store.execute(INSTANCE, OWNER, "c1", "test", add(1)).await })
    });
    let mut done = 0;
    for command in commands {
        // With three attempts each, three concurrent writers all get through.
        if command.await.unwrap().is_ok() {
            done += 1;
        }
    }
    let loaded = store.load::<Counter>(INSTANCE, "c1").await.unwrap();
    assert_eq!(loaded.state.total, done);
    assert_eq!(loaded.sequence, done);
    assert!(done >= 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn inline_projections_commit_or_roll_back_with_the_events(pool: PgPool) {
    let store = EventStore::new(pool.clone());
    let calls = AtomicUsize::new(0);
    let refuse = kernoid_events::inline(|_, events| {
        calls.fetch_add(events.len(), Ordering::SeqCst);
        Box::pin(async { Err(Error::Encode("inline projection failed".into())) })
    });
    assert!(store.execute_with(INSTANCE, OWNER, "c1", "test", add(1), refuse).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!store.load::<Counter>(INSTANCE, "c1").await.unwrap().exists());

    // A successful inline projection sees the stored events, with their sequences.
    let seen = std::sync::Mutex::new(Vec::new());
    let record = kernoid_events::inline(|_, events| {
        seen.lock().unwrap().extend(events.iter().map(|event| event.sequence));
        Box::pin(async { Ok(()) })
    });
    store.execute_with(INSTANCE, OWNER, "c1", "test", add(1), record).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), [1]);
}
