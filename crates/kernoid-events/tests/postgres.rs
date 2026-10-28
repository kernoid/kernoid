// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runs against PostgreSQL: set `DATABASE_URL` to a database user that may create databases (each test gets its own).

use std::time::{Duration, Instant};

use kernoid_events::{AggregateId, Cursor, Error, Event, EventStore, Expected, NewEvent};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn added(name: &str) -> NewEvent {
    NewEvent {
        event_type: "account.added".into(),
        revision: 1,
        payload: json!({ "name": name }),
        creator: "system".into(),
    }
}

/// The tenant owning every test aggregate.
const OWNER: Uuid = Uuid::from_u128(100);

fn account(instance: u128, id: &str) -> AggregateId {
    AggregateId::new(Uuid::from_u128(instance), "account", id)
}

/// Reads all events after `after` until `count` have arrived. Running transactions anywhere in the PostgreSQL cluster
/// – such as other tests – hold events back for a moment, so this waits up to ten seconds.
async fn read_until(store: &EventStore, mut after: Cursor, page: i64, count: usize) -> Vec<Event> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    while events.len() < count {
        assert!(Instant::now() < deadline, "only {} of {count} events arrived", events.len());
        let batch = store.read_all(after, page).await.unwrap();
        match batch.last() {
            Some(last) => after = last.cursor,
            None => tokio::time::sleep(Duration::from_millis(20)).await,
        }
        events.extend(batch);
    }
    events
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn append_and_load(pool: PgPool) {
    let store = EventStore::new(pool);
    let alice = account(1, "alice");
    assert_eq!(store.append(&alice, OWNER, Expected::New, &[added("Alice"), added("Alice B.")]).await.unwrap(), 2);
    assert_eq!(store.append(&alice, OWNER, Expected::Sequence(2), &[added("Alice C.")]).await.unwrap(), 3);

    let events = store.events(&alice).await.unwrap();
    assert_eq!(events.iter().map(|e| e.sequence).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(events[2].payload, json!({ "name": "Alice C." }));
    assert_eq!(events[0].aggregate, alice);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn expected_sequence_is_enforced(pool: PgPool) {
    let store = EventStore::new(pool);
    let alice = account(1, "alice");
    store.append(&alice, OWNER, Expected::New, &[added("Alice")]).await.unwrap();

    assert!(matches!(
        store.append(&alice, OWNER, Expected::New, &[added("again")]).await,
        Err(Error::Conflict { actual: 1, .. })
    ));
    assert!(matches!(
        store.append(&alice, OWNER, Expected::Sequence(0), &[added("stale")]).await,
        Err(Error::Conflict { actual: 1, .. })
    ));
    assert_eq!(store.append(&alice, OWNER, Expected::Any, &[added("any")]).await.unwrap(), 2);
    assert_eq!(store.events(&alice).await.unwrap().len(), 2);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn concurrent_writers_do_not_both_win(pool: PgPool) {
    let store = EventStore::new(pool);
    let alice = account(1, "alice");
    let writers = (0..8).map(|i| {
        let (store, alice) = (store.clone(), alice.clone());
        tokio::spawn(async move { store.append(&alice, OWNER, Expected::New, &[added(&i.to_string())]).await })
    });
    let mut won = 0;
    for writer in writers {
        match writer.await.unwrap() {
            Ok(_) => won += 1,
            Err(Error::Conflict { .. }) => {}
            Err(other) => panic!("{other}"),
        }
    }
    assert_eq!(won, 1);
    assert_eq!(store.events(&alice).await.unwrap().len(), 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn aggregates_and_instances_are_apart(pool: PgPool) {
    let store = EventStore::new(pool);
    store.append(&account(1, "alice"), OWNER, Expected::New, &[added("Alice")]).await.unwrap();
    store.append(&account(2, "alice"), OWNER, Expected::New, &[added("other Alice")]).await.unwrap();
    store.append(&account(1, "bob"), OWNER, Expected::New, &[added("Bob")]).await.unwrap();
    assert_eq!(store.events(&account(1, "alice")).await.unwrap().len(), 1);
    assert_eq!(store.events(&account(2, "alice")).await.unwrap()[0].payload, json!({ "name": "other Alice" }));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn read_all_pages_in_order(pool: PgPool) {
    let store = EventStore::new(pool);
    for i in 0..5 {
        store.append(&account(1, &i.to_string()), OWNER, Expected::New, &[added("x")]).await.unwrap();
    }
    let events = read_until(&store, Cursor::default(), 2, 5).await;
    let ids: Vec<_> = events.iter().map(|e| e.aggregate.aggregate_id.as_str()).collect();
    assert_eq!(ids, ["0", "1", "2", "3", "4"]);
    assert!(events.windows(2).all(|pair| pair[0].cursor < pair[1].cursor));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn read_all_holds_back_running_transactions(pool: PgPool) {
    let store = EventStore::new(pool.clone());
    // A transaction that started earlier and is still open …
    let mut open = pool.begin().await.unwrap();
    sqlx::query_scalar!(r#"SELECT pg_current_xact_id()::text AS "id!""#).fetch_one(&mut *open).await.unwrap();
    // … holds back events committed after it started, until it ends.
    store.append(&account(1, "alice"), OWNER, Expected::New, &[added("Alice")]).await.unwrap();
    assert!(store.read_all(Cursor::default(), 10).await.unwrap().is_empty());
    open.commit().await.unwrap();
    assert_eq!(read_until(&store, Cursor::default(), 10, 1).await.len(), 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn events_cannot_be_changed_even_by_the_owner(pool: PgPool) {
    let store = EventStore::new(pool.clone());
    store.append(&account(1, "alice"), OWNER, Expected::New, &[added("Alice")]).await.unwrap();
    assert!(sqlx::query!("UPDATE events SET creator = 'x'").execute(&pool).await.is_err());
    assert!(sqlx::query!("DELETE FROM events").execute(&pool).await.is_err());
    assert!(sqlx::query!("TRUNCATE events").execute(&pool).await.is_err());
    assert_eq!(store.events(&account(1, "alice")).await.unwrap()[0].creator, "system");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn appends_are_announced(pool: PgPool) {
    let mut listener = sqlx::postgres::PgListener::connect_with(&pool).await.unwrap();
    listener.listen(kernoid_events::NOTIFY_CHANNEL).await.unwrap();
    EventStore::new(pool).append(&account(1, "alice"), OWNER, Expected::New, &[added("Alice")]).await.unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv()).await.unwrap().unwrap();
    assert_eq!(notification.channel(), kernoid_events::NOTIFY_CHANNEL);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn revision_must_be_positive(pool: PgPool) {
    let store = EventStore::new(pool);
    let event = NewEvent { revision: 0, ..added("Alice") };
    assert!(matches!(
        store.append(&account(1, "alice"), OWNER, Expected::New, &[event]).await,
        Err(Error::InvalidRevision)
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_aggregate_keeps_its_owner(pool: PgPool) {
    let store = EventStore::new(pool);
    let alice = account(1, "alice");
    store.append(&alice, OWNER, Expected::New, &[added("Alice")]).await.unwrap();
    let other = Uuid::from_u128(200);
    assert!(matches!(
        store.append(&alice, other, Expected::Any, &[added("moved")]).await,
        Err(Error::OwnerMismatch { given, actual }) if given == other && actual == OWNER
    ));
    assert!(store.events(&alice).await.unwrap().iter().all(|event| event.owner == OWNER));
}
