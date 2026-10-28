// SPDX-License-Identifier: AGPL-3.0-or-later
//! Projections against PostgreSQL; set `DATABASE_URL` as for tests/postgres.rs.
// The test projection writes to a table that exists only in these tests, so its queries cannot be checked against
// the schema at build time.
#![allow(clippy::disallowed_methods)]

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use kernoid_events::{
    AggregateId, Error, Event, EventStore, Expected, NewEvent,
    projection::{CatchUp, Projection, Runner},
};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const OWNER: Uuid = Uuid::from_u128(100);

/// Records every event it sees in the table `seen`; fails on the aggregate named in `fail_on`.
#[derive(Default)]
struct Recorder {
    fail_on: Mutex<Option<String>>,
}

impl Projection for Recorder {
    fn name(&self) -> &'static str {
        "test.recorder"
    }

    async fn apply(&self, connection: &mut PgConnection, event: &Event) -> Result<(), Error> {
        sqlx::query("INSERT INTO seen (position, aggregate_id) VALUES ($1, $2)")
            .bind(event.cursor.position)
            .bind(&event.aggregate.aggregate_id)
            .execute(&mut *connection)
            .await?;
        if self.fail_on.lock().unwrap().as_deref() == Some(event.aggregate.aggregate_id.as_str()) {
            return Err(Error::Database(sqlx::Error::Protocol("refused by the test".into())));
        }
        Ok(())
    }
}

async fn setup(pool: &PgPool) -> EventStore {
    sqlx::query("CREATE TABLE seen (position bigint PRIMARY KEY, aggregate_id text NOT NULL)")
        .execute(pool)
        .await
        .unwrap();
    EventStore::new(pool.clone())
}

async fn add(store: &EventStore, id: &str) {
    let event =
        NewEvent { event_type: "account.added".into(), revision: 1, payload: json!({}), creator: "system".into() };
    store.append(&AggregateId::new(Uuid::from_u128(1), "account", id), OWNER, Expected::New, &[event]).await.unwrap();
}

async fn seen(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT aggregate_id FROM seen ORDER BY position").fetch_all(pool).await.unwrap()
}

/// Calls `catch_up` until `count` events are applied in total; waits for events held back by other tests'
/// transactions, at most ten seconds.
async fn catch_up(runner: &Runner<Recorder>, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut applied = 0;
    while applied < count {
        assert!(Instant::now() < deadline, "only {applied} of {count} events applied");
        match runner.catch_up().await.unwrap() {
            CatchUp::Applied(0) | CatchUp::Busy => tokio::time::sleep(Duration::from_millis(20)).await,
            CatchUp::Applied(n) => applied += n,
        }
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn applies_every_event_once_in_order(pool: PgPool) {
    let store = setup(&pool).await;
    for id in ["a", "b", "c", "d", "e"] {
        add(&store, id).await;
    }
    let runner = Runner::new(pool.clone(), Recorder::default()).batch(2);
    catch_up(&runner, 5).await;
    assert_eq!(seen(&pool).await, ["a", "b", "c", "d", "e"]);
    assert_eq!(runner.catch_up().await.unwrap(), CatchUp::Applied(0));

    // A new runner – e.g. after a restart – continues from the stored cursor.
    add(&store, "f").await;
    let restarted = Runner::new(pool.clone(), Recorder::default());
    catch_up(&restarted, 1).await;
    assert_eq!(seen(&pool).await, ["a", "b", "c", "d", "e", "f"]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_failed_batch_leaves_no_trace(pool: PgPool) {
    let store = setup(&pool).await;
    for id in ["a", "b", "c"] {
        add(&store, id).await;
    }
    let recorder = Recorder { fail_on: Mutex::new(Some("b".into())) };
    let runner = Runner::new(pool.clone(), recorder).batch(10);
    // The batch with "b" is rolled back as a whole – including whatever it had written before "b". ("a" may have
    // been applied in an earlier batch of its own, if other tests' transactions held "b" back for a moment.)
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "the projection never reached event b");
        match runner.catch_up().await {
            Err(_) => break,
            Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let before = seen(&pool).await;
    assert!(before.is_empty() || before == ["a"], "{before:?}");

    *runner.projection().fail_on.lock().unwrap() = None;
    catch_up(&runner, 3 - before.len()).await;
    assert_eq!(seen(&pool).await, ["a", "b", "c"]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn one_process_at_a_time(pool: PgPool) {
    let store = setup(&pool).await;
    add(&store, "a").await;
    let runner = Runner::new(pool.clone(), Recorder::default());
    catch_up(&runner, 1).await;

    // Another process holds the cursor …
    let mut other = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM projection_cursors WHERE name = 'test.recorder' FOR UPDATE")
        .execute(&mut *other)
        .await
        .unwrap();
    add(&store, "b").await;
    assert_eq!(runner.catch_up().await.unwrap(), CatchUp::Busy);
    // … until it is done.
    other.rollback().await.unwrap();
    catch_up(&runner, 1).await;
    assert_eq!(seen(&pool).await, ["a", "b"]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn run_wakes_on_new_events(pool: PgPool) {
    let store = setup(&pool).await;
    // With an hour between polls, only the notification can wake the runner in time.
    let runner = Runner::new(pool.clone(), Recorder::default()).poll(Duration::from_secs(3600));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(runner.run(async {
        let _ = stopped.await;
    }));
    tokio::time::sleep(Duration::from_millis(200)).await;
    add(&store, "a").await;

    let deadline = Instant::now() + Duration::from_secs(10);
    while seen(&pool).await.is_empty() {
        assert!(Instant::now() < deadline, "the runner did not wake up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn several_workers_share_a_projection(pool: PgPool) {
    let store = setup(&pool).await;
    // Three workers run the same projection while events keep coming.
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut workers = Vec::new();
    for _ in 0..3 {
        let runner = Runner::new(pool.clone(), Recorder::default()).batch(3).poll(Duration::from_millis(30));
        let mut stopped = stopped.clone();
        workers.push(tokio::spawn(runner.run(async move {
            let _ = stopped.wait_for(|stop| *stop).await;
        })));
    }
    let names: Vec<String> = (0..40).map(|n| format!("e{n:02}")).collect();
    for name in &names {
        add(&store, name).await;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while seen(&pool).await.len() < names.len() {
        assert!(Instant::now() < deadline, "the workers did not catch up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.send(true).unwrap();
    for worker in workers {
        worker.await.unwrap().unwrap();
    }
    // Each event once, in order – whichever worker applied it.
    assert_eq!(seen(&pool).await, names);
}
