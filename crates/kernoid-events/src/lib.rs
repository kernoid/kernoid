// SPDX-License-Identifier: AGPL-3.0-or-later
//! The event store. Identity and administration are kept as events: every change to a tenant, an account, a role or
//! a policy is one event, and the current state is derived from them – the audit log is the data. The idea follows
//! Zitadel's event store; this code is written from its documentation, not from its source.
//!
//! - Events belong to an **aggregate** (one account, one group …) within an **instance** and are numbered within it by
//!   `sequence`, starting at 1 without gaps. Writers state which sequence they expect, so two writers cannot both
//!   change the same aggregate based on the same state.
//! - **Readers of all events** (projections) follow a [`Cursor`]. Events become visible to them only once every
//!   transaction that started before is finished, so a projection never skips an event that commits late.

pub mod aggregate;
pub mod projection;

use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgExecutor, PgPool};
use uuid::Uuid;

/// One aggregate: the thing a stream of events is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AggregateId {
    pub instance_id: Uuid,
    /// Kind of aggregate, e.g. `account`.
    pub aggregate_type: String,
    pub aggregate_id: String,
}

impl AggregateId {
    pub fn new(instance_id: Uuid, aggregate_type: impl Into<String>, aggregate_id: impl Into<String>) -> Self {
        Self { instance_id, aggregate_type: aggregate_type.into(), aggregate_id: aggregate_id.into() }
    }
}

/// An event to be written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewEvent {
    /// What happened, e.g. `account.added`.
    pub event_type: String,
    /// Version of the payload schema of this event type, starting at 1.
    pub revision: i16,
    pub payload: serde_json::Value,
    /// Who caused it: an account, a service account or the system.
    pub creator: String,
}

/// A stored event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub aggregate: AggregateId,
    /// The tenant that owns the aggregate, or the instance for instance-wide aggregates.
    pub owner: Uuid,
    pub sequence: i64,
    pub event_type: String,
    pub revision: i16,
    pub payload: serde_json::Value,
    pub creator: String,
    pub created_at: DateTime<Utc>,
    /// Where a reader of all events stands after this event.
    pub cursor: Cursor,
}

/// The state of the aggregate a writer bases its events on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// Write regardless of the current state.
    Any,
    /// The aggregate must not have any events yet.
    New,
    /// The last event of the aggregate must have this sequence.
    Sequence(i64),
}

/// Position of a reader in the stream of all events. Start with `Cursor::default()`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Cursor {
    pub transaction_id: i64,
    pub position: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("aggregate changed: expected {expected:?}, last sequence is {actual}")]
    Conflict { expected: Expected, actual: i64 },
    #[error("aggregate belongs to {actual}, not to {given}")]
    OwnerMismatch { given: Uuid, actual: Uuid },
    #[error("revision must be at least 1")]
    InvalidRevision,
    #[error("cannot read event {event_type} revision {revision}: {message}")]
    Decode { event_type: String, revision: i16, message: String },
    #[error("cannot write event: {0}")]
    Encode(String),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// What an inline projection returns: boxed, so that commands stay `Send` – an `async` closure holding references
/// would not be. Write inline projections as `|connection, events| Box::pin(async move { … })`, moving owned copies
/// of what they need into the block, or as `|c, e| Box::pin(some_async_fn(c, e))`.
pub type InlineFuture<'c> = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'c>>;

/// Gives a closure the signature of an inline projection – needed when it is stored in a variable before use.
pub fn inline<F>(projection: F) -> F
where
    F: for<'c> Fn(&'c mut PgConnection, &'c [Event]) -> InlineFuture<'c> + Send + Sync,
{
    projection
}

/// The inline projection that does nothing.
pub fn no_inline<'c>(_: &'c mut PgConnection, _: &'c [Event]) -> InlineFuture<'c> {
    Box::pin(async { Ok(()) })
}

#[derive(Debug, Clone)]
pub struct EventStore {
    pool: PgPool,
}

/// Channel on which every append is announced (after commit), so readers of all events need not poll.
pub const NOTIFY_CHANNEL: &str = "kernoid_events";

impl EventStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Appends `events` to `aggregate` in one transaction and returns the sequence of the last one.
    pub async fn append(
        &self,
        aggregate: &AggregateId,
        owner: Uuid,
        expected: Expected,
        events: &[NewEvent],
    ) -> Result<i64, Error> {
        let stored = self.append_with(aggregate, owner, expected, events, no_inline).await?;
        match stored.last() {
            Some(event) => Ok(event.sequence),
            None => self.last_sequence(aggregate).await,
        }
    }

    /// Like [`append`](Self::append), and runs `inline` with the stored events in the same transaction: state that
    /// must be current the moment the write returns – what decides a login or a permission – is updated there, so
    /// that a read right after the write already sees it. Everything else belongs in asynchronous projections. An
    /// error in `inline` rolls the append back.
    pub async fn append_with(
        &self,
        aggregate: &AggregateId,
        owner: Uuid,
        expected: Expected,
        events: &[NewEvent],
        inline: impl for<'c> FnOnce(&'c mut PgConnection, &'c [Event]) -> InlineFuture<'c> + Send,
    ) -> Result<Vec<Event>, Error> {
        if events.iter().any(|event| event.revision < 1) {
            return Err(Error::InvalidRevision);
        }
        let mut tx = self.pool.begin().await?;
        // Serialises writers of the same aggregate; also covers the first event, where there is no row to lock yet.
        let lock = format!("{}/{}/{}", aggregate.instance_id, aggregate.aggregate_type, aggregate.aggregate_id);
        sqlx::query!(r#"SELECT 1 AS "locked!" FROM pg_advisory_xact_lock(hashtextextended($1, 0))"#, lock)
            .fetch_one(&mut *tx)
            .await?;
        let last = last_sequence(&mut *tx, aggregate).await?;
        let matches = match expected {
            Expected::Any => true,
            Expected::New => last == 0,
            Expected::Sequence(sequence) => last == sequence,
        };
        if !matches {
            return Err(Error::Conflict { expected, actual: last });
        }
        if last > 0 {
            let actual = sqlx::query_scalar!(
                "SELECT owner FROM events
                 WHERE instance_id = $1 AND aggregate_type = $2 AND aggregate_id = $3 AND sequence = 1",
                aggregate.instance_id,
                aggregate.aggregate_type,
                aggregate.aggregate_id,
            )
            .fetch_one(&mut *tx)
            .await?;
            if actual != owner {
                return Err(Error::OwnerMismatch { given: owner, actual });
            }
        }
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let event_types: Vec<&str> = events.iter().map(|event| event.event_type.as_str()).collect();
        let revisions: Vec<i16> = events.iter().map(|event| event.revision).collect();
        let payloads: Vec<serde_json::Value> = events.iter().map(|event| event.payload.clone()).collect();
        let creators: Vec<&str> = events.iter().map(|event| event.creator.as_str()).collect();
        let mut stored: Vec<Event> = sqlx::query_as!(
            EventRow,
            r#"INSERT INTO events
                   (instance_id, owner, aggregate_type, aggregate_id, sequence, event_type, revision, payload, creator)
               SELECT $1, $9, $2, $3, $4 + e.n, e.event_type, e.revision, e.payload, e.creator
               FROM unnest($5::text[], $6::int2[], $7::jsonb[], $8::text[])
                    WITH ORDINALITY AS e(event_type, revision, payload, creator, n)
               ORDER BY e.n
               RETURNING transaction_id::text::int8 AS "transaction_id!", position, instance_id, owner, aggregate_type,
                         aggregate_id, sequence, event_type, revision, payload, creator, created_at"#,
            aggregate.instance_id,
            aggregate.aggregate_type,
            aggregate.aggregate_id,
            last,
            &event_types as &[&str],
            &revisions,
            &payloads,
            &creators as &[&str],
            owner,
        )
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(Event::from)
        .collect();
        stored.sort_by_key(|event| event.sequence);
        inline(&mut tx, &stored).await?;
        sqlx::query!(r#"SELECT 1 AS "notified!" FROM pg_notify($1, '')"#, NOTIFY_CHANNEL).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(stored)
    }

    /// The sequence of the last event of `aggregate`, 0 if it has none.
    pub async fn last_sequence(&self, aggregate: &AggregateId) -> Result<i64, Error> {
        last_sequence(&self.pool, aggregate).await
    }

    /// All events of `aggregate`, oldest first.
    pub async fn events(&self, aggregate: &AggregateId) -> Result<Vec<Event>, Error> {
        let rows = sqlx::query_as!(
            EventRow,
            r#"SELECT transaction_id::text::int8 AS "transaction_id!", position, instance_id, owner, aggregate_type,
                      aggregate_id, sequence, event_type, revision, payload, creator, created_at
               FROM events
               WHERE instance_id = $1 AND aggregate_type = $2 AND aggregate_id = $3
               ORDER BY sequence"#,
            aggregate.instance_id,
            aggregate.aggregate_type,
            aggregate.aggregate_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Event::from).collect())
    }

    /// Up to `limit` events of all instances after `after`, in the order readers see them. Events of transactions that
    /// may still be running are held back, so an empty result means "nothing new yet", not "nothing ever again".
    /// Any open transaction in the PostgreSQL cluster holds events back while it runs – keep transactions short.
    pub async fn read_all(&self, after: Cursor, limit: i64) -> Result<Vec<Event>, Error> {
        read_all(&self.pool, after, limit).await
    }
}

async fn last_sequence<'c>(executor: impl PgExecutor<'c>, aggregate: &AggregateId) -> Result<i64, Error> {
    Ok(sqlx::query_scalar!(
        r#"SELECT coalesce(max(sequence), 0) AS "last!" FROM events
           WHERE instance_id = $1 AND aggregate_type = $2 AND aggregate_id = $3"#,
        aggregate.instance_id,
        aggregate.aggregate_type,
        aggregate.aggregate_id,
    )
    .fetch_one(executor)
    .await?)
}

/// [`EventStore::read_all`] on any connection or transaction.
pub async fn read_all<'c>(executor: impl PgExecutor<'c>, after: Cursor, limit: i64) -> Result<Vec<Event>, Error> {
    let rows = sqlx::query_as!(
        EventRow,
        r#"SELECT transaction_id::text::int8 AS "transaction_id!", position, instance_id, owner, aggregate_type,
                  aggregate_id, sequence, event_type, revision, payload, creator, created_at
           FROM events
           WHERE (transaction_id, position) > ($1::int8::text::xid8, $2)
             AND transaction_id < pg_snapshot_xmin(pg_current_snapshot())
           ORDER BY transaction_id, position
           LIMIT $3"#,
        after.transaction_id,
        after.position,
        limit,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(Event::from).collect())
}

/// One row of `events`, as the queries above select it.
struct EventRow {
    transaction_id: i64,
    position: i64,
    instance_id: Uuid,
    owner: Uuid,
    aggregate_type: String,
    aggregate_id: String,
    sequence: i64,
    event_type: String,
    revision: i16,
    payload: serde_json::Value,
    creator: String,
    created_at: DateTime<Utc>,
}

impl From<EventRow> for Event {
    fn from(row: EventRow) -> Self {
        Self {
            aggregate: AggregateId {
                instance_id: row.instance_id,
                aggregate_type: row.aggregate_type,
                aggregate_id: row.aggregate_id,
            },
            owner: row.owner,
            sequence: row.sequence,
            event_type: row.event_type,
            revision: row.revision,
            payload: row.payload,
            creator: row.creator,
            created_at: row.created_at,
            cursor: Cursor { transaction_id: row.transaction_id, position: row.position },
        }
    }
}
