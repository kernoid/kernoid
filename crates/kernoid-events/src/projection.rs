// SPDX-License-Identifier: AGPL-3.0-or-later
//! Projections derive the current state – tables to query – from the stream of all events.
//!
//! A [`Runner`] takes a batch of events after the projection's cursor, applies them and moves the cursor, all in one
//! transaction: an event takes effect exactly once, or not at all and is tried again. The cursor row is locked with
//! `FOR UPDATE SKIP LOCKED`, so any number of processes may run the same projection – one works, the others wait.
//! A runner wakes on the notification every append sends and, as a fallback, at a fixed interval (events of a
//! transaction that commits late become visible without a notification of their own).

use std::{future::Future, time::Duration};

use sqlx::{PgConnection, PgPool, postgres::PgListener};

use crate::{Cursor, Error, Event, NOTIFY_CHANNEL, read_all};

/// Derives state from events. Implementations write only to their own tables, through `connection`.
pub trait Projection: Send + Sync {
    /// Stable, unique name; the cursor is kept under it. A new name builds the projection again from the start.
    fn name(&self) -> &'static str;

    /// Applies one event. It runs in the transaction that also moves the cursor; an error rolls the whole batch back.
    fn apply(&self, connection: &mut PgConnection, event: &Event) -> impl Future<Output = Result<(), Error>> + Send;
}

/// First look again after a notification that found nothing.
const FIRST_RETRY: Duration = Duration::from_millis(20);

/// What one call of [`Runner::catch_up`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUp {
    /// Applied this many events (0: nothing new yet).
    Applied(usize),
    /// Another process is working on this projection.
    Busy,
}

#[derive(Debug)]
pub struct Runner<P> {
    pool: PgPool,
    projection: P,
    batch: i64,
    poll: Duration,
}

impl<P: Projection> Runner<P> {
    pub fn new(pool: PgPool, projection: P) -> Self {
        Self { pool, projection, batch: 100, poll: Duration::from_secs(1) }
    }

    /// Events per transaction (default 100).
    pub fn batch(mut self, batch: i64) -> Self {
        self.batch = batch.max(1);
        self
    }

    /// Longest wait without a notification (default 1 s).
    pub fn poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    pub fn projection(&self) -> &P {
        &self.projection
    }

    /// Applies the next batch of events, if this process gets the projection.
    pub async fn catch_up(&self) -> Result<CatchUp, Error> {
        let name = self.projection.name();
        let mut tx = self.pool.begin().await?;
        sqlx::query!("INSERT INTO projection_cursors (name) VALUES ($1) ON CONFLICT (name) DO NOTHING", name)
            .execute(&mut *tx)
            .await?;
        let Some(row) = sqlx::query!(
            "SELECT transaction_id, position FROM projection_cursors WHERE name = $1 FOR UPDATE SKIP LOCKED",
            name
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(CatchUp::Busy);
        };
        let cursor = Cursor { transaction_id: row.transaction_id, position: row.position };
        let events = read_all(&mut *tx, cursor, self.batch).await?;
        let Some(last) = events.last().map(|event| event.cursor) else {
            return Ok(CatchUp::Applied(0));
        };
        for event in &events {
            self.projection.apply(&mut tx, event).await?;
        }
        sqlx::query!(
            "UPDATE projection_cursors SET transaction_id = $2, position = $3, updated_at = now() WHERE name = $1",
            name,
            last.transaction_id,
            last.position,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(CatchUp::Applied(events.len()))
    }

    /// Keeps the projection current until `shutdown` completes. Errors are logged and tried again after the poll
    /// interval; an event that cannot be applied stops the projection there until it is fixed.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
        let name = self.projection.name();
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.listen(NOTIFY_CHANNEL).await?;
        tokio::pin!(shutdown);
        // After a notification that found nothing, the event is held back by a transaction still running somewhere
        // in the cluster; no second notification will come for it. Look again soon, then less and less often.
        let mut retry: Option<Duration> = None;
        loop {
            let mut applied = 0;
            loop {
                match self.catch_up().await {
                    Ok(CatchUp::Applied(count)) => {
                        applied += count;
                        if (count as i64) < self.batch {
                            break;
                        }
                    }
                    Ok(CatchUp::Busy) => break,
                    Err(error) => {
                        tracing::error!(projection = name, %error, "projection failed; trying again");
                        break;
                    }
                }
            }
            if applied > 0 {
                tracing::debug!(projection = name, count = applied, "applied");
                retry = None;
            }
            let wait = match retry {
                Some(delay) => {
                    retry = (delay < self.poll).then(|| (delay * 2).min(self.poll));
                    delay
                }
                None => self.poll,
            };
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                notification = listener.recv() => match notification {
                    Ok(_) => retry = Some(retry.unwrap_or(FIRST_RETRY)),
                    Err(error) => {
                        tracing::warn!(projection = name, %error, "lost the notification channel");
                        tokio::time::sleep(self.poll).await;
                    }
                },
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}
