// SPDX-License-Identifier: AGPL-3.0-or-later
//! Objects in object storage waiting to be removed (RFC 0002, 7). Object storage is not transactional, so a row in
//! `blob_garbage` names an object before it is written and is removed in the transaction that commits whatever
//! needs the object; a row that removes something writes one due at once. The worker deletes what is due.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::{BlobError, BlobStore};

/// How long an object written for a transaction may wait for it before it counts as left behind.
pub const PENDING: Duration = Duration::hours(1);

#[derive(Debug, thiserror::Error)]
pub enum GarbageError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Blob(#[from] BlobError),
}

/// Marks `key` as garbage once `due_at` is reached, unless [`keep`] takes it back before.
pub async fn mark(
    connection: &mut PgConnection,
    tenant: Uuid,
    key: &str,
    due_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO blob_garbage (tenant_id, key, due_at) VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, key) DO UPDATE SET due_at = least(blob_garbage.due_at, EXCLUDED.due_at)",
        tenant,
        key,
        due_at,
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Marks `key` as garbage now – by the database's clock, which collecting compares with: the clocks of the database
/// and of kernoid may differ a little.
pub async fn mark_now(connection: &mut PgConnection, tenant: Uuid, key: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO blob_garbage (tenant_id, key, due_at) VALUES ($1, $2, now())
         ON CONFLICT (tenant_id, key) DO UPDATE SET due_at = least(blob_garbage.due_at, now())",
        tenant,
        key,
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// Marks `key` before the object is written: garbage in [`PENDING`] unless the transaction that needs it commits.
pub async fn pending(pool: &PgPool, tenant: Uuid, key: &str) -> Result<(), sqlx::Error> {
    let mut connection = pool.acquire().await?;
    mark(&mut connection, tenant, key, Utc::now() + PENDING).await
}

/// Takes `key` back from the garbage, in the transaction that now needs the object. `false` if it is too late: the
/// mark is gone or due within [`MARGIN`], so the object may be deleted – the transaction must not commit then.
pub async fn keep(connection: &mut PgConnection, tenant: Uuid, key: &str) -> Result<bool, sqlx::Error> {
    // clock_timestamp, not now(): the transaction may have started a while ago.
    let kept = sqlx::query!(
        "DELETE FROM blob_garbage WHERE tenant_id = $1 AND key = $2 AND due_at > clock_timestamp() + make_interval(secs => $3)",
        tenant,
        key,
        MARGIN.num_seconds() as f64,
    )
    .execute(connection)
    .await?;
    Ok(kept.rows_affected() == 1)
}

/// Time a transaction that took an object back has left to commit before the worker could collect it.
pub const MARGIN: Duration = Duration::minutes(10);

/// Deletes up to `limit` due objects and their rows; returns how many. A row goes only after its object did, so an
/// object storage that fails leaves the row for the next run. Meant for one process at a time
/// ([`crate::lock::Lock`]).
pub async fn collect(pool: &PgPool, blobs: &BlobStore, limit: i64) -> Result<usize, GarbageError> {
    let due =
        sqlx::query!("SELECT tenant_id, key FROM blob_garbage WHERE due_at <= now() ORDER BY due_at LIMIT $1", limit)
            .fetch_all(pool)
            .await?;
    let mut collected = 0;
    for row in due {
        blobs.delete(row.tenant_id, &row.key).await?;
        // A row taken back meanwhile (`keep`) is gone already; `keep` refuses rows this close to being due.
        sqlx::query!(
            "DELETE FROM blob_garbage WHERE tenant_id = $1 AND key = $2 AND due_at <= now()",
            row.tenant_id,
            row.key,
        )
        .execute(pool)
        .await?;
        collected += 1;
    }
    Ok(collected)
}
