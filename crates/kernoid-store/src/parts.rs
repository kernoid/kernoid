// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content of any size in object storage (RFC 0005, 5): a stream is stored in parts of [`PART_SIZE`] below a prefix
//! – `<prefix>/0`, `<prefix>/1`, … – each sealed on its own like every object (bound to its own path, so parts cannot
//! be swapped). The number of parts, the size and a SHA-256 of the whole are kept by the caller in PostgreSQL; a part
//! missing or cut off fails to open. Only one part is in memory at a time.
//!
//! Each part is marked as garbage before it is written (`garbage`): the transaction that gives the content a home
//! takes the marks back with [`keep`].

use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use futures_util::{Stream, StreamExt, stream};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::{BlobError, BlobStore, garbage};

/// Size of every part but the last.
pub const PART_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PartsError {
    #[error("the content is larger than {limit} bytes")]
    TooLarge { limit: u64 },
    /// Reading what was to be stored failed (the client went away).
    #[error("the content could not be read: {0}")]
    Source(String),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// What was stored: the number of parts, the size and the SHA-256 of the whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub parts: u32,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// The key of part `n` below `prefix`.
pub fn part_key(prefix: &str, n: u32) -> String {
    format!("{prefix}/{n}")
}

/// Stores `content` in parts below `prefix`, refusing more than `limit` bytes; every part is garbage at `due` unless
/// [`keep`] takes it back.
pub async fn put<S, E>(
    blobs: &BlobStore,
    pool: &PgPool,
    tenant: Uuid,
    prefix: &str,
    content: S,
    limit: u64,
    due: DateTime<Utc>,
) -> Result<Stored, PartsError>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: std::fmt::Display,
{
    let mut content = std::pin::pin!(content);
    let mut buffer = BytesMut::new();
    let mut hash = Sha256::new();
    let mut size: u64 = 0;
    let mut parts: u32 = 0;
    let store = async |part: Bytes, parts: &mut u32| -> Result<(), PartsError> {
        let key = part_key(prefix, *parts);
        let mut connection = pool.acquire().await?;
        garbage::mark(&mut connection, tenant, &key, due).await?;
        drop(connection);
        blobs.put(tenant, &key, part).await?;
        *parts += 1;
        Ok(())
    };
    while let Some(chunk) = content.next().await {
        let chunk = chunk.map_err(|error| PartsError::Source(error.to_string()))?;
        size += chunk.len() as u64;
        if size > limit {
            return Err(PartsError::TooLarge { limit });
        }
        hash.update(&chunk);
        buffer.extend_from_slice(&chunk);
        while buffer.len() >= PART_SIZE {
            let part = buffer.split_to(PART_SIZE).freeze();
            store(part, &mut parts).await?;
        }
    }
    if !buffer.is_empty() {
        store(buffer.freeze(), &mut parts).await?;
    }
    Ok(Stored { parts, size, sha256: hash.finalize().into() })
}

/// Stores content that is in memory already.
pub async fn put_bytes(
    blobs: &BlobStore,
    pool: &PgPool,
    tenant: Uuid,
    prefix: &str,
    content: Bytes,
    limit: u64,
    due: DateTime<Utc>,
) -> Result<Stored, PartsError> {
    put(blobs, pool, tenant, prefix, stream::iter([Ok::<_, std::convert::Infallible>(content)]), limit, due).await
}

/// Takes the parts back from the garbage, in the transaction that now needs them; `false` if it is too late for any.
pub async fn keep(connection: &mut PgConnection, tenant: Uuid, prefix: &str, parts: u32) -> Result<bool, sqlx::Error> {
    for n in 0..parts {
        if !garbage::keep(connection, tenant, &part_key(prefix, n)).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Marks the parts as garbage at `due`, in the transaction that removes what needed them.
pub async fn mark(
    connection: &mut PgConnection,
    tenant: Uuid,
    prefix: &str,
    parts: u32,
    due: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    for n in 0..parts {
        garbage::mark(connection, tenant, &part_key(prefix, n), due).await?;
    }
    Ok(())
}

/// The content from byte `start` to `end` (exclusive), part by part.
pub fn read(
    blobs: &BlobStore,
    tenant: Uuid,
    prefix: &str,
    parts: u32,
    start: u64,
    end: u64,
) -> impl Stream<Item = Result<Bytes, BlobError>> + Send + 'static {
    let blobs = blobs.clone();
    let prefix = prefix.to_owned();
    let part_size = PART_SIZE as u64;
    let first = (start / part_size) as u32;
    let last = if end == 0 { 0 } else { ((end - 1) / part_size) as u32 + 1 };
    stream::iter(first..last.min(parts)).then(move |n| {
        let blobs = blobs.clone();
        let key = part_key(&prefix, n);
        async move {
            let part = blobs.get(tenant, &key).await?;
            let offset = u64::from(n) * part_size;
            let from = start.saturating_sub(offset).min(part.len() as u64) as usize;
            let to = end.saturating_sub(offset).min(part.len() as u64) as usize;
            Ok(part.slice(from..to.max(from)))
        }
    })
}

/// The whole content in memory – for content known to be small.
pub async fn read_all(
    blobs: &BlobStore,
    tenant: Uuid,
    prefix: &str,
    parts: u32,
    size: u64,
) -> Result<Bytes, BlobError> {
    let mut out = BytesMut::with_capacity(size as usize);
    let mut content = std::pin::pin!(read(blobs, tenant, prefix, parts, 0, size));
    while let Some(part) = content.next().await {
        out.extend_from_slice(&part?);
    }
    if out.len() as u64 != size {
        return Err(BlobError::NotFound);
    }
    Ok(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_keys_count_from_zero() {
        assert_eq!(part_key("upload/a/b", 0), "upload/a/b/0");
        assert_eq!(part_key("upload/a/b", 12), "upload/a/b/12");
    }
}
