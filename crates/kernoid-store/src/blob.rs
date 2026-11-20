// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content in object storage, kept apart and encrypted per tenant.
//!
//! Every object lives below `tenants/<tenant id>/` and is sealed with the tenant's current key before it leaves
//! kernoid (see [`crate::crypto`]): object storage only ever sees ciphertext. No other part of kernoid writes to
//! object storage. Large content is stored in parts (`crate::parts`). An installation of identity alone may keep its
//! few objects in PostgreSQL instead (`[blob] kind = "database"`, table `blob_objects`, RFC 0008, 5) – sealed alike.

use std::sync::Arc;

use bytes::Bytes;
pub use kernoid_blob::{
    S3Config,
    objects::{self, MemoryObjects, ObjectError, Objects},
};
use kernoid_config::Blob;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{self, CryptoError},
    keys::{KeyError, TenantKeys},
    scan::Scanner,
};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("invalid key {0:?}")]
    InvalidKey(String),
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Store(ObjectError),
    #[error(transparent)]
    TenantKey(#[from] KeyError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("objects in PostgreSQL need its pool: BlobStore::open")]
    NeedsDatabase,
    #[error("{0} bytes is more than objects kept in PostgreSQL may have")]
    TooLarge(usize),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// The largest object kept in PostgreSQL, before sealing.
pub const DATABASE_OBJECT_LIMIT: usize = 4 * 1024 * 1024;

impl From<ObjectError> for BlobError {
    fn from(error: ObjectError) -> Self {
        match error {
            ObjectError::NotFound => Self::NotFound,
            other => Self::Store(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobStore {
    inner: Backend,
    keys: Arc<TenantKeys>,
    scanner: Option<Arc<dyn Scanner>>,
}

#[derive(Debug, Clone)]
enum Backend {
    Objects(Arc<dyn Objects>),
    Database(PgPool),
}

impl BlobStore {
    /// The store `config` names; `db` keeps the objects when it says `database`.
    pub fn open(config: &Blob, keys: Arc<TenantKeys>, db: PgPool) -> Result<Self, BlobError> {
        match config {
            Blob::Database => Ok(Self::in_database(db, keys)),
            other => Self::from_config(other, keys),
        }
    }

    /// Object storage as `config` names it – not `database`, which needs a pool (`open`).
    pub fn from_config(config: &Blob, keys: Arc<TenantKeys>) -> Result<Self, BlobError> {
        let inner: Arc<dyn Objects> = match config {
            Blob::Database => return Err(BlobError::NeedsDatabase),
            Blob::Memory => Arc::new(MemoryObjects::new()),
            // kernoid's own S3 client (the kit's `kernoid_blob::objects::s3`): self-hosted object storage is
            // addressed by path, AWS by the bucket's host.
            Blob::S3(s3) => Arc::new(objects::s3::S3Objects::new(&s3_config(s3))?),
        };
        Ok(Self::new(inner, keys))
    }

    /// Over any object store – for tests, which keep their own handle to look at what it holds.
    pub fn new(inner: Arc<dyn Objects>, keys: Arc<TenantKeys>) -> Self {
        Self { inner: Backend::Objects(inner), keys, scanner: None }
    }

    /// In memory, lost with the store – for tests.
    pub fn in_memory(keys: Arc<TenantKeys>) -> Self {
        Self::new(Arc::new(MemoryObjects::new()), keys)
    }

    /// In PostgreSQL – for tests of an installation without object storage.
    pub fn in_database(db: PgPool, keys: Arc<TenantKeys>) -> Self {
        Self { inner: Backend::Database(db), keys, scanner: None }
    }

    /// Scans what tenants that switched the scanner's module on store (`crate::scan`).
    pub fn with_scanner(mut self, scanner: Arc<dyn Scanner>) -> Self {
        self.scanner = Some(scanner);
        self
    }

    pub fn scanner(&self) -> Option<&Arc<dyn Scanner>> {
        self.scanner.as_ref()
    }

    /// Stores `content` at `key`, sealed with the tenant's current key.
    pub async fn put(&self, tenant: Uuid, key: &str, content: Bytes) -> Result<(), BlobError> {
        let path = path(tenant, key)?;
        if matches!(self.inner, Backend::Database(_)) && content.len() > DATABASE_OBJECT_LIMIT {
            return Err(BlobError::TooLarge(content.len()));
        }
        let (number, tenant_key) = self.keys.current(tenant).await?;
        let location = path.clone();
        let sealed = blocking(move || crypto::seal(&tenant_key, number, &location, &content)).await?;
        match &self.inner {
            Backend::Objects(store) => {
                store.put(&path, Bytes::from(sealed)).await?;
            }
            Backend::Database(db) => {
                let location = path.clone();
                sqlx::query!(
                    "INSERT INTO blob_objects (path, content) VALUES ($1, $2)
                     ON CONFLICT (path) DO UPDATE SET content = EXCLUDED.content, stored_at = now()",
                    location,
                    &sealed[..],
                )
                .execute(db)
                .await?;
            }
        }
        Ok(())
    }

    /// The content at `key`; fails if it was changed, moved or sealed for another tenant.
    pub async fn get(&self, tenant: Uuid, key: &str) -> Result<Bytes, BlobError> {
        let path = path(tenant, key)?;
        let sealed = match &self.inner {
            Backend::Objects(store) => store.read(&path).await?,
            Backend::Database(db) => {
                let location = path.clone();
                sqlx::query_scalar!("SELECT content FROM blob_objects WHERE path = $1", location)
                    .fetch_optional(db)
                    .await?
                    .map(Bytes::from)
                    .ok_or(BlobError::NotFound)?
            }
        };
        let tenant_key = self.keys.get(tenant, crypto::key_number(&sealed)?).await?;
        let location = path.clone();
        Ok(blocking(move || crypto::open(&tenant_key, &location, &sealed)).await?.into())
    }

    /// Deletes `key`; deleting a key that does not exist is not an error.
    pub async fn delete(&self, tenant: Uuid, key: &str) -> Result<(), BlobError> {
        let path = path(tenant, key)?;
        match &self.inner {
            Backend::Objects(store) => match store.delete(&path).await {
                Ok(()) | Err(ObjectError::NotFound) => Ok(()),
                Err(error) => Err(error.into()),
            },
            Backend::Database(db) => {
                let location = path.clone();
                sqlx::query!("DELETE FROM blob_objects WHERE path = $1", location).execute(db).await?;
                Ok(())
            }
        }
    }

    /// Checks that object storage answers, the bucket exists and the credentials may list it.
    pub async fn ping(&self) -> Result<(), BlobError> {
        match &self.inner {
            // Listing a prefix nothing is stored under: one cheap request, which fails without the bucket.
            Backend::Objects(store) => store.list("kernoid-ping/").await.map(drop).map_err(BlobError::Store),
            Backend::Database(db) => Ok(crate::ping(db).await?),
        }
    }
}

/// Runs encryption off the async worker threads; large content would otherwise stall other requests.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, CryptoError> + Send + 'static,
) -> Result<T, CryptoError> {
    tokio::task::spawn_blocking(work).await.expect("encryption does not panic")
}

/// The settings of kernoid's S3 client.
pub fn s3_config(s3: &kernoid_config::S3) -> S3Config {
    S3Config {
        bucket: s3.bucket.clone(),
        region: s3.region.clone(),
        endpoint: s3.endpoint.clone(),
        access_key_id: s3.access_key_id.expose().to_owned(),
        secret_access_key: s3.secret_access_key.expose().to_owned(),
        allow_http: s3.allow_http,
    }
}

/// `tenants/<tenant>/<key>`; `key` is a relative path of non-empty segments without `.` or `..` and without control
/// characters or backslashes.
fn path(tenant: Uuid, key: &str) -> Result<String, BlobError> {
    let invalid = || BlobError::InvalidKey(key.to_owned());
    if key.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || key.chars().any(|c| c.is_control() || c == '\\')
    {
        return Err(invalid());
    }
    Ok(format!("tenants/{tenant}/{key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_cannot_leave_the_tenant() {
        let tenant = Uuid::nil();
        for key in ["", "/x", "x/", "a//b", "..", "a/../b", "./a"] {
            assert!(matches!(path(tenant, key), Err(BlobError::InvalidKey(_))), "{key:?}");
        }
        assert_eq!(path(tenant, "files/a.txt").unwrap(), "tenants/00000000-0000-0000-0000-000000000000/files/a.txt");
    }
}
