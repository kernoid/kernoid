// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content in object storage, kept apart and encrypted per tenant.
//!
//! Every object lives below `tenants/<tenant id>/` and is sealed with the tenant's current key before it leaves
//! kernoid (see [`crate::crypto`]): object storage only ever sees ciphertext. No other part of kernoid writes to
//! object storage. Large content is stored in parts (`crate::parts`). An installation of identity alone may keep its
//! few objects in PostgreSQL instead (`[blob] kind = "database"`, table `blob_objects`, RFC 0008, 5) – sealed alike.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use kernoid_config::Blob;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, aws::AmazonS3Builder, memory::InMemory, path::Path};
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
    Store(object_store::Error),
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

impl From<object_store::Error> for BlobError {
    fn from(error: object_store::Error) -> Self {
        match error {
            object_store::Error::NotFound { .. } => Self::NotFound,
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
    Objects(Arc<dyn ObjectStore>),
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
        let inner: Arc<dyn ObjectStore> = match config {
            Blob::Database => return Err(BlobError::NeedsDatabase),
            Blob::Memory => Arc::new(InMemory::new()),
            Blob::S3(s3) => {
                let mut builder = AmazonS3Builder::new()
                    .with_region(&s3.region)
                    .with_bucket_name(&s3.bucket)
                    .with_access_key_id(s3.access_key_id.expose())
                    .with_secret_access_key(s3.secret_access_key.expose())
                    .with_allow_http(s3.allow_http);
                if let Some(endpoint) = &s3.endpoint {
                    // Self-hosted object storage is addressed by path, not by a bucket subdomain.
                    builder = builder.with_endpoint(endpoint).with_virtual_hosted_style_request(false);
                }
                Arc::new(builder.build()?)
            }
        };
        Ok(Self::new(inner, keys))
    }

    /// Over any object store – for tests, which keep their own handle to look at what it holds.
    pub fn new(inner: Arc<dyn ObjectStore>, keys: Arc<TenantKeys>) -> Self {
        Self { inner: Backend::Objects(inner), keys, scanner: None }
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
        let location = path.to_string();
        let sealed = blocking(move || crypto::seal(&tenant_key, number, &location, &content)).await?;
        match &self.inner {
            Backend::Objects(store) => {
                store.put(&path, PutPayload::from(sealed)).await?;
            }
            Backend::Database(db) => {
                let location = path.to_string();
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
            Backend::Objects(store) => store.get(&path).await?.bytes().await?,
            Backend::Database(db) => {
                let location = path.to_string();
                sqlx::query_scalar!("SELECT content FROM blob_objects WHERE path = $1", location)
                    .fetch_optional(db)
                    .await?
                    .map(Bytes::from)
                    .ok_or(BlobError::NotFound)?
            }
        };
        let tenant_key = self.keys.get(tenant, crypto::key_number(&sealed)?).await?;
        let location = path.to_string();
        Ok(blocking(move || crypto::open(&tenant_key, &location, &sealed)).await?.into())
    }

    /// Deletes `key`; deleting a key that does not exist is not an error.
    pub async fn delete(&self, tenant: Uuid, key: &str) -> Result<(), BlobError> {
        let path = path(tenant, key)?;
        match &self.inner {
            Backend::Objects(store) => match store.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
                Err(error) => Err(error.into()),
            },
            Backend::Database(db) => {
                let location = path.to_string();
                sqlx::query!("DELETE FROM blob_objects WHERE path = $1", location).execute(db).await?;
                Ok(())
            }
        }
    }

    /// Checks that object storage answers, the bucket exists and the credentials may list it.
    pub async fn ping(&self) -> Result<(), BlobError> {
        match &self.inner {
            // Listing a prefix nothing is stored under: one cheap request, which fails without the bucket.
            Backend::Objects(store) => match store.list(Some(&Path::from("kernoid-ping"))).next().await {
                None | Some(Ok(_)) => Ok(()),
                Some(Err(error)) => Err(BlobError::Store(error)),
            },
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

/// `tenants/<tenant>/<key>`; `key` is a relative path of non-empty segments without `.` or `..`.
fn path(tenant: Uuid, key: &str) -> Result<Path, BlobError> {
    let invalid = || BlobError::InvalidKey(key.to_owned());
    if key.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..") {
        return Err(invalid());
    }
    Path::parse(format!("tenants/{tenant}/{key}")).map_err(|_| invalid())
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
        assert_eq!(
            path(tenant, "files/a.txt").unwrap().as_ref(),
            "tenants/00000000-0000-0000-0000-000000000000/files/a.txt"
        );
    }
}
