// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content in object storage, kept apart and encrypted per tenant.
//!
//! Every object lives below `tenants/<tenant id>/` and is sealed with the tenant's current key before it leaves
//! kernoid (see [`crate::crypto`]): object storage only ever sees ciphertext. No other part of kernoid writes to
//! object storage. Large content is stored in parts (`crate::parts`).

use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use kernoid_config::Blob;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, aws::AmazonS3Builder, memory::InMemory, path::Path};
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
}

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
    inner: Arc<dyn ObjectStore>,
    keys: Arc<TenantKeys>,
    scanner: Option<Arc<dyn Scanner>>,
}

impl BlobStore {
    pub fn from_config(config: &Blob, keys: Arc<TenantKeys>) -> Result<Self, BlobError> {
        let inner: Arc<dyn ObjectStore> = match config {
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
        Self { inner, keys, scanner: None }
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
        let (number, tenant_key) = self.keys.current(tenant).await?;
        let location = path.to_string();
        let sealed = blocking(move || crypto::seal(&tenant_key, number, &location, &content)).await?;
        self.inner.put(&path, PutPayload::from(sealed)).await?;
        Ok(())
    }

    /// The content at `key`; fails if it was changed, moved or sealed for another tenant.
    pub async fn get(&self, tenant: Uuid, key: &str) -> Result<Bytes, BlobError> {
        let path = path(tenant, key)?;
        let sealed = self.inner.get(&path).await?.bytes().await?;
        let tenant_key = self.keys.get(tenant, crypto::key_number(&sealed)?).await?;
        let location = path.to_string();
        Ok(blocking(move || crypto::open(&tenant_key, &location, &sealed)).await?.into())
    }

    /// Deletes `key`; deleting a key that does not exist is not an error.
    pub async fn delete(&self, tenant: Uuid, key: &str) -> Result<(), BlobError> {
        match self.inner.delete(&path(tenant, key)?).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Checks that object storage answers, the bucket exists and the credentials may list it.
    pub async fn ping(&self) -> Result<(), BlobError> {
        // Listing a prefix nothing is stored under: one cheap request, which fails without the bucket.
        match self.inner.list(Some(&Path::from("kernoid-ping"))).next().await {
            None | Some(Ok(_)) => Ok(()),
            Some(Err(error)) => Err(BlobError::Store(error)),
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
