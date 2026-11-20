// SPDX-License-Identifier: MIT
//! Object storage: bytes under keys, read whole or in ranges, written whole or in parts – [`Objects`], kept in memory
//! ([`MemoryObjects`]) or – with the feature `s3` – in S3 and S3-compatible storage ([`s3::S3Objects`]). kernoid's own
//! client, in place of the crate object_store: [`crate::ObjectBlobs`] keeps originals by their hash in it, kernoid's
//! server its sealed content.
//!
//! Keys are plain strings, `/` separating their parts; a listing gives every key that starts with a prefix.

use std::{
    collections::BTreeMap,
    fmt,
    ops::Range,
    pin::Pin,
    sync::{Arc, Mutex},
};

use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};

#[cfg(feature = "s3")]
pub mod s3;

/// A future of a call to object storage.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The bytes of an object as they arrive, in parts.
pub type Body = Pin<Box<dyn Stream<Item = Result<Bytes, ObjectError>> + Send>>;

/// Why a call to object storage failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectError {
    /// There is no object under the key.
    #[error("not found")]
    NotFound,
    /// The service answered with an error.
    #[error("object storage answered {status}: {message}")]
    Service {
        /// The HTTP status.
        status: u16,
        /// S3's error code and message, or the start of the answer.
        message: String,
    },
    /// The service could not be reached, or its answer broke off.
    #[error("object storage: {0}")]
    Transport(String),
    /// What was asked for or configured cannot be done.
    #[error("object storage: {0}")]
    Invalid(String),
}

/// Object storage.
pub trait Objects: fmt::Debug + Send + Sync {
    /// Stores `bytes` under `key`, replacing what was there.
    fn put(&self, key: &str, bytes: Bytes) -> BoxFuture<'_, Result<(), ObjectError>>;

    /// The bytes under `key` – or those in `range`, which must lie within them and not be empty – as they arrive.
    fn get(&self, key: &str, range: Option<Range<u64>>) -> BoxFuture<'_, Result<Body, ObjectError>>;

    /// The length of what is stored under `key`.
    fn head(&self, key: &str) -> BoxFuture<'_, Result<u64, ObjectError>>;

    /// Removes `key`; removing a key that does not exist is not an error.
    fn delete(&self, key: &str) -> BoxFuture<'_, Result<(), ObjectError>>;

    /// Every key that starts with `prefix`, in order.
    fn list(&self, prefix: &str) -> BoxFuture<'_, Result<Vec<String>, ObjectError>>;

    /// Copies what is under `from` to `to`.
    fn copy(&self, from: &str, to: &str) -> BoxFuture<'_, Result<(), ObjectError>>;

    /// Starts writing `key` in parts: the object appears once the upload is completed.
    fn upload(&self, key: &str) -> BoxFuture<'_, Result<Box<dyn Upload>, ObjectError>>;

    /// All the bytes under `key`.
    fn read(&self, key: &str) -> BoxFuture<'_, Result<Bytes, ObjectError>> {
        let key = key.to_owned();
        Box::pin(async move { collect(self.get(&key, None).await?).await })
    }
}

/// An object written in parts. Every part but the last must have at least 5 MiB (S3's rule).
pub trait Upload: Send {
    /// Sends the next part.
    fn part(&mut self, bytes: Bytes) -> BoxFuture<'_, Result<(), ObjectError>>;

    /// Joins the parts into the object.
    fn complete(self: Box<Self>) -> BoxFuture<'static, Result<(), ObjectError>>;

    /// Gives the upload up; its parts are removed.
    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<(), ObjectError>>;
}

/// The parts of `body` joined.
pub async fn collect(mut body: Body) -> Result<Bytes, ObjectError> {
    let first = match body.next().await {
        None => return Ok(Bytes::new()),
        Some(part) => part?,
    };
    let Some(second) = body.next().await else { return Ok(first) };
    let mut all = BytesMut::from(&first[..]);
    all.extend_from_slice(&second?);
    while let Some(part) = body.next().await {
        all.extend_from_slice(&part?);
    }
    Ok(all.freeze())
}

/// `range` checked against an object of `size` bytes.
fn within(range: &Range<u64>, size: u64) -> Result<(), ObjectError> {
    if range.start < range.end && range.end <= size {
        Ok(())
    } else {
        Err(ObjectError::Invalid(format!("the range {range:?} is not within {size} bytes")))
    }
}

/// Objects in memory, gone when the last handle is dropped – for tests and for trying things out.
#[derive(Debug, Clone, Default)]
pub struct MemoryObjects {
    objects: Arc<Mutex<BTreeMap<String, Bytes>>>,
}

impl MemoryObjects {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Bytes>> {
        self.objects.lock().expect("not poisoned")
    }

    fn found(&self, key: &str) -> Result<Bytes, ObjectError> {
        self.lock().get(key).cloned().ok_or(ObjectError::NotFound)
    }
}

impl Objects for MemoryObjects {
    fn put(&self, key: &str, bytes: Bytes) -> BoxFuture<'_, Result<(), ObjectError>> {
        self.lock().insert(key.to_owned(), bytes);
        Box::pin(async { Ok(()) })
    }

    fn get(&self, key: &str, range: Option<Range<u64>>) -> BoxFuture<'_, Result<Body, ObjectError>> {
        let found = self.found(key).and_then(|bytes| match range {
            None => Ok(bytes),
            Some(range) => {
                within(&range, bytes.len() as u64)?;
                Ok(bytes.slice(range.start as usize..range.end as usize))
            }
        });
        Box::pin(async move { found.map(|bytes| Box::pin(futures_util::stream::iter([Ok(bytes)])) as Body) })
    }

    fn head(&self, key: &str) -> BoxFuture<'_, Result<u64, ObjectError>> {
        let found = self.found(key).map(|bytes| bytes.len() as u64);
        Box::pin(async move { found })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, Result<(), ObjectError>> {
        self.lock().remove(key);
        Box::pin(async { Ok(()) })
    }

    fn list(&self, prefix: &str) -> BoxFuture<'_, Result<Vec<String>, ObjectError>> {
        let keys = self
            .lock()
            .range(prefix.to_owned()..)
            .map(|(key, _)| key)
            .take_while(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        Box::pin(async move { Ok(keys) })
    }

    fn copy(&self, from: &str, to: &str) -> BoxFuture<'_, Result<(), ObjectError>> {
        let copied = self.found(from).map(|bytes| {
            self.lock().insert(to.to_owned(), bytes);
        });
        Box::pin(async move { copied })
    }

    fn upload(&self, key: &str) -> BoxFuture<'_, Result<Box<dyn Upload>, ObjectError>> {
        let upload = MemoryUpload { store: self.clone(), key: key.to_owned(), parts: BytesMut::new() };
        Box::pin(async move { Ok(Box::new(upload) as Box<dyn Upload>) })
    }
}

struct MemoryUpload {
    store: MemoryObjects,
    key: String,
    parts: BytesMut,
}

impl Upload for MemoryUpload {
    fn part(&mut self, bytes: Bytes) -> BoxFuture<'_, Result<(), ObjectError>> {
        self.parts.extend_from_slice(&bytes);
        Box::pin(async { Ok(()) })
    }

    fn complete(self: Box<Self>) -> BoxFuture<'static, Result<(), ObjectError>> {
        self.store.lock().insert(self.key, self.parts.freeze());
        Box::pin(async { Ok(()) })
    }

    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<(), ObjectError>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What every store must do; `prefix` keeps a run apart from others in a shared bucket.
    pub(crate) async fn behaves(store: &dyn Objects, prefix: &str) {
        let key = format!("{prefix}/a/one");
        assert_eq!(store.head(&key).await, Err(ObjectError::NotFound));
        assert!(matches!(store.get(&key, None).await, Err(ObjectError::NotFound)));
        assert_eq!(store.read(&key).await, Err(ObjectError::NotFound));
        store.put(&key, Bytes::from_static(b"0123456789")).await.unwrap();
        assert_eq!(store.head(&key).await, Ok(10));
        assert_eq!(store.read(&key).await.unwrap(), &b"0123456789"[..]);
        assert_eq!(collect(store.get(&key, Some(2..5)).await.unwrap()).await.unwrap(), &b"234"[..]);
        assert_eq!(collect(store.get(&key, Some(9..10)).await.unwrap()).await.unwrap(), &b"9"[..]);
        store.put(&key, Bytes::from_static(b"replaced")).await.unwrap();
        assert_eq!(store.read(&key).await.unwrap(), &b"replaced"[..]);

        // Keys with characters that need encoding, and an empty object.
        let odd = format!("{prefix}/a/with space+plus=equals&amp~tilde ü");
        store.put(&odd, Bytes::new()).await.unwrap();
        assert_eq!(store.head(&odd).await, Ok(0));
        assert_eq!(store.read(&odd).await.unwrap(), Bytes::new());

        store.copy(&key, &format!("{prefix}/b/copy")).await.unwrap();
        assert_eq!(store.read(&format!("{prefix}/b/copy")).await.unwrap(), &b"replaced"[..]);
        assert_eq!(store.copy(&format!("{prefix}/none"), &format!("{prefix}/x")).await, Err(ObjectError::NotFound));
        assert_eq!(
            store.list(&format!("{prefix}/")).await.unwrap(),
            vec![key.clone(), odd.clone(), format!("{prefix}/b/copy")]
        );
        assert_eq!(store.list(&format!("{prefix}/a/")).await.unwrap(), vec![key.clone(), odd.clone()]);
        assert!(store.list(&format!("{prefix}/c")).await.unwrap().is_empty());

        // In parts: 5 MiB and a rest; given up, nothing appears.
        let long: Vec<u8> = (0..(5 << 20) + 7).map(|i: u32| (i % 249) as u8).collect();
        let parted = format!("{prefix}/parted");
        let mut upload = store.upload(&parted).await.unwrap();
        upload.part(Bytes::copy_from_slice(&long[..5 << 20])).await.unwrap();
        upload.part(Bytes::copy_from_slice(&long[5 << 20..])).await.unwrap();
        upload.complete().await.unwrap();
        assert_eq!(store.head(&parted).await, Ok(long.len() as u64));
        assert!(store.read(&parted).await.unwrap() == long[..]);
        let given_up = format!("{prefix}/given-up");
        let mut upload = store.upload(&given_up).await.unwrap();
        upload.part(Bytes::from_static(b"some")).await.unwrap();
        upload.abort().await.unwrap();
        assert_eq!(store.head(&given_up).await, Err(ObjectError::NotFound));

        for key in [key, odd, format!("{prefix}/b/copy"), parted] {
            store.delete(&key).await.unwrap();
            assert_eq!(store.head(&key).await, Err(ObjectError::NotFound));
        }
        store.delete(&format!("{prefix}/never")).await.unwrap();
        assert!(store.list(&format!("{prefix}/")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn in_memory() {
        behaves(&MemoryObjects::new(), "test").await;
    }
}
