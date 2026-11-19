// SPDX-License-Identifier: MIT
//! Originals in an object store – S3 and everything `object_store` reaches: `sha256/<two digits>/<64 digits>` below
//! a prefix of the caller's choice.
//!
//! [`Blobs`] is synchronous; the object store is not. Every call runs on a runtime the store has – a small one of its
//! own, or one the program hands over ([`ObjectBlobs::with_handle`]) – on a helper thread, so that it works from plain
//! threads as well as from within another async runtime. Stores below other prefixes share it ([`ObjectBlobs::with_prefix`]).
//! An async program may also call the async methods ([`ObjectBlobs::get_async`], [`ObjectBlobs::stream`] …): they
//! run on the same runtime and are awaited from any other.
//!
//! Long originals are written in parts (a multipart upload below `incoming/`, moved to their place once their hash is
//! known) and read as a stream of parts, never as a whole.

use std::{
    io::{self, Read},
    ops::Range,
    pin::Pin,
    sync::{Arc, mpsc},
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use object_store::{GetOptions, GetRange, ObjectStore, ObjectStoreExt, PutPayload, path::Path};
use tokio::runtime::{Handle, Runtime};

use crate::{BlobError, Blobs, Checked, Sha256Hash, checked, in_parts};

/// The size of a part of an upload, and of what a reader asks for at a time: 8 MiB (S3 asks at least 5 MiB a part).
const PART: usize = 8 << 20;

/// A stream of the bytes of an original, in parts.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, BlobError>> + Send>>;

/// Where an S3 bucket is and how to reach it.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Config {
    /// The bucket.
    pub bucket: String,
    /// The region, e.g. `eu-central-1`.
    pub region: String,
    /// The endpoint of self-hosted object storage (MinIO, Garage, Ceph); none for AWS.
    pub endpoint: Option<String>,
    /// The access key.
    pub access_key_id: String,
    /// The secret key.
    pub secret_access_key: String,
    /// Whether plain HTTP is allowed – for a store on the same machine only.
    pub allow_http: bool,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

/// A runtime of the store's own, shut down without waiting when the last store using it is dropped – also from
/// within an async context, where dropping a runtime the usual way is not allowed.
struct Own(Option<Runtime>);

impl Drop for Own {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// Originals in an object store.
#[derive(Clone)]
pub struct ObjectBlobs {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
    handle: Handle,
    _own: Option<Arc<Own>>,
}

impl std::fmt::Debug for ObjectBlobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectBlobs").field("inner", &self.inner.to_string()).field("prefix", &self.prefix).finish()
    }
}

fn store_error(error: object_store::Error) -> BlobError {
    BlobError::Object(error.to_string())
}

fn not_found(error: &object_store::Error) -> bool {
    matches!(error, object_store::Error::NotFound { .. })
}

fn prefix_of(prefix: &str) -> String {
    prefix.trim_matches('/').to_owned()
}

impl ObjectBlobs {
    /// Originals in any object store, below `prefix` (empty for the top), on a small runtime of their own.
    pub fn new(inner: Arc<dyn ObjectStore>, prefix: &str) -> Result<Self, BlobError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("kernoid-blob")
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        Ok(ObjectBlobs { inner, prefix: prefix_of(prefix), handle, _own: Some(Arc::new(Own(Some(runtime)))) })
    }

    /// Originals in any object store, below `prefix`, on the program's runtime – no runtime of their own. The
    /// synchronous calls still run on a helper thread; call them from async code in `spawn_blocking`, or use the async
    /// methods.
    pub fn with_handle(inner: Arc<dyn ObjectStore>, prefix: &str, handle: Handle) -> Self {
        ObjectBlobs { inner, prefix: prefix_of(prefix), handle, _own: None }
    }

    /// The same object store below another prefix – one per organisation, say – sharing its connections and runtime.
    pub fn with_prefix(&self, prefix: &str) -> Self {
        ObjectBlobs { prefix: prefix_of(prefix), ..self.clone() }
    }

    /// The prefix the originals are below.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Originals in an S3 bucket, below `prefix`.
    #[cfg(feature = "s3")]
    pub fn s3(config: &S3Config, prefix: &str) -> Result<Self, BlobError> {
        Self::new(s3_store(config)?, prefix)
    }

    fn root(&self) -> Path {
        if self.prefix.is_empty() { Path::from("sha256") } else { Path::from(format!("{}/sha256", self.prefix)) }
    }

    fn path(&self, hash: &Sha256Hash) -> Path {
        let hex = hash.hex();
        self.root().join(&hex[..2]).join(hex.as_str())
    }

    fn incoming(&self) -> Path {
        let name = format!("incoming/{}", crate::hex_suffix());
        if self.prefix.is_empty() { Path::from(name) } else { Path::from(format!("{}/{name}", self.prefix)) }
    }

    /// Runs `work` on the store's runtime, on a helper thread, and waits for it.
    fn run<T: Send>(&self, work: impl Future<Output = T> + Send) -> T {
        std::thread::scope(|scope| scope.spawn(|| self.handle.block_on(work)).join().expect("object store call"))
    }

    /// Runs `work` on the store's runtime and awaits it from whichever runtime the caller is on.
    async fn spawn<T: Send + 'static>(&self, work: impl Future<Output = T> + Send + 'static) -> T {
        self.handle.spawn(work).await.expect("object store task")
    }

    /// The bytes stored under `hash`, checked against it; none if there are none.
    pub async fn get_async(&self, hash: &Sha256Hash) -> Result<Option<Bytes>, BlobError> {
        let (inner, path, hash) = (self.inner.clone(), self.path(hash), *hash);
        self.spawn(async move {
            let bytes = match inner.get(&path).await {
                Ok(result) => result.bytes().await.map_err(store_error)?,
                Err(error) if not_found(&error) => return Ok(None),
                Err(error) => return Err(store_error(error)),
            };
            if Sha256Hash::of(&bytes) == hash { Ok(Some(bytes)) } else { Err(BlobError::Damaged(hash)) }
        })
        .await
    }

    /// Stores bytes under their hash, without copying them, and returns it.
    pub async fn put_async(&self, bytes: Bytes) -> Result<Sha256Hash, BlobError> {
        let hash = Sha256Hash::of(&bytes);
        let (inner, path) = (self.inner.clone(), self.path(&hash));
        self.spawn(async move {
            match inner.head(&path).await {
                Ok(_) => return Ok(hash),
                Err(error) if not_found(&error) => {}
                Err(error) => return Err(store_error(error)),
            }
            inner.put(&path, PutPayload::from(bytes)).await.map_err(store_error)?;
            Ok(hash)
        })
        .await
    }

    /// The length of the bytes stored under `hash`; none if there are none.
    pub async fn size_async(&self, hash: &Sha256Hash) -> Result<Option<u64>, BlobError> {
        let (inner, path) = (self.inner.clone(), self.path(hash));
        self.spawn(async move {
            match inner.head(&path).await {
                Ok(meta) => Ok(Some(meta.size)),
                Err(error) if not_found(&error) => Ok(None),
                Err(error) => Err(store_error(error)),
            }
        })
        .await
    }

    /// Removes the bytes stored under `hash`; whether there were any.
    pub async fn remove_async(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        let (inner, path) = (self.inner.clone(), self.path(hash));
        self.spawn(async move {
            match inner.head(&path).await {
                Ok(_) => {}
                Err(error) if not_found(&error) => return Ok(false),
                Err(error) => return Err(store_error(error)),
            }
            match inner.delete(&path).await {
                Ok(()) => Ok(true),
                Err(error) if not_found(&error) => Ok(true),
                Err(error) => Err(store_error(error)),
            }
        })
        .await
    }

    /// The bytes stored under `hash` – or those in `range`, cut to the end – as a stream of parts, with the length of
    /// the whole; none if there are none. Made for an HTTP answer, with `Range` too: the stream is read on the store's
    /// runtime and handed over part by part. The whole is checked against the hash and its stream ends with
    /// [`BlobError::Damaged`] if it differs; a range cannot be checked.
    pub async fn stream(
        &self,
        hash: &Sha256Hash,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ByteStream)>, BlobError> {
        let (inner, path, hash) = (self.inner.clone(), self.path(hash), *hash);
        let opened = self
            .spawn(async move {
                let size = match inner.head(&path).await {
                    Ok(meta) => meta.size,
                    Err(error) if not_found(&error) => return Ok(None),
                    Err(error) => return Err(store_error(error)),
                };
                let range = range.map(|r| {
                    let start = r.start.min(size);
                    start..r.end.clamp(start, size)
                });
                if range.as_ref().is_some_and(|r| r.is_empty()) {
                    return Ok(Some((size, None)));
                }
                let options = GetOptions { range: range.clone().map(GetRange::Bounded), ..GetOptions::default() };
                let result = inner.get_opts(&path, options).await.map_err(store_error)?;
                Ok(Some((size, Some((result.into_stream(), range.is_none())))))
            })
            .await?;
        let Some((size, stream)) = opened else { return Ok(None) };
        let Some((stream, whole)) = stream else {
            return Ok(Some((size, Box::pin(futures_util::stream::empty()) as ByteStream)));
        };
        // Polled on the store's runtime; the parts come over a channel of a few.
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, BlobError>>(4);
        self.handle.spawn(async move {
            let mut stream = stream;
            let mut hasher = whole.then(<sha2::Sha256 as sha2::Digest>::new);
            while let Some(part) = stream.next().await {
                let part = part.map_err(store_error);
                if let (Ok(bytes), Some(hasher)) = (&part, &mut hasher) {
                    sha2::Digest::update(hasher, bytes);
                }
                let failed = part.is_err();
                if sender.send(part).await.is_err() || failed {
                    return;
                }
            }
            if let Some(hasher) = hasher
                && Sha256Hash(sha2::Digest::finalize(hasher).into()) != hash
            {
                let _ = sender.send(Err(BlobError::Damaged(hash))).await;
            }
        });
        let parts = futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|part| (part, receiver))
        });
        Ok(Some((size, Box::pin(parts) as ByteStream)))
    }
}

/// An S3 store as `object_store` makes it.
#[cfg(feature = "s3")]
pub(crate) fn s3_store(config: &S3Config) -> Result<Arc<dyn ObjectStore>, BlobError> {
    let mut builder = object_store::aws::AmazonS3Builder::new()
        .with_region(&config.region)
        .with_bucket_name(&config.bucket)
        .with_access_key_id(&config.access_key_id)
        .with_secret_access_key(&config.secret_access_key)
        .with_allow_http(config.allow_http);
    if let Some(endpoint) = &config.endpoint {
        // Self-hosted object storage is addressed by path, not by a bucket subdomain.
        builder = builder.with_endpoint(endpoint).with_virtual_hosted_style_request(false);
    }
    Ok(Arc::new(builder.build().map_err(store_error)?))
}

/// A reader of a stream of parts that is polled on another runtime.
struct Parts {
    receiver: mpsc::Receiver<Result<Bytes, BlobError>>,
    current: Bytes,
}

impl Read for Parts {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.current.is_empty() {
            match self.receiver.recv() {
                Ok(Ok(bytes)) => self.current = bytes,
                Ok(Err(BlobError::Io(error))) => return Err(error),
                Ok(Err(error)) => return Err(io::Error::other(error)),
                Err(_) => return Ok(0),
            }
        }
        let n = buffer.len().min(self.current.len());
        buffer[..n].copy_from_slice(&self.current.split_to(n));
        Ok(n)
    }
}

impl ObjectBlobs {
    /// A reader of `range` of the object at `path` (all of it if none), fed from the store's runtime.
    fn reader(&self, path: Path, range: Option<Range<u64>>) -> Result<Parts, BlobError> {
        let (sender, receiver) = mpsc::sync_channel::<Result<Bytes, BlobError>>(4);
        let inner = self.inner.clone();
        let (ready, opened) = mpsc::sync_channel::<Result<(), BlobError>>(1);
        self.handle.spawn(async move {
            let options = GetOptions { range: range.map(GetRange::Bounded), ..GetOptions::default() };
            let mut stream = match inner.get_opts(&path, options).await {
                Ok(result) => {
                    let _ = ready.send(Ok(()));
                    result.into_stream()
                }
                Err(error) => {
                    let _ = ready.send(Err(store_error(error)));
                    return;
                }
            };
            while let Some(part) = stream.next().await {
                let failed = part.is_err();
                // A full channel waits on a thread of its own, not on the runtime's.
                let sender = sender.clone();
                let sent = tokio::task::spawn_blocking(move || sender.send(part.map_err(store_error)).is_ok()).await;
                if failed || !matches!(sent, Ok(true)) {
                    return;
                }
            }
        });
        opened.recv().map_err(|_| BlobError::Object("the object store's runtime stopped".into()))??;
        Ok(Parts { receiver, current: Bytes::new() })
    }
}

impl Blobs for ObjectBlobs {
    fn put(&self, bytes: &[u8]) -> Result<Sha256Hash, BlobError> {
        let hash = Sha256Hash::of(bytes);
        if !self.contains(&hash)? {
            let path = self.path(&hash);
            let payload = PutPayload::from(bytes.to_vec());
            self.run(async { self.inner.put(&path, payload).await }).map_err(store_error)?;
        }
        Ok(hash)
    }

    fn get(&self, hash: &Sha256Hash) -> Result<Option<Vec<u8>>, BlobError> {
        let path = self.path(hash);
        let bytes = self.run(async {
            match self.inner.get(&path).await {
                Ok(result) => result.bytes().await.map(Some),
                Err(object_store::Error::NotFound { .. }) => Ok(None),
                Err(error) => Err(error),
            }
        });
        bytes.map_err(store_error)?.map(|bytes| checked(hash, bytes.to_vec())).transpose()
    }

    fn contains(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        let path = self.path(hash);
        match self.run(async { self.inner.head(&path).await }) {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(error) => Err(store_error(error)),
        }
    }

    fn list(&self) -> Result<Vec<Sha256Hash>, BlobError> {
        let root = self.root();
        let found: Vec<Result<String, object_store::Error>> = self.run(async {
            self.inner
                .list(Some(&root))
                .map(|meta| meta.map(|meta| meta.location.filename().unwrap_or("").to_owned()))
                .collect()
                .await
        });
        let mut hashes = Vec::new();
        for name in found {
            if let Ok(hash) = format!("sha256:{}", name.map_err(store_error)?).parse() {
                hashes.push(hash);
            }
        }
        hashes.sort();
        Ok(hashes)
    }

    fn remove(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        if !self.contains(hash)? {
            return Ok(false);
        }
        let path = self.path(hash);
        match self.run(async { self.inner.delete(&path).await }) {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(true),
            Err(error) => Err(store_error(error)),
        }
    }

    fn size(&self, hash: &Sha256Hash) -> Result<Option<u64>, BlobError> {
        let path = self.path(hash);
        match self.run(async { self.inner.head(&path).await }) {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(store_error(error)),
        }
    }

    fn get_range(&self, hash: &Sha256Hash, range: Range<u64>) -> Result<Option<Vec<u8>>, BlobError> {
        let Some(mut reader) = self.open_range(hash, range)? else { return Ok(None) };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn put_reader(&self, reader: &mut dyn Read) -> Result<Sha256Hash, BlobError> {
        let incoming = self.incoming();
        let mut upload = self.run(async { self.inner.put_multipart(&incoming).await }).map_err(store_error)?;
        let sent = in_parts(reader, PART, |part| {
            let part = upload.put_part(PutPayload::from(part));
            self.run(part).map_err(store_error)
        });
        let hash = match sent {
            Ok(hash) => hash,
            Err(error) => {
                let _ = self.run(async { upload.abort().await });
                return Err(error);
            }
        };
        self.run(async { upload.complete().await }).map_err(store_error)?;
        let path = self.path(&hash);
        self.run(async {
            match self.inner.head(&path).await {
                Ok(_) => self.inner.delete(&incoming).await,
                Err(error) if not_found(&error) => self.inner.rename(&incoming, &path).await,
                Err(error) => Err(error),
            }
        })
        .map_err(store_error)?;
        Ok(hash)
    }

    fn open(&self, hash: &Sha256Hash) -> Result<Option<Box<dyn Read + Send>>, BlobError> {
        if !self.contains(hash)? {
            return Ok(None);
        }
        Ok(Some(Box::new(Checked::new(self.reader(self.path(hash), None)?, *hash))))
    }

    fn open_range(&self, hash: &Sha256Hash, range: Range<u64>) -> Result<Option<Box<dyn Read + Send>>, BlobError> {
        let Some(len) = self.size(hash)? else { return Ok(None) };
        let start = range.start.min(len);
        let end = range.end.clamp(start, len);
        if start == end {
            return Ok(Some(Box::new(io::empty())));
        }
        Ok(Some(Box::new(self.reader(self.path(hash), Some(start..end))?)))
    }
}

#[cfg(test)]
mod tests {
    use object_store::memory::InMemory;

    use super::*;

    #[test]
    fn in_an_object_store() {
        let inner = Arc::new(InMemory::new());
        let store = ObjectBlobs::new(inner.clone(), "/archive/").unwrap();
        crate::tests::behaves(&store);
        let hash = Sha256Hash::of(b"<Invoice/>");
        let at = Path::from(format!("archive/sha256/{}/{}", &hash.hex()[..2], hash.hex()));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async { inner.put(&at, PutPayload::from(b"changed".to_vec())).await }).unwrap();
        assert!(matches!(store.get(&hash), Err(BlobError::Damaged(_))));
    }

    #[test]
    fn works_from_within_another_runtime() {
        let store = ObjectBlobs::new(Arc::new(InMemory::new()), "").unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let hash = runtime.block_on(async { store.put(b"inside").unwrap() });
        assert_eq!(store.get(&hash).unwrap().as_deref(), Some(&b"inside"[..]));
    }

    #[test]
    fn prefixes_share_one_store_and_runtime() {
        let one = ObjectBlobs::new(Arc::new(InMemory::new()), "org-1").unwrap();
        let two = one.with_prefix("/org-2/");
        assert_eq!(two.prefix(), "org-2");
        let hash = one.put(b"score").unwrap();
        assert!(one.contains(&hash).unwrap() && !two.contains(&hash).unwrap());
        drop(one);
        two.put(b"part").unwrap();
        assert_eq!(two.list().unwrap().len(), 1, "the runtime lives as long as a store uses it");
    }

    #[test]
    fn async_calls_and_streams_from_another_runtime() {
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // The program's runtime only; and a store with a runtime of its own, both awaited from the program's.
        for store in [
            ObjectBlobs::with_handle(inner.clone(), "a", runtime.handle().clone()),
            ObjectBlobs::new(inner.clone(), "b").unwrap(),
        ] {
            runtime.block_on(async {
                let long = Bytes::from((0..20_000_000u32).map(|i| (i % 253) as u8).collect::<Vec<u8>>());
                let hash = store.put_async(long.clone()).await.unwrap();
                assert_eq!(store.put_async(long.clone()).await.unwrap(), hash);
                assert_eq!(store.size_async(&hash).await.unwrap(), Some(20_000_000));
                assert!(store.get_async(&hash).await.unwrap().unwrap() == long);

                let (size, stream) = store.stream(&hash, None).await.unwrap().unwrap();
                let parts: Vec<Bytes> = stream.map(Result::unwrap).collect().await;
                assert_eq!(size, 20_000_000);
                assert!(parts.concat() == long[..]);
                let (_, stream) = store.stream(&hash, Some(19_999_990..30_000_000)).await.unwrap().unwrap();
                let parts: Vec<Bytes> = stream.map(Result::unwrap).collect().await;
                assert_eq!(parts.concat(), long[19_999_990..]);
                let (_, stream) = store.stream(&hash, Some(30_000_000..30_000_001)).await.unwrap().unwrap();
                assert_eq!(stream.count().await, 0);
                assert!(store.stream(&Sha256Hash::of(b"none"), None).await.unwrap().is_none());

                assert!(store.remove_async(&hash).await.unwrap());
                assert!(!store.remove_async(&hash).await.unwrap());
                assert_eq!(store.get_async(&hash).await.unwrap(), None);
            });
        }
        // Dropped within an async context: no panic.
        runtime.block_on(async { drop(ObjectBlobs::new(inner.clone(), "c").unwrap()) });
    }

    #[test]
    fn long_originals_go_up_in_parts_and_damage_is_reported_by_streams() {
        let inner = Arc::new(InMemory::new());
        let store = ObjectBlobs::new(inner.clone(), "").unwrap();
        let long: Vec<u8> = (0..(PART as u32 * 2 + 5)).map(|i| (i % 241) as u8).collect();
        let hash = store.put_reader(&mut &long[..]).unwrap();
        assert_eq!(hash, Sha256Hash::of(&long));
        let mut back = Vec::new();
        store.open(&hash).unwrap().unwrap().read_to_end(&mut back).unwrap();
        assert!(back == long);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let leftovers = runtime.block_on(async { inner.list(Some(&Path::from("incoming"))).count().await });
        assert_eq!(leftovers, 0, "nothing left below incoming/");

        let at = store.path(&hash);
        runtime.block_on(async { inner.put(&at, PutPayload::from(b"changed".to_vec())).await }).unwrap();
        let mut read = Vec::new();
        assert_eq!(
            store.open(&hash).unwrap().unwrap().read_to_end(&mut read).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let ends = runtime.block_on(async {
            let (_, stream) = store.stream(&hash, None).await.unwrap().unwrap();
            stream.collect::<Vec<_>>().await
        });
        assert!(matches!(ends.last(), Some(Err(BlobError::Damaged(_)))));
    }

    #[test]
    fn s3_secrets_are_not_shown() {
        let config = S3Config {
            bucket: "archive".into(),
            region: "eu-central-1".into(),
            endpoint: None,
            access_key_id: "key".into(),
            secret_access_key: "secret".into(),
            allow_http: false,
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("\"secret\"") && !shown.contains("\"key\""), "{shown}");
    }
}
