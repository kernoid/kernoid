// SPDX-License-Identifier: MIT
//! Originals stored by their SHA-256 hash, on any storage: in memory, in a folder, and – with the feature `object`
//! or `s3` – in an object store such as S3. OPEN: kernoid.
//!
//! A store keeps bytes under the hash of those bytes and checks them on every read, so damaged or changed bytes are
//! reported, never returned. Storing the same bytes again changes nothing. Whether the bytes are plain or an
//! encrypted envelope is the caller's choice; the store only sees bytes.
//!
//! Long originals – recordings, films, scans of whole books – need not be held in memory: [`Blobs::put_reader`] stores
//! what a reader gives, [`Blobs::open`] and [`Blobs::open_range`] give a reader back. A reader of a whole original
//! checks it as it goes and fails at its end if the bytes do not have their hash.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
    path::{Path, PathBuf},
    sync::RwLock,
};

pub use kernoid_base::Sha256Hash;
use sha2::{Digest, Sha256};

#[cfg(feature = "object")]
mod object;

/// The bytes type of [`ObjectBlobs`]' async calls.
#[cfg(feature = "object")]
pub use bytes::Bytes;
#[cfg(feature = "object")]
pub use object::{ByteStream, ObjectBlobs, S3Config};
#[cfg(feature = "object")]
pub use object_store;

/// Why a store failed.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The file system.
    #[error("file system: {0}")]
    Io(#[from] io::Error),
    /// The object store.
    #[error("object store: {0}")]
    Object(String),
    /// Stored bytes that do not have the hash they are stored under.
    #[error("the original {0} is damaged")]
    Damaged(Sha256Hash),
}

/// Where originals are kept, by their hash.
pub trait Blobs: Send + Sync {
    /// Stores bytes under their hash and returns it. Storing them again changes nothing.
    fn put(&self, bytes: &[u8]) -> Result<Sha256Hash, BlobError>;

    /// The bytes stored under `hash`, checked against it; none if there are none.
    fn get(&self, hash: &Sha256Hash) -> Result<Option<Vec<u8>>, BlobError>;

    /// Whether bytes are stored under `hash`, without reading or checking them.
    fn contains(&self, hash: &Sha256Hash) -> Result<bool, BlobError>;

    /// The hashes of everything stored, in order.
    fn list(&self) -> Result<Vec<Sha256Hash>, BlobError>;

    /// Removes the bytes stored under `hash`; whether there were any. What else refers to them is the caller's
    /// concern: a store keeps no count of references.
    fn remove(&self, hash: &Sha256Hash) -> Result<bool, BlobError>;

    /// The length of the bytes stored under `hash`, without checking them; none if there are none.
    fn size(&self, hash: &Sha256Hash) -> Result<Option<u64>, BlobError> {
        Ok(self.get(hash)?.map(|bytes| bytes.len() as u64))
    }

    /// The bytes in `range` of what is stored under `hash`, cut to its end – to stream a long recording or film
    /// in parts. A part cannot be checked against the hash of the whole: a store that reads only the part (a
    /// folder, an object store) returns it unchecked; read everything with [`Blobs::get`] to check it.
    fn get_range(&self, hash: &Sha256Hash, range: Range<u64>) -> Result<Option<Vec<u8>>, BlobError> {
        Ok(self.get(hash)?.map(|bytes| cut(&bytes, range).to_vec()))
    }

    /// Stores what `reader` gives under its hash and returns it – without holding it all in memory, where the store
    /// can (a folder, an object store). Storing the same bytes again changes nothing.
    fn put_reader(&self, reader: &mut dyn Read) -> Result<Sha256Hash, BlobError> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        self.put(&bytes)
    }

    /// The bytes stored under `hash` as a reader, checked as they are read: at their end, a read fails (an error of
    /// the kind `InvalidData`) if they do not have the hash. None if there are none.
    fn open(&self, hash: &Sha256Hash) -> Result<Option<Box<dyn Read + Send>>, BlobError> {
        Ok(self.get(hash)?.map(|bytes| Box::new(io::Cursor::new(bytes)) as Box<dyn Read + Send>))
    }

    /// The bytes in `range` of what is stored under `hash` as a reader, cut to its end and unchecked, like
    /// [`Blobs::get_range`]. None if there are none.
    fn open_range(&self, hash: &Sha256Hash, range: Range<u64>) -> Result<Option<Box<dyn Read + Send>>, BlobError> {
        Ok(self.get_range(hash, range)?.map(|bytes| Box::new(io::Cursor::new(bytes)) as Box<dyn Read + Send>))
    }
}

/// A reader that checks what it reads against a hash and fails at the end if it differs.
pub(crate) struct Checked<R> {
    inner: R,
    hasher: Option<Sha256>,
    hash: Sha256Hash,
}

impl<R> Checked<R> {
    pub(crate) fn new(inner: R, hash: Sha256Hash) -> Self {
        Checked { inner, hasher: Some(Sha256::new()), hash }
    }
}

impl<R: Read> Read for Checked<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buffer)?;
        if n > 0 {
            if let Some(hasher) = &mut self.hasher {
                hasher.update(&buffer[..n]);
            }
        } else if !buffer.is_empty()
            && let Some(hasher) = self.hasher.take()
            && Sha256Hash(hasher.finalize().into()) != self.hash
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, BlobError::Damaged(self.hash)));
        }
        Ok(n)
    }
}

/// Reads `reader` to its end in parts of up to `part` bytes, handing each to `each`; returns the hash of it all.
pub(crate) fn in_parts(
    reader: &mut dyn Read,
    part: usize,
    mut each: impl FnMut(Vec<u8>) -> Result<(), BlobError>,
) -> Result<Sha256Hash, BlobError> {
    let mut hasher = Sha256::new();
    loop {
        let mut buffer = Vec::with_capacity(part);
        reader.take(part as u64).read_to_end(&mut buffer)?;
        if buffer.is_empty() {
            break;
        }
        hasher.update(&buffer);
        let full = buffer.len() == part;
        each(buffer)?;
        if !full {
            break;
        }
    }
    Ok(Sha256Hash(hasher.finalize().into()))
}

/// The part of `bytes` in `range`, cut to their end; empty if the range starts after it or is reversed.
fn cut(bytes: &[u8], range: Range<u64>) -> &[u8] {
    let len = bytes.len() as u64;
    let start = range.start.min(len);
    let end = range.end.clamp(start, len);
    &bytes[start as usize..end as usize]
}

/// The bytes if they have the hash, or [`BlobError::Damaged`].
fn checked(hash: &Sha256Hash, bytes: Vec<u8>) -> Result<Vec<u8>, BlobError> {
    if Sha256Hash::of(&bytes) == *hash { Ok(bytes) } else { Err(BlobError::Damaged(*hash)) }
}

/// Originals in memory, gone when the program ends – for tests and for what is only passed through.
#[derive(Debug, Default)]
pub struct MemoryBlobs {
    blobs: RwLock<BTreeMap<Sha256Hash, Vec<u8>>>,
}

impl MemoryBlobs {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Blobs for MemoryBlobs {
    fn put(&self, bytes: &[u8]) -> Result<Sha256Hash, BlobError> {
        let hash = Sha256Hash::of(bytes);
        self.blobs.write().expect("not poisoned").entry(hash).or_insert_with(|| bytes.to_vec());
        Ok(hash)
    }

    fn get(&self, hash: &Sha256Hash) -> Result<Option<Vec<u8>>, BlobError> {
        let bytes = self.blobs.read().expect("not poisoned").get(hash).cloned();
        bytes.map(|bytes| checked(hash, bytes)).transpose()
    }

    fn contains(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        Ok(self.blobs.read().expect("not poisoned").contains_key(hash))
    }

    fn list(&self) -> Result<Vec<Sha256Hash>, BlobError> {
        Ok(self.blobs.read().expect("not poisoned").keys().copied().collect())
    }

    fn remove(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        Ok(self.blobs.write().expect("not poisoned").remove(hash).is_some())
    }

    fn size(&self, hash: &Sha256Hash) -> Result<Option<u64>, BlobError> {
        Ok(self.blobs.read().expect("not poisoned").get(hash).map(|bytes| bytes.len() as u64))
    }
}

/// Originals as files in a folder: `sha256/<first two digits>/<all 64 digits>`.
///
/// A file is written next to its place and renamed into it, so that a file under a hash is always complete.
#[derive(Debug, Clone)]
pub struct FolderBlobs {
    root: PathBuf,
}

impl FolderBlobs {
    /// The store in `folder`, created if needed.
    pub fn open(folder: &Path) -> Result<Self, BlobError> {
        let root = folder.join("sha256");
        fs::create_dir_all(&root)?;
        Ok(FolderBlobs { root })
    }

    fn path(&self, hash: &Sha256Hash) -> PathBuf {
        let hex = hash.hex();
        self.root.join(&hex[..2]).join(hex)
    }
}

impl Blobs for FolderBlobs {
    fn put(&self, bytes: &[u8]) -> Result<Sha256Hash, BlobError> {
        let hash = Sha256Hash::of(bytes);
        let path = self.path(&hash);
        if !path.exists() {
            fs::create_dir_all(path.parent().expect("a file in a folder"))?;
            let partial = path.with_extension(format!("partial-{}", hex_suffix()));
            fs::write(&partial, bytes)?;
            fs::rename(&partial, &path)?;
        }
        Ok(hash)
    }

    fn get(&self, hash: &Sha256Hash) -> Result<Option<Vec<u8>>, BlobError> {
        match fs::read(self.path(hash)) {
            Ok(bytes) => checked(hash, bytes).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn contains(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        Ok(self.path(hash).is_file())
    }

    fn list(&self) -> Result<Vec<Sha256Hash>, BlobError> {
        let mut hashes = Vec::new();
        for folder in fs::read_dir(&self.root)? {
            let folder = folder?;
            if !folder.file_type()?.is_dir() {
                continue;
            }
            for file in fs::read_dir(folder.path())? {
                let name = file?.file_name();
                if let Some(hash) = name.to_str().and_then(|name| format!("sha256:{name}").parse().ok()) {
                    hashes.push(hash);
                }
            }
        }
        hashes.sort();
        Ok(hashes)
    }

    fn remove(&self, hash: &Sha256Hash) -> Result<bool, BlobError> {
        remove_file(&self.path(hash))
    }

    fn size(&self, hash: &Sha256Hash) -> Result<Option<u64>, BlobError> {
        match fs::metadata(self.path(hash)) {
            Ok(meta) => Ok(Some(meta.len())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn get_range(&self, hash: &Sha256Hash, range: Range<u64>) -> Result<Option<Vec<u8>>, BlobError> {
        let Some(mut reader) = self.open_range(hash, range)? else { return Ok(None) };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn put_reader(&self, reader: &mut dyn Read) -> Result<Sha256Hash, BlobError> {
        // Written beside the store's folders, then renamed into place once the hash is known.
        let partial = self.root.join(format!("incoming-{}", hex_suffix()));
        let mut file = fs::File::create(&partial)?;
        let written = in_parts(reader, 1 << 20, |part| Ok(io::Write::write_all(&mut file, &part)?));
        let hash = match written.and_then(|hash| Ok((hash, file.sync_all()?))) {
            Ok((hash, ())) => hash,
            Err(error) => {
                let _ = fs::remove_file(&partial);
                return Err(error);
            }
        };
        drop(file);
        let path = self.path(&hash);
        if path.exists() {
            fs::remove_file(&partial)?;
        } else {
            fs::create_dir_all(path.parent().expect("a file in a folder"))?;
            fs::rename(&partial, &path)?;
        }
        Ok(hash)
    }

    fn open(&self, hash: &Sha256Hash) -> Result<Option<Box<dyn Read + Send>>, BlobError> {
        match fs::File::open(self.path(hash)) {
            Ok(file) => Ok(Some(Box::new(Checked::new(io::BufReader::new(file), *hash)))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn open_range(&self, hash: &Sha256Hash, range: Range<u64>) -> Result<Option<Box<dyn Read + Send>>, BlobError> {
        let mut file = match fs::File::open(self.path(hash)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let len = file.metadata()?.len();
        let start = range.start.min(len);
        let end = range.end.clamp(start, len);
        file.seek(SeekFrom::Start(start))?;
        Ok(Some(Box::new(file.take(end - start))))
    }
}

/// Removes a file; whether there was one.
fn remove_file(path: &Path) -> Result<bool, BlobError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// A random suffix for a file being written, so that two writers never share one.
pub(crate) fn hex_suffix() -> String {
    let bytes: [u8; 8] = kernoid_base::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A temporary folder, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("kernoid-blob-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn behaves(store: &dyn Blobs) {
        let hash = store.put(b"<Invoice/>").unwrap();
        assert_eq!(hash, Sha256Hash::of(b"<Invoice/>"));
        assert_eq!(store.put(b"<Invoice/>").unwrap(), hash);
        assert_eq!(store.get(&hash).unwrap().as_deref(), Some(&b"<Invoice/>"[..]));
        assert!(store.contains(&hash).unwrap());
        let other = Sha256Hash::of(b"other");
        assert_eq!(store.get(&other).unwrap(), None);
        assert!(!store.contains(&other).unwrap());
        let empty = store.put(b"").unwrap();
        let mut expected = vec![hash, empty];
        expected.sort();
        assert_eq!(store.list().unwrap(), expected);

        assert_eq!(store.size(&hash).unwrap(), Some(10));
        assert_eq!(store.size(&other).unwrap(), None);
        assert_eq!(store.get_range(&hash, 1..8).unwrap().as_deref(), Some(&b"Invoice"[..]));
        assert_eq!(store.get_range(&hash, 8..100).unwrap().as_deref(), Some(&b"/>"[..]));
        assert_eq!(store.get_range(&hash, 50..60).unwrap().as_deref(), Some(&b""[..]));
        assert_eq!(store.get_range(&other, 0..1).unwrap(), None);

        // Streaming: stored from a reader in parts, read back as a reader, checked.
        let long: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let streamed = store.put_reader(&mut &long[..]).unwrap();
        assert_eq!(streamed, Sha256Hash::of(&long));
        assert_eq!(store.put_reader(&mut &long[..]).unwrap(), streamed, "again: nothing changes");
        let mut back = Vec::new();
        store.open(&streamed).unwrap().unwrap().read_to_end(&mut back).unwrap();
        assert!(back == long, "read back as it was");
        let mut part = Vec::new();
        store.open_range(&streamed, 1_000_000..1_000_010).unwrap().unwrap().read_to_end(&mut part).unwrap();
        assert_eq!(part, long[1_000_000..1_000_010]);
        assert!(store.open(&other).unwrap().is_none() && store.open_range(&other, 0..1).unwrap().is_none());
        assert!(store.remove(&streamed).unwrap());

        assert!(store.remove(&empty).unwrap());
        assert!(!store.remove(&empty).unwrap());
        assert!(!store.contains(&empty).unwrap());
        assert_eq!(store.list().unwrap(), vec![hash]);
    }

    #[test]
    fn in_memory() {
        behaves(&MemoryBlobs::new());
    }

    #[test]
    fn in_a_folder() {
        let scratch = Scratch::new("folder");
        let store = FolderBlobs::open(&scratch.0).unwrap();
        behaves(&store);
        let reopened = FolderBlobs::open(&scratch.0).unwrap();
        assert_eq!(reopened.list().unwrap().len(), 1);
    }

    #[test]
    fn damaged_bytes_are_reported() {
        let scratch = Scratch::new("damaged");
        let store = FolderBlobs::open(&scratch.0).unwrap();
        let hash = store.put(b"original").unwrap();
        fs::write(store.path(&hash), b"changed").unwrap();
        assert!(matches!(store.get(&hash), Err(BlobError::Damaged(h)) if h == hash));
        let mut read = Vec::new();
        let error = store.open(&hash).unwrap().unwrap().read_to_end(&mut read).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "a reader fails at the end");
    }
}
