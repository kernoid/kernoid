// SPDX-License-Identifier: MIT
//! A device's vaults kept sealed (RFC 0010, 5): the store – keys of streams and persons, what was read – lives in
//! memory and goes to its file as a whole, sealed with XChaCha20-Poly1305 under a key the program keeps in the
//! system's key store (the apps' secure storage, the terminal app's keyring). Without the key the file says nothing
//! but its size. The file is `KVS1`, a nonce of 24 bytes and the sealed database; the magic is bound in as associated
//! data. It is written to a file beside it first and then renamed over, so that a crash leaves the old one.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use kernoid_spaces::store::Store;
use kernoid_spaces::{SyncError, streams::Streams, transport::Transport};

use crate::Result;

const MAGIC: &[u8; 4] = b"KVS1";

fn failed(message: impl Into<String>) -> SyncError {
    SyncError::State(message.into())
}

/// Where a device's sealed vaults are kept, and with which key.
#[derive(Clone)]
pub struct Sealed {
    path: PathBuf,
    key: [u8; 32],
    /// The store's count of changes when it was last written.
    written: u64,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed").field("path", &self.path).finish_non_exhaustive()
    }
}

/// Seals a database's bytes.
pub fn seal(key: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = kernoid_base::random();
    let sealed = XChaCha20Poly1305::new(key.into())
        .encrypt(&XNonce::from(nonce), Payload { msg: bytes, aad: MAGIC })
        .expect("sealing in memory");
    let mut out = Vec::with_capacity(4 + 24 + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

/// Opens what [`seal`] sealed.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 4 + 24 + 16 || &sealed[..4] != MAGIC {
        return Err(failed("not a sealed store of vaults"));
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(&XNonce::try_from(&sealed[4..28]).expect("24 bytes"), Payload { msg: &sealed[28..], aad: MAGIC })
        .map_err(|_| failed("the store of vaults does not open with this key"))
}

impl Sealed {
    /// The vaults sealed in `path` under `key` (none yet: an empty store), this device named after `name`.
    pub fn open(
        path: &Path,
        key: [u8; 32],
        name: &str,
        transport: Option<Arc<dyn Transport>>,
    ) -> Result<(Streams, Sealed)> {
        let store = match std::fs::read(path) {
            Ok(sealed) => Store::from_bytes(&open(&key, &sealed)?)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Store::in_memory()?,
            Err(error) => return Err(failed(format!("{}: {error}", path.display()))),
        };
        let streams = crate::open(store, name, transport)?;
        let written = changes(&streams);
        let sealed = Sealed { path: path.to_owned(), key, written };
        Ok((streams, sealed))
    }

    /// Writes the store if it changed since it was last written.
    pub fn save(&mut self, streams: &mut Streams) -> Result<()> {
        let now = changes(streams);
        if now == self.written && self.path.exists() {
            return Ok(());
        }
        let bytes = streams.store_mut().to_bytes()?;
        let partial = self.path.with_extension("sealing");
        std::fs::write(&partial, seal(&self.key, &bytes)).map_err(|e| failed(format!("{}: {e}", partial.display())))?;
        std::fs::rename(&partial, &self.path).map_err(|e| failed(format!("{}: {e}", self.path.display())))?;
        self.written = now;
        Ok(())
    }
}

/// How many rows the store's connection changed so far: what tells that it needs writing.
fn changes(streams: &Streams) -> u64 {
    streams.store().connection().total_changes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_opens_only_with_its_key() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"database");
        assert_eq!(open(&key, &sealed).unwrap(), b"database");
        assert!(open(&[8u8; 32], &sealed).is_err());
        let mut forged = sealed.clone();
        forged[30] ^= 1;
        assert!(open(&key, &forged).is_err());
    }

    #[test]
    fn a_store_comes_back_from_its_file() {
        let dir = std::env::temp_dir().join(format!("kernoid-vault-sealed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vaults.sealed");
        let key = [3u8; 32];
        let (mut streams, mut sealed) = Sealed::open(&path, key, "laptop", None).unwrap();
        let device =
            streams.store().connection().query_row("SELECT value FROM settings", [], |r| r.get::<_, String>(0));
        sealed.save(&mut streams).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"laptop"), "nothing readable in the file");
        let (again, _) = Sealed::open(&path, key, "other", None).unwrap();
        let back = again.store().connection().query_row("SELECT value FROM settings", [], |r| r.get::<_, String>(0));
        assert_eq!(device.unwrap(), back.unwrap(), "the device keeps its name");
        assert!(Sealed::open(&path, [4u8; 32], "x", None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
