// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encryption of content before it leaves kernoid (whitepaper, Security: "a key per tenant").
//!
//! - The **main key** comes from the configuration. It only wraps tenant keys; losing it loses all content.
//! - Each tenant has **tenant keys** (random, 256 bit), stored wrapped by the main key in `tenant_keys`, numbered from
//!   1. Wrapping binds the key to its tenant and number, so a wrapped key cannot be moved to another tenant.
//! - **Content** is encrypted with XChaCha20-Poly1305 in the STREAM construction (Hoang, Reyhanitabar, Rogaway,
//!   Vizár 2015) in chunks of 64 KiB, each with its own tag; the last chunk is marked. Every chunk authenticates the
//!   header and the object's path, so reordering, truncating, extending or moving an object to another path or
//!   tenant is detected.
//!
//! Sealed format, version 1:
//!
//! ```text
//! "KRNO" | version 1 (1 byte) | key number (u32, big endian) | stream nonce (19 random bytes) | chunks …
//! chunk: ciphertext of 64 KiB plaintext + 16-byte tag; the last chunk has less than 64 KiB (possibly none)
//! ```

use std::fmt;

use sha2::{Digest, Sha256};

use aead_stream::{DecryptorBE32, EncryptorBE32, StreamBE32};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
const MAGIC: &[u8; 4] = b"KRNO";
const VERSION: u8 = 1;
const STREAM_NONCE_LEN: usize = 19;
const HEADER_LEN: usize = MAGIC.len() + 1 + 4 + STREAM_NONCE_LEN;
const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const WRAP_NONCE_LEN: usize = 24;
const WRAP_CONTEXT: &[u8] = b"kernoid/tenant-key/v1";

/// Errors say as little as possible: which check failed is no business of a caller.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("no randomness available")]
    Random,
    #[error("not sealed content of a known version")]
    Format,
    #[error("content or key failed authentication")]
    Authentication,
    #[error("a key must be {KEY_LEN} bytes as 64 hex characters")]
    InvalidKey,
}

/// A 256-bit key; zeroed when dropped, never printed.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0; KEY_LEN]);
        getrandom::fill(bytes.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self(bytes))
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let hex = hex.trim().as_bytes();
        if hex.len() != KEY_LEN * 2 {
            return Err(CryptoError::InvalidKey);
        }
        let mut bytes = Zeroizing::new([0; KEY_LEN]);
        for (byte, pair) in bytes.iter_mut().zip(hex.as_chunks::<2>().0) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = <&chacha20poly1305::Key>::try_from(self.0.as_slice()).expect("KEY_LEN is the key size of XChaCha20");
        XChaCha20Poly1305::new(key)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(***)")
    }
}

fn nibble(c: u8) -> Result<u8, CryptoError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CryptoError::InvalidKey),
    }
}

type StreamNonce = aead_stream::Nonce<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>;

fn stream_nonce(bytes: &[u8]) -> Result<&StreamNonce, CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::Format)
}

fn xnonce(bytes: &[u8]) -> Result<&XNonce, CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::Format)
}

fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(bytes)
}

/// Identifies a main key without revealing it: the first 8 bytes of SHA-256 over a fixed context and the key.
pub fn fingerprint(key: &Key) -> [u8; 8] {
    let digest = Sha256::new().chain_update(b"kernoid/main-key-fingerprint/v1").chain_update(key.0.as_ref()).finalize();
    digest[..8].try_into().expect("SHA-256 is longer than 8 bytes")
}

fn wrap_aad(tenant: Uuid, number: u32) -> Vec<u8> {
    [WRAP_CONTEXT, tenant.as_bytes(), &number.to_be_bytes()].concat()
}

/// Wraps tenant key `key` (number `number` of `tenant`) with the main key: nonce followed by ciphertext and tag.
pub fn wrap(main: &Key, tenant: Uuid, number: u32, key: &Key) -> Result<Vec<u8>, CryptoError> {
    let nonce: [u8; WRAP_NONCE_LEN] = random()?;
    let aad = wrap_aad(tenant, number);
    let sealed = main
        .cipher()
        .encrypt(xnonce(&nonce)?, Payload { msg: key.0.as_ref(), aad: &aad })
        .map_err(|_| CryptoError::Authentication)?;
    Ok([&nonce[..], &sealed].concat())
}

/// Unwraps a key made by [`wrap`] for the same tenant and number.
pub fn unwrap(main: &Key, tenant: Uuid, number: u32, wrapped: &[u8]) -> Result<Key, CryptoError> {
    let (nonce, sealed) = wrapped.split_at_checked(WRAP_NONCE_LEN).ok_or(CryptoError::Format)?;
    let aad = wrap_aad(tenant, number);
    let plain = Zeroizing::new(
        main.cipher()
            .decrypt(xnonce(nonce)?, Payload { msg: sealed, aad: &aad })
            .map_err(|_| CryptoError::Authentication)?,
    );
    let bytes: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| CryptoError::Format)?;
    Ok(Key(Zeroizing::new(bytes)))
}

/// Seals a secret kernoid must read again (a signing key, a client secret of a connected service) with `key`,
/// bound to `context` – what it is and whose it is – so that it cannot be used for something else: nonce followed by
/// ciphertext and tag.
pub fn seal_secret(key: &Key, context: &[u8], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce: [u8; WRAP_NONCE_LEN] = random()?;
    let sealed = key
        .cipher()
        .encrypt(xnonce(&nonce)?, Payload { msg: secret, aad: context })
        .map_err(|_| CryptoError::Authentication)?;
    Ok([&nonce[..], &sealed].concat())
}

/// Opens a secret sealed by [`seal_secret`] with the same `context`.
pub fn open_secret(key: &Key, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (nonce, sealed) = sealed.split_at_checked(WRAP_NONCE_LEN).ok_or(CryptoError::Format)?;
    key.cipher()
        .decrypt(xnonce(nonce)?, Payload { msg: sealed, aad: context })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

/// Encrypts `plaintext`, stored at `path`, with tenant key number `number`.
pub fn seal(key: &Key, number: u32, path: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let stream_nonce: [u8; STREAM_NONCE_LEN] = random()?;
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + (plaintext.len() / CHUNK + 1) * TAG);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&stream_nonce);
    let aad = [&out[..], path.as_bytes()].concat();

    let mut encryptor = EncryptorBE32::from_aead(key.cipher(), self::stream_nonce(&stream_nonce)?);
    let (full, last) = plaintext.as_chunks::<CHUNK>();
    for chunk in full {
        out.extend(encryptor.encrypt_next(Payload { msg: chunk, aad: &aad }).map_err(|_| CryptoError::Authentication)?);
    }
    out.extend(encryptor.encrypt_last(Payload { msg: last, aad: &aad }).map_err(|_| CryptoError::Authentication)?);
    Ok(out)
}

/// The tenant key number `sealed` was encrypted with.
pub fn key_number(sealed: &[u8]) -> Result<u32, CryptoError> {
    if sealed.len() < HEADER_LEN + TAG || &sealed[..4] != MAGIC || sealed[4] != VERSION {
        return Err(CryptoError::Format);
    }
    Ok(u32::from_be_bytes(sealed[5..9].try_into().map_err(|_| CryptoError::Format)?))
}

/// Decrypts content made by [`seal`] for the same `path`, with the key named by [`key_number`].
pub fn open(key: &Key, path: &str, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    key_number(sealed)?;
    let (header, mut rest) = sealed.split_at(HEADER_LEN);
    let stream_nonce = &header[HEADER_LEN - STREAM_NONCE_LEN..];
    let aad = [header, path.as_bytes()].concat();

    let mut decryptor = DecryptorBE32::from_aead(key.cipher(), self::stream_nonce(stream_nonce)?);
    let mut out = Vec::with_capacity(rest.len());
    // A full chunk is followed by at least the last chunk's tag; a rest of exactly one full chunk can only be a
    // last chunk, which its flag then refuses – so cutting a stream at a chunk boundary is detected.
    while rest.len() > CHUNK + TAG {
        let (chunk, tail) = rest.split_at(CHUNK + TAG);
        out.extend(decryptor.decrypt_next(Payload { msg: chunk, aad: &aad }).map_err(|_| CryptoError::Authentication)?);
        rest = tail;
    }
    out.extend(decryptor.decrypt_last(Payload { msg: rest, aad: &aad }).map_err(|_| CryptoError::Authentication)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "tenants/00000000-0000-0000-0000-000000000001/mail/1";

    fn content(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn round_trip_at_chunk_boundaries() {
        let key = Key::random().unwrap();
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7] {
            let plain = content(len);
            let sealed = seal(&key, 7, PATH, &plain).unwrap();
            assert_eq!(key_number(&sealed).unwrap(), 7);
            assert_eq!(open(&key, PATH, &sealed).unwrap(), plain, "{len}");
            if len >= 16 {
                assert!(!sealed.windows(16).any(|window| window == &plain[..16]), "plaintext visible at {len}");
            }
        }
    }

    #[test]
    fn every_sealing_is_different() {
        let key = Key::random().unwrap();
        assert_ne!(seal(&key, 1, PATH, b"same").unwrap(), seal(&key, 1, PATH, b"same").unwrap());
    }

    #[test]
    fn tampering_is_detected() {
        let key = Key::random().unwrap();
        let plain = content(2 * CHUNK + 100);
        let sealed = seal(&key, 1, PATH, &plain).unwrap();

        for position in [0, 4, 5, 9, HEADER_LEN, HEADER_LEN + CHUNK + 3, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[position] ^= 1;
            assert!(open(&key, PATH, &changed).is_err(), "byte {position}");
        }
        // Cut at a chunk boundary, cut inside a chunk, extended, or chunks swapped.
        assert!(open(&key, PATH, &sealed[..HEADER_LEN + CHUNK + TAG]).is_err());
        assert!(open(&key, PATH, &sealed[..sealed.len() - 1]).is_err());
        assert!(open(&key, PATH, &[&sealed[..], &[0; 16]].concat()).is_err());
        let first = HEADER_LEN..HEADER_LEN + CHUNK + TAG;
        let second = HEADER_LEN + CHUNK + TAG..HEADER_LEN + 2 * (CHUNK + TAG);
        let swapped =
            [&sealed[..HEADER_LEN], &sealed[second], &sealed[first], &sealed[HEADER_LEN + 2 * (CHUNK + TAG)..]]
                .concat();
        assert_eq!(open(&key, PATH, &swapped), Err(CryptoError::Authentication));
    }

    #[test]
    fn content_is_bound_to_its_path_and_key() {
        let key = Key::random().unwrap();
        let sealed = seal(&key, 1, PATH, b"hello").unwrap();
        let other_path = "tenants/00000000-0000-0000-0000-000000000002/mail/1";
        assert_eq!(open(&key, other_path, &sealed), Err(CryptoError::Authentication));
        assert_eq!(open(&Key::random().unwrap(), PATH, &sealed), Err(CryptoError::Authentication));
        assert_eq!(key_number(b"not sealed at all, just text"), Err(CryptoError::Format));
    }

    #[test]
    fn wrapped_keys_are_bound_to_tenant_and_number() {
        let main = Key::random().unwrap();
        let key = Key::random().unwrap();
        let tenant = Uuid::from_u128(1);
        let wrapped = wrap(&main, tenant, 1, &key).unwrap();
        let unwrapped = unwrap(&main, tenant, 1, &wrapped).unwrap();
        assert_eq!(unwrapped.0.as_ref(), key.0.as_ref());
        assert!(unwrap(&main, Uuid::from_u128(2), 1, &wrapped).is_err());
        assert!(unwrap(&main, tenant, 2, &wrapped).is_err());
        assert!(unwrap(&Key::random().unwrap(), tenant, 1, &wrapped).is_err());
    }

    #[test]
    fn fingerprints_tell_keys_apart() {
        let (a, b) = (Key::random().unwrap(), Key::random().unwrap());
        assert_eq!(fingerprint(&a), fingerprint(&a.clone()));
        assert_ne!(fingerprint(&a), fingerprint(&b));
        assert!(!a.0.windows(8).any(|window| window == fingerprint(&a)));
    }

    #[test]
    fn sealed_secrets_are_bound_to_their_context() {
        let key = Key::random().unwrap();
        let sealed = seal_secret(&key, b"signing-key/instance-1/kid-1", b"private").unwrap();
        assert_eq!(open_secret(&key, b"signing-key/instance-1/kid-1", &sealed).unwrap().as_slice(), b"private");
        assert!(open_secret(&key, b"signing-key/instance-2/kid-1", &sealed).is_err());
        assert!(open_secret(&Key::random().unwrap(), b"signing-key/instance-1/kid-1", &sealed).is_err());
        assert_ne!(sealed, seal_secret(&key, b"signing-key/instance-1/kid-1", b"private").unwrap());
    }

    #[test]
    fn keys_from_hex() {
        let key = Key::from_hex(&"0f".repeat(KEY_LEN)).unwrap();
        assert_eq!(key.0.as_ref(), &[0x0f; KEY_LEN]);
        assert!(Key::from_hex(&"0F".repeat(KEY_LEN)).is_ok());
        for bad in ["", "00", &"0g".repeat(KEY_LEN), &"00".repeat(KEY_LEN + 1)] {
            assert_eq!(Key::from_hex(bad).unwrap_err(), CryptoError::InvalidKey);
        }
        assert_eq!(format!("{key:?}"), "Key(***)");
    }
}
