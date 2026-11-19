// SPDX-License-Identifier: MIT
//! The base of kernoid's foundation: the canonical encoding of JSON, hashes, identities of spaces, bytes as text and root
//! objects with their type. No I/O. The design is in kernoid's RFC 0010 (from aktujo's RFC 0001).

use std::{fmt, str::FromStr};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

mod canonical;

pub use canonical::{CanonicalError, MAX_SAFE_INTEGER, canonicalize, to_canonical_vec};

/// Text that is not what it should be.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a valid {what}: {text:?}")]
pub struct ParseError {
    /// What was expected.
    pub what: &'static str,
    /// The text.
    pub text: String,
}

impl ParseError {
    /// An error for `text`, which is not a valid `what`.
    pub fn new(what: &'static str, text: &str) -> Self {
        ParseError { what, text: text.to_owned() }
    }
}

/// Implements `Display`, `FromStr`, `Serialize` and `Deserialize` through the text of a type.
#[macro_export]
macro_rules! as_text {
    ($name:ty) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// A SHA-256 hash, written `sha256:` and 64 lower-case hexadecimal digits – of an original's bytes, of an event's
/// canonical encoding, of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Hash(pub [u8; 32]);

impl Sha256Hash {
    /// The hash of these bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Sha256Hash(Sha256::digest(bytes).into())
    }

    /// The 64 hexadecimal digits without the prefix – usable as a file name.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl FromStr for Sha256Hash {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || ParseError::new("hash", s);
        let digits = s.strip_prefix("sha256:").ok_or_else(invalid)?;
        if digits.len() != 64 || digits.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(invalid());
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(digits, &mut bytes).map_err(|_| invalid())?;
        Ok(Sha256Hash(bytes))
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

as_text!(Sha256Hash);

/// A new UUID of version 7 (RFC 9562) in lower case, from the time in milliseconds since 1970 and random bits.
pub fn uuid7(unix_ms: u64) -> String {
    let mut bytes: [u8; 16] = random();
    bytes[..6].copy_from_slice(&unix_ms.to_be_bytes()[2..]);
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    let h = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Whether `text` is a UUID in lower case, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// The identity of a space – what is shared and encrypted as a whole: a UUID in lower case, given when the space is
/// founded and never changed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId(String);

impl SpaceId {
    /// A new identity: a UUID of version 7 (RFC 9562) from the time in milliseconds since 1970 and random bits.
    pub fn generate(unix_ms: u64) -> Self {
        SpaceId(uuid7(unix_ms))
    }

    /// The identity as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SpaceId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_uuid(s) { Ok(SpaceId(s.to_owned())) } else { Err(ParseError::new("space identity", s)) }
    }
}

impl fmt::Display for SpaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

as_text!(SpaceId);

/// Bytes, written as base64url without padding (RFC 4648, section 5).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Bytes(pub Vec<u8>);

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({})", BASE64URL.encode(&self.0))
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64URL.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        BASE64URL.decode(text.as_bytes()).map(Bytes).map_err(|_| de::Error::custom("not base64url without padding"))
    }
}

/// Text in base64url without padding.
pub fn base64url(bytes: &[u8]) -> String {
    BASE64URL.encode(bytes)
}

/// Bytes from base64url without padding.
pub fn from_base64url(text: &str) -> Option<Vec<u8>> {
    BASE64URL.decode(text.as_bytes()).ok()
}

/// `N` random bytes from the operating system.
///
/// # Panics
///
/// If the operating system gives none.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system's random numbers");
    bytes
}

/// Deserialises an integer that is at most 2^53 − 1, as the canonical encoding requires.
pub fn safe_u64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value > MAX_SAFE_INTEGER {
        return Err(de::Error::custom(format!("{value} is larger than 2^53 - 1")));
    }
    Ok(value)
}

/// An object that can stand on its own – stored, sent, exported – and then carries its type as `"type"`.
pub trait Object {
    /// The type, e.g. `event` or `member_record`.
    const TYPE: &'static str;
}

/// Why JSON is not the expected root object.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectError {
    /// Not JSON that has a canonical encoding.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// A root object without its type, or of another type.
    #[error("expected an object of type {expected:?}, found {found:?}")]
    Type {
        /// The type expected.
        expected: &'static str,
        /// The type found, if any.
        found: Option<String>,
    },
    /// Of the right type, but not valid content of it.
    #[error("not a valid {0}: {1}")]
    Content(&'static str, String),
}

/// The canonical encoding of `value` as a root object: its members and its `type`.
pub fn to_root<T: Object + Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut json = serde_json::to_value(value).map_err(|e| CanonicalError::Json(e.to_string()))?;
    let Value::Object(members) = &mut json else {
        return Err(CanonicalError::Json(format!("a {} is not a JSON object", T::TYPE)));
    };
    members.insert("type".into(), T::TYPE.into());
    to_canonical_vec(&json)
}

/// The canonical encoding of a root object without its `signature`: what its author signs.
pub fn unsigned<T: Object + Serialize>(value: &T) -> Vec<u8> {
    let mut json = serde_json::to_value(value).expect("an object of the core is JSON");
    if let Value::Object(members) = &mut json {
        members.remove("signature");
        members.insert("type".into(), T::TYPE.into());
    }
    to_canonical_vec(&json).expect("an object of the core has a canonical encoding")
}

/// Reads a root object of type `T` from JSON in any formatting.
pub fn from_root<T: Object + DeserializeOwned>(json: &[u8]) -> Result<T, ObjectError> {
    let canonical = canonicalize(json)?;
    let mut value: Value = serde_json::from_slice(&canonical).map_err(|e| CanonicalError::Json(e.to_string()))?;
    match value.as_object_mut().and_then(|members| members.remove("type")) {
        Some(Value::String(found)) if found == T::TYPE => {}
        found => {
            let found = found.map(|t| t.as_str().map_or_else(|| t.to_string(), str::to_owned));
            return Err(ObjectError::Type { expected: T::TYPE, found });
        }
    }
    serde_json::from_value(value).map_err(|e| ObjectError::Content(T::TYPE, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Note {
        text: String,
    }

    impl Object for Note {
        const TYPE: &'static str = "note";
    }

    #[test]
    fn hashes_are_written_with_their_algorithm() {
        let hash = Sha256Hash::of(b"abc");
        let text = hash.to_string();
        assert_eq!(text, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(text.parse::<Sha256Hash>().unwrap(), hash);
        for bad in ["ba7816bf", "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", "sha256:00"]
        {
            assert!(bad.parse::<Sha256Hash>().is_err(), "{bad}");
        }
    }

    #[test]
    fn space_identities_are_uuids_of_version_7() {
        let id = SpaceId::generate(1_790_812_800_000);
        assert_eq!(id.as_str().parse::<SpaceId>().unwrap(), id);
        assert_eq!(&id.as_str()[14..15], "7");
        assert!(matches!(&id.as_str()[19..20], "8" | "9" | "a" | "b"));
        assert!(id.as_str().starts_with(&format!("{:012x}", 1_790_812_800_000u64)[..8]));
        assert_ne!(SpaceId::generate(1), SpaceId::generate(1));
        assert!("0192F1E4-0000-7000-8000-000000000001".parse::<SpaceId>().is_err());
    }

    #[test]
    fn bytes_are_base64url_without_padding() {
        let json = serde_json::to_string(&Bytes(vec![0xfb, 0xff])).unwrap();
        assert_eq!(json, "\"-_8\"");
        assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), Bytes(vec![0xfb, 0xff]));
        assert!(serde_json::from_str::<Bytes>("\"-_8=\"").is_err());
    }

    #[test]
    fn root_objects_carry_their_type() {
        let note = Note { text: "hi".into() };
        let json = to_root(&note).unwrap();
        assert_eq!(json, br#"{"text":"hi","type":"note"}"#);
        assert_eq!(from_root::<Note>(br#"{ "type": "note", "text": "hi" }"#).unwrap(), note);
        assert!(matches!(from_root::<Note>(br#"{"text":"hi"}"#), Err(ObjectError::Type { found: None, .. })));
        assert!(matches!(from_root::<Note>(br#"{"type":"x","text":"hi"}"#), Err(ObjectError::Type { .. })));
    }
}
