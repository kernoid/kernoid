// SPDX-License-Identifier: MIT
//! Streams (RFC 0012): a space as many logs – one per thing –, joined by a tree of keys, on hybrid post-quantum keys
//! ([`crate::pq`]).
//!
//! - The **roster** is the one strictly ordered list a relay reads: devices with the permissions the relay enforces,
//!   persons, each person's key (its seed sealed to its devices, chained back), and the links of the space stream to
//!   every person.
//! - A **stream** has a key per generation, chained back; **records** in it are events, new generations, links to the
//!   keys of streams below, or links sealed to a person (written into the person's stream without its key).
//! - The relay reads a stream for whoever shows a **read token** and appends for whoever shows a **write token** and
//!   signs as a device with `write`; tokens come from the stream key, the relay keeps their hashes.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use kernoid_base::{
    Bytes, Object, ParseError, Sha256Hash, SpaceId, base64url, from_base64url, random, to_canonical_vec, to_root,
    unsigned,
};
use kernoid_log::{DeviceId, Event};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Sha256;

use crate::{
    Domain, EncryptionError,
    pq::{self, HybridKeys, HybridReceivingKey, HybridVerifyingKey},
};

/// Crockford's base32 in lower case: the characters of the identities of streams and persons.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// 26 characters of [`ALPHABET`] from 16 random bytes (128 bits; the last character carries 3).
fn random_name() -> String {
    let bytes: [u8; 16] = random();
    let mut bits = u128::from_be_bytes(bytes);
    let mut name = [0u8; 26];
    for slot in name.iter_mut().rev() {
        *slot = ALPHABET[(bits & 31) as usize];
        bits >>= 5;
    }
    String::from_utf8(name.to_vec()).expect("ASCII")
}

fn valid_name(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix).is_some_and(|rest| rest.len() == 26 && rest.bytes().all(|b| ALPHABET.contains(&b)))
}

macro_rules! name {
    ($name:ident, $prefix:literal, $what:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// A new random identity.
            pub fn generate() -> Self {
                $name(format!("{}{}", $prefix, random_name()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if valid_name(s, $prefix) { Ok($name(s.to_owned())) } else { Err(ParseError::new($what, s)) }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?.parse().map_err(de::Error::custom)
            }
        }
    };
}

name!(StreamId, "s-", "stream identity");
name!(PersonId, "p-", "person identity");

/// The identity of a device: SHA-256 of its hybrid verifying key.
pub type DeviceKeyId = Sha256Hash;

/// A permission the relay enforces (RFC 0012, 7). Reading needs only membership and a token; a program's other
/// permissions are data of its space stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Append records to streams one holds the write token of.
    Write,
    /// Add and remove devices and persons.
    Members,
    /// Remove streams with what they hold.
    Purge,
}

/// The key of one generation of a stream: 32 random bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamKey(pub [u8; 32]);

impl fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamKey(…)")
    }
}

/// Which token of a stream's generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Read,
    Write,
}

impl StreamKey {
    pub fn generate() -> Self {
        StreamKey(random())
    }

    /// The key of a person's stream in one generation of the person's key.
    pub fn of_person(domain: Domain, person: &PersonId, seed: &[u8; 32]) -> Self {
        StreamKey(derive(seed, &format!("{} person stream {person}", domain.label)))
    }

    /// A token of this generation (RFC 0012, 5): what the relay asks of whoever reads or writes the stream.
    pub fn token(&self, domain: Domain, which: Token, stream: &StreamId, generation: u32) -> [u8; 32] {
        let what = match which {
            Token::Read => "read",
            Token::Write => "write",
        };
        derive(&self.0, &format!("{} stream {what} {stream} {generation}", domain.label))
    }

    /// The token as a request carries it, base64url.
    pub fn token_text(&self, domain: Domain, which: Token, stream: &StreamId, generation: u32) -> String {
        base64url(&self.token(domain, which, stream, generation))
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> ([u8; 24], Vec<u8>) {
        let nonce: [u8; 24] = random();
        let ciphertext = XChaCha20Poly1305::new(&self.0.into())
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
            .expect("XChaCha20-Poly1305 encrypts any length");
        (nonce, ciphertext)
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| EncryptionError::Format("nonce"))?;
        XChaCha20Poly1305::new(&self.0.into())
            .decrypt(&XNonce::from(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| EncryptionError::Decrypt)
    }

    /// `previous`, sealed with this key – what lets whoever has this generation read the ones before.
    fn chain(&self, label: &str, previous: &[u8; 32]) -> Bytes {
        let (nonce, ciphertext) = self.seal(previous, label.as_bytes());
        Bytes([nonce.as_slice(), &ciphertext].concat())
    }

    fn unchain(&self, label: &str, chained: &Bytes) -> Result<[u8; 32], EncryptionError> {
        if chained.0.len() < 24 {
            return Err(EncryptionError::Format("chained key"));
        }
        let (nonce, ciphertext) = chained.0.split_at(24);
        self.open(nonce, ciphertext, label.as_bytes())?.try_into().map_err(|_| EncryptionError::Decrypt)
    }

    /// Encrypts bytes of an original of the stream: the nonce, then the ciphertext. The original's identity is the
    /// hash of what this returns.
    pub fn seal_original(&self, domain: Domain, stream: &StreamId, plaintext: &[u8]) -> Vec<u8> {
        let (nonce, ciphertext) = self.seal(plaintext, format!("{} original {stream}", domain.label).as_bytes());
        [nonce.as_slice(), &ciphertext].concat()
    }

    pub fn open_original(&self, domain: Domain, stream: &StreamId, sealed: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if sealed.len() < 24 {
            return Err(EncryptionError::Format("original"));
        }
        let (nonce, ciphertext) = sealed.split_at(24);
        self.open(nonce, ciphertext, format!("{} original {stream}", domain.label).as_bytes())
    }
}

/// SHA-256 of a token: all the relay keeps of it.
pub fn token_hash(token: &[u8]) -> Sha256Hash {
    Sha256Hash::of(token)
}

fn derive(seed: &[u8; 32], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed).expand(info.as_bytes(), &mut out).expect("32 bytes from HKDF-SHA256");
    out
}

// The roster

/// A device of the space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// SHA-256 of `verifying`.
    pub id: DeviceKeyId,
    /// Its hybrid verifying key.
    pub verifying: Bytes,
    /// Its hybrid receiving key.
    pub receiving: Bytes,
    /// Whose device it is.
    pub person: PersonId,
    /// The device name its events carry (`kernoid_log`).
    pub device: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What the relay lets it do besides reading.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub permissions: BTreeSet<Permission>,
    /// A server: always online, every key sealed for it too – every member sees that its operator can read the space.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub server: bool,
}

impl Object for Device {
    const TYPE: &'static str = "device";
}

impl Device {
    /// The device these keys are.
    pub fn new(keys: &HybridKeys, person: PersonId, device: DeviceId, name: Option<String>) -> Self {
        Device {
            id: keys.verifying().id(),
            verifying: Bytes(keys.verifying().0.clone()),
            receiving: Bytes(keys.receiving().0.clone()),
            person,
            device,
            name,
            permissions: BTreeSet::new(),
            server: false,
        }
    }

    pub fn with(mut self, permissions: &[Permission]) -> Self {
        self.permissions.extend(permissions.iter().copied());
        self
    }

    pub fn as_server(mut self) -> Self {
        self.server = true;
        self
    }

    pub fn may(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey(self.verifying.0.clone())
    }

    /// Whether `signature` is this device's over `message`.
    pub fn verify(&self, domain: Domain, message: &[u8], signature: &[u8]) -> bool {
        self.verifying_key().id() == self.id && self.verifying_key().verify(domain, message, signature)
    }
}

/// A person of the space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    pub id: PersonId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Something sealed to one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    pub device: DeviceKeyId,
    pub sealed: Bytes,
}

/// A generation of a person's key: its public receiving key, its seed sealed to the person's devices, and the seed
/// before, sealed with a key from this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonKey {
    pub person: PersonId,
    pub generation: u32,
    /// The receiving key of the person's [`HybridKeys`] of this seed.
    pub receiving: Bytes,
    pub seals: Vec<Seal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Bytes>,
}

/// The key of a generation of the space stream, sealed to one person's key of a generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonLink {
    pub person: PersonId,
    pub person_generation: u32,
    pub sealed: Bytes,
}

/// Links of a generation of the space stream: new persons' links of the current one, or a new generation for all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceLinks {
    pub generation: u32,
    pub links: Vec<PersonLink>,
    /// The generation before, sealed with this one; only with a new generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Bytes>,
}

/// A record of the roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterRecord {
    pub space: SpaceId,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Sha256Hash>,
    /// The device that wrote it.
    pub author: DeviceKeyId,
    /// The space stream – named once, in record 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_stream: Option<StreamId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_persons: Vec<Person>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_persons: Vec<PersonId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_devices: Vec<Device>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_devices: Vec<DeviceKeyId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub person_keys: Vec<PersonKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_links: Option<SpaceLinks>,
    pub signature: Bytes,
}

impl Object for RosterRecord {
    const TYPE: &'static str = "roster_record";
}

impl RosterRecord {
    /// SHA-256 of its canonical encoding with its signature.
    pub fn hash(&self) -> Sha256Hash {
        Sha256Hash::of(&to_root(self).expect("a record has a canonical encoding"))
    }

    /// An empty record of a space, to fill and then [`RosterRecord::sign`].
    pub fn blank(space: &SpaceId) -> Self {
        RosterRecord {
            space: space.clone(),
            seq: 0,
            prev: None,
            author: Sha256Hash([0; 32]),
            space_stream: None,
            add_persons: vec![],
            remove_persons: vec![],
            add_devices: vec![],
            remove_devices: vec![],
            person_keys: vec![],
            space_links: None,
            signature: Bytes(vec![]),
        }
    }

    pub fn sign(mut self, author: &HybridKeys) -> Self {
        self.author = author.verifying().id();
        self.signature = Bytes(author.sign(&unsigned(&self)));
        self
    }
}

/// Why a roster record is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterProblem {
    #[error("the record is of other space")]
    OtherSpace,
    #[error("the record does not follow the head of the roster")]
    NotNext,
    #[error("the record's signature is not its author's")]
    Signature,
    #[error("record 0 must name the space stream, add its author with `members` and its person, and link them")]
    Founding,
    #[error("the author may not do this: {0}")]
    NotAllowed(&'static str),
    #[error("{0} is already there")]
    Duplicate(String),
    #[error("{0} is not there")]
    Unknown(String),
    #[error("a person key is missing or not the next generation: {0}")]
    PersonKey(String),
    #[error("a link of the space stream is missing or of the wrong generation: {0}")]
    SpaceLink(String),
    #[error("no device left that may manage members")]
    NoManager,
}

/// The roster of a space, applied record by record.
#[derive(Debug, Clone)]
pub struct Roster {
    domain: Domain,
    space: SpaceId,
    records: Vec<RosterRecord>,
    space_stream: Option<StreamId>,
    devices: BTreeMap<DeviceKeyId, Device>,
    persons: BTreeMap<PersonId, Person>,
    /// Every generation of every person's key, current or not.
    person_keys: BTreeMap<(PersonId, u32), PersonKey>,
    /// Seals of person keys: (person, generation, device).
    seals: BTreeMap<(PersonId, u32, DeviceKeyId), Bytes>,
    /// Links of the space stream: (generation, person) → (person generation, sealed).
    space_links: BTreeMap<(u32, PersonId), (u32, Bytes)>,
    space_chain: BTreeMap<u32, Bytes>,
    space_generation: Option<u32>,
}

impl Roster {
    pub fn new(domain: Domain, space: SpaceId) -> Self {
        Roster {
            domain,
            space,
            records: vec![],
            space_stream: None,
            devices: BTreeMap::new(),
            persons: BTreeMap::new(),
            person_keys: BTreeMap::new(),
            seals: BTreeMap::new(),
            space_links: BTreeMap::new(),
            space_chain: BTreeMap::new(),
            space_generation: None,
        }
    }

    pub fn from_records(domain: Domain, space: SpaceId, records: &[RosterRecord]) -> Result<Self, RosterProblem> {
        let mut roster = Roster::new(domain, space);
        for record in records {
            roster.apply(record.clone())?;
        }
        Ok(roster)
    }

    pub fn domain(&self) -> Domain {
        self.domain
    }

    pub fn space(&self) -> &SpaceId {
        &self.space
    }

    pub fn records(&self) -> &[RosterRecord] {
        &self.records
    }

    pub fn head(&self) -> Option<Sha256Hash> {
        self.records.last().map(RosterRecord::hash)
    }

    pub fn space_stream(&self) -> Option<&StreamId> {
        self.space_stream.as_ref()
    }

    pub fn space_generation(&self) -> Option<u32> {
        self.space_generation
    }

    pub fn device(&self, id: &DeviceKeyId) -> Option<&Device> {
        self.devices.get(id)
    }

    /// A device as it was last added – current or removed since; what it wrote as a member stays its.
    pub fn device_ever(&self, id: &DeviceKeyId) -> Option<&Device> {
        self.records.iter().rev().flat_map(|record| &record.add_devices).find(|device| device.id == *id)
    }

    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    pub fn devices_of<'a>(&'a self, person: &'a PersonId) -> impl Iterator<Item = &'a Device> + 'a {
        self.devices.values().filter(move |device| device.person == *person)
    }

    pub fn person(&self, id: &PersonId) -> Option<&Person> {
        self.persons.get(id)
    }

    pub fn persons(&self) -> impl Iterator<Item = &Person> {
        self.persons.values()
    }

    /// The current generation of a person's key.
    pub fn person_key(&self, person: &PersonId) -> Option<&PersonKey> {
        self.person_keys.range((person.clone(), 0)..=(person.clone(), u32::MAX)).next_back().map(|(_, key)| key)
    }

    /// Checks a record against the roster as it is and applies it.
    pub fn apply(&mut self, record: RosterRecord) -> Result<(), RosterProblem> {
        if record.space != self.space {
            return Err(RosterProblem::OtherSpace);
        }
        if record.seq != self.records.len() as u64 || record.prev != self.head() {
            return Err(RosterProblem::NotNext);
        }
        let mut devices = self.devices.clone();
        let mut persons = self.persons.clone();
        let author = if record.seq == 0 {
            record.add_devices.iter().find(|device| device.id == record.author).cloned()
        } else {
            self.devices.get(&record.author).cloned()
        };
        let author = author.ok_or(RosterProblem::NotAllowed("not a device of the space"))?;
        if !author.verify(self.domain, &unsigned(&record), &record.signature.0) {
            return Err(RosterProblem::Signature);
        }
        let changes_members = !record.add_persons.is_empty()
            || !record.remove_persons.is_empty()
            || !record.remove_devices.is_empty()
            || record.add_devices.iter().any(|device| device.person != author.person);
        if record.seq == 0 {
            if record.space_stream.is_none() || !author.may(Permission::Members) {
                return Err(RosterProblem::Founding);
            }
        } else {
            if record.space_stream.is_some() {
                return Err(RosterProblem::NotAllowed("the space stream is named once"));
            }
            if changes_members && !author.may(Permission::Members) {
                return Err(RosterProblem::NotAllowed("members"));
            }
            // A device adds devices of its own person; giving permissions it lacks needs `members`.
            for device in &record.add_devices {
                if !device.permissions.is_subset(&author.permissions) && !author.may(Permission::Members) {
                    return Err(RosterProblem::NotAllowed("permissions beyond the author's"));
                }
            }
            if record.space_links.as_ref().is_some_and(|links| Some(links.generation) != self.space_generation)
                && !author.may(Permission::Write)
            {
                return Err(RosterProblem::NotAllowed("a new generation of the space stream needs `write`"));
            }
        }
        for id in &record.remove_persons {
            if persons.remove(id).is_none() {
                return Err(RosterProblem::Unknown(id.to_string()));
            }
            devices.retain(|_, device| device.person != *id);
        }
        let mut rotated: BTreeSet<PersonId> = BTreeSet::new();
        for id in &record.remove_devices {
            match devices.remove(id) {
                Some(device) => {
                    if persons.contains_key(&device.person) {
                        rotated.insert(device.person);
                    }
                }
                None if self.devices.get(id).is_some_and(|d| record.remove_persons.contains(&d.person)) => {}
                None => return Err(RosterProblem::Unknown(id.to_string())),
            }
        }
        for person in &record.add_persons {
            if persons.contains_key(&person.id) || self.person_keys.keys().any(|(id, _)| *id == person.id) {
                return Err(RosterProblem::Duplicate(person.id.to_string()));
            }
            persons.insert(person.id.clone(), person.clone());
        }
        for device in &record.add_devices {
            let taken = devices.values().any(|d| d.device == device.device);
            if devices.contains_key(&device.id) || taken || device.verifying_key().id() != device.id {
                return Err(RosterProblem::Duplicate(device.id.to_string()));
            }
            if !persons.contains_key(&device.person) {
                return Err(RosterProblem::Unknown(device.person.to_string()));
            }
            devices.insert(device.id, device.clone());
        }
        // Person keys: a new generation for each new person (0) and each person that lost a device (the next one);
        // devices added to a person get seals of its current generation.
        let mut person_keys = self.person_keys.clone();
        let mut seals = self.seals.clone();
        for key in &record.person_keys {
            if !persons.contains_key(&key.person) {
                return Err(RosterProblem::Unknown(key.person.to_string()));
            }
            let current = person_keys
                .range((key.person.clone(), 0)..=(key.person.clone(), u32::MAX))
                .next_back()
                .map(|((_, g), _)| *g);
            let fits = match current {
                None => key.generation == 0 && key.previous.is_none(),
                Some(g) if g == key.generation => {
                    key.previous.is_none() && person_keys[&(key.person.clone(), g)].receiving == key.receiving
                }
                Some(g) => key.generation == g + 1 && key.previous.is_some(),
            };
            if !fits || key.receiving.0.len() != pq::RECEIVING_KEY_LEN {
                return Err(RosterProblem::PersonKey(key.person.to_string()));
            }
            for seal in &key.seals {
                if devices.get(&seal.device).is_none_or(|d| d.person != key.person) {
                    return Err(RosterProblem::PersonKey(format!("{} for {}", key.person, seal.device)));
                }
                seals.insert((key.person.clone(), key.generation, seal.device), seal.sealed.clone());
            }
            let entry = person_keys.entry((key.person.clone(), key.generation)).or_insert_with(|| key.clone());
            if entry.previous.is_none() {
                entry.previous = key.previous.clone();
            }
            rotated.remove(&key.person);
        }
        if let Some(person) = rotated.into_iter().next() {
            return Err(RosterProblem::PersonKey(format!("{person} lost a device and needs a new generation")));
        }
        for device in devices.values() {
            let current = person_keys
                .range((device.person.clone(), 0)..=(device.person.clone(), u32::MAX))
                .next_back()
                .map(|((_, g), _)| *g)
                .ok_or_else(|| RosterProblem::PersonKey(device.person.to_string()))?;
            if !seals.contains_key(&(device.person.clone(), current, device.id)) {
                return Err(RosterProblem::PersonKey(format!("{} for {}", device.person, device.id)));
            }
        }
        // Links of the space stream.
        let mut space_links = self.space_links.clone();
        let mut space_chain = self.space_chain.clone();
        let mut generation = self.space_generation;
        if let Some(links) = &record.space_links {
            let fits = match generation {
                None => links.generation == 0 && links.previous.is_none(),
                Some(g) if g == links.generation => links.previous.is_none(),
                Some(g) => links.generation == g + 1 && links.previous.is_some(),
            };
            if !fits {
                return Err(RosterProblem::SpaceLink(format!("generation {}", links.generation)));
            }
            for link in &links.links {
                if !persons.contains_key(&link.person)
                    || !person_keys.contains_key(&(link.person.clone(), link.person_generation))
                {
                    return Err(RosterProblem::SpaceLink(link.person.to_string()));
                }
                space_links
                    .insert((links.generation, link.person.clone()), (link.person_generation, link.sealed.clone()));
            }
            if let Some(previous) = &links.previous {
                space_chain.insert(links.generation, previous.clone());
            }
            generation = Some(links.generation);
        }
        let current = generation.ok_or(RosterProblem::Founding)?;
        // Every person reaches the current generation of the space stream: older ones it reads back through the chain.
        for person in persons.keys() {
            if !space_links.contains_key(&(current, person.clone())) {
                return Err(RosterProblem::SpaceLink(person.to_string()));
            }
        }
        if !devices.values().any(|device| device.may(Permission::Members)) {
            return Err(RosterProblem::NoManager);
        }
        if record.seq == 0 {
            self.space_stream = record.space_stream.clone();
        }
        self.devices = devices;
        self.persons = persons;
        self.person_keys = person_keys;
        self.seals = seals;
        self.space_links = space_links;
        self.space_chain = space_chain;
        self.space_generation = generation;
        self.records.push(record);
        Ok(())
    }

    /// The next position and the hash before it, to fill a new record with.
    pub fn next(&self, mut record: RosterRecord) -> RosterRecord {
        record.seq = self.records.len() as u64;
        record.prev = self.head();
        record
    }

    /// Every generation of my person's key I can open, newest first chained back: generation → seed.
    pub fn person_seeds(&self, me: &HybridKeys) -> Result<BTreeMap<u32, [u8; 32]>, EncryptionError> {
        let device = self.device(&me.verifying().id()).ok_or(EncryptionError::NoKey(0))?;
        let person = device.person.clone();
        let (generation, sealed) = self
            .seals
            .iter()
            .filter(|((p, _, d), _)| *p == person && *d == device.id)
            .map(|((_, g, _), sealed)| (*g, sealed))
            .max_by_key(|(g, _)| *g)
            .ok_or(EncryptionError::NoKey(0))?;
        let seed: [u8; 32] = me
            .open(&person_seal_context(self.domain, &self.space, &person, generation, &device.id), &sealed.0)?
            .try_into()
            .map_err(|_| EncryptionError::Decrypt)?;
        let mut seeds = BTreeMap::new();
        let (mut g, mut seed) = (generation, seed);
        loop {
            seeds.insert(g, seed);
            if g == 0 {
                break;
            }
            let previous = self
                .person_keys
                .get(&(person.clone(), g))
                .and_then(|key| key.previous.as_ref())
                .ok_or(EncryptionError::NoKey(g - 1))?;
            seed = StreamKey(derive(&seed, &format!("{} person chain", self.domain.label)))
                .unchain(&person_chain_label(self.domain, &person, g), previous)?;
            g -= 1;
        }
        Ok(seeds)
    }

    /// Every generation of the space stream my person can open: generation → key.
    pub fn space_keys(&self, me: &HybridKeys) -> Result<BTreeMap<u32, StreamKey>, EncryptionError> {
        let current = self.space_generation.ok_or(EncryptionError::NoKey(0))?;
        let stream = self.space_stream.clone().ok_or(EncryptionError::NoKey(0))?;
        let device = self.device(&me.verifying().id()).ok_or(EncryptionError::NoKey(0))?;
        let seeds = self.person_seeds(me)?;
        let (generation, (person_generation, sealed)) = self
            .space_links
            .iter()
            .filter(|((_, p), (pg, _))| *p == device.person && seeds.contains_key(pg))
            .map(|((g, _), link)| (*g, link))
            .max_by_key(|(g, _)| *g)
            .ok_or(EncryptionError::NoKey(current))?;
        let person_keys = HybridKeys::from_seed(self.domain, seeds[person_generation]);
        let key: [u8; 32] = person_keys
            .open(&link_context(self.domain, &stream, generation), &sealed.0)?
            .try_into()
            .map_err(|_| EncryptionError::Decrypt)?;
        let mut keys = BTreeMap::new();
        let (mut g, mut key) = (generation, StreamKey(key));
        loop {
            keys.insert(g, key.clone());
            if g == 0 {
                break;
            }
            let previous = self.space_chain.get(&g).ok_or(EncryptionError::NoKey(g - 1))?;
            key = StreamKey(key.unchain(&stream_chain_label(self.domain, &stream, g), previous)?);
            g -= 1;
        }
        Ok(keys)
    }
}

fn person_seal_context(
    domain: Domain,
    space: &SpaceId,
    person: &PersonId,
    generation: u32,
    device: &DeviceKeyId,
) -> Vec<u8> {
    format!("{} person key {space} {person} {generation} {device}", domain.label).into_bytes()
}

fn person_chain_label(domain: Domain, person: &PersonId, generation: u32) -> String {
    format!("{} person chain {person} {generation}", domain.label)
}

fn stream_chain_label(domain: Domain, stream: &StreamId, generation: u32) -> String {
    format!("{} stream chain {stream} {generation}", domain.label)
}

/// The context a stream's key of a generation is sealed in to a person.
pub fn link_context(domain: Domain, stream: &StreamId, generation: u32) -> Vec<u8> {
    format!("{} link {stream} {generation}", domain.label).into_bytes()
}

/// A person's key of a new generation: the seed sealed to the person's devices, chained to the one before.
pub fn person_key(
    domain: Domain,
    space: &SpaceId,
    person: &PersonId,
    generation: u32,
    seed: &[u8; 32],
    previous: Option<&[u8; 32]>,
    devices: &[&Device],
) -> Result<PersonKey, EncryptionError> {
    let keys = HybridKeys::from_seed(domain, *seed);
    let mut seals = Vec::new();
    for device in devices {
        let sealed = pq::seal(
            domain,
            &HybridReceivingKey(device.receiving.0.clone()),
            &person_seal_context(domain, space, person, generation, &device.id),
            seed,
        )?;
        seals.push(Seal { device: device.id, sealed: Bytes(sealed) });
    }
    let previous = previous.map(|previous| {
        StreamKey(derive(seed, &format!("{} person chain", domain.label)))
            .chain(&person_chain_label(domain, person, generation), previous)
    });
    Ok(PersonKey { person: person.clone(), generation, receiving: Bytes(keys.receiving().0.clone()), seals, previous })
}

/// Seals a stream's key of a generation to a person's key of a generation.
pub fn link_to_person(
    domain: Domain,
    stream: &StreamId,
    generation: u32,
    key: &StreamKey,
    person: &PersonKey,
) -> Result<PersonLink, EncryptionError> {
    let sealed = pq::seal(
        domain,
        &HybridReceivingKey(person.receiving.0.clone()),
        &link_context(domain, stream, generation),
        &key.0,
    )?;
    Ok(PersonLink { person: person.person.clone(), person_generation: person.generation, sealed: Bytes(sealed) })
}

/// A new generation of the space stream, linked to every current person.
pub fn new_space_generation(
    roster: &Roster,
    key: &StreamKey,
    previous: Option<&StreamKey>,
) -> Result<SpaceLinks, EncryptionError> {
    let domain = roster.domain;
    let stream = roster.space_stream.clone().ok_or(EncryptionError::NoKey(0))?;
    let generation = roster.space_generation.map_or(0, |g| g + 1);
    let links = roster
        .persons
        .keys()
        .filter_map(|person| roster.person_key(person))
        .map(|person| link_to_person(domain, &stream, generation, key, person))
        .collect::<Result<_, _>>()?;
    let previous =
        previous.map(|previous| Bytes(key.chain(&stream_chain_label(domain, &stream, generation), &previous.0).0));
    Ok(SpaceLinks { generation, links, previous })
}

// Records of streams

/// What a record of a stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    /// An event of the program (`kernoid_log::Event`), sealed with the stream's key.
    Event,
    /// A new generation: the key before, sealed with the new one.
    Generation,
    /// The key of a stream below, sealed with this stream's key.
    Link,
    /// The key of a stream, sealed to the person whose stream this is (`generation` names the person's key) – what
    /// a device writes into another person's stream without its key.
    Sealed,
}

/// What a link carries: a stream's key of a generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBody {
    pub stream: StreamId,
    pub generation: u32,
    pub key: Bytes,
}

impl Object for LinkBody {
    const TYPE: &'static str = "link";
}

/// A record of a stream, as the relay keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRecord {
    pub space: SpaceId,
    pub stream: StreamId,
    /// The generation of the key it is sealed with – of the stream, or for `sealed` of the person's key.
    pub generation: u32,
    pub author: DeviceKeyId,
    /// The roster's position the author had seen; a program checks rights there.
    pub at: u64,
    pub kind: RecordKind,
    #[serde(default, skip_serializing_if = "Bytes::is_empty")]
    pub nonce: Bytes,
    pub ciphertext: Bytes,
    /// SHA-256 over the nonce and the ciphertext.
    pub id: Sha256Hash,
    pub signature: Bytes,
}

trait EmptyBytes {
    fn is_empty(&self) -> bool;
}

impl EmptyBytes for Bytes {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Object for StreamRecord {
    const TYPE: &'static str = "stream_record";
}

fn record_aad(
    space: &SpaceId,
    stream: &StreamId,
    generation: u32,
    author: &DeviceKeyId,
    at: u64,
    kind: RecordKind,
) -> Vec<u8> {
    let header = serde_json::json!({
        "space": space, "stream": stream, "generation": generation, "author": author, "at": at, "kind": kind,
    });
    to_canonical_vec(&header).expect("a header has a canonical encoding")
}

/// Who writes a record: the device's keys and the roster position it has seen.
#[derive(Debug, Clone, Copy)]
pub struct Writer<'a> {
    pub domain: Domain,
    pub space: &'a SpaceId,
    pub keys: &'a HybridKeys,
    pub at: u64,
}

impl StreamRecord {
    fn finish(mut self, writer: &Writer<'_>) -> Self {
        self.id = Sha256Hash::of(&[self.nonce.0.as_slice(), &self.ciphertext.0].concat());
        self.signature = Bytes(writer.keys.sign(&unsigned(&self)));
        self
    }

    fn sealed(
        writer: &Writer<'_>,
        stream: &StreamId,
        generation: u32,
        key: &StreamKey,
        kind: RecordKind,
        plaintext: &[u8],
    ) -> Self {
        let author = writer.keys.verifying().id();
        let aad = record_aad(writer.space, stream, generation, &author, writer.at, kind);
        let (nonce, ciphertext) = key.seal(plaintext, &aad);
        StreamRecord {
            space: writer.space.clone(),
            stream: stream.clone(),
            generation,
            author,
            at: writer.at,
            kind,
            nonce: Bytes(nonce.to_vec()),
            ciphertext: Bytes(ciphertext),
            id: Sha256Hash([0; 32]),
            signature: Bytes(vec![]),
        }
        .finish(writer)
    }

    /// An event, sealed with the stream's key of `generation`.
    pub fn event(writer: &Writer<'_>, stream: &StreamId, generation: u32, key: &StreamKey, event: &Event) -> Self {
        let plaintext = event.to_canonical().expect("an event written here has a canonical encoding");
        Self::sealed(writer, stream, generation, key, RecordKind::Event, &plaintext)
    }

    /// A new generation `generation` of a stream: the key before, sealed with the new key.
    pub fn generation(
        writer: &Writer<'_>,
        stream: &StreamId,
        generation: u32,
        key: &StreamKey,
        previous: &StreamKey,
    ) -> Self {
        Self::sealed(writer, stream, generation, key, RecordKind::Generation, &previous.0)
    }

    /// A link in `stream` (under its key of `generation`) to the key of a stream below.
    pub fn link(writer: &Writer<'_>, stream: &StreamId, generation: u32, key: &StreamKey, body: &LinkBody) -> Self {
        let plaintext = to_root(body).expect("a link has a canonical encoding");
        Self::sealed(writer, stream, generation, key, RecordKind::Link, &plaintext)
    }

    /// A link sealed to a person, written into the person's stream.
    pub fn sealed_link(
        writer: &Writer<'_>,
        person_stream: &StreamId,
        person: &PersonKey,
        body: &LinkBody,
    ) -> Result<Self, EncryptionError> {
        let author = writer.keys.verifying().id();
        let aad = record_aad(writer.space, person_stream, person.generation, &author, writer.at, RecordKind::Sealed);
        let plaintext = to_root(body).expect("a link has a canonical encoding");
        let sealed = pq::seal(writer.domain, &HybridReceivingKey(person.receiving.0.clone()), &aad, &plaintext)?;
        Ok(StreamRecord {
            space: writer.space.clone(),
            stream: person_stream.clone(),
            generation: person.generation,
            author,
            at: writer.at,
            kind: RecordKind::Sealed,
            nonce: Bytes(vec![]),
            ciphertext: Bytes(sealed),
            id: Sha256Hash([0; 32]),
            signature: Bytes(vec![]),
        }
        .finish(writer))
    }

    /// Whether the identity is that of the ciphertext and the signature is that of the device it names.
    pub fn is_authentic(&self, domain: Domain, author: &Device) -> bool {
        author.id == self.author
            && self.id == Sha256Hash::of(&[self.nonce.0.as_slice(), &self.ciphertext.0].concat())
            && author.verify(domain, &unsigned(self), &self.signature.0)
    }

    fn aad(&self) -> Vec<u8> {
        record_aad(&self.space, &self.stream, self.generation, &self.author, self.at, self.kind)
    }

    /// The plaintext of a record sealed with the stream's key.
    pub fn open(&self, key: &StreamKey) -> Result<Vec<u8>, EncryptionError> {
        if self.kind == RecordKind::Sealed {
            return Err(EncryptionError::Format("a record sealed with the stream's key"));
        }
        key.open(&self.nonce.0, &self.ciphertext.0, &self.aad())
    }

    /// The key before, of a `generation` record.
    pub fn open_generation(&self, key: &StreamKey) -> Result<StreamKey, EncryptionError> {
        if self.kind != RecordKind::Generation {
            return Err(EncryptionError::Format("a generation"));
        }
        Ok(StreamKey(self.open(key)?.try_into().map_err(|_| EncryptionError::Decrypt)?))
    }

    /// The link of a `link` record.
    pub fn open_link(&self, key: &StreamKey) -> Result<LinkBody, EncryptionError> {
        if self.kind != RecordKind::Link {
            return Err(EncryptionError::Format("a link"));
        }
        kernoid_base::from_root(&self.open(key)?).map_err(|_| EncryptionError::Format("a link"))
    }

    /// The link of a `sealed` record, with the person's keys of its generation.
    pub fn open_sealed(&self, person: &HybridKeys) -> Result<LinkBody, EncryptionError> {
        if self.kind != RecordKind::Sealed {
            return Err(EncryptionError::Format("a sealed link"));
        }
        let plaintext = person.open(&self.aad(), &self.ciphertext.0)?;
        kernoid_base::from_root(&plaintext).map_err(|_| EncryptionError::Format("a link"))
    }

    /// The canonical event of an `event` record; its device must be the author's device name.
    pub fn open_event(&self, key: &StreamKey, roster: &Roster) -> Result<Vec<u8>, EncryptionError> {
        if self.kind != RecordKind::Event {
            return Err(EncryptionError::Format("an event"));
        }
        let plaintext = self.open(key)?;
        let event = Event::read(&plaintext)?;
        let device = roster.device_ever(&self.author).map(|device| &device.device);
        if device != Some(&event.time.device) {
            return Err(EncryptionError::Signature);
        }
        Ok(plaintext)
    }
}

// Requests

/// The value of `Authorization` of a request to a relay's `v2`: `<scheme>-pq <device> <time> <signature>`, the hybrid
/// signature over `{method} {path} {time}`.
pub fn request_signature(domain: Domain, keys: &HybridKeys, method: &str, path: &str, time: u64) -> String {
    let signature = keys.sign(format!("{method} {path} {time}").as_bytes());
    format!("{}-pq {} {time} {}", domain.scheme, keys.verifying().id().hex(), base64url(&signature))
}

/// The device and the signature of a request, as the header says: to be checked against the roster with
/// [`verify_request`].
pub fn parse_request(domain: Domain, header: &str) -> Option<(DeviceKeyId, u64, Vec<u8>)> {
    let rest = header.strip_prefix(domain.scheme)?.strip_prefix("-pq ")?;
    let mut parts = rest.split(' ');
    let (device, time, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || device.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    hex::decode_to_slice(device, &mut id).ok()?;
    Some((Sha256Hash(id), time.parse().ok()?, from_base64url(signature)?))
}

/// The device of the roster that signed a request, if its time is within 300 seconds of `now`.
pub fn verify_request<'a>(roster: &'a Roster, header: &str, method: &str, path: &str, now: u64) -> Option<&'a Device> {
    let (id, time, signature) = parse_request(roster.domain, header)?;
    let device = roster.device(&id)?;
    (now.abs_diff(time) <= 300
        && device.verify(roster.domain, format!("{method} {path} {time}").as_bytes(), &signature))
    .then_some(device)
}

/// A request to join a space with a device: a device of an existing person, or of a new person who brings its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Joining {
    pub device: Device,
    /// A new person: who, and the key of its first generation, sealed to `device`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<(Person, PersonKey)>,
    /// HMAC-SHA256 with the invitation's secret over the canonical encoding of the rest.
    pub proof: Bytes,
}

impl Object for Joining {
    const TYPE: &'static str = "joining";
}

impl Joining {
    fn mac(secret: &[u8; 16], device: &Device, person: &Option<(Person, PersonKey)>) -> hmac::Hmac<Sha256> {
        use hmac::Mac;
        let mut mac = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret).expect("HMAC takes any key");
        let body = serde_json::json!({ "device": device, "person": person });
        mac.update(&to_canonical_vec(&body).expect("a request has a canonical encoding"));
        mac
    }

    pub fn new(secret: &[u8; 16], device: Device, person: Option<(Person, PersonKey)>) -> Self {
        use hmac::Mac;
        let proof = Bytes(Self::mac(secret, &device, &person).finalize().into_bytes().to_vec());
        Joining { device, person, proof }
    }

    pub fn proves(&self, secret: &[u8; 16]) -> bool {
        use hmac::Mac;
        Self::mac(secret, &self.device, &self.person).verify_slice(&self.proof.0).is_ok()
    }
}
