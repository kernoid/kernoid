// SPDX-License-Identifier: MIT
//! End-to-end encryption of a space: members and their keys from a seed, the chain of space keys, the strictly ordered member list beside the unordered events, envelopes
//! for events and originals, signed requests to a relay, invitations and recovery codes.
//!
//! | Purpose | Algorithm |
//! |---|---|
//! | signing | Ed25519 (RFC 8032) – hybrid with ML-DSA-65 and X-Wing for what is new: [`pq`] |
//! | wrapping a key for a member | HPKE (RFC 9180), mode Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 |
//! | encrypting events, originals and earlier keys | XChaCha20-Poly1305, random 24-byte nonce |
//! | deriving keys from a seed | HKDF-SHA256 (RFC 5869) |
//! | proving an invitation | HMAC-SHA256 (RFC 2104) |
//!
//! Limits, part of the design: removing a member protects the future, not the past; a compromised device reads until
//! the next change of key; losing every key and the recovery code loses the space; a relay sees which spaces it
//! holds, who sends when and how much, and the member list – not the events.

pub mod pq;
pub mod stream;

use std::{collections::BTreeMap, fmt, str::FromStr};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use kernoid_base::{
    Bytes, Object, ObjectError, Sha256Hash, SpaceId, base64url, from_base64url, random, to_canonical_vec, to_root,
    unsigned,
};
use kernoid_log::{DeviceId, Event, EventError};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Sha256;

/// The labels keys are derived and requests signed with. Keys of one domain never open anything of another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    /// The prefix of the labels of key derivation, wrapping and chaining, e.g. `kernoid/crypt`.
    pub label: &'static str,
    /// The scheme of the header `Authorization` of a request to a relay, e.g. `kernoid`.
    pub scheme: &'static str,
}

impl Domain {
    /// kernoid's own. A program built on kernoid passes its own (aktujo: `aktujo/crypt`, `aktujo`), so that its keys
    /// open nothing of another program's.
    pub const KERNOID: Domain = Domain { label: "kernoid/crypt", scheme: "kernoid" };
}

/// Why something of the encryption failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptionError {
    /// A key, identity or code that cannot be read.
    #[error("not a valid {0}")]
    Format(&'static str),
    /// A signature that is not the author's.
    #[error("the signature is not valid")]
    Signature,
    /// Ciphertext that does not open with the key, or was changed.
    #[error("cannot decrypt: wrong key or changed data")]
    Decrypt,
    /// No grant of a key for this member, or a key missing from the chain.
    #[error("no key {0} for this member")]
    NoKey(u32),
    /// A record of the member list that is not valid.
    #[error(transparent)]
    Record(#[from] RecordProblem),
    /// Content that is not what it should be.
    #[error(transparent)]
    Object(#[from] ObjectError),
    /// An event that is not one.
    #[error(transparent)]
    Event(#[from] EventError),
}

/// 32 bytes written as a prefix and 64 lower-case hexadecimal digits.
fn parse_key(text: &str, prefix: &str, what: &'static str) -> Result<[u8; 32], EncryptionError> {
    let hex = text.strip_prefix(prefix).ok_or(EncryptionError::Format(what))?;
    if hex.len() != 64 || hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EncryptionError::Format(what));
    }
    let bytes = hex::decode(hex).map_err(|_| EncryptionError::Format(what))?;
    bytes.try_into().map_err(|_| EncryptionError::Format(what))
}

macro_rules! key_text {
    ($name:ident, $prefix:literal, $what:literal) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{}"), hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = EncryptionError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_key(s, $prefix, $what).map($name)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?.parse().map_err(de::Error::custom)
            }
        }
    };
}

/// A member's identity: its public signing key, `ed25519:` and 64 hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId(pub [u8; 32]);
key_text!(MemberId, "ed25519:", "member identity");

/// A member's public receiving key, `x25519:` and 64 hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceivingKey(pub [u8; 32]);
key_text!(ReceivingKey, "x25519:", "receiving key");

/// HKDF-SHA256 of a seed, without salt, with an info label.
fn derive(seed: &[u8; 32], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, seed).expand(info.as_bytes(), &mut out).expect("32 bytes from HKDF-SHA256");
    out
}

/// The keys of a member, from its seed of 32 bytes – which never leaves the member.
#[derive(Clone)]
pub struct MemberKeys {
    domain: Domain,
    seed: [u8; 32],
    signing: SigningKey,
    receiving: <X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    receiving_public: ReceivingKey,
}

impl fmt::Debug for MemberKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberKeys({})", self.id())
    }
}

impl MemberKeys {
    /// New keys from a new random seed.
    pub fn generate(domain: Domain) -> Self {
        Self::from_seed(domain, random())
    }

    /// The keys of a seed.
    pub fn from_seed(domain: Domain, seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&derive(&seed, &format!("{} signing", domain.label)));
        let (receiving, public) =
            X25519HkdfSha256::derive_keypair(&derive(&seed, &format!("{} receiving", domain.label)));
        let receiving_public =
            ReceivingKey(public.to_bytes().as_slice().try_into().expect("an X25519 public key has 32 bytes"));
        MemberKeys { domain, seed, signing, receiving, receiving_public }
    }

    /// The domain the keys were made in.
    pub fn domain(&self) -> Domain {
        self.domain
    }

    /// The seed, to keep on the member's device.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// The member's identity.
    pub fn id(&self) -> MemberId {
        MemberId(self.signing.verifying_key().to_bytes())
    }

    /// The member's public receiving key.
    pub fn receiving(&self) -> ReceivingKey {
        self.receiving_public
    }

    /// Ed25519 over `message`.
    pub fn sign(&self, message: &[u8]) -> Bytes {
        Bytes(self.signing.sign(message).to_bytes().to_vec())
    }

    /// Unwraps a key granted to this member.
    fn unwrap(&self, space: &SpaceId, grant: &Grant) -> Result<SpaceKey, EncryptionError> {
        let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&grant.enc.0)
            .map_err(|_| EncryptionError::Format("encapsulated key"))?;
        let info = format!("{} key {space} {} {}", self.domain.label, grant.key, grant.member);
        let key = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.receiving,
            &enc,
            info.as_bytes(),
            &grant.ciphertext.0,
            b"",
        )
        .map_err(|_| EncryptionError::Decrypt)?;
        Ok(SpaceKey(key.try_into().map_err(|_| EncryptionError::Decrypt)?))
    }
}

/// Whether `signature` is the member's Ed25519 signature over `message`.
pub fn verify(member: &MemberId, message: &[u8], signature: &Bytes) -> bool {
    let (Ok(key), Ok(signature)) = (VerifyingKey::from_bytes(&member.0), Signature::from_slice(&signature.0)) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

/// A space key: 32 random bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SpaceKey(pub [u8; 32]);

impl fmt::Debug for SpaceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SpaceKey(…)")
    }
}

impl SpaceKey {
    /// A new key.
    pub fn generate() -> Self {
        SpaceKey(random())
    }

    /// XChaCha20-Poly1305 with a random nonce: the nonce and the ciphertext.
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> ([u8; 24], Vec<u8>) {
        let nonce: [u8; 24] = random();
        let cipher = XChaCha20Poly1305::new(&self.0.into());
        let ciphertext = cipher
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

    /// Wraps this key, of position `index`, for a member.
    pub fn grant(&self, domain: Domain, space: &SpaceId, index: u32, member: &Member) -> Grant {
        let public = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&member.receiving.0)
            .expect("a receiving key read from its text is a valid X25519 key");
        let info = format!("{} key {space} {index} {}", domain.label, member.id);
        let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public,
            info.as_bytes(),
            &self.0,
            b"",
        )
        .expect("HPKE seals 32 bytes");
        Grant { member: member.id, key: index, enc: Bytes(enc.to_bytes().to_vec()), ciphertext: Bytes(ciphertext) }
    }

    /// The previous key, encrypted with this one at position `index`: nonce and ciphertext.
    fn chain(&self, domain: Domain, space: &SpaceId, index: u32, previous: &SpaceKey) -> Bytes {
        let (nonce, ciphertext) = self.seal(&previous.0, format!("{} chain {space} {index}", domain.label).as_bytes());
        Bytes([nonce.as_slice(), &ciphertext].concat())
    }

    /// The key before this one, at position `index`, from what the key change carries.
    fn unchain(
        &self,
        domain: Domain,
        space: &SpaceId,
        index: u32,
        previous: &Bytes,
    ) -> Result<SpaceKey, EncryptionError> {
        if previous.0.len() < 24 {
            return Err(EncryptionError::Format("previous key"));
        }
        let (nonce, ciphertext) = previous.0.split_at(24);
        let key = self.open(nonce, ciphertext, format!("{} chain {space} {index}", domain.label).as_bytes())?;
        Ok(SpaceKey(key.try_into().map_err(|_| EncryptionError::Decrypt)?))
    }
}

/// What a member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    /// A device of a person, writing events under its device name.
    Device,
    /// A backend run for others, writing events under its device name.
    Backend,
    /// A recovery code, which writes no events.
    Recovery,
}

/// What a member may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rights {
    /// Read events.
    Read,
    /// Read and write events.
    Write,
    /// Read and write events, add and remove members.
    Manage,
}

/// A member of a space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Its identity.
    pub id: MemberId,
    /// Its public receiving key.
    pub receiving: ReceivingKey,
    /// What it is.
    pub role: MemberRole,
    /// The device name it writes events under; none for a recovery code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceId>,
    /// What people call it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What it may do.
    pub rights: Rights,
}

impl Object for Member {
    const TYPE: &'static str = "member";
}

impl Member {
    /// The member these keys are, as a device with a name.
    pub fn device(keys: &MemberKeys, device: DeviceId, name: Option<String>, rights: Rights) -> Self {
        Member {
            id: keys.id(),
            receiving: keys.receiving(),
            role: MemberRole::Device,
            device: Some(device),
            name,
            rights,
        }
    }

    /// The member a recovery code is.
    pub fn recovery(keys: &MemberKeys) -> Self {
        Member {
            id: keys.id(),
            receiving: keys.receiving(),
            role: MemberRole::Recovery,
            device: None,
            name: Some("Recovery code".into()),
            rights: Rights::Manage,
        }
    }
}

/// A space key wrapped for a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The member.
    pub member: MemberId,
    /// The position of the key.
    pub key: u32,
    /// The encapsulated key of HPKE.
    pub enc: Bytes,
    /// The wrapped key.
    pub ciphertext: Bytes,
}

impl Object for Grant {
    const TYPE: &'static str = "grant";
}

/// A new space key in a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChange {
    /// Its position.
    pub index: u32,
    /// The key before, encrypted with this one; none for key 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Bytes>,
}

impl Object for KeyChange {
    const TYPE: &'static str = "key_change";
}

/// A record of the member list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// The space.
    pub space: SpaceId,
    /// Its position, from 0.
    pub seq: u64,
    /// The hash of the record before; none at 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Sha256Hash>,
    /// Who wrote it.
    pub author: MemberId,
    /// Members added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<Member>,
    /// Members removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<MemberId>,
    /// A new key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyChange>,
    /// Grants of the current key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    /// The author's signature.
    pub signature: Bytes,
}

impl Object for MemberRecord {
    const TYPE: &'static str = "member_record";
}

impl MemberRecord {
    /// The hash of the record: SHA-256 of its canonical encoding with its signature.
    pub fn hash(&self) -> Sha256Hash {
        Sha256Hash::of(&to_root(self).expect("a record has a canonical encoding"))
    }

    fn signed(mut self, author: &MemberKeys) -> Self {
        self.author = author.id();
        self.signature = author.sign(&unsigned(&self));
        self
    }

    /// The first record of new space: the founder, and further members such as a recovery code, with key 0 – which
    /// is returned.
    pub fn found(space: &SpaceId, founder: &MemberKeys, members: Vec<Member>) -> (Self, SpaceKey) {
        let key = SpaceKey::generate();
        let grants = members.iter().map(|m| key.grant(founder.domain, space, 0, m)).collect();
        let record = MemberRecord {
            space: space.clone(),
            seq: 0,
            prev: None,
            author: founder.id(),
            add: members,
            remove: vec![],
            key: Some(KeyChange { index: 0, previous: None }),
            grants,
            signature: Bytes(vec![]),
        };
        (record.signed(founder), key)
    }
}

/// Why a record of the member list is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordProblem {
    /// Of other space.
    #[error("the record is of other space")]
    OtherSpace,
    /// Not the next position, or not pointing to the head.
    #[error("the record does not follow the head of the list")]
    NotNext,
    /// The signature is not the author's.
    #[error("the record's signature is not its author's")]
    Signature,
    /// The first record is not a founding.
    #[error("the first record must add its author with key 0 and remove nobody")]
    Founding,
    /// The author is not a member with the right to manage.
    #[error("the author {0} may not manage members")]
    NotAllowed(MemberId),
    /// A member added twice, or a device name taken.
    #[error("member {0} is already a member, or its device name is taken")]
    Duplicate(MemberId),
    /// Removing someone who is not a member.
    #[error("{0} is not a member")]
    NotMember(MemberId),
    /// Removing without a new key, or a new key at the wrong position.
    #[error("the key must change to the next position")]
    KeyChange,
    /// A member without a grant of the current key, or a grant for a non-member.
    #[error("member {0} has no grant of the current key")]
    Grant(MemberId),
    /// Nobody left who may manage members.
    #[error("no member left who may manage members")]
    NoManager,
}

/// The member list of a space, applied record by record.
#[derive(Debug, Clone)]
pub struct MemberList {
    domain: Domain,
    space: SpaceId,
    records: Vec<MemberRecord>,
    members: BTreeMap<MemberId, Member>,
    grants: BTreeMap<(MemberId, u32), Grant>,
    chain: BTreeMap<u32, Bytes>,
    key: Option<u32>,
}

impl MemberList {
    /// The empty list of a space.
    pub fn new(domain: Domain, space: SpaceId) -> Self {
        MemberList {
            domain,
            space,
            records: vec![],
            members: BTreeMap::new(),
            grants: BTreeMap::new(),
            chain: BTreeMap::new(),
            key: None,
        }
    }

    /// The list of these records, checked in order.
    pub fn from_records(domain: Domain, space: SpaceId, records: &[MemberRecord]) -> Result<Self, RecordProblem> {
        let mut list = MemberList::new(domain, space);
        for record in records {
            list.apply(record.clone())?;
        }
        Ok(list)
    }

    /// The space.
    pub fn space(&self) -> &SpaceId {
        &self.space
    }

    /// The records applied.
    pub fn records(&self) -> &[MemberRecord] {
        &self.records
    }

    /// The current members.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    /// A current member.
    pub fn member(&self, id: &MemberId) -> Option<&Member> {
        self.members.get(id)
    }

    /// A member as it was last added – current or removed since. Events written while it was a member stay its
    /// events after it is removed.
    pub fn member_ever(&self, id: &MemberId) -> Option<&Member> {
        self.records.iter().rev().flat_map(|record| &record.add).find(|member| member.id == *id)
    }

    /// The position of the current key; none before the first record.
    pub fn key_index(&self) -> Option<u32> {
        self.key
    }

    /// The hash of the last record.
    pub fn head(&self) -> Option<Sha256Hash> {
        self.records.last().map(MemberRecord::hash)
    }

    /// Checks a record against the list as it is and applies it.
    pub fn apply(&mut self, record: MemberRecord) -> Result<(), RecordProblem> {
        if record.space != self.space {
            return Err(RecordProblem::OtherSpace);
        }
        if record.seq != self.records.len() as u64 || record.prev != self.head() {
            return Err(RecordProblem::NotNext);
        }
        if !verify(&record.author, &unsigned(&record), &record.signature) {
            return Err(RecordProblem::Signature);
        }
        let mut members = self.members.clone();
        if record.seq == 0 {
            let founding = record.add.iter().any(|m| m.id == record.author)
                && record.remove.is_empty()
                && record.key.as_ref().is_some_and(|k| k.index == 0 && k.previous.is_none());
            if !founding {
                return Err(RecordProblem::Founding);
            }
        } else if self.members.get(&record.author).is_none_or(|m| m.rights != Rights::Manage) {
            return Err(RecordProblem::NotAllowed(record.author));
        }
        for id in &record.remove {
            if members.remove(id).is_none() {
                return Err(RecordProblem::NotMember(*id));
            }
        }
        for member in &record.add {
            let taken =
                member.device.is_some() && members.values().any(|m| m.device.is_some() && m.device == member.device);
            if members.contains_key(&member.id) || taken {
                return Err(RecordProblem::Duplicate(member.id));
            }
            members.insert(member.id, member.clone());
        }
        let next = self.key.map_or(0, |k| k + 1);
        let key = match &record.key {
            Some(change) if change.index == next && (change.index == 0) == change.previous.is_none() => change.index,
            Some(_) => return Err(RecordProblem::KeyChange),
            None if !record.remove.is_empty() || self.key.is_none() => return Err(RecordProblem::KeyChange),
            None => self.key.expect("a key after the first record"),
        };
        let mut grants = self.grants.clone();
        for grant in &record.grants {
            if !members.contains_key(&grant.member) || grant.key != key {
                return Err(RecordProblem::Grant(grant.member));
            }
            grants.insert((grant.member, grant.key), grant.clone());
        }
        if let Some(missing) = members.keys().find(|id| !grants.contains_key(&(**id, key))) {
            return Err(RecordProblem::Grant(*missing));
        }
        if !members.values().any(|m| m.rights == Rights::Manage) {
            return Err(RecordProblem::NoManager);
        }
        if let Some(previous) = record.key.as_ref().and_then(|k| k.previous.clone()) {
            self.chain.insert(key, previous);
        }
        self.members = members;
        self.grants = grants;
        self.key = Some(key);
        self.records.push(record);
        Ok(())
    }

    /// Every key of the space this member can open, by position: its grant of the latest key it has one for, and the
    /// chain back from there.
    pub fn keys(&self, me: &MemberKeys) -> Result<BTreeMap<u32, SpaceKey>, EncryptionError> {
        let current = self.key.ok_or(EncryptionError::NoKey(0))?;
        let (_, grant) =
            self.grants.range((me.id(), 0)..=(me.id(), current)).next_back().ok_or(EncryptionError::NoKey(current))?;
        let mut keys = BTreeMap::new();
        let mut index = grant.key;
        let mut key = me.unwrap(&self.space, grant)?;
        loop {
            keys.insert(index, key.clone());
            if index == 0 {
                break;
            }
            let previous = self.chain.get(&index).ok_or(EncryptionError::NoKey(index - 1))?;
            key = key.unchain(self.domain, &self.space, index, previous)?;
            index -= 1;
        }
        Ok(keys)
    }

    /// The next record: members added, with grants of the current key; signed by `author`, who holds `current`.
    pub fn add(&self, author: &MemberKeys, current: &SpaceKey, members: Vec<Member>) -> MemberRecord {
        let index = self.key.unwrap_or(0);
        let grants = members.iter().map(|m| current.grant(self.domain, &self.space, index, m)).collect();
        self.next(MemberRecord { add: members, grants, ..self.blank() }).signed(author)
    }

    /// The next record: members removed and a new key for those who stay, which is returned.
    pub fn remove(&self, author: &MemberKeys, current: &SpaceKey, ids: Vec<MemberId>) -> (MemberRecord, SpaceKey) {
        let index = self.key.map_or(0, |k| k + 1);
        let key = SpaceKey::generate();
        let grants = self
            .members
            .values()
            .filter(|m| !ids.contains(&m.id))
            .map(|m| key.grant(self.domain, &self.space, index, m))
            .collect();
        let record = MemberRecord {
            remove: ids,
            key: Some(KeyChange { index, previous: Some(key.chain(self.domain, &self.space, index, current)) }),
            grants,
            ..self.blank()
        };
        (self.next(record).signed(author), key)
    }

    fn blank(&self) -> MemberRecord {
        MemberRecord {
            space: self.space.clone(),
            seq: 0,
            prev: None,
            author: MemberId([0; 32]),
            add: vec![],
            remove: vec![],
            key: None,
            grants: vec![],
            signature: Bytes(vec![]),
        }
    }

    fn next(&self, mut record: MemberRecord) -> MemberRecord {
        record.seq = self.records.len() as u64;
        record.prev = self.head();
        record
    }
}

/// What an envelope carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvelopeContent {
    /// An event.
    Event,
    /// The bytes of an original.
    Original,
}

/// An encrypted event or original on its way between members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The space.
    pub space: SpaceId,
    /// The position of the key it is encrypted with.
    pub key: u32,
    /// Who sent it.
    pub author: MemberId,
    /// What it carries.
    pub content: EnvelopeContent,
    /// The nonce, 24 bytes.
    pub nonce: Bytes,
    /// The encrypted content.
    pub ciphertext: Bytes,
    /// SHA-256 over the nonce and the ciphertext.
    pub id: Sha256Hash,
    /// The author's signature.
    pub signature: Bytes,
}

impl Object for Envelope {
    const TYPE: &'static str = "envelope";
}

/// The additional data of an envelope: its space, key, author and content.
fn envelope_aad(space: &SpaceId, key: u32, author: &MemberId, content: EnvelopeContent) -> Vec<u8> {
    let header = serde_json::json!({"space": space, "key": key, "author": author, "content": content});
    to_canonical_vec(&header).expect("the header of an envelope has a canonical encoding")
}

impl Envelope {
    /// Encrypts content with the key at `index` and signs it.
    pub fn seal(
        space: &SpaceId,
        index: u32,
        key: &SpaceKey,
        author: &MemberKeys,
        content: EnvelopeContent,
        plaintext: &[u8],
    ) -> Self {
        let aad = envelope_aad(space, index, &author.id(), content);
        let (nonce, ciphertext) = key.seal(plaintext, &aad);
        let id = Sha256Hash::of(&[nonce.as_slice(), &ciphertext].concat());
        let mut envelope = Envelope {
            space: space.clone(),
            key: index,
            author: author.id(),
            content,
            nonce: Bytes(nonce.to_vec()),
            ciphertext: Bytes(ciphertext),
            id,
            signature: Bytes(vec![]),
        };
        envelope.signature = author.sign(&unsigned(&envelope));
        envelope
    }

    /// An event in an envelope.
    pub fn seal_event(space: &SpaceId, index: u32, key: &SpaceKey, author: &MemberKeys, event: &Event) -> Self {
        let plaintext = event.to_canonical().expect("an event written here has a canonical encoding");
        Self::seal(space, index, key, author, EnvelopeContent::Event, &plaintext)
    }

    /// Whether the signature is the author's and the identity is that of the ciphertext.
    pub fn is_authentic(&self) -> bool {
        self.id == Sha256Hash::of(&[self.nonce.0.as_slice(), &self.ciphertext.0].concat())
            && verify(&self.author, &unsigned(self), &self.signature)
    }

    /// The content, decrypted with the keys of the space, after checking the signature.
    pub fn open(&self, keys: &BTreeMap<u32, SpaceKey>) -> Result<Vec<u8>, EncryptionError> {
        if !self.is_authentic() {
            return Err(EncryptionError::Signature);
        }
        let key = keys.get(&self.key).ok_or(EncryptionError::NoKey(self.key))?;
        key.open(&self.nonce.0, &self.ciphertext.0, &envelope_aad(&self.space, self.key, &self.author, self.content))
    }

    /// The canonical encoding of the event in the envelope; its device must be the device name its author was added
    /// with to the member list.
    pub fn open_event(&self, keys: &BTreeMap<u32, SpaceKey>, members: &MemberList) -> Result<Vec<u8>, EncryptionError> {
        if self.content != EnvelopeContent::Event {
            return Err(EncryptionError::Format("envelope of an event"));
        }
        let plaintext = self.open(keys)?;
        let event = Event::read(&plaintext)?;
        // The author may have been removed since: what it wrote as a member stays readable.
        let device = members.member_ever(&self.author).and_then(|m| m.device.as_ref());
        if device != Some(&event.time.device) {
            return Err(EncryptionError::Signature);
        }
        Ok(plaintext)
    }
}

/// The value of the header `Authorization` of a request to a relay: the member, the time and the signature over
/// `{method} {path} {time}`.
pub fn request_signature(keys: &MemberKeys, method: &str, path: &str, time: u64) -> String {
    let signature = keys.sign(format!("{method} {path} {time}").as_bytes());
    format!("{} {} {time} {}", keys.domain.scheme, keys.id(), base64url(&signature.0))
}

/// The member who signed a request, if the header is valid and its time within 300 seconds of `now`.
pub fn verify_request(domain: Domain, header: &str, method: &str, path: &str, now: u64) -> Option<MemberId> {
    let mut parts = header.strip_prefix(domain.scheme)?.strip_prefix(' ')?.split(' ');
    let (member, time, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let member: MemberId = member.parse().ok()?;
    let time: u64 = time.parse().ok()?;
    let signature = Bytes(from_base64url(signature)?);
    (now.abs_diff(time) <= 300 && verify(&member, format!("{method} {path} {time}").as_bytes(), &signature))
        .then_some(member)
}

/// An invitation to add a device: the relay, the space and a secret, carried to the new device by its person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The address of the relay.
    pub relay: String,
    /// The space.
    pub space: SpaceId,
    /// 16 random bytes.
    pub secret: [u8; 16],
}

/// A request to join a space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The member the device would be.
    pub member: Member,
    /// HMAC-SHA256 with the invitation's secret over the canonical encoding of the member.
    pub proof: Bytes,
}

impl Object for JoinRequest {
    const TYPE: &'static str = "join_request";
}

impl Invitation {
    /// A new invitation.
    pub fn new(relay: &str, space: SpaceId) -> Self {
        Invitation { relay: relay.to_owned(), space, secret: random() }
    }

    fn mac(&self, member: &Member) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&self.secret).expect("HMAC takes any key");
        mac.update(&to_root(member).expect("a member has a canonical encoding"));
        mac
    }

    /// The request of a new member.
    pub fn request(&self, member: Member) -> JoinRequest {
        let proof = Bytes(self.mac(&member).finalize().into_bytes().to_vec());
        JoinRequest { member, proof }
    }

    /// Whether a request was made with this invitation.
    pub fn proves(&self, request: &JoinRequest) -> bool {
        self.mac(&request.member).verify_slice(&request.proof.0).is_ok()
    }
}

/// Crockford's base32 alphabet.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A recovery code: the seed of a recovery member, in Crockford's base32 with a check character, in groups of four.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode(pub [u8; 32]);

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(…)")
    }
}

impl RecoveryCode {
    /// A new code.
    pub fn generate() -> Self {
        RecoveryCode(random())
    }

    /// The keys of the recovery member.
    pub fn keys(&self, domain: Domain) -> MemberKeys {
        MemberKeys::from_seed(domain, self.0)
    }
}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digits = Vec::with_capacity(53);
        let (mut buffer, mut bits) = (0u32, 0u32);
        for byte in self.0 {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                digits.push(CROCKFORD[((buffer >> bits) & 31) as usize]);
            }
        }
        if bits > 0 {
            digits.push(CROCKFORD[((buffer << (5 - bits)) & 31) as usize]);
        }
        let check = self.0.iter().map(|b| u32::from(*b)).sum::<u32>() % 32;
        digits.push(CROCKFORD[check as usize]);
        let groups: Vec<String> = digits.chunks(4).map(|g| String::from_utf8_lossy(g).into_owned()).collect();
        f.write_str(&groups.join("-"))
    }
}

impl FromStr for RecoveryCode {
    type Err = EncryptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = EncryptionError::Format("recovery code");
        let mut values = Vec::with_capacity(53);
        for c in s.chars().filter(|c| !c.is_whitespace() && *c != '-') {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            let value = CROCKFORD.iter().position(|d| char::from(*d) == c).ok_or(invalid.clone())?;
            values.push(value as u32);
        }
        if values.len() != 53 {
            return Err(invalid);
        }
        let check = values.pop().expect("53 values");
        let (mut buffer, mut bits, mut bytes) = (0u32, 0u32, Vec::with_capacity(32));
        for value in values {
            buffer = (buffer << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes.push((buffer >> bits) as u8);
            }
        }
        let seed: [u8; 32] = bytes.try_into().map_err(|_| invalid.clone())?;
        if seed.iter().map(|b| u32::from(*b)).sum::<u32>() % 32 != check {
            return Err(invalid);
        }
        Ok(RecoveryCode(seed))
    }
}

#[cfg(test)]
mod tests {
    use kernoid_log::{Clock, Log};

    use super::*;

    const D: Domain = Domain::KERNOID;
    /// Another domain, to show that its keys open nothing of kernoid's.
    const OTHER: Domain = Domain { label: "example/other", scheme: "other" };

    fn space() -> SpaceId {
        "0192f1e4-0000-7000-8000-0000000000b1".parse().unwrap()
    }

    fn device(keys: &MemberKeys, name: &str) -> Member {
        Member::device(keys, name.parse().unwrap(), Some(name.into()), Rights::Manage)
    }

    #[test]
    fn keys_come_from_the_seed_and_domain_and_sign() {
        let keys = MemberKeys::generate(D);
        let again = MemberKeys::from_seed(D, keys.seed());
        assert_eq!((keys.id(), keys.receiving()), (again.id(), again.receiving()));
        let elsewhere = MemberKeys::from_seed(OTHER, keys.seed());
        assert_ne!(keys.id(), elsewhere.id(), "another domain, other keys");
        let signature = keys.sign(b"text");
        assert!(verify(&keys.id(), b"text", &signature) && !verify(&keys.id(), b"other", &signature));
        let id: MemberId = keys.id().to_string().parse().unwrap();
        assert_eq!(id, keys.id());
        assert!(keys.id().to_string().starts_with("ed25519:") && keys.receiving().to_string().starts_with("x25519:"));
    }

    #[test]
    fn the_labels_of_a_domain_give_its_keys() {
        // The member identity of the seed 0x01… under the labels of another domain: HKDF-SHA256 of the seed with the
        // info `{label} signing`, then Ed25519.
        let seed = [1u8; 32];
        let mut expected = [0u8; 32];
        Hkdf::<Sha256>::new(None, &seed).expand(b"example/other signing", &mut expected).unwrap();
        let expected = SigningKey::from_bytes(&expected).verifying_key().to_bytes();
        assert_eq!(MemberKeys::from_seed(OTHER, seed).id().0, expected);
    }

    #[test]
    fn a_device_is_added_and_reads_the_history_after_a_removal() {
        let (laptop, phone, old) = (MemberKeys::generate(D), MemberKeys::generate(D), MemberKeys::generate(D));
        let recovery = RecoveryCode::generate();
        let (first, key0) = MemberRecord::found(
            &space(),
            &laptop,
            vec![device(&laptop, "laptop"), Member::recovery(&recovery.keys(D)), device(&old, "old")],
        );
        let mut list = MemberList::new(D, space());
        list.apply(first).unwrap();
        // The old device is removed: a new key, which the old device cannot open.
        let (second, key1) = list.remove(&laptop, &key0, vec![old.id()]);
        list.apply(second).unwrap();
        assert_eq!(list.key_index(), Some(1));
        // What it could read, it keeps; the new key it cannot open.
        assert_eq!(list.keys(&old).unwrap().keys().copied().collect::<Vec<_>>(), vec![0]);
        // The phone is added and reads key 1 and, through the chain, key 0.
        let third = list.add(&laptop, &key1, vec![device(&phone, "phone")]);
        list.apply(third).unwrap();
        let keys = list.keys(&phone).unwrap();
        assert_eq!((keys.get(&0), keys.get(&1)), (Some(&key0), Some(&key1)));
        // The recovery code reads them, too; the records check again from the start.
        assert_eq!(list.keys(&recovery.keys(D)).unwrap().len(), 2);
        assert!(MemberList::from_records(D, space(), list.records()).is_ok());
        // A record from someone else's hand, or out of order, is not applied.
        let stranger = MemberKeys::generate(D);
        let forged = list.add(&stranger, &key1, vec![device(&stranger, "stranger")]);
        assert_eq!(list.clone().apply(forged), Err(RecordProblem::NotAllowed(stranger.id())));
        let mut late = list.add(&laptop, &key1, vec![device(&stranger, "phone")]);
        assert!(matches!(list.clone().apply(late.clone()), Err(RecordProblem::Duplicate(_))));
        late.seq = 1;
        assert_eq!(list.clone().apply(late), Err(RecordProblem::NotNext));
        let mut tampered = list.add(&laptop, &key1, vec![device(&stranger, "tablet")]);
        tampered.add[0].rights = Rights::Read;
        assert_eq!(list.clone().apply(tampered), Err(RecordProblem::Signature));
    }

    #[test]
    fn events_travel_in_envelopes() {
        let (laptop, phone) = (MemberKeys::generate(D), MemberKeys::generate(D));
        let (first, key0) = MemberRecord::found(&space(), &laptop, vec![device(&laptop, "laptop")]);
        let mut list = MemberList::new(D, space());
        list.apply(first).unwrap();
        list.apply(list.add(&laptop, &key0, vec![device(&phone, "phone")])).unwrap();
        let mut clock = Clock::new("laptop".parse().unwrap());
        let event = Event::new(clock.now(1), 1, None, &serde_json::json!({"kind": "space_founded"})).unwrap();
        let envelope = Envelope::seal_event(&space(), 0, &key0, &laptop, &event);
        let json = to_root(&envelope).unwrap();
        let received: Envelope = kernoid_base::from_root(&json).unwrap();
        let keys = list.keys(&phone).unwrap();
        let mut log = Log::new();
        let (hash, _) = log.receive(&received.open_event(&keys, &list).unwrap()).unwrap();
        assert_eq!(log.get(&hash), Some(&event));
        // From the phone, the laptop's event would be a forgery.
        let wrong = Envelope::seal_event(&space(), 0, &key0, &phone, &event);
        assert_eq!(wrong.open_event(&keys, &list), Err(EncryptionError::Signature));
        let mut changed = received.clone();
        changed.ciphertext.0[0] ^= 1;
        assert_eq!(changed.open(&keys), Err(EncryptionError::Signature));
    }

    #[test]
    fn events_of_a_removed_member_stay_readable() {
        let (laptop, phone, tablet) = (MemberKeys::generate(D), MemberKeys::generate(D), MemberKeys::generate(D));
        let (first, key0) = MemberRecord::found(&space(), &laptop, vec![device(&laptop, "laptop")]);
        let mut list = MemberList::new(D, space());
        list.apply(first).unwrap();
        list.apply(list.add(&laptop, &key0, vec![device(&phone, "phone")])).unwrap();
        let event = Event::new(Clock::new("phone".parse().unwrap()).now(1), 1, None, &serde_json::json!({"kind": "x"}));
        let envelope = Envelope::seal_event(&space(), 0, &key0, &phone, &event.unwrap());
        let (removal, key1) = list.remove(&laptop, &key0, vec![phone.id()]);
        list.apply(removal).unwrap();
        list.apply(list.add(&laptop, &key1, vec![device(&tablet, "tablet")])).unwrap();
        assert!(list.member(&phone.id()).is_none());
        assert!(list.member_ever(&phone.id()).is_some());
        assert!(envelope.open_event(&list.keys(&tablet).unwrap(), &list).is_ok());
    }

    #[test]
    fn requests_are_signed_and_invitations_proven() {
        let keys = MemberKeys::generate(D);
        let path = "/v1/spaces/x/envelopes?after=0";
        let header = request_signature(&keys, "GET", path, 1_000);
        assert!(header.starts_with("kernoid ed25519:"));
        assert_eq!(verify_request(D, &header, "GET", path, 1_200), Some(keys.id()));
        assert_eq!(verify_request(D, &header, "GET", path, 1_400), None);
        assert_eq!(verify_request(D, &header, "POST", path, 1_000), None);
        assert_eq!(verify_request(OTHER, &header, "GET", path, 1_000), None);
        let invitation = Invitation::new("https://relay.example", space());
        let request = invitation.request(device(&keys, "phone"));
        assert!(invitation.proves(&request));
        assert!(!Invitation::new("https://relay.example", space()).proves(&request));
    }

    #[test]
    fn recovery_codes_read_back_and_check_themselves() {
        let code = RecoveryCode::generate();
        let text = code.to_string();
        assert_eq!((text.len(), text.matches('-').count()), (53 + 13, 13));
        assert_eq!(text.to_lowercase().replace('0', "o").parse::<RecoveryCode>().unwrap(), code);
        let mut wrong = text.clone().into_bytes();
        let i = wrong.iter().position(|b| *b != b'-').unwrap();
        let value = CROCKFORD.iter().position(|d| *d == wrong[i]).unwrap();
        wrong[i] = CROCKFORD[value ^ 1];
        assert!(String::from_utf8(wrong).unwrap().parse::<RecoveryCode>().is_err());
    }
}
