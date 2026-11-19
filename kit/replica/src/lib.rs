// SPDX-License-Identifier: MIT
//! Synchronisation of spaces between the devices of their members through a relay, end-to-end encrypted.
//!
//! A [`Replica`] is what one device holds: the events and member records of its spaces (`kernoid-space-store`), their
//! originals (`kernoid-blob`) and its clock. Each space that is synchronised has, on the device, a member seed, the
//! address of its relay and how far it has read there. The member list lives on the relay and is checked again here,
//! record by record, before a key is used. Events and originals travel in envelopes; what was sent or received is
//! noted, so that nothing travels twice. A person's devices join by an invitation; when every device is lost, the
//! recovery code made when the space was first synchronised adds a new one.
//!
//! OPEN: the seed is kept in the store beside the data; the key store of the operating system is not used yet.

pub mod streams;
pub mod transport;

use std::{collections::BTreeMap, sync::Arc};

use kernoid_base::{Sha256Hash, SpaceId, base64url, from_base64url, from_root, to_root};
use kernoid_blob::{BlobError, Blobs};
use kernoid_crypt::{
    Domain, EncryptionError, Envelope, EnvelopeContent, Invitation, JoinRequest, Member, MemberKeys, MemberList,
    MemberRecord, MemberRole, RecoveryCode, Rights, SpaceKey, request_signature,
};
use kernoid_log::{Clock, DeviceId, EventError, EventHash, Log};
use kernoid_space_store::{Backend, Store, StoreError};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

/// The setting under which the state of synchronising a space is kept.
const SYNC: &str = "sync";
/// The setting that lists the spaces this device has asked to join.
const JOINING: &str = "joining";
/// How long an invitation is good for, in seconds.
pub const INVITATION_LIFETIME: u64 = 24 * 60 * 60;
/// How many envelopes are asked for at once.
const PAGE: usize = 500;

/// Why synchronising failed.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The store.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The originals.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// An event.
    #[error(transparent)]
    Event(#[from] EventError),
    /// The encryption: a key, a signature, a record.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// The relay could not be reached, or refused.
    #[error("the relay: {0}")]
    Relay(String),
    /// What was asked does not fit the state of the space.
    #[error("{0}")]
    State(String),
}

fn state_error(message: impl Into<String>) -> SyncError {
    SyncError::State(message.into())
}

fn relay_error(message: impl std::fmt::Display) -> SyncError {
    SyncError::Relay(message.to_string())
}

/// Milliseconds since 1970-01-01 UTC.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_millis() as u64)
}

/// Milliseconds since 1970-01-01 UTC: the browser's clock.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn now_s() -> u64 {
    now_ms() / 1000
}

/// The state of synchronising one space on this device.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncState {
    /// The address of the relay.
    relay: String,
    /// The seed of this device as a member, in hexadecimal.
    seed: String,
    /// The relay's position up to which envelopes were received.
    position: i64,
    /// Whether this device is a member yet – after asking to join, it is not until it was added.
    joined: bool,
    /// Invitations made here that are still open.
    #[serde(default)]
    invited: Vec<Invited>,
    /// What this device may do, as the member list said at the last synchronisation.
    #[serde(default)]
    rights: Option<Rights>,
}

/// An invitation made here: its secret in hexadecimal, when it was made, and what the one it brings may do.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Invited {
    secret: String,
    made: u64,
    rights: Rights,
}

/// What a synchronisation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Events and originals received.
    pub received: usize,
    /// Events and originals sent.
    pub sent: usize,
    /// Devices added by invitation, by name.
    pub added: Vec<String>,
    /// Whether this device still waits to be added.
    pub waiting: bool,
}

/// An invitation as text: the relay, `#join=`, the space, `.` and the secret in base64url.
pub fn invitation_text(invitation: &Invitation) -> String {
    format!("{}#join={}.{}", invitation.relay.trim_end_matches('/'), invitation.space, base64url(&invitation.secret))
}

/// Reads an invitation from its text.
pub fn parse_invitation(text: &str) -> Result<Invitation, SyncError> {
    let invalid = || state_error("not an invitation to a space");
    let (relay, rest) = text.trim().split_once("#join=").ok_or_else(invalid)?;
    let (space, secret) = rest.split_once('.').ok_or_else(invalid)?;
    let secret = from_base64url(secret).ok_or_else(invalid)?;
    Ok(Invitation {
        relay: relay.to_owned(),
        space: space.parse().map_err(|_| invalid())?,
        secret: secret.try_into().map_err(|_| invalid())?,
    })
}

/// The header with the token of the account that founds a space at a kernoid that keeps spaces only for its accounts.
pub const FOUNDER_HEADER: &str = "kernoid-session";

/// Requests to a relay, signed by a member.
struct Client<'a> {
    transport: Arc<dyn transport::Transport>,
    base: String,
    keys: &'a MemberKeys,
    /// The token of the account founding a space, sent in [`FOUNDER_HEADER`].
    founder: Option<&'a str>,
}

impl<'a> Client<'a> {
    fn new(base: &str, keys: &'a MemberKeys) -> Self {
        Client {
            transport: transport::default_transport(),
            base: base.trim_end_matches('/').to_owned(),
            keys,
            founder: None,
        }
    }

    /// The same, founding a space for the account of `token`.
    fn founding(mut self, token: Option<&'a str>) -> Self {
        self.founder = token;
        self
    }

    /// The path as the relay receives it: the base's own path, if any, and the request's.
    fn signed_path(&self, path: &str) -> String {
        let prefix = self.base.split("://").nth(1).and_then(|rest| rest.find('/').map(|i| &rest[i..])).unwrap_or("");
        format!("{prefix}{path}")
    }

    fn get(&self, path: &str) -> Result<(u16, Vec<u8>), SyncError> {
        let signature = request_signature(self.keys, "GET", &self.signed_path(path), now_s());
        self.transport
            .send("GET", &format!("{}{path}", self.base), &[("Authorization", &signature)], None)
            .map_err(|e| relay_error(format!("{}: {e}", self.base)))
    }

    fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), SyncError> {
        let signature = request_signature(self.keys, "POST", &self.signed_path(path), now_s());
        let mut headers = vec![("Authorization", signature.as_str()), ("Content-Type", "application/json")];
        if let Some(token) = self.founder {
            headers.push((FOUNDER_HEADER, token));
        }
        self.transport
            .send("POST", &format!("{}{path}", self.base), &headers, Some(body))
            .map_err(|e| relay_error(format!("{}: {e}", self.base)))
    }

    /// The error of an answer that is not a success.
    fn refused(status: u16, body: &[u8]) -> SyncError {
        let message = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
        relay_error(format!("refused ({status}): {message}"))
    }

    /// A JSON answer of status 200.
    fn json<T: DeserializeOwned>(&self, path: &str) -> Result<T, SyncError> {
        let (status, body) = self.get(path)?;
        if status != 200 {
            return Err(Self::refused(status, &body));
        }
        serde_json::from_slice(&body).map_err(relay_error)
    }

    /// The member list of the space, checked record by record.
    fn members(&self, domain: Domain, space: &SpaceId) -> Result<MemberList, SyncError> {
        let records: Vec<Value> = self.json(&format!("/v1/spaces/{space}/members"))?;
        let mut list = MemberList::new(domain, space.clone());
        for record in records {
            let record: MemberRecord = from_root(record.to_string().as_bytes()).map_err(relay_error)?;
            list.apply(record).map_err(|e| relay_error(format!("the member list is not valid: {e}")))?;
        }
        Ok(list)
    }

    /// Sends a record; whether it was taken (or the head had moved on).
    fn record(&self, space: &SpaceId, record: &MemberRecord) -> Result<bool, SyncError> {
        let body = to_root(record).expect("a record has a canonical encoding");
        let (status, body) = self.post(&format!("/v1/spaces/{space}/members"), body)?;
        match status {
            201 => Ok(true),
            409 => Ok(false),
            _ => Err(Self::refused(status, &body)),
        }
    }

    fn envelope(&self, space: &SpaceId, envelope: &Envelope) -> Result<(), SyncError> {
        let body = to_root(envelope).expect("an envelope has a canonical encoding");
        let (status, body) = self.post(&format!("/v1/spaces/{space}/envelopes"), body)?;
        if status == 200 || status == 201 { Ok(()) } else { Err(Self::refused(status, &body)) }
    }
}

/// The current key of a space for a member.
fn current_key(list: &MemberList, keys: &MemberKeys) -> Result<SpaceKey, SyncError> {
    let index = list.key_index().ok_or_else(|| state_error("the space has no key yet"))?;
    list.keys(keys)?.remove(&index).ok_or_else(|| state_error("no current key for this device"))
}

/// What one device holds: its spaces, their originals and its clock – and how it synchronises them. The store is
/// SQLite ([`Store`]) on a device, or any other [`Backend`].
pub struct Replica<S: Backend = Store> {
    domain: Domain,
    device: DeviceId,
    store: S,
    blobs: Arc<dyn Blobs>,
    clock: Clock,
}

impl<S: Backend> std::fmt::Debug for Replica<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replica").field("domain", &self.domain).field("device", &self.device).finish_non_exhaustive()
    }
}

impl<S: Backend> Replica<S> {
    /// The replica of the device `device` on a store and a store of originals; its clock observes every event held.
    pub fn open(domain: Domain, device: DeviceId, store: S, blobs: Arc<dyn Blobs>) -> Result<Self, SyncError> {
        let mut clock = Clock::new(device.clone());
        for space in store.spaces()? {
            if let Some(latest) = store.load(&space)?.latest() {
                clock.observe(latest, now_ms());
            }
        }
        Ok(Replica { domain, device, store, blobs, clock })
    }

    /// The device name this replica writes under.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// The store, for the program's own reads – settings and the like.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The spaces held, and those this device has asked to join.
    pub fn spaces(&self) -> Result<Vec<SpaceId>, SyncError> {
        let mut spaces = self.store.spaces()?;
        for space in self.joining()? {
            if !spaces.contains(&space) {
                spaces.push(space);
            }
        }
        spaces.sort();
        Ok(spaces)
    }

    /// A new space on this device; nothing is written until the first event.
    pub fn new_space(&self) -> SpaceId {
        SpaceId::generate(now_ms())
    }

    /// The log of a space.
    pub fn log(&self, space: &SpaceId) -> Result<Log, SyncError> {
        Ok(self.store.load(space)?)
    }

    /// Writes an event of `payload` in a space on this device; returns its hash.
    pub fn write(&mut self, space: &SpaceId, payload: &impl Serialize) -> Result<EventHash, SyncError> {
        let mut log = self.store.load(space)?;
        if let Some(latest) = log.latest() {
            self.clock.observe(latest, now_ms());
        }
        let hash = log.append(&mut self.clock, now_ms(), payload)?;
        let mut new = Log::new();
        new.insert(log.get(&hash).expect("just written").clone()).map_err(EventError::from)?;
        self.store.save(&[(space, &new)])?;
        Ok(hash)
    }

    /// Keeps an original of a space; returns its hash.
    pub fn put_original(&self, space: &SpaceId, bytes: &[u8]) -> Result<Sha256Hash, SyncError> {
        let hash = self.blobs.put(bytes)?;
        self.store.add_original(space, &hash)?;
        Ok(hash)
    }

    /// The bytes of an original, if held.
    pub fn original(&self, hash: &Sha256Hash) -> Result<Option<Vec<u8>>, SyncError> {
        Ok(self.blobs.get(hash)?)
    }

    fn state(&self, space: &SpaceId) -> Result<Option<SyncState>, SyncError> {
        let Some(json) = self.store.setting(Some(space), SYNC)? else { return Ok(None) };
        serde_json::from_str(&json).map(Some).map_err(|e| state_error(format!("the stored state is damaged: {e}")))
    }

    fn save_state(&self, space: &SpaceId, state: &SyncState) -> Result<(), SyncError> {
        let json = serde_json::to_string(state).expect("the state is JSON");
        Ok(self.store.set_setting(Some(space), SYNC, &json)?)
    }

    fn synchronised(&self, space: &SpaceId) -> Result<SyncState, SyncError> {
        self.state(space)?.ok_or_else(|| state_error("this space is not synchronised"))
    }

    fn keys_of(&self, state: &SyncState) -> Result<MemberKeys, SyncError> {
        let seed = hex::decode(&state.seed).ok().and_then(|seed| seed.try_into().ok());
        let seed = seed.ok_or_else(|| state_error("the stored seed is damaged"))?;
        Ok(MemberKeys::from_seed(self.domain, seed))
    }

    fn new_state(relay: &str, keys: &MemberKeys, joined: bool) -> SyncState {
        SyncState {
            relay: relay.to_owned(),
            seed: hex::encode(keys.seed()),
            position: 0,
            joined,
            invited: vec![],
            rights: joined.then_some(Rights::Manage),
        }
    }

    fn joining(&self) -> Result<Vec<SpaceId>, SyncError> {
        let Some(json) = self.store.setting(None, JOINING)? else { return Ok(Vec::new()) };
        serde_json::from_str(&json).map_err(|e| state_error(format!("the stored state is damaged: {e}")))
    }

    fn note_joining(&self, space: &SpaceId) -> Result<(), SyncError> {
        let mut joining = self.joining()?;
        if !joining.contains(space) {
            joining.push(space.clone());
        }
        Ok(self.store.set_setting(None, JOINING, &serde_json::to_string(&joining).expect("JSON"))?)
    }

    /// The member this device is in a space.
    fn me(&self, keys: &MemberKeys, name: Option<&str>) -> Member {
        Member::device(keys, self.device.clone(), name.map(str::to_owned), Rights::Manage)
    }

    /// The relay a space is synchronised through, if it is.
    pub fn relay(&self, space: &SpaceId) -> Result<Option<String>, SyncError> {
        Ok(self.state(space)?.map(|state| state.relay))
    }

    /// What this device may do in a synchronised space, as last seen.
    pub fn rights(&self, space: &SpaceId) -> Result<Option<Rights>, SyncError> {
        Ok(self.state(space)?.and_then(|state| state.rights))
    }

    /// Starts synchronising a space through a relay: founds its member list – this device and a recovery code – and
    /// sends everything. Returns the recovery code, which the person keeps on paper: without it and without a
    /// device, the space is lost.
    pub fn start_sync(&mut self, space: &SpaceId, relay: &str, name: Option<&str>) -> Result<RecoveryCode, SyncError> {
        self.start_sync_for(space, relay, name, None)
    }

    /// The same at a relay that keeps spaces only for its accounts – kernoid's, unless open (RFC 0010, 4): `account`
    /// is the token of the account the space is founded for (a session, or an access token of kernoid's apps).
    pub fn start_sync_for(
        &mut self,
        space: &SpaceId,
        relay: &str,
        name: Option<&str>,
        account: Option<&str>,
    ) -> Result<RecoveryCode, SyncError> {
        if self.state(space)?.is_some() {
            return Err(state_error("this space is synchronised already"));
        }
        let keys = MemberKeys::generate(self.domain);
        let recovery = RecoveryCode::generate();
        let me = self.me(&keys, name);
        let (record, _) = MemberRecord::found(space, &keys, vec![me, Member::recovery(&recovery.keys(self.domain))]);
        if !Client::new(relay, &keys).founding(account).record(space, &record)? {
            return Err(state_error("the relay holds this space already"));
        }
        self.save_state(space, &Self::new_state(relay, &keys, true))?;
        self.sync(space)?;
        Ok(recovery)
    }

    /// An invitation for another device, good for a day: the device joins with it, and the next synchronisation
    /// here adds it with these rights.
    pub fn invite(&self, space: &SpaceId, rights: Rights) -> Result<String, SyncError> {
        let mut state = self.synchronised(space)?;
        if state.rights != Some(Rights::Manage) {
            return Err(state_error("only a device that may manage the space invites"));
        }
        let invitation = Invitation::new(&state.relay, space.clone());
        state.invited.retain(|i| now_s().saturating_sub(i.made) < INVITATION_LIFETIME);
        state.invited.push(Invited { secret: hex::encode(invitation.secret), made: now_s(), rights });
        self.save_state(space, &state)?;
        Ok(invitation_text(&invitation))
    }

    /// Asks to join a space with an invitation; the space arrives once a device that may manage it has added this
    /// one, at a later synchronisation.
    pub fn join(&mut self, invitation: &str, name: Option<&str>) -> Result<SpaceId, SyncError> {
        let invitation = parse_invitation(invitation)?;
        let space = invitation.space.clone();
        if self.state(&space)?.is_some() || !self.store.load(&space)?.is_empty() {
            return Err(state_error("this space is on this device already"));
        }
        let keys = MemberKeys::generate(self.domain);
        let request: JoinRequest = invitation.request(self.me(&keys, name));
        let client = Client::new(&invitation.relay, &keys);
        let body = to_root(&request).expect("a request has a canonical encoding");
        let (status, body) = client.post(&format!("/v1/spaces/{space}/requests"), body)?;
        if status != 201 {
            return Err(Client::refused(status, &body));
        }
        self.save_state(&space, &Self::new_state(&invitation.relay, &keys, false))?;
        self.note_joining(&space)?;
        Ok(space)
    }

    /// Brings a space back to this device with its recovery code, when no other device is left: the recovery member
    /// adds this device, which then receives everything.
    pub fn recover(
        &mut self,
        relay: &str,
        space: &SpaceId,
        code: &RecoveryCode,
        name: Option<&str>,
    ) -> Result<SyncReport, SyncError> {
        if self.state(space)?.is_some() {
            return Err(state_error("this space is synchronised on this device already"));
        }
        let recovery = code.keys(self.domain);
        let client = Client::new(relay, &recovery);
        let list = client.members(self.domain, space)?;
        if list.member(&recovery.id()).is_none_or(|m| m.role != MemberRole::Recovery) {
            return Err(state_error("this is not the recovery code of this space"));
        }
        if list.members().any(|m| m.device.as_ref() == Some(&self.device)) {
            return Err(state_error(format!("a device named {} belongs to this space already", self.device)));
        }
        let keys = MemberKeys::generate(self.domain);
        let current = current_key(&list, &recovery)?;
        if !client.record(space, &list.add(&recovery, &current, vec![self.me(&keys, name)]))? {
            return Err(state_error("the member list changed meanwhile – try again"));
        }
        self.save_state(space, &Self::new_state(relay, &keys, true))?;
        self.note_joining(space)?;
        self.sync(space)
    }

    /// The members of a synchronised space, as the relay lists them, checked.
    pub fn members(&self, space: &SpaceId) -> Result<Vec<Member>, SyncError> {
        let state = self.synchronised(space)?;
        let keys = self.keys_of(&state)?;
        Ok(Client::new(&state.relay, &keys).members(self.domain, space)?.members().cloned().collect())
    }

    /// Removes a member – by its name, device name or identity: a new key is made, which it does not get. What it
    /// has read, it may have kept. Returns its name.
    pub fn remove_member(&mut self, space: &SpaceId, who: &str) -> Result<String, SyncError> {
        let state = self.synchronised(space)?;
        let keys = self.keys_of(&state)?;
        let client = Client::new(&state.relay, &keys);
        for _ in 0..3 {
            let list = client.members(self.domain, space)?;
            let member = list
                .members()
                .find(|m| {
                    m.id.to_string() == who
                        || m.device.as_ref().is_some_and(|d| d.as_str() == who)
                        || m.name.as_deref() == Some(who)
                })
                .cloned()
                .ok_or_else(|| state_error(format!("no member {who:?} in this space")))?;
            if member.id == keys.id() {
                return Err(state_error("this device cannot remove itself"));
            }
            let current = current_key(&list, &keys)?;
            let (record, _) = list.remove(&keys, &current, vec![member.id]);
            list.clone().apply(record.clone()).map_err(EncryptionError::from)?;
            if client.record(space, &record)? {
                return Ok(member.name.or(member.device.map(|d| d.to_string())).unwrap_or_default());
            }
        }
        Err(state_error("the member list keeps changing – try again"))
    }

    /// Synchronises every space that is; see [`Replica::sync`].
    pub fn sync_all(&mut self) -> Result<BTreeMap<SpaceId, SyncReport>, SyncError> {
        let mut reports = BTreeMap::new();
        for space in self.spaces()? {
            if self.state(&space)?.is_some() {
                reports.insert(space.clone(), self.sync(&space)?);
            }
        }
        Ok(reports)
    }

    /// Synchronises a space with its relay: reads and checks the member list, adds devices that joined with an
    /// invitation from here, receives what other devices sent and sends what this one has not sent yet.
    pub fn sync(&mut self, space: &SpaceId) -> Result<SyncReport, SyncError> {
        let mut state = self.synchronised(space)?;
        let keys = self.keys_of(&state)?;
        let client = Client::new(&state.relay, &keys);
        let mut report = SyncReport::default();
        let mut list = client.members(self.domain, space)?;
        let Some(me) = list.member(&keys.id()) else {
            let was_added = list.records().iter().any(|r| r.add.iter().any(|m| m.id == keys.id()));
            if state.joined || was_added {
                return Err(state_error("this device was removed from the space"));
            }
            report.waiting = true;
            return Ok(report);
        };
        state.joined = true;
        state.rights = Some(me.rights);

        state.invited.retain(|i| now_s().saturating_sub(i.made) < INVITATION_LIFETIME);
        if !state.invited.is_empty() && state.rights == Some(Rights::Manage) {
            report.added = self.add_requested(space, &client, &keys, &mut list, &mut state)?;
        }

        // What other devices sent.
        let all_keys = list.keys(&keys)?;
        let mut received = Log::new();
        loop {
            #[derive(Deserialize)]
            struct Item {
                position: i64,
                envelope: Value,
            }
            #[derive(Deserialize)]
            struct Page {
                envelopes: Vec<Item>,
                more: bool,
            }
            let page: Page =
                client.json(&format!("/v1/spaces/{space}/envelopes?after={}&limit={PAGE}", state.position))?;
            for item in &page.envelopes {
                let envelope: Envelope = from_root(item.envelope.to_string().as_bytes()).map_err(relay_error)?;
                state.position = item.position;
                if envelope.author == keys.id() {
                    continue; // sent from here
                }
                match envelope.content {
                    EnvelopeContent::Event => {
                        let (hash, _) = received.receive(&envelope.open_event(&all_keys, &list)?)?;
                        self.store.mark_sent(space, "event", &hash)?;
                    }
                    EnvelopeContent::Original => {
                        let hash = self.put_original(space, &envelope.open(&all_keys)?)?;
                        self.store.mark_sent(space, "original", &hash)?;
                    }
                }
                report.received += 1;
            }
            if !page.more || page.envelopes.is_empty() {
                break;
            }
        }
        if let Some(latest) = received.latest() {
            self.clock.observe(latest, now_ms());
        }
        self.store.save(&[(space, &received)])?;
        self.save_state(space, &state)?;

        // What this device has not sent yet: events and originals.
        if state.rights.is_some_and(|rights| rights >= Rights::Write) {
            let index = list.key_index().ok_or_else(|| state_error("the space has no key yet"))?;
            let key = all_keys.get(&index).ok_or_else(|| state_error("no current key for this device"))?;
            let log = self.store.load(space)?;
            let sent = self.store.sent(space, "event")?;
            for (hash, event) in log.ordered() {
                if event.device() != &self.device || sent.contains(&hash) {
                    continue;
                }
                client.envelope(space, &Envelope::seal_event(space, index, key, &keys, event))?;
                self.store.mark_sent(space, "event", &hash)?;
                report.sent += 1;
            }
            let sent = self.store.sent(space, "original")?;
            for hash in self.store.originals(space)? {
                if sent.contains(&hash) {
                    continue;
                }
                if let Some(bytes) = self.blobs.get(&hash)? {
                    let envelope = Envelope::seal(space, index, key, &keys, EnvelopeContent::Original, &bytes);
                    client.envelope(space, &envelope)?;
                    self.store.mark_sent(space, "original", &hash)?;
                    report.sent += 1;
                }
            }
        }
        Ok(report)
    }

    /// Adds the devices that asked to join with an open invitation; returns their names.
    fn add_requested(
        &mut self,
        space: &SpaceId,
        client: &Client<'_>,
        keys: &MemberKeys,
        list: &mut MemberList,
        state: &mut SyncState,
    ) -> Result<Vec<String>, SyncError> {
        let requests: Vec<Value> = client.json(&format!("/v1/spaces/{space}/requests"))?;
        let invitations: Vec<(Invitation, Rights)> = state
            .invited
            .iter()
            .filter_map(|invited| {
                let secret = hex::decode(&invited.secret).ok()?.try_into().ok()?;
                Some((Invitation { relay: state.relay.clone(), space: space.clone(), secret }, invited.rights))
            })
            .collect();
        let mut used = Vec::new();
        let mut members: Vec<Member> = Vec::new();
        for request in requests {
            let Ok(request) = from_root::<JoinRequest>(request.to_string().as_bytes()) else { continue };
            let Some((invitation, rights)) = invitations.iter().find(|(i, _)| i.proves(&request)) else { continue };
            // What the device may do is the inviting member's to say.
            let member = Member { rights: *rights, ..request.member };
            let taken = list.member(&member.id).is_some()
                || members.iter().chain(list.members()).any(|m| m.device.is_some() && m.device == member.device);
            if member.role != MemberRole::Device || taken {
                continue;
            }
            used.push(hex::encode(invitation.secret));
            members.push(member);
        }
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let names = members
            .iter()
            .map(|m| m.name.clone().or_else(|| m.device.as_ref().map(ToString::to_string)).unwrap_or_default())
            .collect();
        for _ in 0..3 {
            let current = current_key(list, keys)?;
            if client.record(space, &list.add(keys, &current, members.clone()))? {
                *list = client.members(self.domain, space)?;
                state.invited.retain(|i| !used.contains(&i.secret));
                self.save_state(space, state)?;
                return Ok(names);
            }
            *list = client.members(self.domain, space)?;
        }
        Err(state_error("the member list keeps changing – try again"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitations_read_back() {
        let invitation =
            Invitation::new("https://relay.example", "0192f1e4-0000-7000-8000-0000000000b1".parse().unwrap());
        let text = invitation_text(&invitation);
        assert!(text.starts_with("https://relay.example#join=0192f1e4-0000-7000-8000-0000000000b1."));
        assert_eq!(parse_invitation(&text).unwrap(), invitation);
        assert!(parse_invitation("https://relay.example").is_err());
    }

    #[test]
    fn the_signed_path_has_the_relays_own_path() {
        let keys = MemberKeys::generate(Domain::KERNOID);
        assert_eq!(Client::new("https://relay.example", &keys).signed_path("/v1/x"), "/v1/x");
        assert_eq!(Client::new("https://example.org/relay/", &keys).signed_path("/v1/x"), "/relay/v1/x");
    }
}
