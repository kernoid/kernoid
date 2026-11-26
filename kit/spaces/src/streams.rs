// SPDX-License-Identifier: MIT
//! A device's spaces of streams (RFC 0012), synchronised through a relay's protocol 2.
//!
//! [`Streams`] founds a space, invites devices and persons, follows the streams the device can open – starting at its
//! person's stream and the space stream, going down the links it finds –, writes events into a stream (making a new
//! generation first when the stream is due since someone was removed), makes streams below others or for a person
//! alone, shares a stream with a person, keeps originals of a stream (large ones in parts), and purges a stream.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[cfg(feature = "sqlite")]
use crate::store::Store;
use crate::store::streams::{Parent, StreamBackend, StreamState};
use kernoid_base::{Bytes, Sha256Hash, SpaceId, base64url, from_base64url, from_root, to_root};
use kernoid_crypt::{
    Domain, EncryptionError, RecoveryCode,
    pq::HybridKeys,
    stream::{
        Device, DeviceKeyId, Joining, LinkBody, Permission, Person, PersonId, RecordKind, Request, Roster,
        RosterRecord, SpaceLinks, StreamId, StreamKey, StreamRecord, Token, Writer, found_as, link_to_person,
        new_space_generation_from, person_key, proves_recovery, recovery_proof, request_signature, token_hash,
    },
};
use kernoid_log::{Clock, DeviceId, Event, EventHash, Log};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{FOUNDER_HEADER, INVITATION_LIFETIME, SyncError, now_ms, relay_error, state_error, transport::Transport};

/// The kind of the event that names a stream's audience – the members of a group (RFC 0012, 7): the persons whose
/// streams its keys are sealed into. Kinds beginning with `kernoid_` are the foundation's.
pub const AUDIENCE: &str = "kernoid_audience";
/// The largest part of an original: the relay takes requests of at most 64 MiB.
pub const PART: usize = 16 * 1024 * 1024;

fn now_s() -> u64 {
    now_ms() / 1000
}

/// The state of a space of streams on this device.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    relay: String,
    /// The device's seed, hexadecimal.
    seed: String,
    person: Option<PersonId>,
    joined: bool,
    #[serde(default)]
    invited: Vec<Invited>,
    /// The hash of record 0 of the roster, hexadecimal: what the space was known by when this device came to it – from
    /// the invitation, the recovery code's proof, or its own founding. A roster that begins otherwise is another space.
    #[serde(default)]
    founding: Option<String>,
    /// The seed of the person's key this device made when it asked to join as a new person, hexadecimal: the key the
    /// roster gives the person must be this one. Gone once checked.
    #[serde(default)]
    person_seed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Invited {
    secret: String,
    made: u64,
    /// A new person, or a device of this device's person.
    new_person: bool,
}

/// What a synchronisation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamsReport {
    /// Events received.
    pub received: usize,
    /// Streams this device can now open that it could not before.
    pub new_streams: Vec<StreamId>,
    /// Devices added by invitation from here.
    pub added: Vec<DeviceKeyId>,
    /// Whether this device still waits to be added.
    pub waiting: bool,
    /// Records the relay handed out that this device did not take: not authentic, not their author's to write, of a
    /// generation that had ended, or not to be opened. They are passed over – one of them does not stop the rest.
    pub refused: usize,
    /// Records that name one before them this device was not handed: something a device wrote was left out, or came
    /// out of order. What a program makes of it is its own – the relay is not to be trusted with what it shows.
    pub missing: usize,
}

/// An invitation to a space of streams as text: the relay, `#streams=`, the space, the secret, `p` for a new
/// person or `d` for a device of the inviting person, and the hash of record 0 of the roster – what the invited device
/// knows the space by, so that a relay cannot hand it a roster of its own making.
pub fn invitation_text(
    relay: &str,
    space: &SpaceId,
    secret: &[u8; 16],
    new_person: bool,
    founding: &Sha256Hash,
) -> String {
    let kind = if new_person { "p" } else { "d" };
    format!("{}#streams={space}.{}.{kind}.{}", relay.trim_end_matches('/'), base64url(secret), base64url(&founding.0))
}

fn parse_invitation(text: &str) -> Result<(String, SpaceId, [u8; 16], bool, Sha256Hash), SyncError> {
    let invalid = || state_error("not an invitation to a space of streams");
    let (relay, rest) = text.trim().split_once("#streams=").ok_or_else(invalid)?;
    let mut parts = rest.split('.');
    let (space, secret, kind, founding) = (parts.next(), parts.next(), parts.next(), parts.next());
    // An invitation without the roster's first record is one of before 0.7.0: it cannot tell the space from a forgery.
    let founding: [u8; 32] = from_base64url(
        founding
            .ok_or_else(|| state_error("an invitation that does not name the roster it is for: ask for a new one"))?,
    )
    .ok_or_else(invalid)?
    .try_into()
    .map_err(|_| invalid())?;
    let space: SpaceId = space.ok_or_else(invalid)?.parse().map_err(|_| invalid())?;
    let secret: [u8; 16] =
        from_base64url(secret.ok_or_else(invalid)?).ok_or_else(invalid)?.try_into().map_err(|_| invalid())?;
    let new_person = match kind {
        Some("p") => true,
        Some("d") => false,
        _ => return Err(invalid()),
    };
    if parts.next().is_some() {
        return Err(invalid());
    }
    Ok((relay.to_owned(), space, secret, new_person, Sha256Hash(founding)))
}

/// Requests to a relay's protocol 2, signed by a device.
struct Client<'a> {
    transport: Arc<dyn Transport>,
    base: String,
    domain: Domain,
    keys: &'a HybridKeys,
}

/// Tokens a request carries.
#[derive(Default)]
struct Tokens {
    read: Option<String>,
    write: Option<String>,
    founder: Option<String>,
}

impl<'a> Client<'a> {
    fn new(transport: &Arc<dyn Transport>, base: &str, domain: Domain, keys: &'a HybridKeys) -> Self {
        Client { transport: transport.clone(), base: base.trim_end_matches('/').to_owned(), domain, keys }
    }

    fn signed_path(&self, path: &str) -> String {
        let prefix = self.base.split("://").nth(1).and_then(|rest| rest.find('/').map(|i| &rest[i..])).unwrap_or("");
        format!("{prefix}{path}")
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        tokens: Tokens,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), SyncError> {
        let url = format!("{}{path}", self.base);
        let signed = Request {
            method,
            path: &self.signed_path(path),
            body: body.as_deref().unwrap_or_default(),
            read: tokens.read.as_deref(),
            write: tokens.write.as_deref(),
        };
        let signature = request_signature(self.domain, self.keys, &signed, now_s());
        let mut headers = vec![("Authorization", signature.as_str())];
        if let Some(token) = &tokens.read {
            headers.push((kernoid_crypt::stream::READ_HEADER, token));
        }
        if let Some(token) = &tokens.write {
            headers.push((kernoid_crypt::stream::WRITE_HEADER, token));
        }
        if let Some(token) = &tokens.founder {
            headers.push((FOUNDER_HEADER, token));
        }
        if body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        self.transport.send(method, &url, &headers, body).map_err(|e| relay_error(format!("{}: {e}", self.base)))
    }

    fn refused(status: u16, body: &[u8]) -> SyncError {
        let message = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
        relay_error(format!("refused ({status}): {message}"))
    }

    fn json<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        tokens: Tokens,
        body: Option<Vec<u8>>,
    ) -> Result<T, SyncError> {
        let (status, answer) = self.send(method, path, tokens, body)?;
        if status != 200 {
            return Err(Self::refused(status, &answer));
        }
        serde_json::from_slice(&answer).map_err(relay_error)
    }

    fn expect(
        &self,
        method: &str,
        path: &str,
        tokens: Tokens,
        body: Option<Vec<u8>>,
        ok: &[u16],
    ) -> Result<u16, SyncError> {
        let (status, answer) = self.send(method, path, tokens, body)?;
        if ok.contains(&status) { Ok(status) } else { Err(Self::refused(status, &answer)) }
    }
}

fn stream_tokens(domain: Domain, key: &StreamKey, stream: &StreamId, generation: u32) -> Vec<u8> {
    let hash = |which| Bytes(token_hash(&key.token(domain, which, stream, generation)).0.to_vec());
    serde_json::to_vec(&json!({
        "generation": generation, "read": hash(Token::Read), "write": hash(Token::Write),
    }))
    .expect("JSON")
}

/// Whether a node was removed from a space it had: its device is no longer in the roster at the relay.
pub fn is_removed(error: &SyncError) -> bool {
    matches!(error, SyncError::State(message) if message.contains("removed from the space"))
}

/// What one node – a device, or a server – holds of its spaces of streams, and how it synchronises them; kept in a
/// [`StreamBackend`]: SQLite on a device ([`Store`], the default), PostgreSQL on a server (kernoid-relay's `node`).
#[cfg(feature = "sqlite")]
pub struct Streams<B: StreamBackend = Store> {
    domain: Domain,
    device: DeviceId,
    store: B,
    clock: Clock,
    transport: Arc<dyn Transport>,
    server: bool,
    heads: Heads,
}

/// What one node – a device, or a server – holds of its spaces of streams, and how it synchronises them; kept in a
/// [`StreamBackend`] – PostgreSQL on a server (kernoid-relay's `node`).
#[cfg(not(feature = "sqlite"))]
pub struct Streams<B: StreamBackend> {
    domain: Domain,
    device: DeviceId,
    store: B,
    clock: Clock,
    transport: Arc<dyn Transport>,
    server: bool,
    heads: Heads,
}

/// The identity of the record this node wrote last into each stream it wrote into since it started: what its next
/// record there names as the one before.
type Heads = std::sync::Mutex<BTreeMap<(SpaceId, StreamId), Option<Sha256Hash>>>;

/// What a round of following knows of a stream from the records the node keeps of it.
#[derive(Default)]
struct Seen {
    /// The newest generation whose generation record was taken.
    begun: u32,
    /// The identity of the last record of each device.
    heads: BTreeMap<DeviceKeyId, Sha256Hash>,
}

impl<B: StreamBackend> std::fmt::Debug for Streams<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Streams").field("domain", &self.domain).field("device", &self.device).finish_non_exhaustive()
    }
}

impl<B: StreamBackend> Streams<B> {
    /// The spaces of streams of a device named `device`, kept in `store`.
    pub fn open(domain: Domain, device: DeviceId, store: B) -> Self {
        Self::with_transport(domain, device, store, crate::transport::default_transport())
    }

    /// The same, reaching relays through `transport` – e.g. a web page's worker.
    pub fn with_transport(domain: Domain, device: DeviceId, store: B, transport: Arc<dyn Transport>) -> Self {
        Streams {
            domain,
            clock: Clock::new(device.clone()),
            device,
            store,
            transport,
            server: false,
            heads: Heads::default(),
        }
    }

    /// A server's node: its devices say so in the roster (`Device::server`), so that every member sees that its
    /// operator can read what the node is shown.
    pub fn as_server(mut self) -> Self {
        self.server = true;
        self
    }

    /// The store, to change it as a whole – e.g. to keep it elsewhere than in a file.
    pub fn store_mut(&mut self) -> &mut B {
        &mut self.store
    }

    pub fn store(&self) -> &B {
        &self.store
    }

    /// The spaces of streams on this device.
    pub fn spaces(&self) -> Result<Vec<SpaceId>, SyncError> {
        Ok(self.store.stream_spaces()?)
    }

    fn state(&self, space: &SpaceId) -> Result<State, SyncError> {
        let text = self.store.space_state(space)?.ok_or_else(|| state_error("not a space of streams here"))?;
        serde_json::from_str(&text).map_err(|e| state_error(e.to_string()))
    }

    fn save_state(&self, space: &SpaceId, state: &State) -> Result<(), SyncError> {
        Ok(self.store.set_space_state(space, &serde_json::to_string(state).expect("JSON"))?)
    }

    fn device_keys(&self, state: &State) -> Result<HybridKeys, SyncError> {
        let seed: [u8; 32] = hex::decode(&state.seed)
            .ok()
            .and_then(|seed| seed.try_into().ok())
            .ok_or_else(|| state_error("the stored seed is not valid"))?;
        Ok(HybridKeys::from_seed(self.domain, seed))
    }

    /// The roster of a space as this device has it.
    pub fn roster(&self, space: &SpaceId) -> Result<Roster, SyncError> {
        Ok(self.store.roster(self.domain, space)?)
    }

    /// This device's person in a space.
    pub fn person(&self, space: &SpaceId) -> Result<PersonId, SyncError> {
        self.state(space)?.person.ok_or_else(|| state_error("this device is not added yet"))
    }

    /// The identity of this device in a space.
    pub fn device_id(&self, space: &SpaceId) -> Result<DeviceKeyId, SyncError> {
        Ok(self.device_keys(&self.state(space)?)?.verifying().id())
    }

    /// The space stream: every person reads it.
    pub fn space_stream(&self, space: &SpaceId) -> Result<StreamId, SyncError> {
        self.roster(space)?.space_stream().cloned().ok_or_else(|| state_error("the space has no roster yet"))
    }

    /// A person's stream, where links shown to the person alone go.
    pub fn person_stream(&self, space: &SpaceId, person: &PersonId) -> StreamId {
        StreamId::of_person(self.domain, space, person)
    }

    /// The streams this device can open.
    pub fn streams(&self, space: &SpaceId) -> Result<Vec<StreamState>, SyncError> {
        Ok(self.store.streams(space)?)
    }

    /// The events of a stream on this device.
    pub fn log(&self, space: &SpaceId, stream: &StreamId) -> Result<Log, SyncError> {
        Ok(self.store.stream_log(space, stream)?)
    }

    /// Founds a space at a relay: this device, its person, the space stream and the person's stream; a recovery code
    /// that brings the person back on a new device when every device is lost. `founder` is an account's token where
    /// the relay asks for one.
    pub fn found(
        &mut self,
        relay: &str,
        founder: Option<&str>,
        device_name: Option<&str>,
        person_name: Option<&str>,
    ) -> Result<(SpaceId, RecoveryCode), SyncError> {
        let space = SpaceId::generate(now_ms());
        let keys = HybridKeys::generate(self.domain);
        let founding = found_as(
            self.domain,
            &space,
            &keys,
            self.device.clone(),
            device_name.map(str::to_owned),
            person_name.map(str::to_owned),
            self.server,
        )?;
        let client = Client::new(&self.transport, relay, self.domain, &keys);
        let roster_path = format!("/v2/spaces/{space}/roster");
        let tokens = Tokens { founder: founder.map(str::to_owned), ..Tokens::default() };
        client.expect("POST", &roster_path, tokens, Some(to_root(&founding.record).expect("canonical")), &[201])?;
        self.store.add_roster_record(self.domain, &founding.record)?;
        let first = founding.record.hash();
        let state = State {
            relay: relay.to_owned(),
            seed: hex::encode(keys.seed()),
            person: Some(founding.person.clone()),
            joined: true,
            invited: vec![],
            founding: Some(first.hex()),
            person_seed: None,
        };
        self.save_state(&space, &state)?;

        // The space stream at the relay.
        let stream = &founding.space_stream;
        client.expect(
            "PUT",
            &format!("/v2/spaces/{space}/streams/{stream}"),
            Tokens::default(),
            Some(stream_tokens(self.domain, &founding.space_key, stream, 0)),
            &[201],
        )?;
        self.store.add_stream(&space, stream, false)?;
        self.store.put_stream_key(&space, stream, 0, &founding.space_key)?;

        // The recovery code: a device of the person that may only add devices.
        let code = RecoveryCode::generate();
        let recovery = HybridKeys::from_seed(self.domain, code.0);
        let roster = self.roster(&space)?;
        let name: DeviceId =
            format!("recovery-{}", &recovery.verifying().id().hex()[..12]).parse().expect("a device name");
        // What the recovery code's device may, the devices it brings back may.
        let device = Device::new(&recovery, founding.person.clone(), name, Some("Recovery code".into()))
            .with(&[Permission::Write, Permission::Members, Permission::Purge])
            .with_proof(recovery_proof(self.domain, &code.0, &space, &first));
        let seals = person_key(self.domain, &space, &founding.person, 0, &founding.person_seed, None, &[&device])?;
        let record = roster.next(RosterRecord {
            add_devices: vec![device],
            person_keys: vec![seals],
            ..RosterRecord::blank(&space)
        });
        let record = record.sign(&keys);
        client.expect("POST", &roster_path, Tokens::default(), Some(to_root(&record).expect("canonical")), &[201])?;
        self.store.add_roster_record(self.domain, &record)?;
        self.sync(&space)?;
        Ok((space, code))
    }

    /// An invitation: for a new person, or for another device of this device's person.
    pub fn invite(&self, space: &SpaceId, new_person: bool) -> Result<String, SyncError> {
        let mut state = self.state(space)?;
        let keys = self.device_keys(&state)?;
        let roster = self.roster(space)?;
        let me = roster.device(&keys.verifying().id()).ok_or_else(|| state_error("this device is not added yet"))?;
        if new_person && !me.may(Permission::Members) {
            return Err(state_error("only a device with `members` invites new persons"));
        }
        let secret: [u8; 16] = kernoid_base::random();
        state.invited.retain(|i| now_s().saturating_sub(i.made) < INVITATION_LIFETIME);
        state.invited.push(Invited { secret: hex::encode(secret), made: now_s(), new_person });
        self.save_state(space, &state)?;
        let founding = roster.founding().ok_or_else(|| state_error("the space has no roster yet"))?;
        Ok(invitation_text(&state.relay, space, &secret, new_person, &founding))
    }

    /// Asks to join a space with an invitation; the space arrives once the inviting device has added this one.
    pub fn join(
        &mut self,
        invitation: &str,
        device_name: Option<&str>,
        person_name: Option<&str>,
    ) -> Result<SpaceId, SyncError> {
        let (relay, space, secret, new_person, founding) = parse_invitation(invitation)?;
        if self.store.space_state(&space)?.is_some() {
            return Err(state_error("this space is on this device already"));
        }
        let keys = HybridKeys::generate(self.domain);
        let mut person_seed = None;
        let (person, request) = if new_person {
            let person = PersonId::generate();
            let seed: [u8; 32] = kernoid_base::random();
            person_seed = Some(hex::encode(seed));
            let device = Device::new(&keys, person.clone(), self.device.clone(), device_name.map(str::to_owned))
                .with(&[Permission::Write]);
            let device = if self.server { device.as_server() } else { device };
            let key = person_key(self.domain, &space, &person, 0, &seed, None, &[&device])?;
            let who = Person { id: person.clone(), name: person_name.map(str::to_owned) };
            (Some(person), Joining::new(&secret, device, Some((who, key))))
        } else {
            // A device of the inviting person: the person is known once it is added.
            let placeholder = PersonId::generate();
            let device = Device::new(&keys, placeholder, self.device.clone(), device_name.map(str::to_owned));
            let device = if self.server { device.as_server() } else { device };
            (None, Joining::new(&secret, device, None))
        };
        let client = Client::new(&self.transport, &relay, self.domain, &keys);
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/requests"),
            Tokens::default(),
            Some(to_root(&request).expect("canonical")),
            &[201],
        )?;
        let state = State {
            relay,
            seed: hex::encode(keys.seed()),
            person,
            joined: false,
            invited: vec![],
            founding: Some(founding.hex()),
            person_seed,
        };
        self.save_state(&space, &state)?;
        Ok(space)
    }

    /// Brings a person back on this device with a recovery code – the one made when the space was founded, or the one
    /// a person was added with. The roster the relay hands out must carry the code's proof ([`recovery_proof`]): a
    /// relay that makes a roster up, with the code's device copied into it, does not have it.
    pub fn recover(
        &mut self,
        relay: &str,
        space: &SpaceId,
        code: &RecoveryCode,
        device_name: Option<&str>,
    ) -> Result<StreamsReport, SyncError> {
        let recovery = HybridKeys::from_seed(self.domain, code.0);
        let client = Client::new(&self.transport, relay, self.domain, &recovery);
        let roster = self.fetch_roster(&client, space, &Roster::new(self.domain, space.clone()), None)?;
        let rdevice = roster
            .device(&recovery.verifying().id())
            .cloned()
            .ok_or_else(|| state_error("not a recovery code of this space"))?;
        if !proves_recovery(&roster, &code.0) {
            return Err(state_error("the roster the relay hands out is not the one this recovery code was made for"));
        }
        let founding = roster.founding().map(|hash| hash.hex());
        let seeds = roster.person_seeds(&recovery)?;
        let (generation, seed) =
            seeds.iter().next_back().map(|(g, s)| (*g, *s)).ok_or_else(|| state_error("no key of the person"))?;
        let keys = HybridKeys::generate(self.domain);
        let permissions: Vec<Permission> = rdevice.permissions.iter().copied().collect();
        let device = Device::new(&keys, rdevice.person.clone(), self.device.clone(), device_name.map(str::to_owned))
            .with(&permissions);
        let seals = person_key(self.domain, space, &rdevice.person, generation, &seed, None, &[&device])?;
        let record = roster
            .next(RosterRecord { add_devices: vec![device], person_keys: vec![seals], ..RosterRecord::blank(space) })
            .sign(&recovery);
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/roster"),
            Tokens::default(),
            Some(to_root(&record).expect("canonical")),
            &[201],
        )?;
        let state = State {
            relay: relay.to_owned(),
            seed: hex::encode(keys.seed()),
            person: Some(rdevice.person),
            joined: true,
            invited: vec![],
            founding,
            person_seed: None,
        };
        self.save_state(space, &state)?;
        self.sync(space)
    }

    /// Adds a person without asking them: the person, its key, the space stream linked to it, and a recovery code
    /// whose device brings the person's first device in ([`Streams::recover`]) with `permissions` – none: reading. For
    /// handing a space to someone over another channel – kernoid's vaults give the code to an account's OpenPGP key
    /// (RFC 0010, 5). Whoever adds the person knew the code: until the person's devices remove the recovery device, its
    /// maker could act as the person. Needs `members`.
    pub fn add_person(
        &mut self,
        space: &SpaceId,
        name: Option<&str>,
        permissions: &[Permission],
    ) -> Result<(PersonId, RecoveryCode), SyncError> {
        // A record follows the roster's newest one: read what is new first.
        self.sync(space)?;
        let (state, keys, roster) = self.context(space)?;
        if !roster.device(&keys.verifying().id()).is_some_and(|d| d.may(Permission::Members)) {
            return Err(state_error("only a device with `members` adds persons"));
        }
        let code = RecoveryCode::generate();
        let recovery = HybridKeys::from_seed(self.domain, code.0);
        let person = PersonId::generate();
        let seed: [u8; 32] = kernoid_base::random();
        let device_name: DeviceId =
            format!("recovery-{}", &recovery.verifying().id().hex()[..12]).parse().expect("a device name");
        let founding = roster.founding().ok_or_else(|| state_error("the space has no roster yet"))?;
        let device = Device::new(&recovery, person.clone(), device_name, Some("Recovery code".into()))
            .with(permissions)
            .with_proof(recovery_proof(self.domain, &code.0, space, &founding));
        let key = person_key(self.domain, space, &person, 0, &seed, None, &[&device])?;
        let current = roster.space_generation().ok_or_else(|| state_error("no space stream"))?;
        let space_stream = roster.space_stream().cloned().ok_or_else(|| state_error("no space stream"))?;
        let space_key = self
            .store
            .stream_keys(space, &space_stream)?
            .remove(&current)
            .ok_or_else(|| state_error("no current key of the space stream"))?;
        let link = link_to_person(self.domain, space, &space_stream, current, &space_key, &key)?;
        let record = roster
            .next(RosterRecord {
                add_persons: vec![Person { id: person.clone(), name: name.map(str::to_owned) }],
                add_devices: vec![device],
                person_keys: vec![key],
                space_links: Some(SpaceLinks {
                    generation: current,
                    read: None,
                    links: vec![link],
                    previous: None,
                    previous_generation: None,
                }),
                ..RosterRecord::blank(space)
            })
            .sign(&keys);
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/roster"),
            Tokens::default(),
            Some(to_root(&record).expect("canonical")),
            &[201],
        )?;
        self.store.add_roster_record(self.domain, &record)?;
        Ok((person, code))
    }

    /// Forgets a space on this device – after it was removed from it, before it comes in again with a recovery code.
    pub fn forget(&mut self, space: &SpaceId) -> Result<(), SyncError> {
        Ok(self.store.remove_stream_space(space)?)
    }

    /// Whether this device was removed from a space it had: its device is no longer in the roster at the relay. The
    /// same as [`is_removed`], which needs no type of store.
    pub fn is_removed(error: &SyncError) -> bool {
        is_removed(error)
    }

    /// Whether this device is a device of the space already (it may still wait to be added).
    pub fn has_space(&self, space: &SpaceId) -> Result<bool, SyncError> {
        Ok(self.store.space_state(space)?.is_some())
    }

    /// The relay a space is kept at.
    pub fn relay(&self, space: &SpaceId) -> Result<String, SyncError> {
        Ok(self.state(space)?.relay)
    }

    /// Reads the roster's new records from the relay, checks them on top of `roster` and returns the result. With
    /// `founding`, the roster must begin with the record of that hash: what this device knows the space by.
    fn fetch_roster(
        &self,
        client: &Client<'_>,
        space: &SpaceId,
        roster: &Roster,
        founding: Option<&str>,
    ) -> Result<Roster, SyncError> {
        let after = roster.records().len() as i64 - 1;
        let records: Vec<Value> =
            client.json("GET", &format!("/v2/spaces/{space}/roster?after={after}"), Tokens::default(), None)?;
        let mut roster = roster.clone();
        for record in records {
            let record: RosterRecord = from_root(record.to_string().as_bytes()).map_err(relay_error)?;
            roster.apply(record).map_err(|e| relay_error(format!("the roster is not valid: {e}")))?;
        }
        if let (Some(expected), Some(found)) = (founding, roster.founding())
            && found.hex() != expected
        {
            return Err(relay_error("the roster is not the one of the space this device came to"));
        }
        Ok(roster)
    }

    /// Synchronises a space: the roster, requests to join made with invitations from here, and every stream this
    /// device can open – following links down to streams it did not know.
    pub fn sync(&mut self, space: &SpaceId) -> Result<StreamsReport, SyncError> {
        let mut state = self.state(space)?;
        let keys = self.device_keys(&state)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let mut report = StreamsReport::default();
        let before = self.store.roster(self.domain, space)?;
        // A device that came to the space before 0.7.0 knows it by the roster it holds.
        if state.founding.is_none() {
            let Some(founding) = before.founding() else {
                return Err(state_error(
                    "asked to join with an invitation that does not name the roster: ask for a new one",
                ));
            };
            state.founding = Some(founding.hex());
            self.save_state(space, &state)?;
        }
        let mut roster = match self.fetch_roster(&client, space, &before, state.founding.as_deref()) {
            // The relay hands the roster to the space's devices alone: one it no longer knows was removed.
            Err(SyncError::Relay(message)) if state.joined && message.starts_with("refused (401)") => {
                return Err(state_error("this device was removed from the space"));
            }
            roster => roster?,
        };
        let Some(me) = roster.device(&keys.verifying().id()).cloned() else {
            for record in &roster.records()[before.records().len()..] {
                self.store.add_roster_record(self.domain, record)?;
            }
            if state.joined {
                return Err(state_error("this device was removed from the space"));
            }
            report.waiting = true;
            return Ok(report);
        };
        // The person's key this device made when it asked to join: the roster must give the person that one, not a
        // key of whoever added it.
        if let Some(made) = &state.person_seed {
            let seeds = roster.person_seeds(&keys)?;
            if seeds.get(&0).map(hex::encode).as_ref() != Some(made) {
                return Err(state_error("the roster gives this person a key this device did not make"));
            }
        }
        for record in &roster.records()[before.records().len()..] {
            self.store.add_roster_record(self.domain, record)?;
        }
        if !state.joined || state.person.as_ref() != Some(&me.person) || state.person_seed.is_some() {
            state.joined = true;
            state.person = Some(me.person.clone());
            state.person_seed = None;
            self.save_state(space, &state)?;
        }
        // Another person's device made this person's key (it removed one of the person's devices) and so knows its
        // seed: move on to a seed of this person's own.
        if self.rekey(space, &client, &keys, &roster, &me)? {
            roster = self.roster(space)?;
        }

        // Someone left: every stream this device knows gets a new generation before it is written to again.
        let left = before.devices().any(|d| roster.device(&d.id).is_none())
            || before.persons().any(|p| roster.person(&p.id).is_none());
        if left && !before.records().is_empty() {
            for stream in self.store.streams(space)? {
                if !stream.inbox {
                    self.store.set_due(space, &stream.stream, true)?;
                }
            }
        }

        // The person's stream, one generation per generation of the person's key – the relay makes it from the roster.
        let seeds = roster.person_seeds(&keys)?;
        let person_stream = self.person_stream(space, &me.person);
        self.store.add_stream(space, &person_stream, true)?;
        for (generation, seed) in &seeds {
            let key = StreamKey::of_person(self.domain, &me.person, seed);
            self.store.put_stream_key(space, &person_stream, *generation, &key)?;
        }

        // The space stream.
        let space_stream = roster.space_stream().cloned().ok_or_else(|| state_error("no space stream"))?;
        for (generation, key) in roster.space_keys(&keys)? {
            self.store.put_stream_key(space, &space_stream, generation, &key)?;
        }
        if self.store.add_stream(space, &space_stream, false)? {
            report.new_streams.push(space_stream.clone());
        }

        // Requests to join made with invitations from here.
        if !state.invited.is_empty() {
            report.added = self.admit(space, &client, &keys, &me, &mut state)?;
        }

        // Every stream this device can open, until no new one turns up.
        loop {
            let mut more = false;
            let found = self.follow(space, &client, &me.person, &seeds, &mut report, &mut more)?;
            if found.is_empty() && !more {
                break;
            }
            report.new_streams.extend(found);
        }
        Ok(report)
    }

    /// Adds the devices and persons that asked with an invitation from here.
    fn admit(
        &mut self,
        space: &SpaceId,
        client: &Client<'_>,
        keys: &HybridKeys,
        me: &Device,
        state: &mut State,
    ) -> Result<Vec<DeviceKeyId>, SyncError> {
        let requests: Vec<Value> =
            client.json("GET", &format!("/v2/spaces/{space}/requests"), Tokens::default(), None)?;
        let mut added = Vec::new();
        for request in requests {
            let Ok(joining) = from_root::<Joining>(request.to_string().as_bytes()) else { continue };
            let Some(index) = state.invited.iter().position(|invited| {
                hex::decode(&invited.secret)
                    .ok()
                    .and_then(|s| <[u8; 16]>::try_from(s).ok())
                    .is_some_and(|secret| joining.proves(&secret) && invited.new_person == joining.person.is_some())
            }) else {
                continue;
            };
            let roster = self.roster(space)?;
            // What an invited device may is what the inviting device gives it, not what it asks for: `write`.
            let invited = |person: PersonId| Device {
                person,
                permissions: [Permission::Write].into(),
                // What a device says of itself to be trusted less, it may say.
                proof: None,
                ..joining.device.clone()
            };
            let record = match &joining.person {
                Some((person, key)) => {
                    let current = roster.space_generation().ok_or_else(|| state_error("no space stream"))?;
                    let space_stream = roster.space_stream().cloned().ok_or_else(|| state_error("no space stream"))?;
                    let Some(space_key) = self.store.stream_keys(space, &space_stream)?.remove(&current) else {
                        // The space stream moved on to a key this device does not hold yet: a later round admits.
                        continue;
                    };
                    let Ok(link) = link_to_person(self.domain, space, &space_stream, current, &space_key, key) else {
                        continue;
                    };
                    RosterRecord {
                        add_persons: vec![person.clone()],
                        add_devices: vec![invited(person.id.clone())],
                        person_keys: vec![key.clone()],
                        space_links: Some(SpaceLinks {
                            generation: current,
                            read: None,
                            links: vec![link],
                            previous: None,
                            previous_generation: None,
                        }),
                        ..RosterRecord::blank(space)
                    }
                }
                None => {
                    let seeds = roster.person_seeds(keys)?;
                    let (generation, seed) = seeds
                        .iter()
                        .next_back()
                        .map(|(g, s)| (*g, *s))
                        .ok_or_else(|| state_error("no key of the person"))?;
                    let device = invited(me.person.clone());
                    let Ok(seals) = person_key(self.domain, space, &me.person, generation, &seed, None, &[&device])
                    else {
                        continue;
                    };
                    RosterRecord { add_devices: vec![device], person_keys: vec![seals], ..RosterRecord::blank(space) }
                }
            };
            let record = roster.next(record).sign(keys);
            // A request the roster's rules refuse (a person or a device name taken, a key of another generation) is
            // passed over: it must not stop this device's synchronisation.
            if roster.clone().apply(record.clone()).is_err() {
                continue;
            }
            let (status, _) = client.send(
                "POST",
                &format!("/v2/spaces/{space}/roster"),
                Tokens::default(),
                Some(to_root(&record).expect("canonical")),
            )?;
            if status == 201 {
                self.store.add_roster_record(self.domain, &record)?;
                added.push(joining.device.id);
                state.invited.remove(index);
                self.save_state(space, state)?;
            }
        }
        Ok(added)
    }

    /// Moves this device's person on to a key of its own making when the current one was made by another person's
    /// device – which removed one of the person's devices, and so knows the seed (RFC 0012, 8). The seed before is
    /// chained, so that what was linked to it stays read. Whether a record was written.
    fn rekey(
        &mut self,
        space: &SpaceId,
        client: &Client<'_>,
        keys: &HybridKeys,
        roster: &Roster,
        me: &Device,
    ) -> Result<bool, SyncError> {
        let Some(current) = roster.person_key(&me.person).map(|key| key.generation) else { return Ok(false) };
        let foreign = current > 0
            && roster.person_key_author(&me.person, current).is_some_and(|author| author.person != me.person);
        if !foreign {
            return Ok(false);
        }
        let Ok(seeds) = roster.person_seeds(keys) else { return Ok(false) };
        let Some(known) = seeds.get(&current) else { return Ok(false) };
        let devices: Vec<&Device> = roster.devices_of(&me.person).collect();
        let seed: [u8; 32] = kernoid_base::random();
        let Ok(next) = person_key(self.domain, space, &me.person, current + 1, &seed, Some(known), &devices) else {
            return Ok(false);
        };
        let record = roster.next(RosterRecord { person_keys: vec![next], ..RosterRecord::blank(space) }).sign(keys);
        let (status, _) = client.send(
            "POST",
            &format!("/v2/spaces/{space}/roster"),
            Tokens::default(),
            Some(to_root(&record).expect("canonical")),
        )?;
        // Refused: another device of the person was first, or the roster moved on – the next round sees.
        if status != 201 {
            return Ok(false);
        }
        self.store.add_roster_record(self.domain, &record)?;
        Ok(true)
    }

    /// One round of following: what is new in every stream this device can open; the streams newly found.
    fn follow(
        &mut self,
        space: &SpaceId,
        client: &Client<'_>,
        person: &PersonId,
        seeds: &BTreeMap<u32, [u8; 32]>,
        report: &mut StreamsReport,
        more: &mut bool,
    ) -> Result<Vec<StreamId>, SyncError> {
        let mut roster = self.roster(space)?;
        let me = client.keys.verifying().id();
        let space_stream = roster.space_stream().cloned();
        let mut asked = Vec::new();
        for state in self.store.streams(space)? {
            let keys = self.store.stream_keys(space, &state.stream)?;
            let Some((generation, key)) = keys.iter().next_back() else { continue };
            asked.push(json!({
                "stream": state.stream, "after": state.position,
                "read": key.token_text(self.domain, Token::Read, &state.stream, *generation),
            }));
        }
        let answer: Value = client.json(
            "POST",
            &format!("/v2/spaces/{space}/follow"),
            Tokens::default(),
            Some(serde_json::to_vec(&asked).expect("JSON")),
        )?;
        let mut found = Vec::new();
        // The roster is read again once a round at most, however many records name a position beyond it.
        let mut refreshed = false;
        for (stream, result) in answer["streams"].as_object().into_iter().flatten() {
            let Ok(stream) = stream.parse::<StreamId>() else { continue };
            let Some(records) = result["records"].as_array() else { continue };
            if records.is_empty() {
                continue;
            }
            // The audience before these records: whoever is not in it after them has left.
            let before = self.audience(space, &stream)?;
            // The space stream's keys are the roster's: its generation records bring none.
            let chained = space_stream.as_ref() != Some(&stream);
            if chained {
                self.unchain(space, &stream, &roster, records)?;
            }
            let mut seen: Option<Seen> = None;
            let mut events = false;
            for item in records {
                let position = item["position"].as_i64().unwrap_or(0);
                let Ok(record) = from_root::<StreamRecord>(item["record"].to_string().as_bytes()) else {
                    report.refused += 1;
                    self.store.set_position(space, &stream, position)?;
                    continue;
                };
                // Written by a device that had seen more of the roster than this one has: read the roster again –
                // for this round alone; the next synchronisation takes its records in, with what follows from them.
                if record.at >= roster.records().len() as u64 && !refreshed {
                    roster = self.fetch_roster(client, space, &roster, None)?;
                    refreshed = true;
                }
                // Not its author's: passed over, and not kept.
                let Some(author) = self.author(space, &stream, &roster, &record).cloned() else {
                    report.refused += 1;
                    self.store.set_position(space, &stream, position)?;
                    continue;
                };
                let seen = self.seen(space, &stream, &mut seen)?;
                // A generation that has ended in the relay's order: what is of it after that is written with a key
                // someone was to lose, and not taken.
                let ended = record.kind != RecordKind::Sealed
                    && record.kind != RecordKind::Generation
                    && seen.begun > record.generation;
                // The record its author wrote here before is the one this device saw last of it – or one is missing.
                let missing = author.id != me && seen.heads.get(&author.id) != record.previous.as_ref();
                let taken = if ended {
                    Taken::Refused
                } else {
                    match self.take(space, client, &stream, &roster, &author, person, seeds, &record, chained) {
                        Ok(taken) => taken,
                        // What does not open, or opens to what is not an event or a link, is passed over.
                        Err(SyncError::Encryption(_) | SyncError::Event(_)) => Taken::Refused,
                        Err(error) => return Err(error),
                    }
                };
                let refused = matches!(taken, Taken::Refused);
                match taken {
                    Taken::Event => {
                        report.received += 1;
                        events = true;
                    }
                    Taken::Stream(child) => found.push(child),
                    Taken::Key => *more = true,
                    Taken::Nothing => {}
                    Taken::Refused => report.refused += 1,
                    // A key this device does not have yet: read on from here once a link brings it.
                    Taken::Later => break,
                }
                if missing {
                    report.missing += 1;
                }
                seen.heads.insert(author.id, record.id);
                if record.kind == RecordKind::Generation && !refused {
                    seen.begun = seen.begun.max(record.generation);
                }
                self.store.put_stream_record(space, &stream, position, &to_root(&record).expect("canonical"))?;
                self.store.set_position(space, &stream, position)?;
            }
            // A new audience: whoever left it is no longer linked, and what lies below gets new keys.
            if events {
                self.reconcile(space, &stream, before.as_ref(), true)?;
            }
        }
        Ok(found)
    }

    /// What the records this node keeps of a stream say – read once a round.
    fn seen<'s>(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        seen: &'s mut Option<Seen>,
    ) -> Result<&'s mut Seen, SyncError> {
        if seen.is_none() {
            let mut known = Seen::default();
            for (_, canonical) in self.store.stream_records(space, stream)? {
                let Ok(record) = from_root::<StreamRecord>(&canonical) else { continue };
                if record.kind == RecordKind::Generation {
                    known.begun = known.begun.max(record.generation);
                }
                known.heads.insert(record.author, record.id);
            }
            *seen = Some(known);
        }
        Ok(seen.as_mut().expect("just set"))
    }

    /// The writer of this node's next record in a stream: its keys, the roster's position it has seen, and the record
    /// it wrote there before.
    fn writer<'a>(
        &self,
        space: &'a SpaceId,
        keys: &'a HybridKeys,
        roster: &Roster,
        stream: &StreamId,
    ) -> Result<Writer<'a>, SyncError> {
        let at = (space.clone(), stream.clone());
        let known = self.heads.lock().expect("no panic while held").get(&at).copied();
        let previous = match known {
            Some(previous) => previous,
            None => {
                let me = keys.verifying().id();
                let mut previous = None;
                for (_, canonical) in self.store.stream_records(space, stream)? {
                    if let Ok(record) = from_root::<StreamRecord>(&canonical)
                        && record.author == me
                    {
                        previous = Some(record.id);
                    }
                }
                self.heads.lock().expect("no panic while held").insert(at, previous);
                previous
            }
        };
        Ok(Writer { domain: self.domain, space, keys, at: roster.records().len() as u64 - 1, previous })
    }

    /// The device a record is of, if it is authentic: a device of the roster with `write` at the position the record
    /// names, which signed it.
    fn author<'r>(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        roster: &'r Roster,
        record: &StreamRecord,
    ) -> Option<&'r Device> {
        let author = roster.device_at(&record.author, record.at)?;
        (author.may(Permission::Write)
            && record.space == *space
            && record.stream == *stream
            && record.is_authentic(self.domain, author))
        .then_some(author)
    }

    /// Keys of older generations from newer ones this device holds, out of the generation records among `records`
    /// (each seals the key before with its own) – what a device linked to a newer generation only reads back with: a
    /// person taken into a group again. The records are checked as [`Streams::take`] checks them; one that is not
    /// authentic or does not open brings no key.
    fn unchain(&self, space: &SpaceId, stream: &StreamId, roster: &Roster, records: &[Value]) -> Result<(), SyncError> {
        let mut generations = Vec::new();
        for item in records {
            let Ok(record) = from_root::<StreamRecord>(item["record"].to_string().as_bytes()) else { continue };
            if record.kind != RecordKind::Generation
                || record.generation == 0
                || self.author(space, stream, roster, &record).is_none()
            {
                continue;
            }
            generations.push(record);
        }
        generations.sort_by_key(|record| std::cmp::Reverse(record.generation));
        for record in generations {
            let keys = self.store.stream_keys(space, stream)?;
            if let Some(key) = keys.get(&record.generation)
                && !keys.contains_key(&(record.generation - 1))
                && let Ok(previous) = record.open_generation(key)
            {
                self.store.put_stream_key(space, stream, record.generation - 1, &previous)?;
            }
        }
        Ok(())
    }

    /// What a received record brings.
    #[allow(clippy::too_many_arguments)]
    fn take(
        &mut self,
        space: &SpaceId,
        client: &Client<'_>,
        stream: &StreamId,
        roster: &Roster,
        author: &Device,
        person: &PersonId,
        seeds: &BTreeMap<u32, [u8; 32]>,
        record: &StreamRecord,
        chained: bool,
    ) -> Result<Taken, SyncError> {
        let keys = self.store.stream_keys(space, stream)?;
        if record.kind == RecordKind::Sealed {
            let Some(seed) = seeds.get(&record.generation) else { return Ok(Taken::Nothing) };
            let Ok(body) = record.open_sealed(&HybridKeys::from_seed(self.domain, *seed)) else {
                return Ok(Taken::Refused);
            };
            return self.learn(space, client, roster, &body, Parent::Person(person.clone()));
        }
        let Some(key) = keys.get(&record.generation) else { return Ok(Taken::Later) };
        match record.kind {
            RecordKind::Event => {
                let canonical = record.open_event(key, roster)?;
                // Who names a group's members is one of them: someone taken out does not write themself back in
                // (what the members may beyond that is the program's, RFC 0012, 7).
                let event = Event::read(&canonical)?;
                if event.kind == AUDIENCE {
                    if audience_of(&event).is_none() {
                        return Ok(Taken::Refused);
                    }
                    if self.audience(space, stream)?.is_some_and(|members| !members.contains(&author.person)) {
                        return Ok(Taken::Refused);
                    }
                }
                let hash = Sha256Hash::of(&canonical);
                Ok(if self.store.add_stream_event(space, stream, &hash.to_string(), &canonical)? {
                    Taken::Event
                } else {
                    Taken::Nothing
                })
            }
            RecordKind::Generation => {
                if chained && record.generation > 0 {
                    let previous = record.open_generation(key)?;
                    self.store.put_stream_key(space, stream, record.generation - 1, &previous)?;
                }
                Ok(Taken::Nothing)
            }
            RecordKind::Link => {
                let body = record.open_link(key)?;
                self.learn(space, client, roster, &body, Parent::Stream(stream.clone()))
            }
            RecordKind::Sealed => unreachable!("handled above"),
        }
    }

    /// Takes a key a link brings – if it is the stream's. A link is what its writer says: any device with `write`
    /// seals one into anyone's stream. So a key is taken only when the stream's own records vouch for it: a newer
    /// generation of a stream this device reads must lead back, through the generation records, to the key it holds;
    /// a stream it does not read yet, or an older generation, must be one the relay keeps under that key's read token.
    /// The space stream and persons' streams take their keys from the roster alone.
    fn learn(
        &mut self,
        space: &SpaceId,
        client: &Client<'_>,
        roster: &Roster,
        body: &LinkBody,
        parent: Parent,
    ) -> Result<Taken, SyncError> {
        let Ok(key) = <[u8; 32]>::try_from(body.key.0.as_slice()) else { return Ok(Taken::Refused) };
        let key = StreamKey(key);
        let of_roster = roster.space_stream() == Some(&body.stream)
            || roster
                .records()
                .iter()
                .flat_map(|record| &record.add_persons)
                .any(|person| StreamId::of_person(self.domain, space, &person.id) == body.stream);
        if of_roster {
            return Ok(Taken::Refused);
        }
        let held = self.store.stream_keys(space, &body.stream)?;
        let known = held.contains_key(&body.generation);
        match (held.get(&body.generation), held.iter().next_back()) {
            (Some(held), _) if *held != key => return Ok(Taken::Refused),
            (Some(_), _) => {}
            (None, Some((newest, newest_key))) if body.generation > *newest => {
                let Some(chain) = self.chain_down(
                    space,
                    client,
                    roster,
                    &body.stream,
                    (body.generation, &key),
                    (*newest, newest_key),
                )?
                else {
                    return Ok(Taken::Refused);
                };
                for (generation, key) in chain {
                    self.store.put_stream_key(space, &body.stream, generation, &key)?;
                }
            }
            (None, _) => {
                let read = key.token_text(self.domain, Token::Read, &body.stream, body.generation);
                let (status, answer) = client.send(
                    "GET",
                    &format!("/v2/spaces/{space}/streams/{}/records?after=0&limit=1", body.stream),
                    Tokens { read: Some(read), ..Tokens::default() },
                    None,
                )?;
                match status {
                    200 => self.store.put_stream_key(space, &body.stream, body.generation, &key)?,
                    403 | 404 => return Ok(Taken::Refused),
                    _ => return Err(Client::refused(status, &answer)),
                }
            }
        }
        self.store.add_parent(space, &body.stream, &parent)?;
        let new_stream = self.store.add_stream(space, &body.stream, false)?;
        // A new stream, or a new generation of one: either may hold records this device could not read before.
        Ok(match (new_stream, known) {
            (true, _) => Taken::Stream(body.stream.clone()),
            (false, false) => Taken::Key,
            (false, true) => Taken::Nothing,
        })
    }

    /// The keys from a newer generation `to` a link brings down to the generation `from` this device holds, through
    /// the stream's generation records at the relay (read with the new key's token): each seals the key before. None
    /// unless the chain ends at the very key held – only who held that key could have made it.
    fn chain_down(
        &self,
        space: &SpaceId,
        client: &Client<'_>,
        roster: &Roster,
        stream: &StreamId,
        to: (u32, &StreamKey),
        from: (u32, &StreamKey),
    ) -> Result<Option<Vec<(u32, StreamKey)>>, SyncError> {
        let read = to.1.token_text(self.domain, Token::Read, stream, to.0);
        let mut after = self.store.stream(space, stream)?.map_or(0, |state| state.position);
        let mut generations: BTreeMap<u32, StreamRecord> = BTreeMap::new();
        // At most this many pages: a stream with more between two keys of one device is read on later.
        for _ in 0..64 {
            let (status, answer) = client.send(
                "GET",
                &format!("/v2/spaces/{space}/streams/{stream}/records?after={after}"),
                Tokens { read: Some(read.clone()), ..Tokens::default() },
                None,
            )?;
            if status == 403 || status == 404 {
                return Ok(None);
            }
            if status != 200 {
                return Err(Client::refused(status, &answer));
            }
            let answer: Value = serde_json::from_slice(&answer).map_err(relay_error)?;
            for item in answer["records"].as_array().into_iter().flatten() {
                after = after.max(item["position"].as_i64().unwrap_or(after));
                let Ok(record) = from_root::<StreamRecord>(item["record"].to_string().as_bytes()) else { continue };
                if record.kind == RecordKind::Generation
                    && record.generation > from.0
                    && record.generation <= to.0
                    && self.author(space, stream, roster, &record).is_some()
                {
                    generations.entry(record.generation).or_insert(record);
                }
            }
            if answer["more"].as_bool() != Some(true) || generations.len() as u32 == to.0 - from.0 {
                break;
            }
        }
        let mut chain = Vec::new();
        let mut key = to.1.clone();
        for generation in (from.0 + 1..=to.0).rev() {
            let Some(previous) = generations.get(&generation).and_then(|record| record.open_generation(&key).ok())
            else {
                return Ok(None);
            };
            chain.push((generation, key));
            key = previous;
        }
        Ok((key == *from.1).then_some(chain))
    }

    fn context(&self, space: &SpaceId) -> Result<(State, HybridKeys, Roster), SyncError> {
        let state = self.state(space)?;
        let keys = self.device_keys(&state)?;
        let roster = self.roster(space)?;
        if roster.device(&keys.verifying().id()).is_none() {
            return Err(state_error("this device is not a device of the space (yet)"));
        }
        Ok((state, keys, roster))
    }

    /// The newest key of a stream this device holds, with its generation.
    fn current(&self, space: &SpaceId, stream: &StreamId) -> Result<(u32, StreamKey), SyncError> {
        self.store
            .stream_keys(space, stream)?
            .into_iter()
            .next_back()
            .ok_or_else(|| state_error(format!("this device cannot open {stream}")))
    }

    /// Sends a record of this node's; what it keeps of it then – the record, at the position the relay gave it, and
    /// its identity as the one before the next – makes the chain of its records hold over a restart.
    fn post_record(
        &self,
        space: &SpaceId,
        client: &Client<'_>,
        record: &StreamRecord,
        write: Option<String>,
    ) -> Result<(), SyncError> {
        let canonical = to_root(record).expect("canonical");
        let (status, answer) = client.send(
            "POST",
            &format!("/v2/spaces/{space}/streams/{}/records", record.stream),
            Tokens { write, ..Tokens::default() },
            Some(canonical.clone()),
        )?;
        if status != 200 && status != 201 {
            return Err(Client::refused(status, &answer));
        }
        let position = serde_json::from_slice::<Value>(&answer).ok().and_then(|answer| answer["position"].as_i64());
        if let Some(position) = position {
            self.store.put_stream_record(space, &record.stream, position, &canonical)?;
        }
        self.heads.lock().expect("no panic while held").insert((space.clone(), record.stream.clone()), Some(record.id));
        Ok(())
    }

    /// Writes an event of `payload` into a stream; a stream due for a new generation gets it first.
    pub fn write(
        &mut self,
        space: &SpaceId,
        stream: &StreamId,
        payload: &impl Serialize,
    ) -> Result<EventHash, SyncError> {
        match self.write_once(space, stream, payload) {
            // The stream moved on to a generation this device had not read of: read, then once more.
            Err(SyncError::Relay(message)) if message.starts_with("refused (403)") => {
                self.sync(space)?;
                self.write_once(space, stream, payload)
            }
            result => result,
        }
    }

    fn write_once(
        &mut self,
        space: &SpaceId,
        stream: &StreamId,
        payload: &impl Serialize,
    ) -> Result<EventHash, SyncError> {
        // The space stream's generation the roster names is one this device cannot open (its links were broken):
        // a new one first, as for a stream that is due.
        let roster = self.roster(space)?;
        let behind = roster.space_stream() == Some(stream)
            && roster.space_generation() != self.store.stream_keys(space, stream)?.keys().next_back().copied();
        if behind || self.store.stream(space, stream)?.is_some_and(|s| s.due) {
            self.renew(space, stream)?;
        }
        let (state, keys, roster) = self.context(space)?;
        let (generation, key) = self.current(space, stream)?;
        let mut log = self.store.stream_log(space, stream)?;
        if let Some(latest) = log.latest() {
            self.clock.observe(latest, now_ms());
        }
        let hash = log.append(&mut self.clock, now_ms(), payload)?;
        let event = log.get(&hash).expect("just written").clone();
        let writer = self.writer(space, &keys, &roster, stream)?;
        let record = StreamRecord::event(&writer, stream, generation, &key, &event);
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        self.post_record(space, &client, &record, Some(key.token_text(self.domain, Token::Write, stream, generation)))?;
        let canonical = event.to_canonical().expect("canonical");
        self.store.add_stream_event(space, stream, &hash.to_string(), &canonical)?;
        Ok(hash)
    }

    /// Makes a stream below `parent`: a stream (a folder for a document) or a person alone. Returns it.
    pub fn new_stream(&mut self, space: &SpaceId, parent: &Parent) -> Result<StreamId, SyncError> {
        let (state, keys, _) = self.context(space)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let stream = StreamId::generate();
        let key = StreamKey::generate();
        client.expect(
            "PUT",
            &format!("/v2/spaces/{space}/streams/{stream}"),
            Tokens::default(),
            Some(stream_tokens(self.domain, &key, &stream, 0)),
            &[201],
        )?;
        self.store.add_stream(space, &stream, false)?;
        self.store.put_stream_key(space, &stream, 0, &key)?;
        self.link(space, &stream, parent)?;
        Ok(stream)
    }

    /// Shows a stream to a person: its current key, sealed into the person's stream.
    pub fn share(&mut self, space: &SpaceId, stream: &StreamId, person: &PersonId) -> Result<(), SyncError> {
        self.link(space, stream, &Parent::Person(person.clone()))
    }

    /// Links a stream below another one too – what moving a document into another folder needs: whoever opens
    /// `above` can open `stream` from now on.
    pub fn link_below(&mut self, space: &SpaceId, stream: &StreamId, above: &StreamId) -> Result<(), SyncError> {
        self.link(space, stream, &Parent::Stream(above.clone()))
    }

    /// Writes the current key of `stream` under `parent`.
    fn link(&mut self, space: &SpaceId, stream: &StreamId, parent: &Parent) -> Result<(), SyncError> {
        if let Parent::Stream(above) = parent
            && self.store.stream(space, above)?.is_some_and(|s| s.due)
        {
            self.renew(space, above)?;
        }
        let (state, keys, roster) = self.context(space)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let (generation, key) = self.current(space, stream)?;
        let body = LinkBody { stream: stream.clone(), generation, key: Bytes(key.0.to_vec()) };
        match parent {
            Parent::Stream(above) => {
                let writer = self.writer(space, &keys, &roster, above)?;
                let (above_generation, above_key) = self.current(space, above)?;
                let record = StreamRecord::link(&writer, above, above_generation, &above_key, &body);
                let write = above_key.token_text(self.domain, Token::Write, above, above_generation);
                self.post_record(space, &client, &record, Some(write))?;
            }
            Parent::Person(person) => {
                let key = roster.person_key(person).ok_or_else(|| state_error(format!("no person {person} here")))?;
                let person_stream = self.person_stream(space, person);
                let writer = self.writer(space, &keys, &roster, &person_stream)?;
                let record = StreamRecord::sealed_link(&writer, &person_stream, key, &body)?;
                self.post_record(space, &client, &record, None)?;
            }
        }
        self.store.add_parent(space, stream, parent)?;
        Ok(())
    }

    /// A new generation of a stream: registered at the relay, chained to the one before, and linked again for every
    /// parent still there – what is written from now on, nobody removed can read. A stream with an audience is linked
    /// to every person of it, also those this device did not share it with itself.
    pub fn renew(&mut self, space: &SpaceId, stream: &StreamId) -> Result<u32, SyncError> {
        self.reconcile(space, stream, None, false)?;
        // The space stream's generation is a record of the roster, which follows its newest one: read what is new
        // first (all of it, so that who left since marks the streams due).
        if self.store.roster(self.domain, space)?.space_stream() == Some(stream) {
            self.sync(space)?;
        }
        let (state, keys, roster) = self.context(space)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let (generation, previous) = self.current(space, stream)?;
        let mut next = generation + 1;
        let key = StreamKey::generate();
        let is_space = roster.space_stream() == Some(stream);
        if is_space {
            // The space stream's key goes to every person through the roster – chained to the newest generation this
            // device opens, which is not the roster's current one when that one's links were broken.
            let links = new_space_generation_from(&roster, &key, Some((generation, &previous)))?;
            next = links.generation;
            let record =
                roster.next(RosterRecord { space_links: Some(links), ..RosterRecord::blank(space) }).sign(&keys);
            client.expect(
                "POST",
                &format!("/v2/spaces/{space}/roster"),
                Tokens::default(),
                Some(to_root(&record).expect("canonical")),
                &[201],
            )?;
            self.store.add_roster_record(self.domain, &record)?;
        }
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/streams/{stream}/generations"),
            Tokens {
                write: Some(previous.token_text(self.domain, Token::Write, stream, generation)),
                ..Tokens::default()
            },
            Some(stream_tokens(self.domain, &key, stream, next)),
            &[201],
        )?;
        self.store.put_stream_key(space, stream, next, &key)?;
        let roster = self.roster(space)?;
        let writer = self.writer(space, &keys, &roster, stream)?;
        // The record that says the generation began, with the key before – of the generation before: one that skips
        // a broken generation of the space stream holds none (the roster chains it).
        let before = if next == generation + 1 { previous.clone() } else { StreamKey([0; 32]) };
        let record = StreamRecord::generation(&writer, stream, next, &key, &before);
        self.post_record(space, &client, &record, Some(key.token_text(self.domain, Token::Write, stream, next)))?;
        self.store.set_due(space, stream, false)?;
        if !is_space {
            for parent in self.link_targets(space, stream, &roster)? {
                self.link(space, stream, &parent)?;
            }
        }
        Ok(next)
    }

    /// Removes a device of the space. Its person gets a new key for the devices left; every stream this device knows
    /// gets a new generation before it is written again.
    ///
    /// A device adds devices of its own person without anyone's leave: one that fell into other hands may have added
    /// others first. [`Roster::added_by`] names them; [`Streams::remove_devices`] removes them with it.
    pub fn remove_device(&mut self, space: &SpaceId, device: &DeviceKeyId) -> Result<(), SyncError> {
        self.remove_devices(space, std::slice::from_ref(device))
    }

    /// Removes devices of the space in one record: each person that loses one gets a new key for its devices left.
    pub fn remove_devices(&mut self, space: &SpaceId, devices: &[DeviceKeyId]) -> Result<(), SyncError> {
        // A record follows the roster's newest one: read what is new first.
        self.sync(space)?;
        let (state, keys, roster) = self.context(space)?;
        let me = roster.device(&keys.verifying().id()).cloned().expect("checked");
        let mut targets = Vec::new();
        for device in devices {
            let target = roster.device(device).cloned().ok_or_else(|| state_error("no such device in the space"))?;
            if target.id == me.id {
                return Err(state_error("this device cannot remove itself"));
            }
            if !targets.iter().any(|known: &Device| known.id == target.id) {
                targets.push(target);
            }
        }
        let persons: BTreeSet<PersonId> = targets.iter().map(|target| target.person.clone()).collect();
        let mut rotated = Vec::new();
        for person in persons {
            let current = roster.person_key(&person).map_or(0, |k| k.generation);
            let staying: Vec<&Device> =
                roster.devices_of(&person).filter(|d| !targets.iter().any(|target| target.id == d.id)).collect();
            let seed: [u8; 32] = kernoid_base::random();
            // The person's own device chains the seed before; another person's device cannot.
            let previous = if me.person == person { roster.person_seeds(&keys)?.get(&current).copied() } else { None };
            rotated.push(person_key(self.domain, space, &person, current + 1, &seed, previous.as_ref(), &staying)?);
        }
        let record = roster
            .next(RosterRecord {
                remove_devices: targets.iter().map(|target| target.id).collect(),
                person_keys: rotated,
                ..RosterRecord::blank(space)
            })
            .sign(&keys);
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/roster"),
            Tokens::default(),
            Some(to_root(&record).expect("canonical")),
            &[201],
        )?;
        self.store.add_roster_record(self.domain, &record)?;
        self.mark_due(space)
    }

    /// Removes a person with all its devices; every stream this device knows gets a new generation before it is
    /// written again.
    pub fn remove_person(&mut self, space: &SpaceId, person: &PersonId) -> Result<(), SyncError> {
        // A record follows the roster's newest one: read what is new first.
        self.sync(space)?;
        let (state, keys, roster) = self.context(space)?;
        if roster.device(&keys.verifying().id()).is_some_and(|d| d.person == *person) {
            return Err(state_error("this device cannot remove its own person"));
        }
        let record = roster
            .next(RosterRecord { remove_persons: vec![person.clone()], ..RosterRecord::blank(space) })
            .sign(&keys);
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/roster"),
            Tokens::default(),
            Some(to_root(&record).expect("canonical")),
            &[201],
        )?;
        self.store.add_roster_record(self.domain, &record)?;
        self.mark_due(space)
    }

    /// Where a new generation of a stream is linked: the streams above it still here, and the persons of its audience
    /// – or, without one, the persons this device linked it to – still in the space.
    fn link_targets(&self, space: &SpaceId, stream: &StreamId, roster: &Roster) -> Result<Vec<Parent>, SyncError> {
        let mut targets = Vec::new();
        for parent in self.store.parents(space, stream)? {
            match &parent {
                Parent::Stream(above) if self.store.has_stream(space, above)? => targets.push(parent),
                Parent::Person(_) | Parent::Stream(_) => {}
            }
        }
        let persons: Vec<PersonId> = match self.audience(space, stream)? {
            Some(audience) => audience.into_iter().collect(),
            None => self
                .store
                .parents(space, stream)?
                .into_iter()
                .filter_map(|parent| match parent {
                    Parent::Person(person) => Some(person),
                    Parent::Stream(_) => None,
                })
                .collect(),
        };
        targets.extend(persons.into_iter().filter(|person| roster.person(person).is_some()).map(Parent::Person));
        Ok(targets)
    }

    /// The persons a stream is shown to as its audience names them – a group's members –, from the newest event of kind
    /// [`AUDIENCE`] in it; none if it names none.
    pub fn audience(&self, space: &SpaceId, stream: &StreamId) -> Result<Option<BTreeSet<PersonId>>, SyncError> {
        let log = self.store.stream_log(space, stream)?;
        Ok(log
            .ordered()
            .into_iter()
            .rev()
            .filter(|(_, event)| event.kind == AUDIENCE)
            .find_map(|(_, e)| audience_of(e)))
    }

    /// Follows a stream's audience: a person no longer in it – no longer than in `before`, or linked by this device
    /// – is forgotten as a parent, and every stream below it is due for a new generation, as the person holds their
    /// keys of now; with `due_too`, the stream itself as well. Whether someone left.
    fn reconcile(
        &self,
        space: &SpaceId,
        stream: &StreamId,
        before: Option<&BTreeSet<PersonId>>,
        due_too: bool,
    ) -> Result<bool, SyncError> {
        let Some(audience) = self.audience(space, stream)? else { return Ok(false) };
        let mut left = before.is_some_and(|before| before.iter().any(|person| !audience.contains(person)));
        for parent in self.store.parents(space, stream)? {
            if let Parent::Person(person) = &parent
                && !audience.contains(person)
            {
                self.store.remove_parent(space, stream, &parent)?;
                left = true;
            }
        }
        if left {
            if due_too {
                self.store.set_due(space, stream, true)?;
            }
            let mut below = self.store.children(space, &Parent::Stream(stream.clone()))?;
            let mut seen = BTreeSet::new();
            while let Some(child) = below.pop() {
                if seen.insert(child.clone()) {
                    self.store.set_due(space, &child, true)?;
                    below.extend(self.store.children(space, &Parent::Stream(child))?);
                }
            }
        }
        Ok(left)
    }

    /// Makes a group: a stream shown to `persons` – sealed into their streams – that names them as its audience.
    /// Streams shown to the group are linked below it ([`Streams::show_to_group`]); whoever is in the group opens them.
    pub fn new_group(&mut self, space: &SpaceId, persons: &[PersonId]) -> Result<StreamId, SyncError> {
        let (first, rest) = persons.split_first().ok_or_else(|| state_error("a group of nobody"))?;
        let group = self.new_stream(space, &Parent::Person(first.clone()))?;
        for person in rest {
            self.share(space, &group, person)?;
        }
        self.write_audience(space, &group, persons.iter())?;
        Ok(group)
    }

    /// Shows a stream to a group: whoever is in the group, now or later, opens it.
    pub fn show_to_group(&mut self, space: &SpaceId, stream: &StreamId, group: &StreamId) -> Result<(), SyncError> {
        self.link_below(space, stream, group)
    }

    /// Adds a person to a group: the group's key sealed to the person, the audience written anew.
    pub fn add_to_group(&mut self, space: &SpaceId, group: &StreamId, person: &PersonId) -> Result<(), SyncError> {
        let mut audience = self.audience(space, group)?.ok_or_else(|| state_error("not a group"))?;
        if !audience.insert(person.clone()) {
            return Ok(());
        }
        self.share(space, group, person)?;
        self.write_audience(space, group, audience.iter())
    }

    /// Takes a person out of a group: the audience written without the person, a new generation of the group linked to
    /// those left, and every stream below it due for a new one before it is written again – what is written from then
    /// on, the person cannot read. What the person read before stays read.
    pub fn remove_from_group(&mut self, space: &SpaceId, group: &StreamId, person: &PersonId) -> Result<(), SyncError> {
        // The newest audience first, as another device may have changed it.
        self.sync(space)?;
        let mut audience = self.audience(space, group)?.ok_or_else(|| state_error("not a group"))?;
        if !audience.remove(person) {
            return Ok(());
        }
        if audience.is_empty() {
            return Err(state_error("a group keeps one person at least"));
        }
        let before = self.audience(space, group)?;
        self.write_audience(space, group, audience.iter())?;
        self.reconcile(space, group, before.as_ref(), false)?;
        self.renew(space, group)?;
        Ok(())
    }

    fn write_audience<'a>(
        &mut self,
        space: &SpaceId,
        group: &StreamId,
        persons: impl Iterator<Item = &'a PersonId>,
    ) -> Result<(), SyncError> {
        let persons: Vec<String> = persons.map(ToString::to_string).collect();
        self.write(space, group, &json!({"kind": AUDIENCE, "persons": persons}))?;
        Ok(())
    }

    fn mark_due(&self, space: &SpaceId) -> Result<(), SyncError> {
        for stream in self.store.streams(space)? {
            if !stream.inbox {
                self.store.set_due(space, &stream.stream, true)?;
            }
        }
        Ok(())
    }

    /// Keeps an original in a stream, sealed with its current key, in parts of at most [`PART`] bytes; returns the
    /// parts' identities, in order – what an event names to refer to it.
    pub fn put_original(
        &mut self,
        space: &SpaceId,
        stream: &StreamId,
        bytes: &[u8],
    ) -> Result<Vec<Sha256Hash>, SyncError> {
        let (state, keys, _) = self.context(space)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let (generation, key) = self.current(space, stream)?;
        let write = key.token_text(self.domain, Token::Write, stream, generation);
        let mut parts = Vec::new();
        let chunks: Vec<&[u8]> = if bytes.is_empty() { vec![&[][..]] } else { bytes.chunks(PART).collect() };
        for chunk in chunks {
            let sealed = key.seal_original(self.domain, stream, chunk);
            let hash = Sha256Hash::of(&sealed);
            let (status, answer) = client.send(
                "PUT",
                &format!("/v2/spaces/{space}/streams/{stream}/originals/{hash}"),
                Tokens { write: Some(write.clone()), ..Tokens::default() },
                Some(sealed),
            )?;
            if status != 200 && status != 201 {
                return Err(Client::refused(status, &answer));
            }
            parts.push(hash);
        }
        Ok(parts)
    }

    /// The bytes of an original of a stream from its parts.
    pub fn original(&self, space: &SpaceId, stream: &StreamId, parts: &[Sha256Hash]) -> Result<Vec<u8>, SyncError> {
        let (state, keys, _) = self.context(space)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let held = self.store.stream_keys(space, stream)?;
        let (generation, key) =
            held.iter().next_back().ok_or_else(|| state_error("this device cannot open the stream"))?;
        let read = key.token_text(self.domain, Token::Read, stream, *generation);
        let mut bytes = Vec::new();
        for hash in parts {
            let (status, sealed) = client.send(
                "GET",
                &format!("/v2/spaces/{space}/streams/{stream}/originals/{hash}"),
                Tokens { read: Some(read.clone()), ..Tokens::default() },
                None,
            )?;
            if status != 200 {
                return Err(Client::refused(status, &sealed));
            }
            if Sha256Hash::of(&sealed) != *hash {
                return Err(relay_error("an original that is not the one asked for"));
            }
            // Sealed under whichever generation was current then.
            let part = held
                .values()
                .rev()
                .find_map(|key| key.open_original(self.domain, stream, &sealed).ok())
                .ok_or(SyncError::Encryption(EncryptionError::Decrypt))?;
            bytes.extend_from_slice(&part);
        }
        Ok(bytes)
    }

    /// Removes a stream with its records and originals at the relay (`purge`), and here.
    pub fn purge(&mut self, space: &SpaceId, stream: &StreamId) -> Result<(), SyncError> {
        let (state, keys, _) = self.context(space)?;
        let client = Client::new(&self.transport, &state.relay, self.domain, &keys);
        let (generation, key) = self.current(space, stream)?;
        client.expect(
            "DELETE",
            &format!("/v2/spaces/{space}/streams/{stream}"),
            Tokens { write: Some(key.token_text(self.domain, Token::Write, stream, generation)), ..Tokens::default() },
            None,
            &[204],
        )?;
        self.store.remove_stream(space, stream)?;
        Ok(())
    }
}

/// The persons an event of kind [`AUDIENCE`] names; none if it names something that is no person.
fn audience_of(event: &Event) -> Option<BTreeSet<PersonId>> {
    event.members.get("persons")?.as_array()?.iter().map(|person| person.as_str()?.parse().ok()).collect()
}

enum Taken {
    /// A record that is not taken: not authentic, not its author's to write, or not to be opened.
    Refused,
    Event,
    Stream(StreamId),
    /// A newer key of a stream known already.
    Key,
    Nothing,
    Later,
}
