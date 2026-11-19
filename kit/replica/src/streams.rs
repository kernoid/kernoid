// SPDX-License-Identifier: MIT
//! A device's spaces of streams (RFC 0012), synchronised through a relay's protocol 2.
//!
//! [`Streams`] founds a space, invites devices and persons, follows the streams the device can open – starting at its
//! person's stream and the space stream, going down the links it finds –, writes events into a stream (making a new
//! generation first when the stream is due since someone was removed), makes streams below others or for a person
//! alone, shares a stream with a person, keeps originals of a stream (large ones in parts), and purges a stream.

use std::{collections::BTreeMap, time::Duration};

use kernoid_base::{Bytes, Sha256Hash, SpaceId, base64url, from_base64url, from_root, to_root};
use kernoid_crypt::{
    Domain, EncryptionError, RecoveryCode,
    pq::HybridKeys,
    stream::{
        Device, DeviceKeyId, Joining, LinkBody, Permission, Person, PersonId, RecordKind, Roster, RosterRecord,
        SpaceLinks, StreamId, StreamKey, StreamRecord, Token, Writer, found, link_to_person, new_space_generation,
        person_key, request_signature, token_hash,
    },
};
use kernoid_log::{Clock, DeviceId, EventHash, Log};
use kernoid_space_store::{
    Backend, Store,
    streams::{Parent, StreamState},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{FOUNDER_HEADER, INVITATION_LIFETIME, SyncError, now_ms, relay_error, state_error};

/// The setting under which the state of a space of streams is kept.
const STATE: &str = "streams";
/// The largest part of an original: the relay takes requests of at most 64 MiB.
pub const PART: usize = 16 * 1024 * 1024;
const MAX_RESPONSE: u64 = 512 * 1024 * 1024;

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
}

/// An invitation to a space of streams as text: the relay, `#streams=`, the space, the secret, and `p` for a new
/// person or `d` for a device of the inviting person.
pub fn invitation_text(relay: &str, space: &SpaceId, secret: &[u8; 16], new_person: bool) -> String {
    let kind = if new_person { "p" } else { "d" };
    format!("{}#streams={space}.{}.{kind}", relay.trim_end_matches('/'), base64url(secret))
}

fn parse_invitation(text: &str) -> Result<(String, SpaceId, [u8; 16], bool), SyncError> {
    let invalid = || state_error("not an invitation to a space of streams");
    let (relay, rest) = text.trim().split_once("#streams=").ok_or_else(invalid)?;
    let mut parts = rest.split('.');
    let (space, secret, kind) = (parts.next(), parts.next(), parts.next());
    let space: SpaceId = space.ok_or_else(invalid)?.parse().map_err(|_| invalid())?;
    let secret: [u8; 16] =
        from_base64url(secret.ok_or_else(invalid)?).ok_or_else(invalid)?.try_into().map_err(|_| invalid())?;
    let new_person = match kind {
        Some("p") => true,
        Some("d") => false,
        _ => return Err(invalid()),
    };
    Ok((relay.to_owned(), space, secret, new_person))
}

/// Requests to a relay's protocol 2, signed by a device.
struct Client<'a> {
    agent: ureq::Agent,
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
    fn new(base: &str, domain: Domain, keys: &'a HybridKeys) -> Self {
        let agent = crate::agent(Duration::from_secs(300));
        Client { agent, base: base.trim_end_matches('/').to_owned(), domain, keys }
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
        let signature = request_signature(self.domain, self.keys, method, &self.signed_path(path), now_s());
        let mut builder = ureq::http::Request::builder().method(method).uri(&url).header("Authorization", signature);
        if let Some(token) = tokens.read {
            builder = builder.header(kernoid_crypt::stream::READ_HEADER, token);
        }
        if let Some(token) = tokens.write {
            builder = builder.header(kernoid_crypt::stream::WRITE_HEADER, token);
        }
        if let Some(token) = tokens.founder {
            builder = builder.header(FOUNDER_HEADER, token);
        }
        let response = match body {
            Some(body) => {
                let request = builder.header("Content-Type", "application/json").body(body).map_err(relay_error)?;
                self.agent.run(request)
            }
            None => self.agent.run(builder.body(()).map_err(relay_error)?),
        }
        .map_err(|e| relay_error(format!("{}: {e}", self.base)))?;
        let mut response = response;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| relay_error(format!("its answer: {e}")))?;
        Ok((status, body))
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

fn stream_tokens(domain: Domain, key: &StreamKey, stream: &StreamId, generation: u32, inbox: bool) -> Vec<u8> {
    let hash = |which| Bytes(token_hash(&key.token(domain, which, stream, generation)).0.to_vec());
    serde_json::to_vec(&json!({
        "generation": generation, "read": hash(Token::Read), "write": hash(Token::Write), "inbox": inbox,
    }))
    .expect("JSON")
}

/// What one device holds of its spaces of streams, and how it synchronises them.
#[derive(Debug)]
pub struct Streams {
    domain: Domain,
    device: DeviceId,
    store: Store,
    clock: Clock,
}

impl Streams {
    /// The spaces of streams of a device named `device`, kept in `store`.
    pub fn open(domain: Domain, device: DeviceId, store: Store) -> Self {
        Streams { domain, clock: Clock::new(device.clone()), device, store }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The spaces of streams on this device.
    pub fn spaces(&self) -> Result<Vec<SpaceId>, SyncError> {
        Ok(self.store.stream_spaces()?)
    }

    fn state(&self, space: &SpaceId) -> Result<State, SyncError> {
        let text = self.store.setting(Some(space), STATE)?.ok_or_else(|| state_error("not a space of streams here"))?;
        serde_json::from_str(&text).map_err(|e| state_error(e.to_string()))
    }

    fn save_state(&self, space: &SpaceId, state: &State) -> Result<(), SyncError> {
        Ok(self.store.set_setting(Some(space), STATE, &serde_json::to_string(state).expect("JSON"))?)
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
        let founding = found(
            self.domain,
            &space,
            &keys,
            self.device.clone(),
            device_name.map(str::to_owned),
            person_name.map(str::to_owned),
        )?;
        let client = Client::new(relay, self.domain, &keys);
        let roster_path = format!("/v2/spaces/{space}/roster");
        let tokens = Tokens { founder: founder.map(str::to_owned), ..Tokens::default() };
        client.expect("POST", &roster_path, tokens, Some(to_root(&founding.record).expect("canonical")), &[201])?;
        self.store.add_roster_record(self.domain, &founding.record)?;
        let state = State {
            relay: relay.to_owned(),
            seed: hex::encode(keys.seed()),
            person: Some(founding.person.clone()),
            joined: true,
            invited: vec![],
        };
        self.save_state(&space, &state)?;

        // The space stream at the relay.
        let stream = &founding.space_stream;
        client.expect(
            "PUT",
            &format!("/v2/spaces/{space}/streams/{stream}"),
            Tokens::default(),
            Some(stream_tokens(self.domain, &founding.space_key, stream, 0, false)),
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
        let device = Device::new(&recovery, founding.person.clone(), name, Some("Recovery code".into())).with(&[
            Permission::Write,
            Permission::Members,
            Permission::Purge,
        ]);
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
        Ok(invitation_text(&state.relay, space, &secret, new_person))
    }

    /// Asks to join a space with an invitation; the space arrives once the inviting device has added this one.
    pub fn join(
        &mut self,
        invitation: &str,
        device_name: Option<&str>,
        person_name: Option<&str>,
    ) -> Result<SpaceId, SyncError> {
        let (relay, space, secret, new_person) = parse_invitation(invitation)?;
        if self.store.setting(Some(&space), STATE)?.is_some() {
            return Err(state_error("this space is on this device already"));
        }
        let keys = HybridKeys::generate(self.domain);
        let (person, request) = if new_person {
            let person = PersonId::generate();
            let seed: [u8; 32] = kernoid_base::random();
            let device = Device::new(&keys, person.clone(), self.device.clone(), device_name.map(str::to_owned))
                .with(&[Permission::Write]);
            let key = person_key(self.domain, &space, &person, 0, &seed, None, &[&device])?;
            let who = Person { id: person.clone(), name: person_name.map(str::to_owned) };
            (Some(person), Joining::new(&secret, device, Some((who, key))))
        } else {
            // A device of the inviting person: the person is known once it is added.
            let placeholder = PersonId::generate();
            let device = Device::new(&keys, placeholder, self.device.clone(), device_name.map(str::to_owned));
            (None, Joining::new(&secret, device, None))
        };
        let client = Client::new(&relay, self.domain, &keys);
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/requests"),
            Tokens::default(),
            Some(to_root(&request).expect("canonical")),
            &[201],
        )?;
        let state = State { relay, seed: hex::encode(keys.seed()), person, joined: false, invited: vec![] };
        self.save_state(&space, &state)?;
        Ok(space)
    }

    /// Brings a person back on this device with the recovery code made when the space was founded.
    pub fn recover(
        &mut self,
        relay: &str,
        space: &SpaceId,
        code: &RecoveryCode,
        device_name: Option<&str>,
    ) -> Result<StreamsReport, SyncError> {
        let recovery = HybridKeys::from_seed(self.domain, code.0);
        let client = Client::new(relay, self.domain, &recovery);
        let roster = self.fetch_roster(&client, space, &Roster::new(self.domain, space.clone()))?;
        let rdevice = roster
            .device(&recovery.verifying().id())
            .cloned()
            .ok_or_else(|| state_error("not a recovery code of this space"))?;
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
        };
        self.save_state(space, &state)?;
        self.sync(space)
    }

    /// Adds a person without asking them: the person, its key, the space stream linked to it, and a recovery code
    /// whose device brings the person's first device in ([`Streams::recover`]) with `permissions` (and `write`). For
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
        let mut granted = vec![Permission::Write];
        granted.extend(permissions.iter().copied().filter(|p| *p != Permission::Write));
        let device = Device::new(&recovery, person.clone(), device_name, Some("Recovery code".into())).with(&granted);
        let key = person_key(self.domain, space, &person, 0, &seed, None, &[&device])?;
        let current = roster.space_generation().ok_or_else(|| state_error("no space stream"))?;
        let space_stream = roster.space_stream().cloned().ok_or_else(|| state_error("no space stream"))?;
        let space_key = self
            .store
            .stream_keys(space, &space_stream)?
            .remove(&current)
            .ok_or_else(|| state_error("no current key of the space stream"))?;
        let link = link_to_person(self.domain, &space_stream, current, &space_key, &key)?;
        let record = roster
            .next(RosterRecord {
                add_persons: vec![Person { id: person.clone(), name: name.map(str::to_owned) }],
                add_devices: vec![device],
                person_keys: vec![key],
                space_links: Some(SpaceLinks { generation: current, links: vec![link], previous: None }),
                ..RosterRecord::blank(space)
            })
            .sign(&keys);
        let client = Client::new(&state.relay, self.domain, &keys);
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

    /// Whether this device is a device of the space already (it may still wait to be added).
    pub fn has_space(&self, space: &SpaceId) -> Result<bool, SyncError> {
        Ok(self.store.setting(Some(space), STATE)?.is_some())
    }

    /// The relay a space is kept at.
    pub fn relay(&self, space: &SpaceId) -> Result<String, SyncError> {
        Ok(self.state(space)?.relay)
    }

    /// Reads the roster's new records from the relay, checks them on top of `roster` and returns the result.
    fn fetch_roster(&self, client: &Client<'_>, space: &SpaceId, roster: &Roster) -> Result<Roster, SyncError> {
        let after = roster.records().len() as i64 - 1;
        let records: Vec<Value> =
            client.json("GET", &format!("/v2/spaces/{space}/roster?after={after}"), Tokens::default(), None)?;
        let mut roster = roster.clone();
        for record in records {
            let record: RosterRecord = from_root(record.to_string().as_bytes()).map_err(relay_error)?;
            roster.apply(record).map_err(|e| relay_error(format!("the roster is not valid: {e}")))?;
        }
        Ok(roster)
    }

    /// Synchronises a space: the roster, requests to join made with invitations from here, and every stream this
    /// device can open – following links down to streams it did not know.
    pub fn sync(&mut self, space: &SpaceId) -> Result<StreamsReport, SyncError> {
        let mut state = self.state(space)?;
        let keys = self.device_keys(&state)?;
        let client = Client::new(&state.relay, self.domain, &keys);
        let mut report = StreamsReport::default();
        let before = self.store.roster(self.domain, space)?;
        let roster = self.fetch_roster(&client, space, &before)?;
        for record in &roster.records()[before.records().len()..] {
            self.store.add_roster_record(self.domain, record)?;
        }
        let Some(me) = roster.device(&keys.verifying().id()).cloned() else {
            if state.joined {
                return Err(state_error("this device was removed from the space"));
            }
            report.waiting = true;
            return Ok(report);
        };
        if !state.joined || state.person.as_ref() != Some(&me.person) {
            state.joined = true;
            state.person = Some(me.person.clone());
            self.save_state(space, &state)?;
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

        // The person's stream, one generation per generation of the person's key.
        let seeds = roster.person_seeds(&keys)?;
        let person_stream = self.person_stream(space, &me.person);
        let mut previous: Option<(u32, StreamKey)> = None;
        for (generation, seed) in &seeds {
            let key = StreamKey::of_person(self.domain, &me.person, seed);
            if self.store.stream_keys(space, &person_stream)?.is_empty() {
                let status = client.expect(
                    "PUT",
                    &format!("/v2/spaces/{space}/streams/{person_stream}"),
                    Tokens::default(),
                    Some(stream_tokens(self.domain, &key, &person_stream, 0, true)),
                    &[201, 409],
                )?;
                let _ = status;
            } else if let Some((g, previous)) = &previous
                && !self.store.stream_keys(space, &person_stream)?.contains_key(generation)
            {
                let write = previous.token_text(self.domain, Token::Write, &person_stream, *g);
                client.expect(
                    "POST",
                    &format!("/v2/spaces/{space}/streams/{person_stream}/generations"),
                    Tokens { write: Some(write), ..Tokens::default() },
                    Some(stream_tokens(self.domain, &key, &person_stream, *generation, true)),
                    &[201, 403, 409],
                )?;
            }
            self.store.add_stream(space, &person_stream, true)?;
            self.store.put_stream_key(space, &person_stream, *generation, &key)?;
            previous = Some((*generation, key));
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
            let record = match &joining.person {
                Some((person, key)) => {
                    let current = roster.space_generation().ok_or_else(|| state_error("no space stream"))?;
                    let space_key = self
                        .store
                        .stream_keys(space, roster.space_stream().expect("a space stream"))?
                        .remove(&current)
                        .ok_or_else(|| state_error("no current key of the space stream"))?;
                    let link = link_to_person(
                        self.domain,
                        roster.space_stream().expect("a space stream"),
                        current,
                        &space_key,
                        key,
                    )?;
                    RosterRecord {
                        add_persons: vec![person.clone()],
                        add_devices: vec![joining.device.clone()],
                        person_keys: vec![key.clone()],
                        space_links: Some(SpaceLinks { generation: current, links: vec![link], previous: None }),
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
                    let device = Device {
                        person: me.person.clone(),
                        permissions: [Permission::Write].into(),
                        ..joining.device.clone()
                    };
                    let seals = person_key(self.domain, space, &me.person, generation, &seed, None, &[&device])?;
                    RosterRecord { add_devices: vec![device], person_keys: vec![seals], ..RosterRecord::blank(space) }
                }
            };
            let record = roster.next(record).sign(keys);
            let status = client.expect(
                "POST",
                &format!("/v2/spaces/{space}/roster"),
                Tokens::default(),
                Some(to_root(&record).expect("canonical")),
                &[201, 409],
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
        let roster = self.roster(space)?;
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
        for (stream, result) in answer["streams"].as_object().into_iter().flatten() {
            let stream: StreamId = stream.parse().map_err(relay_error)?;
            let Some(records) = result["records"].as_array() else { continue };
            for item in records {
                let position = item["position"].as_i64().unwrap_or(0);
                let record: StreamRecord = from_root(item["record"].to_string().as_bytes()).map_err(relay_error)?;
                match self.take(space, &stream, &roster, person, seeds, &record)? {
                    Taken::Event => report.received += 1,
                    Taken::Stream(child) => found.push(child),
                    Taken::Key => *more = true,
                    Taken::Nothing => {}
                    // A key this device does not have yet: read on from here once a link brings it.
                    Taken::Later => break,
                }
                self.store.put_stream_record(space, &stream, position, &to_root(&record).expect("canonical"))?;
                self.store.set_position(space, &stream, position)?;
            }
        }
        Ok(found)
    }

    /// What a received record brings.
    fn take(
        &mut self,
        space: &SpaceId,
        stream: &StreamId,
        roster: &Roster,
        person: &PersonId,
        seeds: &BTreeMap<u32, [u8; 32]>,
        record: &StreamRecord,
    ) -> Result<Taken, SyncError> {
        let author =
            roster.device_ever(&record.author).ok_or_else(|| relay_error("a record of a device not in the roster"))?;
        if record.space != *space || record.stream != *stream || !record.is_authentic(self.domain, author) {
            return Err(relay_error("a record that is not authentic"));
        }
        let keys = self.store.stream_keys(space, stream)?;
        if record.kind == RecordKind::Sealed {
            let Some(seed) = seeds.get(&record.generation) else { return Ok(Taken::Nothing) };
            let Ok(body) = record.open_sealed(&HybridKeys::from_seed(self.domain, *seed)) else {
                return Ok(Taken::Nothing);
            };
            return self.learn(space, &body, Parent::Person(person.clone()));
        }
        let Some(key) = keys.get(&record.generation) else { return Ok(Taken::Later) };
        match record.kind {
            RecordKind::Event => {
                let canonical = record.open_event(key, roster)?;
                let hash = Sha256Hash::of(&canonical);
                Ok(if self.store.add_stream_event(space, stream, &hash.to_string(), &canonical)? {
                    Taken::Event
                } else {
                    Taken::Nothing
                })
            }
            RecordKind::Generation => {
                if record.generation > 0 {
                    let previous = record.open_generation(key)?;
                    self.store.put_stream_key(space, stream, record.generation - 1, &previous)?;
                }
                Ok(Taken::Nothing)
            }
            RecordKind::Link => {
                let body = record.open_link(key)?;
                self.learn(space, &body, Parent::Stream(stream.clone()))
            }
            RecordKind::Sealed => unreachable!("handled above"),
        }
    }

    fn learn(&mut self, space: &SpaceId, body: &LinkBody, parent: Parent) -> Result<Taken, SyncError> {
        let key: [u8; 32] = body.key.0.clone().try_into().map_err(|_| EncryptionError::Format("a stream key"))?;
        let known = self.store.stream_keys(space, &body.stream)?.contains_key(&body.generation);
        self.store.put_stream_key(space, &body.stream, body.generation, &StreamKey(key))?;
        self.store.add_parent(space, &body.stream, &parent)?;
        let new_stream = self.store.add_stream(space, &body.stream, false)?;
        // A new stream, or a new generation of one: either may hold records this device could not read before.
        Ok(match (new_stream, known) {
            (true, _) => Taken::Stream(body.stream.clone()),
            (false, false) => Taken::Key,
            (false, true) => Taken::Nothing,
        })
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

    fn post_record(
        &self,
        space: &SpaceId,
        client: &Client<'_>,
        record: &StreamRecord,
        write: Option<String>,
    ) -> Result<(), SyncError> {
        client.expect(
            "POST",
            &format!("/v2/spaces/{space}/streams/{}/records", record.stream),
            Tokens { write, ..Tokens::default() },
            Some(to_root(record).expect("canonical")),
            &[200, 201],
        )?;
        Ok(())
    }

    /// Writes an event of `payload` into a stream; a stream due for a new generation gets it first.
    pub fn write(
        &mut self,
        space: &SpaceId,
        stream: &StreamId,
        payload: &impl Serialize,
    ) -> Result<EventHash, SyncError> {
        if self.store.stream(space, stream)?.is_some_and(|s| s.due) {
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
        let writer = Writer { domain: self.domain, space, keys: &keys, at: roster.records().len() as u64 - 1 };
        let record = StreamRecord::event(&writer, stream, generation, &key, &event);
        let client = Client::new(&state.relay, self.domain, &keys);
        self.post_record(space, &client, &record, Some(key.token_text(self.domain, Token::Write, stream, generation)))?;
        let canonical = event.to_canonical().expect("canonical");
        self.store.add_stream_event(space, stream, &hash.to_string(), &canonical)?;
        Ok(hash)
    }

    /// Makes a stream below `parent`: a stream (a folder for a document) or a person alone. Returns it.
    pub fn new_stream(&mut self, space: &SpaceId, parent: &Parent) -> Result<StreamId, SyncError> {
        let (state, keys, _) = self.context(space)?;
        let client = Client::new(&state.relay, self.domain, &keys);
        let stream = StreamId::generate();
        let key = StreamKey::generate();
        client.expect(
            "PUT",
            &format!("/v2/spaces/{space}/streams/{stream}"),
            Tokens::default(),
            Some(stream_tokens(self.domain, &key, &stream, 0, false)),
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
        let client = Client::new(&state.relay, self.domain, &keys);
        let (generation, key) = self.current(space, stream)?;
        let body = LinkBody { stream: stream.clone(), generation, key: Bytes(key.0.to_vec()) };
        let writer = Writer { domain: self.domain, space, keys: &keys, at: roster.records().len() as u64 - 1 };
        match parent {
            Parent::Stream(above) => {
                let (above_generation, above_key) = self.current(space, above)?;
                let record = StreamRecord::link(&writer, above, above_generation, &above_key, &body);
                let write = above_key.token_text(self.domain, Token::Write, above, above_generation);
                self.post_record(space, &client, &record, Some(write))?;
            }
            Parent::Person(person) => {
                let key = roster.person_key(person).ok_or_else(|| state_error(format!("no person {person} here")))?;
                let person_stream = self.person_stream(space, person);
                let record = StreamRecord::sealed_link(&writer, &person_stream, key, &body)?;
                self.post_record(space, &client, &record, None)?;
            }
        }
        self.store.add_parent(space, stream, parent)?;
        Ok(())
    }

    /// A new generation of a stream: registered at the relay, chained to the one before, and linked again for every
    /// parent still there – what is written from now on, nobody removed can read.
    pub fn renew(&mut self, space: &SpaceId, stream: &StreamId) -> Result<u32, SyncError> {
        let (state, keys, roster) = self.context(space)?;
        let client = Client::new(&state.relay, self.domain, &keys);
        let (generation, previous) = self.current(space, stream)?;
        let next = generation + 1;
        let key = StreamKey::generate();
        let is_space = roster.space_stream() == Some(stream);
        if is_space {
            // The space stream's key goes to every person through the roster.
            let links = new_space_generation(&roster, &key, Some(&previous))?;
            if links.generation != next {
                return Err(state_error("the space stream's generations are out of step"));
            }
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
            Some(stream_tokens(self.domain, &key, stream, next, false)),
            &[201],
        )?;
        self.store.put_stream_key(space, stream, next, &key)?;
        let roster = self.roster(space)?;
        let writer = Writer { domain: self.domain, space, keys: &keys, at: roster.records().len() as u64 - 1 };
        let record = StreamRecord::generation(&writer, stream, next, &key, &previous);
        self.post_record(space, &client, &record, Some(key.token_text(self.domain, Token::Write, stream, next)))?;
        self.store.set_due(space, stream, false)?;
        if !is_space {
            for parent in self.store.parents(space, stream)? {
                let still = match &parent {
                    Parent::Stream(above) => self.store.has_stream(space, above)?,
                    Parent::Person(person) => roster.person(person).is_some(),
                };
                if still {
                    self.link(space, stream, &parent)?;
                }
            }
        }
        Ok(next)
    }

    /// Removes a device of the space. Its person gets a new key for the devices left; every stream this device knows
    /// gets a new generation before it is written again.
    pub fn remove_device(&mut self, space: &SpaceId, device: &DeviceKeyId) -> Result<(), SyncError> {
        // A record follows the roster's newest one: read what is new first.
        self.sync(space)?;
        let (state, keys, roster) = self.context(space)?;
        let target = roster.device(device).cloned().ok_or_else(|| state_error("no such device in the space"))?;
        if target.id == keys.verifying().id() {
            return Err(state_error("this device cannot remove itself"));
        }
        let me = roster.device(&keys.verifying().id()).cloned().expect("checked");
        let current = roster.person_key(&target.person).map_or(0, |k| k.generation);
        let staying: Vec<Device> = roster.devices_of(&target.person).filter(|d| d.id != target.id).cloned().collect();
        let seed: [u8; 32] = kernoid_base::random();
        // The person's own device chains the seed before; another person's device cannot.
        let previous =
            if me.person == target.person { roster.person_seeds(&keys)?.get(&current).copied() } else { None };
        let staying_refs: Vec<&Device> = staying.iter().collect();
        let rotated =
            person_key(self.domain, space, &target.person, current + 1, &seed, previous.as_ref(), &staying_refs)?;
        let record = roster
            .next(RosterRecord {
                remove_devices: vec![target.id],
                person_keys: vec![rotated],
                ..RosterRecord::blank(space)
            })
            .sign(&keys);
        let client = Client::new(&state.relay, self.domain, &keys);
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
        let client = Client::new(&state.relay, self.domain, &keys);
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
        let client = Client::new(&state.relay, self.domain, &keys);
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
        let client = Client::new(&state.relay, self.domain, &keys);
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
        let client = Client::new(&state.relay, self.domain, &keys);
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

enum Taken {
    Event,
    Stream(StreamId),
    /// A newer key of a stream known already.
    Key,
    Nothing,
    Later,
}
