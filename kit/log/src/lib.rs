// SPDX-License-Identifier: MIT
//! The event log of a space: immutable events of any kind, ordered by a hybrid logical clock, chained per device and
//! identified by the hash of their canonical encoding. Two logs merge by union, in any order, any number of times,
//! with the same result; what does not fit a clean chain is reported, never resolved silently.
//!
//! The core knows the frame of an event (`type`, `kind`, `time`, `seq`, `prev`), the program the kinds and their
//! members.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
};

use kernoid_base::{CanonicalError, Object, ObjectError, Sha256Hash, canonicalize, to_canonical_vec};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

mod clock;

pub use clock::{Clock, DeviceId, Hlc};

/// The identity of an event: SHA-256 over its canonical encoding as received.
pub type EventHash = Sha256Hash;

/// The members of an event the core reads itself; a kind may not use them for its own.
pub const FRAME: [&str; 5] = ["type", "kind", "time", "seq", "prev"];

/// Why an event cannot be made or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    /// Not JSON that has a canonical encoding.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// JSON that is not an event.
    #[error(transparent)]
    Object(#[from] ObjectError),
    /// A kind that is not 1–64 characters of `a-z`, `0-9` and `_`, starting with a letter.
    #[error("not a valid kind: {0:?}")]
    Kind(String),
    /// A payload that is not an object with a kind, or uses a member of the frame.
    #[error("not a valid payload: {0}")]
    Payload(String),
}

/// One event: who wrote it when, its place in the device's chain, and what happened – its kind and members.
///
/// As a root object: `{"type": "event", "kind": …, "time": …, "seq": …, "prev": …, …}`, the members of the kind next
/// to those of the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The timestamp; its device is the device that wrote the event.
    pub time: Hlc,
    /// Position in the device's chain, starting at 1.
    pub seq: u64,
    /// The hash of the device's previous event; none for `seq` 1, written as `null`.
    pub prev: Option<EventHash>,
    /// What happened: 1–64 characters of `a-z`, `0-9` and `_`, starting with a letter.
    pub kind: String,
    /// The members that come with the kind.
    pub members: Map<String, Value>,
}

impl Object for Event {
    const TYPE: &'static str = "event";
}

fn valid_kind(kind: &str) -> bool {
    (1..=64).contains(&kind.len())
        && kind.starts_with(|c: char| c.is_ascii_lowercase())
        && kind.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Event {
    /// An event of a payload of the program: anything that serialises to an object with the member `kind`, as an
    /// enum with `#[serde(tag = "kind", rename_all = "snake_case")]` does.
    pub fn new(time: Hlc, seq: u64, prev: Option<EventHash>, payload: &impl Serialize) -> Result<Self, EventError> {
        let payload = serde_json::to_value(payload).map_err(|e| EventError::Payload(e.to_string()))?;
        let Value::Object(mut members) = payload else {
            return Err(EventError::Payload("not an object".into()));
        };
        let kind = match members.remove("kind") {
            Some(Value::String(kind)) => kind,
            _ => return Err(EventError::Payload("without a kind".into())),
        };
        if !valid_kind(&kind) {
            return Err(EventError::Kind(kind));
        }
        if let Some(name) = FRAME.iter().find(|name| members.contains_key(**name)) {
            return Err(EventError::Payload(format!("uses the member {name:?} of the frame")));
        }
        Ok(Event { time, seq, prev, kind, members })
    }

    /// The device that wrote the event.
    pub fn device(&self) -> &DeviceId {
        &self.time.device
    }

    /// The payload as the program reads it: `kind` and the members, deserialised into `P`.
    pub fn payload<P: DeserializeOwned>(&self) -> Result<P, serde_json::Error> {
        let mut members = self.members.clone();
        members.insert("kind".into(), Value::String(self.kind.clone()));
        serde_json::from_value(Value::Object(members))
    }

    /// The canonical encoding of the event as a root object.
    pub fn to_canonical(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut json = self.members.clone();
        json.insert("type".into(), Event::TYPE.into());
        json.insert("kind".into(), Value::String(self.kind.clone()));
        json.insert("time".into(), serde_json::to_value(&self.time).expect("a timestamp is JSON"));
        json.insert("seq".into(), self.seq.into());
        json.insert("prev".into(), self.prev.map_or(Value::Null, |prev| Value::String(prev.to_string())));
        to_canonical_vec(&json)
    }

    /// Reads an event from JSON in any formatting – as it arrives from another device.
    pub fn read(json: &[u8]) -> Result<Self, EventError> {
        Self::from_canonical(&canonicalize(json)?)
    }

    /// Reads an event from its canonical encoding.
    fn from_canonical(canonical: &[u8]) -> Result<Self, EventError> {
        let content = |what: String| ObjectError::Content(Event::TYPE, what);
        let value: Value = serde_json::from_slice(canonical).map_err(|e| CanonicalError::Json(e.to_string()))?;
        let Value::Object(mut members) = value else {
            return Err(content("not an object".into()).into());
        };
        match members.remove("type") {
            Some(Value::String(found)) if found == Event::TYPE => {}
            found => {
                let found = found.map(|t| t.as_str().map_or_else(|| t.to_string(), str::to_owned));
                return Err(ObjectError::Type { expected: Event::TYPE, found }.into());
            }
        }
        let kind = match members.remove("kind") {
            Some(Value::String(kind)) if valid_kind(&kind) => kind,
            Some(Value::String(kind)) => return Err(EventError::Kind(kind)),
            _ => return Err(content("without a kind".into()).into()),
        };
        let time = members.remove("time").ok_or_else(|| content("without a time".into()))?;
        let time: Hlc = serde_json::from_value(time).map_err(|e| content(format!("time: {e}")))?;
        let seq = match members.remove("seq").and_then(|seq| seq.as_u64()) {
            Some(seq) if seq >= 1 => seq,
            _ => return Err(content("without a position from 1".into()).into()),
        };
        let prev = match members.remove("prev") {
            Some(Value::Null) => None,
            Some(Value::String(prev)) => Some(prev.parse().map_err(|e| content(format!("prev: {e}")))?),
            _ => return Err(content("prev must be written, a hash or null".into()).into()),
        };
        Ok(Event { time, seq, prev, kind, members })
    }
}

/// Something in a log that does not fit a clean chain per device.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainProblem {
    /// Two different events of one device with the same position – the device's history was forked.
    #[error("device {device} has two events at position {seq}")]
    Fork {
        /// The device.
        device: DeviceId,
        /// The position.
        seq: u64,
    },
    /// Positions of a device are missing – events have not arrived (yet).
    #[error("device {device} is missing events {from} to {to}")]
    Gap {
        /// The device.
        device: DeviceId,
        /// First missing position.
        from: u64,
        /// Last missing position.
        to: u64,
    },
    /// An event does not point to the device's previous event.
    #[error("event {event} of device {device} does not follow the device's previous event")]
    BrokenLink {
        /// The device.
        device: DeviceId,
        /// The event.
        event: EventHash,
    },
}

/// The log of a space as one device knows it: a set of events. Merging is set union, in any order, any number of
/// times, with the same result.
///
/// Every event is kept in its canonical encoding as well as read: the encoding is what is hashed and what is passed
/// on, so members of a later version survive this one unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    events: BTreeMap<EventHash, Stored>,
}

/// An event as read, and the canonical bytes it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    event: Event,
    canonical: Arc<[u8]>,
}

impl Log {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an event written on this device; returns its hash and whether it was new.
    pub fn insert(&mut self, event: Event) -> Result<(EventHash, bool), CanonicalError> {
        let canonical = event.to_canonical()?;
        Ok(self.add(Stored { event, canonical: canonical.into() }))
    }

    /// Writes a new event of `payload` on the device of `clock`, at the head of its chain; returns its hash.
    pub fn append(
        &mut self,
        clock: &mut Clock,
        physical_ms: u64,
        payload: &impl Serialize,
    ) -> Result<EventHash, EventError> {
        let (seq, prev) = self.chain_head(clock.device());
        let event = Event::new(clock.now(physical_ms), seq, prev, payload)?;
        Ok(self.insert(event)?.0)
    }

    /// Adds an event received as JSON, in any formatting; returns its hash and whether it was new. The hash is taken
    /// over the canonical encoding of what was received, members this version does not know included.
    pub fn receive(&mut self, json: &[u8]) -> Result<(EventHash, bool), EventError> {
        let canonical = canonicalize(json)?;
        let event = Event::from_canonical(&canonical)?;
        Ok(self.add(Stored { event, canonical: canonical.into() }))
    }

    fn add(&mut self, stored: Stored) -> (EventHash, bool) {
        let hash = Sha256Hash::of(&stored.canonical);
        match self.events.entry(hash) {
            Entry::Vacant(slot) => {
                slot.insert(stored);
                (hash, true)
            }
            Entry::Occupied(_) => (hash, false),
        }
    }

    /// Adds all events of another log; returns how many were new.
    pub fn merge(&mut self, other: &Log) -> usize {
        other.events.values().filter(|stored| self.add((*stored).clone()).1).count()
    }

    /// The event with this hash.
    pub fn get(&self, hash: &EventHash) -> Option<&Event> {
        self.events.get(hash).map(|stored| &stored.event)
    }

    /// The canonical encoding of the event with this hash – what is stored and passed on.
    pub fn canonical(&self, hash: &EventHash) -> Option<&[u8]> {
        self.events.get(hash).map(|stored| &*stored.canonical)
    }

    /// The hashes of all events, by hash.
    pub fn hashes(&self) -> impl Iterator<Item = &EventHash> {
        self.events.keys()
    }

    /// The number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether there are no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// All events in the order every device agrees on: by timestamp, then by hash.
    pub fn ordered(&self) -> Vec<(EventHash, &Event)> {
        let mut events: Vec<_> = self.events.iter().map(|(hash, stored)| (*hash, &stored.event)).collect();
        events.sort_by(|(ha, a), (hb, b)| a.time.cmp(&b.time).then(ha.cmp(hb)));
        events
    }

    /// The latest timestamp in the log, to let a clock observe it.
    pub fn latest(&self) -> Option<&Hlc> {
        self.events.values().map(|stored| &stored.event.time).max()
    }

    /// The state of the log: SHA-256 of the canonical encoding of the array of all event hashes in the agreed
    /// order. Two copies with the same events have the same state.
    pub fn state(&self) -> Sha256Hash {
        let hashes: Vec<String> = self.ordered().iter().map(|(hash, _)| hash.to_string()).collect();
        Sha256Hash::of(&to_canonical_vec(&hashes).expect("an array of strings"))
    }

    /// The next position and previous hash for a new event of `device`.
    pub fn chain_head(&self, device: &DeviceId) -> (u64, Option<EventHash>) {
        self.events
            .iter()
            .filter(|(_, stored)| stored.event.device() == device)
            .max_by_key(|(hash, stored)| (stored.event.seq, **hash))
            .map_or((1, None), |(hash, stored)| (stored.event.seq + 1, Some(*hash)))
    }

    /// Checks every device's chain: one event per position, no gaps, each event pointing to its predecessor.
    pub fn verify(&self) -> Vec<ChainProblem> {
        type Positions<'a> = BTreeMap<u64, Vec<(EventHash, &'a Event)>>;
        let mut chains: BTreeMap<&DeviceId, Positions> = BTreeMap::new();
        for (hash, Stored { event, .. }) in &self.events {
            chains.entry(event.device()).or_default().entry(event.seq).or_default().push((*hash, event));
        }
        let mut problems = Vec::new();
        for (device, positions) in chains {
            let mut expected = 1;
            let mut previous: Option<EventHash> = None;
            for (seq, events) in positions {
                if seq > expected {
                    problems.push(ChainProblem::Gap { device: device.clone(), from: expected, to: seq - 1 });
                    previous = None;
                }
                if events.len() > 1 {
                    problems.push(ChainProblem::Fork { device: device.clone(), seq });
                    previous = None;
                } else {
                    let (hash, event) = events[0];
                    let linked =
                        if seq == 1 { event.prev.is_none() } else { previous.is_none() || event.prev == previous };
                    if !linked {
                        problems.push(ChainProblem::BrokenLink { device: device.clone(), event: hash });
                    }
                    previous = Some(hash);
                }
                expected = seq + 1;
            }
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Payload {
        DocumentAdded { title: String },
        LabelSet { label: String },
    }

    fn device(name: &str) -> DeviceId {
        name.parse().unwrap()
    }

    fn added(title: &str) -> Payload {
        Payload::DocumentAdded { title: title.into() }
    }

    #[test]
    fn an_event_is_a_root_object_with_its_kind_beside_the_frame() {
        let mut log = Log::new();
        let mut clock = Clock::new(device("laptop"));
        let hash = log.append(&mut clock, 1_000, &added("Lease")).unwrap();
        let canonical = std::str::from_utf8(log.canonical(&hash).unwrap()).unwrap();
        assert_eq!(
            canonical,
            r#"{"kind":"document_added","prev":null,"seq":1,"time":{"counter":0,"device":"laptop","wall_ms":1000},"title":"Lease","type":"event"}"#
        );
        assert_eq!(hash, Sha256Hash::of(canonical.as_bytes()));
        assert_eq!(log.get(&hash).unwrap().payload::<Payload>().unwrap(), added("Lease"));
    }

    #[test]
    fn payloads_must_not_use_the_frame() {
        let time = Clock::new(device("a")).now(1);
        assert!(matches!(
            Event::new(time.clone(), 1, None, &serde_json::json!({"title": "x"})),
            Err(EventError::Payload(_))
        ));
        assert!(matches!(
            Event::new(time.clone(), 1, None, &serde_json::json!({"kind": "Bad"})),
            Err(EventError::Kind(_))
        ));
        let framed = serde_json::json!({"kind": "x", "seq": 3});
        assert!(matches!(Event::new(time, 1, None, &framed), Err(EventError::Payload(_))));
    }

    #[test]
    fn unknown_members_and_kinds_survive_unchanged() {
        let json = br#"{ "type":"event", "kind":"from_later", "time":{"wall_ms":5,"counter":0,"device":"phone"},
            "seq":1, "prev":null, "extra":{"z":1,"a":[true]} }"#;
        let mut log = Log::new();
        let (hash, new) = log.receive(json).unwrap();
        assert!(new);
        let canonical = log.canonical(&hash).unwrap().to_vec();
        assert_eq!(hash, Sha256Hash::of(&canonical));
        assert_eq!(log.get(&hash).unwrap().to_canonical().unwrap(), canonical);
        assert!(!log.receive(&canonical).unwrap().1, "the same event in another formatting");
    }

    #[test]
    fn what_is_not_an_event_is_rejected() {
        let mut log = Log::new();
        for bad in [
            &br#"{"kind":"x","time":{"wall_ms":5,"counter":0,"device":"a"},"seq":1,"prev":null}"#[..],
            br#"{"type":"event","kind":"x","time":{"wall_ms":5,"counter":0,"device":"a"},"seq":1}"#,
            br#"{"type":"event","kind":"x","time":{"wall_ms":5,"counter":0,"device":"a"},"seq":0,"prev":null}"#,
            br#"{"type":"event","kind":"x","time":{"wall_ms":5,"counter":0,"device":"A"},"seq":1,"prev":null}"#,
            br#"{"type":"event","kind":"x","time":{"wall_ms":5,"counter":0,"device":"a"},"seq":1,"prev":null,"a":1.5}"#,
        ] {
            assert!(log.receive(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(log.is_empty());
    }

    #[test]
    fn merging_is_set_union_in_any_order() {
        let (mut a, mut b) = (Log::new(), Log::new());
        let (mut laptop, mut phone) = (Clock::new(device("laptop")), Clock::new(device("phone")));
        a.append(&mut laptop, 10, &added("Lease")).unwrap();
        a.append(&mut laptop, 20, &Payload::LabelSet { label: "home".into() }).unwrap();
        b.append(&mut phone, 15, &added("Receipt")).unwrap();
        let (mut ab, mut ba) = (a.clone(), b.clone());
        assert_eq!(ab.merge(&b), 1);
        assert_eq!(ba.merge(&a), 2);
        assert_eq!(ab.merge(&b), 0);
        assert_eq!(ab, ba);
        assert_eq!(ab.state(), ba.state());
        assert_ne!(ab.state(), a.state());
        let kinds: Vec<&str> = ab.ordered().iter().map(|(_, e)| e.kind.as_str()).collect();
        assert_eq!(kinds, ["document_added", "document_added", "label_set"]);
        assert!(ab.verify().is_empty());
        assert_eq!(ab.latest().unwrap().wall_ms, 20);
    }

    #[test]
    fn chains_report_forks_gaps_and_broken_links() {
        let mut clock = Clock::new(device("laptop"));
        let mut log = Log::new();
        let first = log.append(&mut clock, 1, &added("a")).unwrap();
        let mut forked = log.clone();
        forked.insert(Event::new(clock.now(2), 1, None, &added("b")).unwrap()).unwrap();
        assert_eq!(forked.verify(), [ChainProblem::Fork { device: device("laptop"), seq: 1 }]);

        let mut gapped = log.clone();
        gapped.insert(Event::new(clock.now(3), 3, Some(first), &added("c")).unwrap()).unwrap();
        assert_eq!(gapped.verify(), [ChainProblem::Gap { device: device("laptop"), from: 2, to: 2 }]);

        let other = Sha256Hash::of(b"elsewhere");
        let (broken, _) = log.insert(Event::new(clock.now(4), 2, Some(other), &added("d")).unwrap()).unwrap();
        assert_eq!(log.verify(), [ChainProblem::BrokenLink { device: device("laptop"), event: broken }]);
    }
}
