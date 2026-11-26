// SPDX-License-Identifier: MIT
//! Spaces of streams through kernoid's relay, end to end (RFC 0012; `scripts/client-check.sh` names the relay in
//! `KERNOID_TEST_RELAY`). Alice founds a space and adds her phone; Bob joins as a new person; a folder for everyone, a
//! document for Alice alone, an original in parts; Carol added with a recovery code; Bob is removed and what is written after is out of his reach;
//! Alice's devices are lost and the recovery code brings her back. Without `KERNOID_TEST_RELAY` it does nothing.

use kernoid_base::{Bytes, SpaceId, base64url, from_base64url, to_root};
use kernoid_crypt::{
    Domain,
    pq::HybridKeys,
    stream::{
        Device, Joining, LinkBody, Permission, Person, PersonId, PersonLink, Request, RosterRecord, SpaceLinks,
        StreamId, StreamKey, StreamRecord, Token, Writer, person_key, request_signature, token_hash,
    },
};
use kernoid_spaces::store::{Store, streams::Parent};
use kernoid_spaces::streams::Streams;
use kernoid_spaces::transport::{Transport, default_transport};
use serde_json::json;

const D: Domain = Domain::KERNOID;

fn relay() -> Option<String> {
    std::env::var("KERNOID_TEST_RELAY").ok()
}

fn device(name: &str) -> Streams {
    Streams::open(D, name.parse().unwrap(), Store::in_memory().unwrap())
}

fn titles(streams: &Streams, space: &kernoid_base::SpaceId, stream: &StreamId) -> Vec<String> {
    let log = streams.log(space, stream).unwrap();
    log.ordered().iter().filter_map(|(_, e)| e.members.get("title")?.as_str().map(str::to_owned)).collect()
}

#[test]
fn persons_devices_streams_and_a_removal() {
    let Some(url) = relay() else { return };
    let mut laptop = device("alice-laptop");
    let (space, code) = laptop.found(&url, None, Some("Laptop"), Some("Alice")).unwrap();
    let alice = laptop.person(&space).unwrap();
    let space_stream = laptop.space_stream(&space).unwrap();
    laptop.write(&space, &space_stream, &json!({"kind": "note", "title": "Welcome"})).unwrap();

    // Alice's phone: a device of her person.
    let mut phone = device("alice-phone");
    let invitation = laptop.invite(&space, false).unwrap();
    assert_eq!(phone.join(&invitation, Some("Phone"), None).unwrap(), space);
    assert!(phone.sync(&space).unwrap().waiting);
    assert_eq!(laptop.sync(&space).unwrap().added.len(), 1);
    phone.sync(&space).unwrap();
    assert_eq!(phone.person(&space).unwrap(), alice);
    assert_eq!(titles(&phone, &space, &space_stream), ["Welcome"]);

    // Bob joins as a person of his own.
    let mut bob = device("bob-tablet");
    let invitation = laptop.invite(&space, true).unwrap();
    bob.join(&invitation, Some("Tablet"), Some("Bob")).unwrap();
    assert_eq!(laptop.sync(&space).unwrap().added.len(), 1);
    bob.sync(&space).unwrap();
    let bob_person = bob.person(&space).unwrap();
    assert_ne!(bob_person, alice);
    assert_eq!(titles(&bob, &space, &space_stream), ["Welcome"]);

    // A folder below the space stream: everyone reads it. A document for Alice alone: Bob never learns of it.
    let folder = laptop.new_stream(&space, &Parent::Stream(space_stream.clone())).unwrap();
    laptop.write(&space, &folder, &json!({"kind": "note", "title": "Minutes"})).unwrap();
    let private = laptop.new_stream(&space, &Parent::Person(alice.clone())).unwrap();
    laptop.write(&space, &private, &json!({"kind": "note", "title": "Diary"})).unwrap();
    let parts = laptop.put_original(&space, &folder, &vec![42u8; 20 * 1024 * 1024]).unwrap();
    assert_eq!(parts.len(), 2, "20 MiB in parts of 16");
    for streams in [&mut phone, &mut bob] {
        streams.sync(&space).unwrap();
    }
    assert_eq!(titles(&bob, &space, &folder), ["Minutes"]);
    assert_eq!(bob.original(&space, &folder, &parts).unwrap().len(), 20 * 1024 * 1024);
    assert!(!bob.streams(&space).unwrap().iter().any(|s| s.stream == private));
    assert_eq!(titles(&phone, &space, &private), ["Diary"]);

    // Carol is added without asking: her recovery code reaches her another way (kernoid's vaults: sealed to her
    // account's key), and her first device comes in with it – a moved document is reached through its new folder.
    let (carol_person, carol_code) = laptop.add_person(&space, Some("Carol"), &[]).unwrap();
    let mut carol = device("carol-laptop");
    carol.recover(&url, &space, &carol_code, Some("Laptop")).unwrap();
    assert_eq!(carol.person(&space).unwrap(), carol_person);
    assert_eq!(titles(&carol, &space, &folder), ["Minutes"]);
    assert!(carol.remove_person(&space, &bob_person).is_err(), "Carol may only write");
    let archive = laptop.new_stream(&space, &Parent::Stream(space_stream.clone())).unwrap();
    let moved = laptop.new_stream(&space, &Parent::Stream(folder.clone())).unwrap();
    laptop.write(&space, &moved, &json!({"kind": "note", "title": "Moved"})).unwrap();
    laptop.link_below(&space, &moved, &archive).unwrap();
    carol.sync(&space).unwrap();
    assert_eq!(titles(&carol, &space, &moved), ["Moved"]);

    // Sharing the document with Bob, then removing Bob: what is written after is out of his reach.
    laptop.share(&space, &private, &bob_person).unwrap();
    bob.sync(&space).unwrap();
    assert_eq!(titles(&bob, &space, &private), ["Diary"]);
    laptop.remove_person(&space, &bob_person).unwrap();
    assert!(bob.sync(&space).is_err(), "removed at once");
    laptop.write(&space, &folder, &json!({"kind": "note", "title": "After Bob"})).unwrap();
    let renewed = laptop.streams(&space).unwrap().into_iter().find(|s| s.stream == folder).unwrap();
    assert!(!renewed.due, "the folder got a new generation before the write");
    phone.sync(&space).unwrap();
    assert_eq!(titles(&phone, &space, &folder), ["Minutes", "After Bob"]);

    // Every device of Alice is lost: the recovery code brings her back with everything.
    let mut tablet = device("alice-tablet");
    tablet.recover(&url, &space, &code, Some("New tablet")).unwrap();
    assert_eq!(tablet.person(&space).unwrap(), alice);
    assert_eq!(titles(&tablet, &space, &space_stream), ["Welcome"]);
    assert_eq!(titles(&tablet, &space, &folder), ["Minutes", "After Bob"]);
    assert_eq!(titles(&tablet, &space, &private), ["Diary"]);

    // The tablet removes the old laptop; the laptop learns it, and Alice's key moves on for the others.
    let laptop_id = laptop.device_id(&space).unwrap();
    assert!(phone.remove_device(&space, &laptop_id).is_err(), "the phone may only write");
    tablet.remove_device(&space, &laptop_id).unwrap();
    assert!(laptop.sync(&space).is_err());
    tablet.sync(&space).unwrap();
    tablet.write(&space, &private, &json!({"kind": "note", "title": "Later"})).unwrap();
    phone.sync(&space).unwrap();
    assert_eq!(titles(&phone, &space, &private), ["Diary", "Later"]);

    // Purging the folder removes it at the relay.
    tablet.purge(&space, &folder).unwrap();
    assert!(!tablet.streams(&space).unwrap().iter().any(|s| s.stream == folder));
}

#[test]
fn groups_take_persons_in_and_out() {
    let Some(url) = relay() else { return };
    let mut laptop = device("alice-laptop2");
    let (space, _code) = laptop.found(&url, None, Some("Laptop"), Some("Alice")).unwrap();
    let alice = laptop.person(&space).unwrap();
    let mut join = |name: &str, person: &str| {
        let mut streams = device(name);
        let invitation = laptop.invite(&space, true).unwrap();
        streams.join(&invitation, Some(name), Some(person)).unwrap();
        assert_eq!(laptop.sync(&space).unwrap().added.len(), 1);
        streams.sync(&space).unwrap();
        let id = streams.person(&space).unwrap();
        (streams, id)
    };
    let (mut bob, bob_person) = join("bob-tablet2", "Bob");
    let (mut carol, carol_person) = join("carol-phone2", "Carol");

    // A group of the three, and a document shown to it.
    let group = laptop.new_group(&space, &[alice.clone(), bob_person.clone(), carol_person.clone()]).unwrap();
    let document = laptop.new_stream(&space, &Parent::Stream(group.clone())).unwrap();
    laptop.write(&space, &document, &json!({"kind": "note", "title": "Plan"})).unwrap();
    for streams in [&mut bob, &mut carol] {
        streams.sync(&space).unwrap();
        assert_eq!(titles(streams, &space, &document), ["Plan"]);
    }
    let members = bob.audience(&space, &group).unwrap().unwrap();
    assert_eq!(members, [alice.clone(), bob_person.clone(), carol_person.clone()].into_iter().collect());

    // Alice takes Carol out. Bob – another device than the one that did – writes to the document afterwards: it gets a
    // new key first, linked below the group's new generation, which Carol cannot open.
    laptop.remove_from_group(&space, &group, &carol_person).unwrap();
    bob.sync(&space).unwrap();
    bob.write(&space, &document, &json!({"kind": "note", "title": "Without Carol"})).unwrap();
    carol.sync(&space).unwrap();
    assert_eq!(titles(&carol, &space, &document), ["Plan"]);
    laptop.sync(&space).unwrap();
    assert_eq!(titles(&laptop, &space, &document), ["Plan", "Without Carol"]);

    // Out of the group, Carol does not write herself back in: the key she holds writes nothing more, and who names a
    // group's members is one of them.
    assert!(carol.add_to_group(&space, &group, &carol_person).is_err());
    bob.sync(&space).unwrap();
    assert_eq!(
        bob.audience(&space, &group).unwrap().unwrap(),
        [alice.clone(), bob_person.clone()].into_iter().collect()
    );

    // Taken in again, Carol reads on.
    laptop.add_to_group(&space, &group, &carol_person).unwrap();
    carol.sync(&space).unwrap();
    assert_eq!(titles(&carol, &space, &document), ["Plan", "Without Carol"]);
}

/// A device that does not go through [`Streams`]: it holds its keys and says to the relay what it likes.
struct Raw {
    keys: HybridKeys,
    relay: String,
    transport: std::sync::Arc<dyn Transport>,
}

impl Raw {
    fn send(&self, method: &str, path: &str, write: Option<&str>, body: Option<Vec<u8>>) -> u16 {
        let prefix = self.relay.split("://").nth(1).and_then(|rest| rest.find('/').map(|i| &rest[i..])).unwrap_or("");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let signed = Request {
            method,
            path: &format!("{prefix}{path}"),
            body: body.as_deref().unwrap_or_default(),
            read: None,
            write,
        };
        let signature = request_signature(D, &self.keys, &signed, now);
        let mut headers = vec![("Authorization", signature.as_str()), ("Content-Type", "application/json")];
        if let Some(write) = write {
            headers.push((kernoid_crypt::stream::WRITE_HEADER, write));
        }
        self.transport.send(method, &format!("{}{path}", self.relay), &headers, body).unwrap().0
    }
}

/// The parts of an invitation: the secret and the hash of the roster's first record.
fn invited(invitation: &str) -> ([u8; 16], String) {
    let parts: Vec<&str> = invitation.split_once("#streams=").unwrap().1.split('.').collect();
    (from_base64url(parts[1]).unwrap().try_into().unwrap(), parts[3].to_owned())
}

/// A request to join as a new person, made by hand: the device asks for whatever it likes.
fn asks(
    space: &SpaceId,
    secret: &[u8; 16],
    keys: &HybridKeys,
    name: &str,
    person: PersonId,
    more: &[Permission],
) -> Vec<u8> {
    let seed = kernoid_base::random::<32>();
    let mut device = Device::new(keys, person.clone(), name.parse().unwrap(), None).with(more).as_server();
    device.proof = Some(Bytes(vec![1; 32]));
    let key = person_key(D, space, &person, 0, &seed, None, &[&device]).unwrap();
    to_root(&Joining::new(secret, device, Some((Person { id: person, name: Some("Mallory".into()) }, key)))).unwrap()
}

#[test]
fn a_device_that_means_harm() {
    let Some(url) = relay() else { return };
    let mut laptop = device("alice-laptop3");
    let (space, _code) = laptop.found(&url, None, Some("Laptop"), Some("Alice")).unwrap();
    let alice = laptop.person(&space).unwrap();
    let space_stream = laptop.space_stream(&space).unwrap();
    laptop.write(&space, &space_stream, &json!({"kind": "note", "title": "Welcome"})).unwrap();
    let folder = laptop.new_stream(&space, &Parent::Stream(space_stream.clone())).unwrap();
    laptop.write(&space, &folder, &json!({"kind": "note", "title": "Minutes"})).unwrap();

    // An invitation names the roster it is for: one that names none, or another, brings nobody in.
    let invitation = laptop.invite(&space, true).unwrap();
    let (_, founding) = invited(&invitation);
    let short = invitation.rsplit_once('.').unwrap().0;
    assert!(device("nobody3").join(short, None, None).is_err());
    let mut fooled = device("fooled3");
    let other = base64url(&[7; 32]);
    fooled.join(&invitation.replace(&founding, &other), Some("Fooled"), Some("Fooled")).unwrap();
    assert_eq!(laptop.sync(&space).unwrap().added.len(), 1);
    assert!(fooled.sync(&space).is_err(), "the roster is not the one the invitation named");

    // Bob joins as he should, with a tablet and a phone.
    let mut bob = device("bob-tablet3");
    bob.join(&laptop.invite(&space, true).unwrap(), Some("Tablet"), Some("Bob")).unwrap();
    assert_eq!(laptop.sync(&space).unwrap().added.len(), 1);
    bob.sync(&space).unwrap();
    let bob_person = bob.person(&space).unwrap();
    let mut bob_phone = device("bob-phone3");
    bob_phone.join(&bob.invite(&space, false).unwrap(), Some("Phone"), None).unwrap();
    assert_eq!(bob.sync(&space).unwrap().added.len(), 1);
    bob_phone.sync(&space).unwrap();
    assert_eq!(titles(&bob, &space, &folder), ["Minutes"]);

    // Mallory is invited as a person – and asks for more than that: every permission, and Alice's person besides.
    let mallory = Raw { keys: HybridKeys::generate(D), relay: url.clone(), transport: default_transport() };
    let (secret_taken, _) = invited(&laptop.invite(&space, true).unwrap());
    let stranger = Raw { keys: HybridKeys::generate(D), relay: url.clone(), transport: default_transport() };
    let requests = format!("/v2/spaces/{space}/requests");
    let taken = asks(&space, &secret_taken, &stranger.keys, "stranger3", alice.clone(), &[]);
    assert_eq!(stranger.send("POST", &requests, None, Some(taken)), 201);
    let (secret, _) = invited(&laptop.invite(&space, true).unwrap());
    let mallory_person = PersonId::generate();
    let all = [Permission::Write, Permission::Members, Permission::Purge];
    let asked = asks(&space, &secret, &mallory.keys, "mallory3", mallory_person.clone(), &all);
    assert_eq!(mallory.send("POST", &requests, None, Some(asked)), 201);
    // The request the roster cannot take is passed over; Mallory comes in with `write`, and nothing else.
    assert_eq!(laptop.sync(&space).unwrap().added, [mallory.keys.verifying().id()]);
    let roster = laptop.roster(&space).unwrap();
    let admitted = roster.device(&mallory.keys.verifying().id()).unwrap();
    assert_eq!(admitted.permissions, [Permission::Write].into());
    // That it is a server it may say of itself: that asks for less trust, not more.
    assert!(admitted.server && admitted.proof.is_none());
    let at = roster.records().len() as u64 - 1;
    let writer = Writer { domain: D, space: &space, keys: &mallory.keys, at, previous: None };
    let space_key = roster.space_keys(&mallory.keys).unwrap().remove(&0).unwrap();
    let space_write = space_key.token_text(D, Token::Write, &space_stream, 0);

    // Records nobody opens, in the space stream; links that name keys of Mallory's making, into Bob's stream: for the
    // space stream, for a newer generation of the folder, of a length no key has.
    let records = |stream: &StreamId| format!("/v2/spaces/{space}/streams/{stream}/records");
    let mut clock = kernoid_log::Clock::new("mallory3".parse().unwrap());
    let event = kernoid_log::Event::new(clock.now(1_800_000_000_000), 1, None, &json!({"kind": "note"})).unwrap();
    let unreadable = StreamRecord::event(&writer, &space_stream, 0, &StreamKey::generate(), &event);
    assert_eq!(
        mallory.send("POST", &records(&space_stream), Some(&space_write), Some(to_root(&unreadable).unwrap())),
        201
    );
    let bobs = StreamId::of_person(D, &space, &bob_person);
    let bob_key = roster.person_key(&bob_person).unwrap().clone();
    let own = StreamKey::generate();
    for (stream, generation, key) in [
        (space_stream.clone(), 1, own.0.to_vec()),
        (folder.clone(), 5, own.0.to_vec()),
        (StreamId::generate(), 0, own.0.to_vec()),
        (StreamId::generate(), 0, vec![1; 7]),
    ] {
        let link = LinkBody { stream, generation, key: Bytes(key) };
        let sealed = StreamRecord::sealed_link(&writer, &bobs, &bob_key, &link).unwrap();
        assert_eq!(mallory.send("POST", &records(&bobs), None, Some(to_root(&sealed).unwrap())), 201);
    }
    // Bob passes them over, and reads and writes as before.
    let report = bob.sync(&space).unwrap();
    assert_eq!(report.refused, 5, "{report:?}");
    // Each of Mallory's links says it is her first record there: Bob sees that they are not a chain.
    assert_eq!(report.missing, 3, "{report:?}");
    assert_eq!(bob.streams(&space).unwrap().len(), bob_phone.streams(&space).unwrap().len(), "no stream of Mallory's");
    bob.write(&space, &folder, &json!({"kind": "note", "title": "Bob still writes"})).unwrap();
    bob.write(&space, &space_stream, &json!({"kind": "note", "title": "Here too"})).unwrap();
    let report = laptop.sync(&space).unwrap();
    assert_eq!((report.refused, report.missing), (1, 0), "{report:?}");
    assert_eq!(titles(&laptop, &space, &folder), ["Minutes", "Bob still writes"]);

    // A generation of the space stream that opens for nobody, registered at the relay as the roster's.
    let broken =
        |person: &PersonId| PersonLink { person: person.clone(), person_generation: 0, sealed: Bytes(vec![7; 1300]) };
    let links = roster.persons().map(|person| broken(&person.id)).collect();
    let record = roster.next(RosterRecord {
        space_links: Some(SpaceLinks {
            generation: 1,
            read: Some(own.read_hash(D, &space_stream, 1)),
            links,
            previous: Some(Bytes(vec![9; 72])),
            previous_generation: None,
        }),
        ..RosterRecord::blank(&space)
    });
    let roster_path = format!("/v2/spaces/{space}/roster");
    assert_eq!(mallory.send("POST", &roster_path, None, Some(to_root(&record.sign(&mallory.keys)).unwrap())), 201);
    let hash = |which| Bytes(token_hash(&own.token(D, which, &space_stream, 1)).0.to_vec());
    let tokens =
        serde_json::to_vec(&json!({"generation": 1, "read": hash(Token::Read), "write": hash(Token::Write)})).unwrap();
    let generations = format!("/v2/spaces/{space}/streams/{space_stream}/generations");
    assert_eq!(mallory.send("POST", &generations, None, Some(tokens)), 201);
    // Everyone keeps what they had; whoever writes next makes a generation that opens, past the broken one.
    bob.sync(&space).unwrap();
    assert_eq!(titles(&bob, &space, &space_stream), ["Welcome", "Here too"]);
    laptop.sync(&space).unwrap();
    laptop.write(&space, &space_stream, &json!({"kind": "note", "title": "Past it"})).unwrap();
    assert_eq!(laptop.roster(&space).unwrap().space_generation(), Some(2));
    for streams in [&mut bob, &mut bob_phone] {
        streams.sync(&space).unwrap();
        assert_eq!(titles(streams, &space, &space_stream), ["Welcome", "Here too", "Past it"]);
    }
    bob.write(&space, &space_stream, &json!({"kind": "note", "title": "And on"})).unwrap();

    // Alice removes Bob's phone and so makes Bob's next key; his tablet moves on to one of its own, and what is shown
    // to Bob after that goes to it.
    laptop.remove_person(&space, &mallory_person).unwrap();
    let phone_id = bob_phone.device_id(&space).unwrap();
    assert!(laptop.roster(&space).unwrap().added_by(&bob.device_id(&space).unwrap()).contains(&phone_id));
    laptop.remove_device(&space, &phone_id).unwrap();
    assert!(bob_phone.sync(&space).is_err());
    bob.sync(&space).unwrap();
    let roster = bob.roster(&space).unwrap();
    let key = roster.person_key(&bob_person).unwrap();
    assert_eq!(key.generation, 2);
    assert_eq!(roster.person_key_author(&bob_person, 1).unwrap().person, alice);
    assert_eq!(roster.person_key_author(&bob_person, 2).unwrap().person, bob_person);
    let private = laptop.new_stream(&space, &Parent::Person(alice.clone())).unwrap();
    laptop.write(&space, &private, &json!({"kind": "note", "title": "For Bob"})).unwrap();
    laptop.sync(&space).unwrap();
    laptop.share(&space, &private, &bob_person).unwrap();
    bob.sync(&space).unwrap();
    assert_eq!(titles(&bob, &space, &private), ["For Bob"]);
    assert_eq!(titles(&bob, &space, &space_stream), ["Welcome", "Here too", "Past it", "And on"]);
}
