// SPDX-License-Identifier: MIT
//! Spaces of streams through kernoid's relay, end to end (RFC 0012; `scripts/client-check.sh` names the relay in
//! `KERNOID_TEST_RELAY`). Alice founds a space and adds her phone; Bob joins as a new person; a folder for everyone, a
//! document for Alice alone, an original in parts; Carol added with a recovery code; Bob is removed and what is written after is out of his reach;
//! Alice's devices are lost and the recovery code brings her back. Without `KERNOID_TEST_RELAY` it does nothing.

use kernoid_crypt::{Domain, stream::StreamId};
use kernoid_spaces::store::{Store, streams::Parent};
use kernoid_spaces::streams::Streams;
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
