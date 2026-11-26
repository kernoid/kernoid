// SPDX-License-Identifier: MIT
//! Streams (RFC 0012): the roster, the keys of persons and of the space stream, records and requests.

use kernoid_base::SpaceId;
use kernoid_crypt::{
    Domain, EncryptionError,
    pq::HybridKeys,
    stream::{
        Device, Joining, LinkBody, Permission, Person, PersonId, RecordKind, Roster, RosterProblem, RosterRecord,
        StreamId, StreamKey, StreamRecord, Token, Writer, link_to_person, new_space_generation, person_key,
        request_signature, verify_request,
    },
};
use kernoid_log::{Clock, DeviceId, Event};

const D: Domain = Domain::KERNOID;

struct Founded {
    space: SpaceId,
    roster: Roster,
    phone: HybridKeys,
    alice: PersonId,
    alice_seed: [u8; 32],
    space_key: StreamKey,
}

fn device(name: &str) -> DeviceId {
    name.parse().unwrap()
}

/// Alice founds a space with her phone.
fn found() -> Founded {
    let space = SpaceId::generate(1_800_000_000_000);
    let phone = HybridKeys::generate(D);
    let alice = PersonId::generate();
    let alice_seed = kernoid_base::random::<32>();
    let phone_device = Device::new(&phone, alice.clone(), device("alice-phone"), Some("Phone".into())).with(&[
        Permission::Write,
        Permission::Members,
        Permission::Purge,
    ]);
    let key = person_key(D, &space, &alice, 0, &alice_seed, None, &[&phone_device]).unwrap();
    let space_stream = StreamId::generate();
    let space_key = StreamKey::generate();
    let link = link_to_person(D, &space_stream, 0, &space_key, &key).unwrap();
    let record = RosterRecord {
        space_stream: Some(space_stream),
        add_persons: vec![Person { id: alice.clone(), name: Some("Alice".into()) }],
        add_devices: vec![phone_device],
        person_keys: vec![key],
        space_links: Some(kernoid_crypt::stream::SpaceLinks { generation: 0, links: vec![link], previous: None }),
        ..RosterRecord::blank(&space)
    }
    .sign(&phone);
    let mut roster = Roster::new(D, space.clone());
    roster.apply(record).unwrap();
    Founded { space, roster, phone, alice, alice_seed, space_key }
}

#[test]
fn identities_have_their_form() {
    let stream = StreamId::generate();
    assert!(stream.as_str().starts_with("s-") && stream.as_str().len() == 28);
    assert_eq!(stream.as_str().parse::<StreamId>().unwrap(), stream);
    assert!("s-0123".parse::<StreamId>().is_err());
    assert!(PersonId::generate().as_str().parse::<StreamId>().is_err());
}

#[test]
fn the_founder_reads_the_space_stream() {
    let f = found();
    assert_eq!(f.roster.person_seeds(&f.phone).unwrap()[&0], f.alice_seed);
    assert_eq!(f.roster.space_keys(&f.phone).unwrap()[&0], f.space_key);
    // Someone else's record 0 for the same space does not follow.
    let other = HybridKeys::generate(D);
    assert_eq!(f.roster.clone().apply(RosterRecord::blank(&f.space).sign(&other)).unwrap_err(), RosterProblem::NotNext);
}

#[test]
fn a_new_person_joins_and_a_lost_device_takes_its_persons_key_along() {
    let mut f = found();
    // Bob's laptop brings Bob's first key; Alice's phone adds both and links the space stream to Bob.
    let secret: [u8; 16] = kernoid_base::random();
    let laptop = HybridKeys::generate(D);
    let bob = PersonId::generate();
    let bob_seed = kernoid_base::random::<32>();
    let laptop_device = Device::new(&laptop, bob.clone(), device("bob-laptop"), None).with(&[Permission::Write]);
    let bob_key = person_key(D, &f.space, &bob, 0, &bob_seed, None, &[&laptop_device]).unwrap();
    let joining =
        Joining::new(&secret, laptop_device.clone(), Some((Person { id: bob.clone(), name: None }, bob_key.clone())));
    assert!(joining.proves(&secret));
    assert!(!joining.proves(&[0; 16]));
    let link = link_to_person(D, f.roster.space_stream().unwrap(), 0, &f.space_key, &bob_key).unwrap();
    let record = f.roster.next(RosterRecord {
        add_persons: vec![Person { id: bob.clone(), name: None }],
        add_devices: vec![laptop_device.clone()],
        person_keys: vec![bob_key.clone()],
        space_links: Some(kernoid_crypt::stream::SpaceLinks { generation: 0, links: vec![link], previous: None }),
        ..RosterRecord::blank(&f.space)
    });
    // Without the link to Bob, the record is refused.
    let without = RosterRecord { space_links: None, ..record.clone() }.sign(&f.phone);
    assert!(matches!(f.roster.clone().apply(without), Err(RosterProblem::SpaceLink(_))));
    // Bob's laptop may not add persons.
    assert!(matches!(f.roster.clone().apply(record.clone().sign(&laptop)), Err(RosterProblem::NotAllowed(_))));
    f.roster.apply(record.sign(&f.phone)).unwrap();
    assert_eq!(f.roster.space_keys(&laptop).unwrap()[&0], f.space_key);

    // Bob adds his tablet himself – a device of his own person.
    let tablet = HybridKeys::generate(D);
    let tablet_device = Device::new(&tablet, bob.clone(), device("bob-tablet"), None).with(&[Permission::Write]);
    let seals = person_key(D, &f.space, &bob, 0, &bob_seed, None, &[&tablet_device]).unwrap();
    let record = f.roster.next(RosterRecord {
        add_devices: vec![tablet_device.clone()],
        person_keys: vec![kernoid_crypt::stream::PersonKey { previous: None, ..seals }],
        ..RosterRecord::blank(&f.space)
    });
    // He may not give it permissions he lacks.
    let more = RosterRecord { add_devices: vec![tablet_device.clone().with(&[Permission::Members])], ..record.clone() }
        .sign(&laptop);
    assert!(matches!(f.roster.clone().apply(more), Err(RosterProblem::NotAllowed(_))));
    f.roster.apply(record.sign(&laptop)).unwrap();
    assert_eq!(f.roster.space_keys(&tablet).unwrap()[&0], f.space_key);

    // The laptop is lost: removing it needs a new generation of Bob's key for the tablet alone.
    let removal =
        f.roster.next(RosterRecord { remove_devices: vec![laptop_device.id], ..RosterRecord::blank(&f.space) });
    assert!(matches!(f.roster.clone().apply(removal.clone().sign(&f.phone)), Err(RosterProblem::PersonKey(_))));
    let new_seed = kernoid_base::random::<32>();
    let new_key = person_key(D, &f.space, &bob, 1, &new_seed, Some(&bob_seed), &[&tablet_device]).unwrap();
    f.roster.apply(RosterRecord { person_keys: vec![new_key], ..removal }.sign(&f.phone)).unwrap();
    let seeds = f.roster.person_seeds(&tablet).unwrap();
    assert_eq!((seeds[&0], seeds[&1]), (bob_seed, new_seed));
    assert!(f.roster.person_seeds(&laptop).is_err());

    // A new generation of the space stream, due since then, for the persons left.
    let next = StreamKey::generate();
    let links = new_space_generation(&f.roster, &next, Some(&f.space_key)).unwrap();
    let record = f.roster.next(RosterRecord { space_links: Some(links), ..RosterRecord::blank(&f.space) });
    f.roster.apply(record.sign(&tablet)).unwrap();
    let keys = f.roster.space_keys(&tablet).unwrap();
    assert_eq!((keys[&0].clone(), keys[&1].clone()), (f.space_key.clone(), next));
    assert_eq!(f.roster.space_keys(&f.phone).unwrap().len(), 2);
    let _ = f.alice;
}

#[test]
fn records_open_with_their_generation_and_links_lead_down() {
    let f = found();
    let space_stream = f.roster.space_stream().unwrap().clone();
    let writer = Writer { domain: D, space: &f.space, keys: &f.phone, at: 0 };
    let phone = f.roster.device(&f.phone.verifying().id()).unwrap().clone();

    // An event in the space stream.
    let mut clock = Clock::new(device("alice-phone"));
    let event = Event::new(clock.now(1_800_000_000_000), 1, None, &serde_json::json!({"kind": "hello"})).unwrap();
    let record = StreamRecord::event(&writer, &space_stream, 0, &f.space_key, &event);
    assert!(record.is_authentic(D, &phone));
    assert_eq!(record.open_event(&f.space_key, &f.roster).unwrap(), event.to_canonical().unwrap());
    assert_eq!(record.open(&StreamKey::generate()).unwrap_err(), EncryptionError::Decrypt);
    let mut moved = record.clone();
    moved.stream = StreamId::generate();
    assert!(moved.open(&f.space_key).is_err());
    assert!(!moved.is_authentic(D, &phone));

    // A folder below the space stream, and a document only Alice sees, sealed into her person stream.
    let folder = StreamId::generate();
    let folder_key = StreamKey::generate();
    let body = LinkBody { stream: folder.clone(), generation: 0, key: kernoid_base::Bytes(folder_key.0.to_vec()) };
    let link = StreamRecord::link(&writer, &space_stream, 0, &f.space_key, &body);
    assert_eq!(link.open_link(&f.space_key).unwrap(), body);
    let person_stream = StreamId::generate();
    let alice_key = f.roster.person_key(&f.alice).unwrap().clone();
    let sealed = StreamRecord::sealed_link(&writer, &person_stream, &alice_key, &body).unwrap();
    assert_eq!(sealed.kind, RecordKind::Sealed);
    assert!(sealed.is_authentic(D, &phone));
    let alice = HybridKeys::from_seed(D, f.alice_seed);
    assert_eq!(sealed.open_sealed(&alice).unwrap(), body);
    assert!(sealed.open_sealed(&HybridKeys::generate(D)).is_err());

    // A new generation of the folder chains back to the old key.
    let next = StreamKey::generate();
    let generation = StreamRecord::generation(&writer, &folder, 1, &next, &folder_key);
    assert_eq!(generation.open_generation(&next).unwrap(), folder_key);

    // Tokens differ by kind, stream and generation.
    let read = folder_key.token(D, Token::Read, &folder, 0);
    assert_ne!(read, folder_key.token(D, Token::Write, &folder, 0));
    assert_ne!(read, folder_key.token(D, Token::Read, &folder, 1));
    assert_ne!(read, folder_key.token(D, Token::Read, &space_stream, 0));

    // Originals.
    let sealed = folder_key.seal_original(D, &folder, b"%PDF");
    assert_eq!(folder_key.open_original(D, &folder, &sealed).unwrap(), b"%PDF");
    assert!(folder_key.open_original(D, &space_stream, &sealed).is_err());
}

#[test]
fn requests_are_signed_by_a_device_of_the_roster() {
    let f = found();
    let header = request_signature(D, &f.phone, "GET", "/relay/kernoid/v2/spaces/x/members", 1_800_000_000);
    let device =
        verify_request(&f.roster, &header, "GET", "/relay/kernoid/v2/spaces/x/members", 1_800_000_100).unwrap();
    assert_eq!(device.id, f.phone.verifying().id());
    assert!(verify_request(&f.roster, &header, "POST", "/relay/kernoid/v2/spaces/x/members", 1_800_000_100).is_none());
    assert!(verify_request(&f.roster, &header, "GET", "/relay/kernoid/v2/spaces/x/members", 1_800_001_000).is_none());
    let stranger = HybridKeys::generate(D);
    let header = request_signature(D, &stranger, "GET", "/x", 1_800_000_000);
    assert!(verify_request(&f.roster, &header, "GET", "/x", 1_800_000_000).is_none());
}

/// Bob joins Alice's space as a person of his own, with `write` only; his laptop's keys.
fn with_bob(f: &mut Founded) -> (HybridKeys, PersonId) {
    let laptop = HybridKeys::generate(D);
    let bob = PersonId::generate();
    let bob_seed = kernoid_base::random::<32>();
    let laptop_device = Device::new(&laptop, bob.clone(), device("bob-laptop"), None).with(&[Permission::Write]);
    let bob_key = person_key(D, &f.space, &bob, 0, &bob_seed, None, &[&laptop_device]).unwrap();
    let link = link_to_person(D, f.roster.space_stream().unwrap(), 0, &f.space_key, &bob_key).unwrap();
    let record = f.roster.next(RosterRecord {
        add_persons: vec![Person { id: bob.clone(), name: None }],
        add_devices: vec![laptop_device],
        person_keys: vec![bob_key],
        space_links: Some(kernoid_crypt::stream::SpaceLinks { generation: 0, links: vec![link], previous: None }),
        ..RosterRecord::blank(&f.space)
    });
    f.roster.apply(record.sign(&f.phone)).unwrap();
    (laptop, bob)
}

#[test]
fn nobody_writes_another_persons_key_seals_or_links() {
    let mut f = found();
    let (laptop, _bob) = with_bob(&mut f);
    let phone_device = f.roster.device(&f.phone.verifying().id()).cloned().unwrap();
    let alice_key = f.roster.person_key(&f.alice).cloned().unwrap();

    // Bob's laptop rotates Alice's key to a seed it chose: refused – it would read what is sealed to her from then on.
    let chosen = kernoid_base::random::<32>();
    let rotation = person_key(D, &f.space, &f.alice, 1, &chosen, None, &[&phone_device]).unwrap();
    let record = f.roster.next(RosterRecord { person_keys: vec![rotation], ..RosterRecord::blank(&f.space) });
    assert_eq!(
        f.roster.clone().apply(record.sign(&laptop)).unwrap_err(),
        RosterProblem::NotAllowed("the key of another person")
    );

    // Nor may it replace the seal of Alice's phone in her current generation – which would lock the phone out.
    let garbage = kernoid_crypt::stream::PersonKey {
        receiving: alice_key.receiving.clone(),
        ..person_key(D, &f.space, &f.alice, 0, &chosen, None, &[&phone_device]).unwrap()
    };
    let record = f.roster.next(RosterRecord { person_keys: vec![garbage.clone()], ..RosterRecord::blank(&f.space) });
    assert!(matches!(f.roster.clone().apply(record.clone().sign(&laptop)), Err(RosterProblem::NotAllowed(_))));
    // Alice's own phone may not either: a seal stays as it was written.
    assert!(matches!(f.roster.clone().apply(record.sign(&f.phone)), Err(RosterProblem::Duplicate(_))));

    // Nor may it link the current generation of the space stream to Alice again, with a key of its own.
    let link = link_to_person(D, f.roster.space_stream().unwrap(), 0, &StreamKey::generate(), &alice_key).unwrap();
    let record = f.roster.next(RosterRecord {
        space_links: Some(kernoid_crypt::stream::SpaceLinks { generation: 0, links: vec![link], previous: None }),
        ..RosterRecord::blank(&f.space)
    });
    assert!(matches!(f.roster.clone().apply(record.clone().sign(&laptop)), Err(RosterProblem::NotAllowed(_))));
    assert!(matches!(f.roster.clone().apply(record.sign(&f.phone)), Err(RosterProblem::NotAllowed(_))));
    assert_eq!(f.roster.space_keys(&f.phone).unwrap()[&0], f.space_key);

    // A key whose receiving key is not its seed's: the roster takes it from Alice's own device, but her devices do not
    // use it – links to it would go to whoever holds the other key.
    let other = HybridKeys::generate(D);
    let mismatch = kernoid_crypt::stream::PersonKey {
        receiving: kernoid_base::Bytes(other.receiving().0.clone()),
        ..person_key(D, &f.space, &f.alice, 1, &chosen, Some(&f.alice_seed), &[&phone_device]).unwrap()
    };
    let record = f.roster.next(RosterRecord { person_keys: vec![mismatch], ..RosterRecord::blank(&f.space) });
    f.roster.apply(record.sign(&f.phone)).unwrap();
    assert!(matches!(f.roster.person_seeds(&f.phone), Err(EncryptionError::Decrypt)));
}
