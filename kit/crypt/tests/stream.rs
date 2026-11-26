// SPDX-License-Identifier: MIT
//! Streams (RFC 0012): the roster, the keys of persons and of the space stream, records and requests.

use kernoid_base::SpaceId;
use kernoid_crypt::{
    Domain, EncryptionError,
    pq::HybridKeys,
    stream::{
        Device, Joining, LinkBody, Permission, Person, PersonId, RecordKind, Request, Roster, RosterProblem,
        RosterRecord, StreamId, StreamKey, StreamRecord, Token, Writer, link_to_person, new_space_generation,
        person_key, request_signature, verify_request,
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
    let link = link_to_person(D, &space, &space_stream, 0, &space_key, &key).unwrap();
    let record = RosterRecord {
        space_stream: Some(space_stream.clone()),
        add_persons: vec![Person { id: alice.clone(), name: Some("Alice".into()) }],
        add_devices: vec![phone_device],
        person_keys: vec![key],
        space_links: Some(kernoid_crypt::stream::SpaceLinks {
            generation: 0,
            read: Some(space_key.read_hash(D, &space_stream, 0)),
            links: vec![link],
            previous: None,
            previous_generation: None,
        }),
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
    let link = link_to_person(D, &f.space, f.roster.space_stream().unwrap(), 0, &f.space_key, &bob_key).unwrap();
    let record = f.roster.next(RosterRecord {
        add_persons: vec![Person { id: bob.clone(), name: None }],
        add_devices: vec![laptop_device.clone()],
        person_keys: vec![bob_key.clone()],
        space_links: Some(kernoid_crypt::stream::SpaceLinks {
            generation: 0,
            read: None,
            links: vec![link],
            previous: None,
            previous_generation: None,
        }),
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
    // Alice's phone cannot chain Bob's seed before; his tablet keeps the seal it had of it.
    let new_key = person_key(D, &f.space, &bob, 1, &new_seed, None, &[&tablet_device]).unwrap();
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
    let writer = Writer { domain: D, space: &f.space, keys: &f.phone, at: 0, previous: None };
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
    let path = "/relay/kernoid/v2/spaces/x/streams/y/records";
    let request = Request { method: "POST", path, body: b"{}", read: None, write: Some("token") };
    let header = request_signature(D, &f.phone, &request, 1_800_000_000);
    let device = verify_request(&f.roster, &header, &request, 1_800_000_100).unwrap();
    assert_eq!(device.id, f.phone.verifying().id());
    // Another method, time, body or token: not this request.
    assert!(verify_request(&f.roster, &header, &Request { method: "PUT", ..request }, 1_800_000_100).is_none());
    assert!(verify_request(&f.roster, &header, &request, 1_800_001_000).is_none());
    assert!(verify_request(&f.roster, &header, &Request { body: b"{ }", ..request }, 1_800_000_100).is_none());
    assert!(verify_request(&f.roster, &header, &Request { write: Some("other"), ..request }, 1_800_000_100).is_none());
    assert!(
        verify_request(&f.roster, &header, &Request { write: None, read: Some("token"), ..request }, 1_800_000_100)
            .is_none()
    );
    // The signature of protocol 2's first version – without the body and the tokens – is no longer one.
    assert!(verify_request(&f.roster, &header.replacen("-pq2 ", "-pq ", 1), &request, 1_800_000_100).is_none());
    let stranger = HybridKeys::generate(D);
    let header = request_signature(D, &stranger, &request, 1_800_000_000);
    assert!(verify_request(&f.roster, &header, &request, 1_800_000_000).is_none());
}

fn with_bob(f: &mut Founded) -> (HybridKeys, PersonId) {
    let laptop = HybridKeys::generate(D);
    let bob = PersonId::generate();
    let bob_seed = kernoid_base::random::<32>();
    let laptop_device = Device::new(&laptop, bob.clone(), device("bob-laptop"), None).with(&[Permission::Write]);
    let bob_key = person_key(D, &f.space, &bob, 0, &bob_seed, None, &[&laptop_device]).unwrap();
    let link = link_to_person(D, &f.space, f.roster.space_stream().unwrap(), 0, &f.space_key, &bob_key).unwrap();
    let record = f.roster.next(RosterRecord {
        add_persons: vec![Person { id: bob.clone(), name: None }],
        add_devices: vec![laptop_device],
        person_keys: vec![bob_key],
        space_links: Some(kernoid_crypt::stream::SpaceLinks {
            generation: 0,
            read: None,
            links: vec![link],
            previous: None,
            previous_generation: None,
        }),
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
        inbox_read: alice_key.inbox_read,
        inbox_write: alice_key.inbox_write,
        ..person_key(D, &f.space, &f.alice, 0, &chosen, None, &[&phone_device]).unwrap()
    };
    let record = f.roster.next(RosterRecord { person_keys: vec![garbage.clone()], ..RosterRecord::blank(&f.space) });
    assert!(matches!(f.roster.clone().apply(record.clone().sign(&laptop)), Err(RosterProblem::NotAllowed(_))));
    // Alice's own phone may not either: a seal stays as it was written.
    assert!(matches!(f.roster.clone().apply(record.sign(&f.phone)), Err(RosterProblem::Duplicate(_))));

    // Nor may it link the current generation of the space stream to Alice again, with a key of its own.
    let link =
        link_to_person(D, &f.space, f.roster.space_stream().unwrap(), 0, &StreamKey::generate(), &alice_key).unwrap();
    let record = f.roster.next(RosterRecord {
        space_links: Some(kernoid_crypt::stream::SpaceLinks {
            generation: 0,
            read: None,
            links: vec![link],
            previous: None,
            previous_generation: None,
        }),
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
    assert_eq!(f.roster.person_seeds(&f.phone).unwrap(), [(0, f.alice_seed)].into_iter().collect());
}

/// Bob joined with `write` alone; his laptop adds a tablet of his.
fn with_bobs_tablet(f: &mut Founded) -> (HybridKeys, HybridKeys, PersonId, [u8; 32]) {
    let laptop = HybridKeys::generate(D);
    let bob = PersonId::generate();
    let seed = kernoid_base::random::<32>();
    let laptop_device = Device::new(&laptop, bob.clone(), device("bob-laptop"), None).with(&[Permission::Write]);
    let key = person_key(D, &f.space, &bob, 0, &seed, None, &[&laptop_device]).unwrap();
    let link = link_to_person(D, &f.space, f.roster.space_stream().unwrap(), 0, &f.space_key, &key).unwrap();
    let record = f.roster.next(RosterRecord {
        add_persons: vec![Person { id: bob.clone(), name: None }],
        add_devices: vec![laptop_device],
        person_keys: vec![key],
        space_links: Some(kernoid_crypt::stream::SpaceLinks {
            generation: 0,
            read: None,
            links: vec![link],
            previous: None,
            previous_generation: None,
        }),
        ..RosterRecord::blank(&f.space)
    });
    f.roster.apply(record.sign(&f.phone)).unwrap();
    let tablet = HybridKeys::generate(D);
    let tablet_device = Device::new(&tablet, bob.clone(), device("bob-tablet"), None).with(&[Permission::Write]);
    let seals = person_key(D, &f.space, &bob, 0, &seed, None, &[&tablet_device]).unwrap();
    let record = f.roster.next(RosterRecord {
        add_devices: vec![tablet_device],
        person_keys: vec![seals],
        ..RosterRecord::blank(&f.space)
    });
    f.roster.apply(record.sign(&laptop)).unwrap();
    (laptop, tablet, bob, seed)
}

#[test]
fn a_generation_of_broken_links_costs_only_itself() {
    use kernoid_base::Bytes;
    use kernoid_crypt::stream::{PersonLink, SpaceLinks, new_space_generation_from};
    let mut f = found();
    let (laptop, _, bob, _) = with_bobs_tablet(&mut f);
    // Bob's laptop – `write` alone – makes a generation whose links and chain open nothing. The roster cannot tell.
    let broken =
        |person: &PersonId| PersonLink { person: person.clone(), person_generation: 0, sealed: Bytes(vec![7; 1300]) };
    let record = f.roster.next(RosterRecord {
        space_links: Some(SpaceLinks {
            generation: 1,
            read: Some(kernoid_base::Sha256Hash([5; 32])),
            links: vec![broken(&f.alice), broken(&bob)],
            previous: Some(Bytes(vec![9; 72])),
            previous_generation: None,
        }),
        ..RosterRecord::blank(&f.space)
    });
    f.roster.apply(record.sign(&laptop)).unwrap();
    // Everyone keeps what they had.
    let keys = f.roster.space_keys(&f.phone).unwrap();
    assert_eq!(keys.keys().copied().collect::<Vec<_>>(), [0]);
    assert_eq!(keys[&0], f.space_key);
    // Alice makes the next generation, chained to the newest she can open; it reads back past the broken one.
    let next = StreamKey::generate();
    let links = new_space_generation_from(&f.roster, &next, Some((0, &f.space_key))).unwrap();
    assert_eq!((links.generation, links.previous_generation), (2, Some(0)));
    let record = f.roster.next(RosterRecord { space_links: Some(links), ..RosterRecord::blank(&f.space) });
    f.roster.apply(record.sign(&f.phone)).unwrap();
    for keys in [&f.phone, &laptop] {
        let keys = f.roster.space_keys(keys).unwrap();
        assert_eq!(keys.keys().copied().collect::<Vec<_>>(), [0, 2]);
        assert_eq!((&keys[&0], &keys[&2]), (&f.space_key, &next));
    }
    assert_eq!(f.roster.space_generation_author(2), Some(f.phone.verifying().id()));
    // A chain that names no older generation is none.
    let links =
        SpaceLinks { previous_generation: Some(3), ..new_space_generation(&f.roster, &next, Some(&next)).unwrap() };
    let record = f.roster.next(RosterRecord { space_links: Some(links), ..RosterRecord::blank(&f.space) });
    assert!(matches!(f.roster.clone().apply(record.sign(&f.phone)), Err(RosterProblem::SpaceLink(_))));
}

#[test]
fn another_persons_device_chains_no_key_and_a_broken_chain_costs_only_what_is_behind_it() {
    use kernoid_base::Bytes;
    let mut f = found();
    let (laptop, tablet, bob, seed) = with_bobs_tablet(&mut f);
    let laptop_device = f.roster.device(&laptop.verifying().id()).unwrap().clone();
    let rotated = kernoid_base::random::<32>();
    // Alice (`members`) removes Bob's tablet and makes his next key: she cannot chain it, and may not pretend to.
    let mut key = person_key(D, &f.space, &bob, 1, &rotated, None, &[&laptop_device]).unwrap();
    key.previous = Some(Bytes(vec![1; 72]));
    let removal = |key| RosterRecord {
        remove_devices: vec![tablet.verifying().id()],
        person_keys: vec![key],
        ..RosterRecord::blank(&f.space)
    };
    let record = f.roster.next(removal(key.clone()));
    assert_eq!(
        f.roster.clone().apply(record.sign(&f.phone)),
        Err(RosterProblem::NotAllowed("the chain of another person's key"))
    );
    key.previous = None;
    let record = f.roster.next(removal(key));
    f.roster.apply(record.sign(&f.phone)).unwrap();
    assert_eq!(f.roster.person_key_author(&bob, 1).unwrap().person, f.alice);
    assert_eq!(f.roster.person_key_author(&bob, 0).unwrap().person, f.alice, "she added him with the key he brought");
    // Bob's laptop moves on to a seed of its own and chains hers – but breaks the chain: the newest seed still opens.
    let own = kernoid_base::random::<32>();
    let mut key = person_key(D, &f.space, &bob, 2, &own, Some(&rotated), &[&laptop_device]).unwrap();
    key.previous = Some(Bytes(vec![2; 72]));
    let record = f.roster.next(RosterRecord { person_keys: vec![key], ..RosterRecord::blank(&f.space) });
    f.roster.apply(record.sign(&laptop)).unwrap();
    let seeds = f.roster.person_seeds(&laptop).unwrap();
    // Generation 2 from its seal, 1 and 0 from the seals the laptop was given then.
    assert_eq!(seeds, [(0, seed), (1, rotated), (2, own)].into_iter().collect());
    assert!(f.roster.space_keys(&laptop).is_ok());
}

#[test]
fn a_record_is_its_authors_as_the_roster_was_where_it_says() {
    let mut f = found();
    let (laptop, tablet, bob, seed) = with_bobs_tablet(&mut f);
    let joined = f.roster.records().len() as u64 - 1;
    let laptop_device = f.roster.device(&laptop.verifying().id()).unwrap().clone();
    let rotated = kernoid_base::random::<32>();
    let key = person_key(D, &f.space, &bob, 1, &rotated, None, &[&laptop_device]).unwrap();
    let record = f.roster.next(RosterRecord {
        remove_devices: vec![tablet.verifying().id()],
        person_keys: vec![key],
        ..RosterRecord::blank(&f.space)
    });
    f.roster.apply(record.sign(&f.phone)).unwrap();
    let removed = f.roster.records().len() as u64 - 1;
    let id = tablet.verifying().id();
    assert!(f.roster.device_at(&id, joined - 1).is_none(), "not yet");
    assert_eq!(f.roster.device_at(&id, joined).unwrap().device, device("bob-tablet"));
    assert!(f.roster.device_at(&id, removed).is_none(), "no longer");
    assert!(f.roster.device_at(&id, removed + 1).is_none(), "a position the roster does not have");
    // What the tablet wrote while it was Bob's stays its; what it says it wrote after is nobody's.
    let mut clock = Clock::new(device("bob-tablet"));
    let event = Event::new(clock.now(1_800_000_000_000), 1, None, &serde_json::json!({"kind": "note"})).unwrap();
    let stream = f.roster.space_stream().unwrap().clone();
    let at = |at| Writer { domain: D, space: &f.space, keys: &tablet, at, previous: None };
    let before = StreamRecord::event(&at(joined), &stream, 0, &f.space_key, &event);
    assert!(before.open_event(&f.space_key, &f.roster).is_ok());
    let after = StreamRecord::event(&at(removed), &stream, 0, &f.space_key, &event);
    assert_eq!(after.open_event(&f.space_key, &f.roster), Err(EncryptionError::Signature));
    // The laptop added the tablet: it goes with a laptop that is removed.
    let _ = (bob, seed);
    let mut again = found();
    let (laptop, tablet, ..) = with_bobs_tablet(&mut again);
    assert_eq!(again.roster.added_by(&laptop.verifying().id()), [tablet.verifying().id()]);
    assert!(again.roster.added_by(&tablet.verifying().id()).is_empty());
}

#[test]
fn a_recovery_code_proves_the_roster_it_was_made_for() {
    use kernoid_crypt::stream::{proves_recovery, recovery_proof};
    let mut f = found();
    let code = kernoid_base::random::<32>();
    let recovery = HybridKeys::from_seed(D, code);
    let proof = recovery_proof(D, &code, &f.space, &f.roster.founding().unwrap());
    let recovery_device = Device::new(&recovery, f.alice.clone(), device("recovery-1"), None).with_proof(proof.clone());
    let seals = person_key(D, &f.space, &f.alice, 0, &f.alice_seed, None, &[&recovery_device]).unwrap();
    let record = f.roster.next(RosterRecord {
        add_devices: vec![recovery_device.clone()],
        person_keys: vec![seals],
        ..RosterRecord::blank(&f.space)
    });
    f.roster.apply(record.sign(&f.phone)).unwrap();
    assert!(proves_recovery(&f.roster, &code));
    assert!(!proves_recovery(&f.roster, &kernoid_base::random::<32>()));
    // A roster a relay makes up – its own founder, the code's device copied in with its proof – is not that roster.
    let mut forged = found();
    let forged_seed = forged.alice_seed;
    let copied = Device { person: forged.alice.clone(), ..recovery_device };
    let seals = person_key(D, &forged.space, &forged.alice, 0, &forged_seed, None, &[&copied]).unwrap();
    let record = forged.roster.next(RosterRecord {
        add_devices: vec![copied],
        person_keys: vec![seals],
        ..RosterRecord::blank(&forged.space)
    });
    forged.roster.apply(record.sign(&forged.phone)).unwrap();
    assert!(forged.roster.person_seeds(&recovery).is_ok(), "it opens what the relay sealed to it");
    assert!(!proves_recovery(&forged.roster, &code));
}
