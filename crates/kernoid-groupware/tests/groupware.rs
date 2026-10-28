// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendars and contacts against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use chrono::{TimeZone, Utc};
use kernoid_events::EventStore;
use kernoid_groupware::{CalendarUpdate, Expect, Groupware, GroupwareError, NewAddressBook, NewCalendar, ObjectType};
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_mail::{Limits, Mail};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use sqlx::PgPool;
use uuid::Uuid;

const WHO: &str = "operator";

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

struct Setup {
    identity: Identity,
    groupware: Groupware,
    tenant: Uuid,
}

async fn setup(pool: PgPool) -> Setup {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let domain = DomainName::parse("firma.example").unwrap();
    let token = identity.add_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    let dns = FakeDns::default();
    dns.0
        .lock()
        .unwrap()
        .insert(format!("{CHALLENGE_LABEL}.firma.example"), vec![format!("kernoid-verification={token}")]);
    identity.verify_tenant_domain(instance, tenant, &domain, &dns, WHO).await.unwrap();
    let keys = Arc::new(TenantKeys::with_main_keys(pool.clone(), MainKeys::new(Key::random().unwrap(), Vec::new())));
    let blobs = BlobStore::new(Arc::new(InMemory::new()), keys.clone());
    let mail = Mail::new(pool, blobs, Limits::default());
    Setup { identity, groupware: Groupware::new(mail, keys), tenant }
}

impl Setup {
    async fn account(&self, local: &str) -> Uuid {
        let address = Address::parse(&format!("{local}@firma.example")).unwrap();
        self.identity.add_account(self.tenant, &address, local, WHO).await.unwrap()
    }
}

fn event(uid: &str, start: &str, rule: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20261001T080000Z\r\n\
         DTSTART:{start}\r\nDURATION:PT1H\r\n{rule}SUMMARY:{summary}\r\nORGANIZER:mailto:alice@firma.example\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

fn card(uid: &str, name: &str, email: &str) -> String {
    format!("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:{uid}\r\nFN:{name}\r\nEMAIL:{email}\r\nEND:VCARD\r\n")
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_first_use_creates_a_default_calendar_and_address_book(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let groupware = &setup.groupware;

    let calendars = groupware.calendars(alice).await.unwrap();
    assert_eq!(calendars.len(), 1);
    assert_eq!(calendars[0].name, "Calendar");
    assert!(calendars[0].is_default);
    assert_eq!(calendars[0].components, ["VEVENT", "VTODO"]);
    let books = groupware.addressbooks(alice).await.unwrap();
    assert_eq!(books.len(), 1);
    assert!(books[0].is_default);

    // The default cannot go; another can be made the default instead.
    let default = calendars[0].id;
    assert!(matches!(groupware.destroy_calendar(alice, default, true).await, Err(GroupwareError::IsDefault)));
    let work = groupware
        .create_calendar(
            alice,
            NewCalendar { name: "Work".into(), timezone: Some("Europe/Berlin".into()), ..NewCalendar::default() },
        )
        .await
        .unwrap();
    groupware
        .update_calendar(alice, work, CalendarUpdate { is_default: Some(true), ..CalendarUpdate::default() })
        .await
        .unwrap();
    assert_eq!(groupware.default_calendar(alice).await.unwrap().id, work);
    groupware.destroy_calendar(alice, default, false).await.unwrap();
    assert!(
        groupware
            .create_calendar(
                alice,
                NewCalendar { timezone: Some("Mars/Base".into()), name: "X".into(), ..NewCalendar::default() }
            )
            .await
            .is_err()
    );
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn events_are_stored_sealed_found_by_time_and_synced(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let alice = setup.account("alice").await;
    let groupware = &setup.groupware;
    let calendar = groupware.default_calendar(alice).await.unwrap().id;
    let start_state = groupware.state(alice).await.unwrap();

    let weekly = event("weekly@firma", "20261005T090000Z", "RRULE:FREQ=WEEKLY\r\n", "Weekly");
    let written = groupware.put_event(alice, calendar, "weekly.ics", &weekly, Expect::New).await.unwrap();
    assert!(written.created);
    assert!(written.event.organized);
    let once = event("once@firma", "20261102T140000Z", "", "Once");
    let once = groupware.put_event(alice, calendar, "once.ics", &once, Expect::Any).await.unwrap().event;

    // The content is sealed in the database, and comes back as written.
    let sealed = sqlx::query_scalar!("SELECT data FROM calendar_events WHERE id = $1", written.event.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("Weekly"));
    let data = groupware.event_data(alice, &[written.event.id]).await.unwrap();
    assert_eq!(data[0].1, weekly);

    // Time ranges: an endless recurrence meets every later window; a single event only its own.
    let window = |from: (u32, u32), to: (u32, u32)| {
        (
            Some(Utc.with_ymd_and_hms(2026, from.0, from.1, 0, 0, 0).unwrap()),
            Some(Utc.with_ymd_and_hms(2026, to.0, to.1, 0, 0, 0).unwrap()),
        )
    };
    let (from, to) = window((12, 1), (12, 31));
    let found = groupware.events_between(alice, Some(calendar), from, to).await.unwrap();
    assert_eq!(found.iter().map(|e| e.uid.as_str()).collect::<Vec<_>>(), ["weekly@firma"]);
    let (from, to) = window((11, 2), (11, 3));
    assert_eq!(groupware.events_between(alice, None, from, to).await.unwrap().len(), 2);
    let (from, to) = window((9, 1), (9, 30));
    assert!(groupware.events_between(alice, None, from, to).await.unwrap().is_empty());

    // Preconditions and UIDs.
    let again = event("weekly@firma", "20261005T090000Z", "", "Weekly");
    assert!(matches!(
        groupware.put_event(alice, calendar, "weekly.ics", &again, Expect::New).await,
        Err(GroupwareError::PreconditionFailed)
    ));
    assert!(matches!(
        groupware.put_event(alice, calendar, "copy.ics", &again, Expect::Any).await,
        Err(GroupwareError::UidConflict(name)) if name == "weekly.ics"
    ));
    assert!(matches!(
        groupware.put_event(alice, calendar, "weekly.ics", &again, Expect::Version(written.event.modseq - 1)).await,
        Err(GroupwareError::PreconditionFailed)
    ));
    let replaced = groupware
        .put_event(alice, calendar, "weekly.ics", &again, Expect::Version(written.event.modseq))
        .await
        .unwrap();
    assert!(!replaced.created);
    assert!(replaced.event.modseq > written.event.modseq);

    // Sync: from the start everything, then only what changed – a move leaves one collection for another.
    let all = groupware.sync(alice, calendar, 0).await.unwrap();
    assert_eq!(all.changed.len(), 2);
    let other =
        groupware.create_calendar(alice, NewCalendar { name: "Other".into(), ..NewCalendar::default() }).await.unwrap();
    groupware.move_event(alice, once.id, other, Some("moved.ics")).await.unwrap();
    let since = groupware.sync(alice, calendar, all.token).await.unwrap();
    assert_eq!(since.removed, ["once.ics"]);
    assert!(since.changed.is_empty());
    assert_eq!(groupware.sync(alice, other, all.token).await.unwrap().changed, ["moved.ics"]);

    // JMAP's changes: the moved event is an update, the new calendar a creation.
    let changes = groupware.changes(alice, ObjectType::Event, start_state, None).await.unwrap();
    assert_eq!(changes.created.len(), 2);
    let changes = groupware.changes(alice, ObjectType::Event, all.token, None).await.unwrap();
    assert_eq!(changes.updated, [once.id]);
    assert_eq!(groupware.changes(alice, ObjectType::Calendar, all.token, None).await.unwrap().created, [other]);

    // Quota: what is stored counts, and destroying frees it.
    let used = || async { setup.groupware.mail().quota(alice).await.unwrap().0 };
    let before = used().await;
    groupware.destroy_event(alice, once.id, Expect::Any).await.unwrap();
    assert!(used().await < before);
    assert!(matches!(groupware.destroy_event(alice, once.id, Expect::Any).await, Err(GroupwareError::NotFound(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn contacts_are_found_by_address(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let groupware = &setup.groupware;
    let book = groupware.addressbooks(alice).await.unwrap()[0].id;

    let (bob, created) = groupware
        .put_contact(alice, book, "bob.vcf", &card("bob", "Bob", "Bob@Example.org"), Expect::New)
        .await
        .unwrap();
    assert!(created);
    assert_eq!(bob.emails, ["bob@example.org"]);
    let carol = groupware.create_contact(alice, book, &card("carol-1", "Carol", "carol@example.org")).await.unwrap();
    assert_eq!(carol.resource_name, "carol-1.vcf");
    assert!(matches!(
        groupware.create_contact(alice, book, &card("bob", "Bob 2", "b@example.org")).await,
        Err(GroupwareError::UidConflict(_))
    ));
    assert_eq!(groupware.contacts_by_email(alice, "BOB@example.org").await.unwrap()[0].id, bob.id);

    let private = groupware
        .create_addressbook(alice, NewAddressBook { name: "Private".into(), ..NewAddressBook::default() })
        .await
        .unwrap();
    groupware.move_contact(alice, carol.id, private, None).await.unwrap();
    assert_eq!(groupware.contacts(alice, Some(private)).await.unwrap().len(), 1);
    assert!(matches!(groupware.destroy_addressbook(alice, private, false).await, Err(GroupwareError::NotEmpty)));
    groupware.destroy_addressbook(alice, private, true).await.unwrap();
    assert_eq!(groupware.contacts(alice, None).await.unwrap().len(), 1);
    let data = groupware.contact_data(alice, &[bob.id]).await.unwrap();
    assert!(data[0].1.contains("FN:Bob"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn calendars_are_shared_by_level(pool: PgPool) {
    use kernoid_groupware::{CollectionType, Level};
    use kernoid_identity::role::Principal;
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let bob = setup.account("bob").await;
    let carol = setup.account("carol").await;
    let groupware = &setup.groupware;
    let identity = &setup.identity;
    let calendar = groupware.default_calendar(alice).await.unwrap().id;
    let book = groupware.addressbooks(alice).await.unwrap()[0].id;

    assert!(!groupware.access(bob, alice).await.unwrap().any());
    identity.share_collection(alice, alice, calendar, Principal::Account(bob), "rsvp").await.unwrap();
    let access = groupware.access(bob, alice).await.unwrap();
    assert_eq!(access.level(calendar), Some(Level::Rsvp));
    assert!(!access.allows(calendar, Level::Write));
    assert!(access.level(book).is_none());

    // Bob may not pass it on; with admin he may.
    assert!(identity.share_collection(bob, alice, calendar, Principal::Account(carol), "read").await.is_err());
    identity.share_collection(alice, alice, calendar, Principal::Account(bob), "admin").await.unwrap();
    identity.share_collection(bob, alice, calendar, Principal::Account(carol), "read").await.unwrap();
    assert_eq!(groupware.access(carol, alice).await.unwrap().level(calendar), Some(Level::Read));

    // Address books know no free/busy; unknown collections are refused.
    assert!(identity.share_collection(alice, alice, book, Principal::Account(bob), "freebusy").await.is_err());
    assert!(identity.share_collection(alice, alice, Uuid::now_v7(), Principal::Account(bob), "read").await.is_err());

    let shared = groupware.shared_with(carol).await.unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].collection_type, CollectionType::Calendar);
    assert_eq!(shared[0].owner, alice);

    identity.unshare_collection(alice, alice, calendar, Principal::Account(carol)).await.unwrap();
    assert!(!groupware.access(carol, alice).await.unwrap().any());
    assert_eq!(identity.collection_access(alice, None).await.unwrap().len(), 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn calendars_and_address_books_go_out_and_in(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let bob = setup.account("bob").await;
    let groupware = &setup.groupware;
    let calendar = groupware.default_calendar(alice).await.unwrap().id;
    let zone = "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\n\
                TZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n";
    for (uid, summary) in [("one", "One"), ("two", "Two")] {
        let object =
            event(uid, "20261105T090000Z", "", summary).replace("BEGIN:VEVENT", &format!("{zone}BEGIN:VEVENT"));
        groupware.create_event(alice, calendar, &object).await.unwrap();
    }
    let exported = groupware.export_calendar(alice, calendar).await.unwrap();
    assert_eq!(exported.matches("BEGIN:VTIMEZONE").count(), 1);
    assert_eq!(exported.matches("BEGIN:VEVENT").count(), 2);

    let target = groupware.default_calendar(bob).await.unwrap().id;
    let imported = groupware.import_calendar(bob, target, &exported).await.unwrap();
    assert_eq!(imported.stored, 2);
    assert_eq!(groupware.events(bob, target).await.unwrap().len(), 2);
    // Again: replaced, not doubled.
    assert_eq!(groupware.import_calendar(bob, target, &exported).await.unwrap().stored, 2);
    assert_eq!(groupware.events(bob, target).await.unwrap().len(), 2);

    let book = groupware.addressbooks(alice).await.unwrap()[0].id;
    let file =
        format!("{}BEGIN:VCARD\r\nVERSION:3.0\r\nFN:No Uid\r\nEND:VCARD\r\n", card("dave", "Dave", "dave@example.org"));
    let imported = groupware.import_addressbook(alice, book, &file).await.unwrap();
    assert_eq!(imported.stored, 2);
    let exported = groupware.export_addressbook(alice, book).await.unwrap();
    assert_eq!(exported.matches("BEGIN:VCARD").count(), 2);
    assert!(exported.contains("UID:urn:uuid:"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn invitations_travel_and_answers_come_back(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let alice = setup.account("alice").await;
    let bob = setup.account("bob").await;
    let groupware = &setup.groupware;
    let calendar = groupware.default_calendar(alice).await.unwrap().id;
    let meeting = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:meeting@firma\r\n\
        DTSTAMP:20261001T080000Z\r\nDTSTART:20261110T100000Z\r\nDURATION:PT1H\r\nSUMMARY:Planning\r\n\
        ORGANIZER;CN=Alice:mailto:alice@firma.example\r\n\
        ATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@firma.example\r\n\
        ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:bob@firma.example\r\n\
        ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:carol@remote.example\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";

    // Alice invites: Bob has it in his calendar and his inbox at once, Carol's goes into the queue.
    let scheduled =
        groupware.put_event_scheduled(alice, calendar, "meeting.ics", meeting, Expect::New).await.unwrap().unwrap();
    assert!(scheduled.changed);
    assert_eq!(scheduled.sent, 1);
    let bobs = groupware.events_by_uid(bob, "meeting@firma").await.unwrap();
    assert_eq!(bobs.len(), 1, "the invitation is in Bob's default calendar");
    let notes = groupware.notifications(bob).await.unwrap();
    assert_eq!(notes[0].changed_by, "alice@firma.example");
    let queued = setup.groupware.mail().queue(10).await.unwrap();
    assert_eq!(queued.iter().map(|q| q.address.as_str()).collect::<Vec<_>>(), ["carol@remote.example"]);
    let inbox = setup.groupware.mail().mailboxes(bob).await.unwrap();
    assert_eq!(inbox[0].total_emails, 1);

    // Bob accepts on his copy: Alice's event knows.
    let (_, copy) = groupware.event_data(bob, &[bobs[0].id]).await.unwrap().pop().unwrap();
    let accepted = copy.replace(
        "RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:bob@firma.example",
        "RSVP=TRUE;PARTSTAT=ACCEPTED:mailto:bob@firma.example",
    );
    assert_ne!(accepted, copy, "{copy}");
    let bob_calendar = bobs[0].calendar;
    groupware
        .put_event_scheduled(bob, bob_calendar, &bobs[0].resource_name, &accepted, Expect::Any)
        .await
        .unwrap()
        .unwrap();
    let alices = groupware.events_by_uid(alice, "meeting@firma").await.unwrap();
    let (_, organizer) = groupware.event_data(alice, &[alices[0].id]).await.unwrap().pop().unwrap();
    let unfolded = organizer.replace("\r\n ", "");
    assert!(unfolded.contains("PARTSTAT=ACCEPTED") && unfolded.contains("mailto:bob@firma.example"), "{unfolded}");
    let bob_line = unfolded.lines().find(|line| line.contains("mailto:bob@firma.example")).unwrap();
    assert!(bob_line.contains("ACCEPTED"), "{bob_line}");

    // Alice cancels: Bob's copy is cancelled.
    groupware.destroy_event_scheduled(alice, alices[0].id, Expect::Any).await.unwrap();
    let (_, cancelled) = groupware.event_data(bob, &[bobs[0].id]).await.unwrap().pop().unwrap();
    assert!(cancelled.contains("STATUS:CANCELLED"), "{cancelled}");
}
