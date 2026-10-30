// SPDX-License-Identifier: AGPL-3.0-or-later
//! The mail store against PostgreSQL, with object storage in memory; set `DATABASE_URL` as for the other crates'
//! tests.

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use bytes::Bytes;
use chrono::{Duration, Timelike, Utc};
use kernoid_events::EventStore;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_mail::{
    EmailQuery, Keyword, Limits, Mail, MailError, MailboxUpdate, NewEmail, NewMailbox, ObjectType, Role,
};
use kernoid_store::{BlobError, BlobStore, MainKeys, TenantKeys, crypto::Key, garbage};
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
    mail: Mail,
    blobs: BlobStore,
    tenant: Uuid,
}

async fn setup(pool: PgPool, limits: Limits) -> Setup {
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
    let blobs = BlobStore::new(Arc::new(InMemory::new()), keys);
    Setup { identity, mail: Mail::new(pool, blobs.clone(), limits), blobs, tenant }
}

impl Setup {
    async fn account(&self, local: &str) -> Uuid {
        let address = Address::parse(&format!("{local}@firma.example")).unwrap();
        self.identity.add_account(self.tenant, &address, local, WHO).await.unwrap()
    }
}

fn message(subject: &str, id: &str, in_reply_to: Option<&str>, body: &str) -> Bytes {
    let reply = in_reply_to.map(|parent| format!("In-Reply-To: <{parent}>\r\n")).unwrap_or_default();
    Bytes::from(format!(
        "From: Alice <alice@firma.example>\r\nTo: bob@firma.example\r\nSubject: {subject}\r\n\
         Date: Sat, 24 Oct 2026 10:00:00 +0200\r\nMessage-ID: <{id}>\r\n{reply}\r\n{body}\r\n"
    ))
}

fn keyword(value: &str) -> Keyword {
    Keyword::parse(value).unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_new_account_has_the_default_mailboxes_and_a_tree_of_its_own(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;

    let boxes = mail.mailboxes(alice).await.unwrap();
    let roles: Vec<_> = boxes.iter().filter_map(|mailbox| mailbox.role).collect();
    assert_eq!(roles, Role::ALL);
    assert_eq!(boxes[0].name, "Inbox");
    assert!(boxes.iter().all(|mailbox| mailbox.uid_next == 1 && mailbox.uid_validity != 0));

    let projects =
        mail.create_mailbox(alice, NewMailbox { name: "Projects".into(), ..NewMailbox::default() }).await.unwrap();
    let kernoid = mail
        .create_mailbox(
            alice,
            NewMailbox { name: "kernoid".into(), parent_id: Some(projects), ..NewMailbox::default() },
        )
        .await
        .unwrap();
    // Names are unique among siblings only.
    assert!(matches!(
        mail.create_mailbox(alice, NewMailbox { name: "Projects".into(), ..NewMailbox::default() }).await,
        Err(MailError::Exists(_))
    ));
    mail.create_mailbox(alice, NewMailbox { name: "Inbox".into(), parent_id: Some(projects), ..NewMailbox::default() })
        .await
        .unwrap();
    for refused in ["", "a/b", "tab\there", &"x".repeat(256)] {
        assert!(matches!(
            mail.create_mailbox(alice, NewMailbox { name: refused.into(), ..NewMailbox::default() }).await,
            Err(MailError::Invalid(_))
        ));
    }
    assert!(matches!(
        mail.create_mailbox(
            alice,
            NewMailbox { name: "Second".into(), role: Some(Role::Trash), ..NewMailbox::default() }
        )
        .await,
        Err(MailError::Exists(_))
    ));

    // Not below itself.
    assert!(matches!(
        mail.update_mailbox(
            alice,
            projects,
            MailboxUpdate { parent_id: Some(Some(kernoid)), ..MailboxUpdate::default() }
        )
        .await,
        Err(MailError::Invalid(_))
    ));
    mail.update_mailbox(
        alice,
        kernoid,
        MailboxUpdate { name: Some("Kernoid".into()), parent_id: Some(None), ..MailboxUpdate::default() },
    )
    .await
    .unwrap();
    let renamed = mail.mailboxes(alice).await.unwrap().into_iter().find(|mailbox| mailbox.id == kernoid).unwrap();
    assert_eq!((renamed.name.as_str(), renamed.parent_id), ("Kernoid", None));

    let inbox = mail.mailbox_with_role(alice, Role::Inbox).await.unwrap();
    assert!(matches!(mail.destroy_mailbox(alice, inbox, true).await, Err(MailError::Invalid(_))));
    assert!(matches!(mail.destroy_mailbox(alice, projects, true).await, Err(MailError::MailboxHasChild)));

    // Another account's mailboxes are not reachable.
    let bob = setup.account("bob").await;
    assert!(matches!(
        mail.create_mailbox(bob, NewMailbox { name: "x".into(), parent_id: Some(projects), ..NewMailbox::default() })
            .await,
        Err(MailError::NotFound(_))
    ));
    assert!(matches!(mail.destroy_mailbox(bob, kernoid, true).await, Err(MailError::NotFound(_))));
    assert!(matches!(mail.ensure_account(Uuid::now_v7()).await, Err(MailError::NotFound(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn emails_are_stored_sealed_threaded_and_counted(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    let inbox = mail.mailbox_with_role(alice, Role::Inbox).await.unwrap();
    let into_inbox = || NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() };

    let first_raw = message("Lunch", "a@firma.example", None, "Shall we meet at noon?");
    let first = mail.import_email(alice, first_raw.clone(), into_inbox()).await.unwrap();
    let reply = mail
        .import_email(alice, message("Re: Lunch", "b@firma.example", Some("a@firma.example"), "Yes"), into_inbox())
        .await
        .unwrap();
    // Same subject, no shared id; shared id, other subject: threads of their own.
    let unrelated =
        mail.import_email(alice, message("Lunch", "c@firma.example", None, "Another one"), into_inbox()).await.unwrap();
    let other_subject = mail
        .import_email(alice, message("Dinner", "d@firma.example", Some("a@firma.example"), "Later"), into_inbox())
        .await
        .unwrap();
    assert_eq!(reply.thread_id, first.thread_id);
    assert_ne!(unrelated.thread_id, first.thread_id);
    assert_ne!(other_subject.thread_id, first.thread_id);
    assert_eq!(mail.thread(alice, first.thread_id).await.unwrap(), [first.id, reply.id]);

    // Content is the message as received, and sealed in object storage under the tenant.
    assert_eq!(mail.raw_email(alice, first.id).await.unwrap(), first_raw);
    let stored = setup.blobs.get(setup.tenant, &format!("mail/{alice}/{}", first.id)).await.unwrap();
    assert_eq!(stored, first_raw);
    let info = mail.email(alice, first.id).await.unwrap();
    assert_eq!(info.subject.as_deref(), Some("Lunch"));
    assert_eq!(info.message_id.as_deref(), Some("a@firma.example"));
    assert_eq!(info.from[0].email, "alice@firma.example");
    assert_eq!(info.preview, "Shall we meet at noon?");
    assert_eq!(info.mailboxes, [(inbox, 1)]);
    assert_eq!(info.size, first_raw.len() as u64);
    // Nothing is left marked as garbage after an import.
    let marks = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM blob_garbage"#).fetch_one(&pool).await.unwrap();
    assert_eq!(marks, 0);

    let counts = |boxes: Vec<kernoid_mail::MailboxInfo>| {
        let inbox = boxes.into_iter().find(|mailbox| mailbox.role == Some(Role::Inbox)).unwrap();
        (inbox.total_emails, inbox.unread_emails, inbox.total_threads, inbox.unread_threads, inbox.uid_next)
    };
    assert_eq!(counts(mail.mailboxes(alice).await.unwrap()), (4, 4, 3, 3, 5));
    mail.update_keywords(alice, first.id, &[keyword("$Seen"), keyword("$flagged")], &[]).await.unwrap();
    assert_eq!(counts(mail.mailboxes(alice).await.unwrap()), (4, 3, 3, 3, 5));
    mail.update_keywords(alice, reply.id, &[keyword("$seen")], &[]).await.unwrap();
    assert_eq!(counts(mail.mailboxes(alice).await.unwrap()), (4, 2, 3, 2, 5));
    assert_eq!(mail.email(alice, first.id).await.unwrap().keywords, ["$flagged", "$seen"]);
    mail.set_keywords(alice, first.id, &[keyword("$seen")]).await.unwrap();
    assert_eq!(mail.email(alice, first.id).await.unwrap().keywords, ["$seen"]);
    for refused in ["", "two words", "a(b", "ü"] {
        assert!(matches!(Keyword::parse(refused), Err(MailError::Invalid(_))));
    }

    let (unseen, total) = mail
        .query(alice, &EmailQuery { not_keyword: Some(keyword("$seen")), ..EmailQuery::default() }, 0, 10)
        .await
        .unwrap();
    assert_eq!((unseen, total), (vec![other_subject.id, unrelated.id], 2));
    let (page, total) =
        mail.query(alice, &EmailQuery { in_mailbox: Some(inbox), ..EmailQuery::default() }, 1, 2).await.unwrap();
    assert_eq!((page, total), (vec![unrelated.id, reply.id], 4));
    let (beyond, total) = mail.query(alice, &EmailQuery::default(), 10, 2).await.unwrap();
    assert_eq!((beyond.len(), total), (0, 4));

    // Not a message at all; no mailbox; a mailbox of another account.
    assert!(matches!(mail.import_email(alice, Bytes::new(), into_inbox()).await, Err(MailError::Unparsable)));
    assert!(matches!(
        mail.import_email(alice, first_raw.clone(), NewEmail::default()).await,
        Err(MailError::Invalid(_))
    ));
    let bob = setup.account("bob").await;
    assert!(matches!(mail.import_email(bob, first_raw.clone(), into_inbox()).await, Err(MailError::NotFound(_))));
    assert!(matches!(mail.email(bob, first.id).await, Err(MailError::NotFound(_))));
    assert!(matches!(mail.raw_email(bob, first.id).await, Err(MailError::NotFound(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn moving_gives_new_uids_and_destroying_frees_the_space(pool: PgPool) {
    let setup = setup(pool.clone(), Limits { max_message_size: 1000, ..Limits::default() }).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    let inbox = mail.mailbox_with_role(alice, Role::Inbox).await.unwrap();
    let archive = mail.mailbox_with_role(alice, Role::Archive).await.unwrap();
    let raw = message("Hello", "h@firma.example", None, "Hi");
    let email = mail
        .import_email(alice, raw.clone(), NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() })
        .await
        .unwrap();

    mail.set_mailboxes(alice, email.id, &[archive]).await.unwrap();
    assert_eq!(mail.email(alice, email.id).await.unwrap().mailboxes, [(archive, 1)]);
    mail.set_mailboxes(alice, email.id, &[inbox, archive]).await.unwrap();
    let mut boxes = mail.email(alice, email.id).await.unwrap().mailboxes;
    boxes.sort_by_key(|(mailbox, _)| *mailbox == archive);
    assert_eq!(boxes, [(inbox, 2), (archive, 1)]);
    assert!(matches!(mail.set_mailboxes(alice, email.id, &[]).await, Err(MailError::Invalid(_))));

    // Size and quota.
    let large = Bytes::from(vec![b'a'; 1001]);
    assert!(matches!(
        mail.import_email(alice, large, NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() }).await,
        Err(MailError::TooLarge { limit: 1000 })
    ));
    assert_eq!(mail.quota(alice).await.unwrap(), (raw.len() as u64, None));
    setup.identity.set_mail_quota(alice, Some(raw.len() as u64 + 10), WHO).await.unwrap();
    assert!(matches!(
        mail.import_email(alice, raw.clone(), NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() }).await,
        Err(MailError::OverQuota)
    ));
    // A refused import leaves no object behind: only the mark, which the worker would collect.
    mail.destroy_email(alice, email.id).await.unwrap();
    assert_eq!(mail.quota(alice).await.unwrap(), (0, Some(raw.len() as u64 + 10)));
    assert!(matches!(mail.email(alice, email.id).await, Err(MailError::NotFound(_))));
    assert!(matches!(mail.thread(alice, email.thread_id).await, Err(MailError::NotFound(_))));
    // Its object is collected by the worker.
    assert_eq!(garbage::collect(&pool, &setup.blobs, 100).await.unwrap(), 1);
    assert!(matches!(mail.raw_email(alice, email.id).await, Err(MailError::NotFound(_))));
    assert!(matches!(
        setup.blobs.get(setup.tenant, &format!("mail/{alice}/{}", email.id)).await,
        Err(BlobError::NotFound)
    ));
    let again =
        mail.import_email(alice, raw, NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() }).await.unwrap();
    // UIDs only grow.
    assert_eq!(mail.email(alice, again.id).await.unwrap().mailboxes, [(inbox, 3)]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn destroying_a_mailbox_takes_the_emails_only_it_holds(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    let inbox = mail.mailbox_with_role(alice, Role::Inbox).await.unwrap();
    let old = mail.create_mailbox(alice, NewMailbox { name: "Old".into(), ..NewMailbox::default() }).await.unwrap();
    let only_old = mail
        .import_email(
            alice,
            message("One", "1@x", None, "1"),
            NewEmail { mailbox_ids: vec![old], ..NewEmail::default() },
        )
        .await
        .unwrap();
    let both = mail
        .import_email(
            alice,
            message("Two", "2@x", None, "2"),
            NewEmail { mailbox_ids: vec![old, inbox], ..NewEmail::default() },
        )
        .await
        .unwrap();
    assert!(matches!(mail.destroy_mailbox(alice, old, false).await, Err(MailError::MailboxHasEmail)));
    let state = mail.state(alice).await.unwrap();
    mail.destroy_mailbox(alice, old, true).await.unwrap();
    assert!(matches!(mail.email(alice, only_old.id).await, Err(MailError::NotFound(_))));
    assert_eq!(mail.email(alice, both.id).await.unwrap().mailboxes, [(inbox, 1)]);

    let boxes = mail.changes(alice, ObjectType::Mailbox, state, None).await.unwrap();
    // The inbox keeps its emails and counts: unchanged.
    assert_eq!((boxes.destroyed, boxes.updated), (vec![old], Vec::<Uuid>::new()));
    let emails = mail.changes(alice, ObjectType::Email, state, None).await.unwrap();
    assert_eq!((emails.destroyed, emails.updated), (vec![only_old.id], vec![both.id]));
    let threads = mail.changes(alice, ObjectType::Thread, state, None).await.unwrap();
    assert_eq!(threads.destroyed, [only_old.thread_id]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn changes_are_reported_from_a_state_on(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    let inbox = mail.mailbox_with_role(alice, Role::Inbox).await.unwrap();
    let into_inbox = || NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() };
    let start = mail.state(alice).await.unwrap();
    assert_eq!(start, 1, "creating the default mailboxes is the first change");

    let kept = mail.import_email(alice, message("A", "a@x", None, "a"), into_inbox()).await.unwrap();
    let gone = mail.import_email(alice, message("B", "b@x", None, "b"), into_inbox()).await.unwrap();
    let middle = mail.state(alice).await.unwrap();
    mail.update_keywords(alice, kept.id, &[keyword("$seen")], &[]).await.unwrap();
    mail.destroy_email(alice, gone.id).await.unwrap();
    let third = mail.import_email(alice, message("C", "c@x", None, "c"), into_inbox()).await.unwrap();

    // Created and destroyed in between: not reported; created and changed: created.
    let all = mail.changes(alice, ObjectType::Email, start, None).await.unwrap();
    assert_eq!((all.created.len(), all.updated.len(), all.destroyed.len()), (2, 0, 0));
    assert!(all.created.contains(&kept.id) && all.created.contains(&third.id));
    assert_eq!(all.new_state, mail.state(alice).await.unwrap());
    assert!(!all.has_more_changes);

    let later = mail.changes(alice, ObjectType::Email, middle, None).await.unwrap();
    assert_eq!((later.created, later.updated, later.destroyed), (vec![third.id], vec![kept.id], vec![gone.id]));

    // A few at a time.
    let first = mail.changes(alice, ObjectType::Email, start, Some(1)).await.unwrap();
    assert!(first.has_more_changes);
    assert_eq!(first.created, [kept.id]);
    let mut state = first.new_state;
    let mut rounds = 1;
    loop {
        let next = mail.changes(alice, ObjectType::Email, state, Some(1)).await.unwrap();
        state = next.new_state;
        rounds += 1;
        if !next.has_more_changes {
            break;
        }
    }
    assert_eq!(state, mail.state(alice).await.unwrap());
    assert!(rounds >= 3);

    // Unknown future states and pruned history cannot be brought up to date.
    assert!(matches!(mail.changes(alice, ObjectType::Email, 1000, None).await, Err(MailError::CannotCalculateChanges)));
    assert!(mail.prune_changes(Utc::now() + Duration::seconds(1), 1000).await.unwrap() > 0);
    assert!(matches!(
        mail.changes(alice, ObjectType::Email, start, None).await,
        Err(MailError::CannotCalculateChanges)
    ));
    let now = mail.state(alice).await.unwrap();
    assert_eq!(mail.changes(alice, ObjectType::Email, now, None).await.unwrap().created, Vec::<Uuid>::new());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn garbage_waits_for_its_time_and_can_be_taken_back(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let tenant = setup.tenant;
    setup.blobs.put(tenant, "mail/x/kept", Bytes::from_static(b"kept")).await.unwrap();
    setup.blobs.put(tenant, "mail/x/left", Bytes::from_static(b"left")).await.unwrap();
    garbage::pending(&pool, tenant, "mail/x/kept").await.unwrap();
    garbage::pending(&pool, tenant, "mail/x/left").await.unwrap();
    let mut connection = pool.acquire().await.unwrap();
    assert!(garbage::keep(&mut connection, tenant, "mail/x/kept").await.unwrap());
    assert!(!garbage::keep(&mut connection, tenant, "mail/x/kept").await.unwrap(), "taken back once");
    // Not due yet.
    assert_eq!(garbage::collect(&pool, &setup.blobs, 10).await.unwrap(), 0);
    garbage::mark(&mut connection, tenant, "mail/x/left", Utc::now() - Duration::seconds(1)).await.unwrap();
    assert_eq!(garbage::collect(&pool, &setup.blobs, 10).await.unwrap(), 1);
    assert!(setup.blobs.get(tenant, "mail/x/kept").await.is_ok());
    assert!(matches!(setup.blobs.get(tenant, "mail/x/left").await, Err(BlobError::NotFound)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn sieve_scripts_are_checked_and_one_is_active(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    assert!(matches!(mail.put_sieve_script(alice, "broken", "fileinto \"x\"", true).await, Err(MailError::Invalid(_))));
    mail.put_sieve_script(alice, "one", "keep;", true).await.unwrap();
    mail.put_sieve_script(alice, "two", "discard;", false).await.unwrap();
    let active = |scripts: Vec<kernoid_mail::SieveScript>| {
        scripts.into_iter().filter(|script| script.active).map(|script| script.name).collect::<Vec<_>>()
    };
    assert_eq!(active(mail.sieve_scripts(alice).await.unwrap()), ["one"]);
    mail.activate_sieve_script(alice, Some("two")).await.unwrap();
    assert_eq!(active(mail.sieve_scripts(alice).await.unwrap()), ["two"]);
    // Replacing a script keeps whether it is active.
    mail.put_sieve_script(alice, "two", "keep;", false).await.unwrap();
    assert_eq!(active(mail.sieve_scripts(alice).await.unwrap()), ["two"]);
    mail.activate_sieve_script(alice, None).await.unwrap();
    assert!(active(mail.sieve_scripts(alice).await.unwrap()).is_empty());
    assert!(matches!(mail.activate_sieve_script(alice, Some("three")).await, Err(MailError::NotFound(_))));
    mail.remove_sieve_script(alice, "one").await.unwrap();
    assert!(matches!(mail.remove_sieve_script(alice, "one").await, Err(MailError::NotFound(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn scripts_redirect_and_answer_through_the_queue(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    let incoming = |id: &str| {
        Bytes::from(format!(
            "From: carol@other.example\r\nTo: alice@firma.example\r\nSubject: Hello\r\nMessage-ID: <{id}@other.example>\r\n\r\nHi\r\n"
        ))
    };
    let delivery = kernoid_mail::Delivery { from: "carol@other.example", to: "alice+in@firma.example", junk: false };
    let queued = || async {
        sqlx::query!(
            "SELECT r.address, m.envelope_from FROM outbound_recipients r JOIN outbound_messages m ON m.id = r.message_id
             ORDER BY m.created_at, r.address"
        )
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.address, row.envelope_from))
        .collect::<Vec<_>>()
    };

    // A vacation reply goes once per sender within :days, from an empty envelope sender.
    mail.put_sieve_script(alice, "away", r#"require "vacation"; vacation :days 7 "Back on Monday.";"#, true)
        .await
        .unwrap();
    for id in ["v1", "v2"] {
        assert!(matches!(
            mail.deliver(alice, incoming(id), delivery).await.unwrap(),
            kernoid_mail::Delivered::Stored(_)
        ));
    }
    assert_eq!(queued().await, [("carol@other.example".to_owned(), String::new())]);

    // A redirect sends the message on and keeps no copy – with the original sender rewritten by SRS into an address
    // of the account's domain, which takes the bounce back to that sender.
    mail.put_sieve_script(alice, "forward", r#"redirect "alice@elsewhere.example";"#, true).await.unwrap();
    assert_eq!(mail.deliver(alice, incoming("r1"), delivery).await.unwrap(), kernoid_mail::Delivered::Discarded);
    let (to, srs) = queued().await[1].clone();
    assert_eq!(to, "alice@elsewhere.example");
    assert!(srs.starts_with("SRS0=") && srs.ends_with("=other.example=carol@firma.example"), "{srs}");
    match mail.resolve_recipient(&srs.to_lowercase()).await.unwrap() {
        kernoid_mail::Recipient::Forwarded { to, .. } => assert_eq!(to, "carol@other.example"),
        other => panic!("{other:?}"),
    }
    let forged = srs.replace("=other.example=", "=evil.example=").to_lowercase();
    assert!(matches!(mail.resolve_recipient(&forged).await.unwrap(), kernoid_mail::Recipient::Unknown));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn text_is_found_retention_empties_trash_and_mbox_round_trips(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    mail.ensure_account(alice).await.unwrap();
    let inbox = mail.mailbox_with_role(alice, Role::Inbox).await.unwrap();
    let trash = mail.mailbox_with_role(alice, Role::Trash).await.unwrap();
    let into =
        |mailbox| NewEmail { mailbox_ids: vec![mailbox], keywords: vec![keyword("$seen")], ..NewEmail::default() };
    let lunch =
        mail.import_email(alice, message("Plans", "a@x", None, "Lunch at the Brauhaus?"), into(inbox)).await.unwrap();
    let old = mail.import_email(alice, message("Old", "b@x", None, "Nothing to see"), into(trash)).await.unwrap();

    // Words and word beginnings, every word of the query, any case.
    assert_eq!(mail.search_text(alice, "brau").await.unwrap(), [lunch.id].into());
    assert_eq!(mail.search_text(alice, "LUNCH brauhaus").await.unwrap(), [lunch.id].into());
    assert!(mail.search_text(alice, "lunch nothing").await.unwrap().is_empty());
    assert!(mail.search_text(alice, "' | !").await.unwrap().is_empty());
    // An email stored before the index gets it from the worker.
    sqlx::query!("UPDATE emails SET body_search = NULL WHERE id = $1", lunch.id).execute(&pool).await.unwrap();
    assert!(mail.search_text(alice, "brauhaus").await.unwrap().is_empty());
    assert_eq!(mail.index_pending(100).await.unwrap(), 1);
    assert_eq!(mail.search_text(alice, "brauhaus").await.unwrap(), [lunch.id].into());

    // Retention: only what has been in the Trash longer than the tenant keeps it.
    assert_eq!(mail.apply_retention(100).await.unwrap(), 0);
    sqlx::query!("UPDATE tenants SET trash_retention_days = 30 WHERE id = $1", setup.tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(mail.apply_retention(100).await.unwrap(), 0);
    sqlx::query!(
        "UPDATE email_mailboxes SET added_at = now() - interval '31 days' WHERE email_id = ANY($1)",
        &[old.id, lunch.id][..]
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(mail.apply_retention(100).await.unwrap(), 1);
    assert!(matches!(mail.email(alice, old.id).await, Err(MailError::NotFound(_))));
    assert!(mail.email(alice, lunch.id).await.is_ok(), "the inbox is kept");

    // mbox: exported with keywords, imported into another mailbox.
    let entries = mail.mailbox_entries(alice, inbox).await.unwrap();
    let mbox = mail.mbox_entry(alice, &entries[0]).await.unwrap();
    assert!(String::from_utf8_lossy(&mbox).starts_with("From alice@firma.example "));
    let archive = mail.mailbox_with_role(alice, Role::Archive).await.unwrap();
    let mut data = mbox.clone();
    data.extend_from_slice(b"From nobody Sat Oct 24 10:00:00 2026\nnot a message at all\n\n");
    let done = mail.import_mbox(alice, archive, &data).await.unwrap();
    assert_eq!(done.imported, 1);
    let imported = mail.mailbox_entries(alice, archive).await.unwrap();
    assert_eq!(imported[0].keywords, ["$seen"]);
    assert_eq!(imported[0].received_at, entries[0].received_at.with_nanosecond(0).unwrap());
    let raw = mail.raw_email(alice, imported[0].email).await.unwrap();
    assert_eq!(raw, mail.raw_email(alice, lunch.id).await.unwrap(), "the message is as it was");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn only_accounts_with_mail_receive_it(pool: PgPool) {
    use kernoid_identity::services::Service;
    use kernoid_mail::Recipient;
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    assert!(matches!(setup.mail.resolve_recipient("alice@firma.example").await.unwrap(), Recipient::Account { .. }));
    setup.identity.revoke_service(alice, Service::Mail, WHO).await.unwrap();
    assert!(matches!(setup.mail.resolve_recipient("alice@firma.example").await.unwrap(), Recipient::Unknown));
    setup.identity.grant_service(alice, Service::Mail, WHO).await.unwrap();
    assert!(matches!(setup.mail.resolve_recipient("alice@firma.example").await.unwrap(), Recipient::Account { .. }));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_vacation_response_answers_while_it_is_on(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    let incoming = |from: &str, id: &str, extra: &str| {
        Bytes::from(format!(
            "From: {from}\r\nTo: alice@firma.example\r\nSubject: Hello\r\nMessage-ID: <{id}@other.example>\r\n{extra}\r\nHi\r\n"
        ))
    };
    let replies = || async {
        sqlx::query_scalar!("SELECT r.address FROM outbound_recipients r ORDER BY r.address")
            .fetch_all(&pool)
            .await
            .unwrap()
    };
    let deliver = |from: &'static str, id: &'static str, extra: &'static str, junk: bool| {
        let delivery = kernoid_mail::Delivery { from, to: "alice@firma.example", junk };
        mail.deliver(alice, incoming(from, id, extra), delivery)
    };
    assert_eq!(mail.vacation_response(alice).await.unwrap(), kernoid_mail::VacationResponse::default());

    // Off: no reply.
    deliver("carol@other.example", "a1", "", false).await.unwrap();
    assert!(replies().await.is_empty());

    // On, with the account's own script beside it: one reply per sender – not to junk, nor to automatic mail.
    mail.put_sieve_script(alice, "files", r#"require "fileinto"; keep;"#, true).await.unwrap();
    // Whole seconds: PostgreSQL keeps microseconds, and Linux's clock has nanoseconds.
    let now = chrono::Utc::now().with_nanosecond(0).unwrap();
    let vacation = kernoid_mail::VacationResponse {
        enabled: true,
        from_date: Some(now - chrono::Duration::hours(1)),
        to_date: Some(now + chrono::Duration::days(3)),
        subject: Some("Away".into()),
        text_body: Some("Back on Monday.".into()),
        html_body: None,
    };
    mail.set_vacation_response(alice, &vacation).await.unwrap();
    assert_eq!(mail.vacation_response(alice).await.unwrap(), vacation);
    deliver("carol@other.example", "a2", "", false).await.unwrap();
    deliver("carol@other.example", "a3", "", false).await.unwrap();
    deliver("spam@other.example", "a4", "", true).await.unwrap();
    deliver("list@other.example", "a5", "Auto-Submitted: auto-generated\r\n", false).await.unwrap();
    assert_eq!(replies().await, ["carol@other.example"]);

    // Its dates hold, and they must make sense.
    let later = kernoid_mail::VacationResponse { from_date: Some(now + chrono::Duration::days(1)), ..vacation.clone() };
    mail.set_vacation_response(alice, &later).await.unwrap();
    deliver("dave@other.example", "a6", "", false).await.unwrap();
    assert_eq!(replies().await, ["carol@other.example"]);
    let backwards = kernoid_mail::VacationResponse { to_date: Some(now - chrono::Duration::days(1)), ..vacation };
    assert!(matches!(mail.set_vacation_response(alice, &backwards).await, Err(MailError::Invalid(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_account_keeps_its_trash_as_long_as_it_chooses_and_sends_from_its_address(pool: PgPool) {
    let setup = setup(pool.clone(), Limits::default()).await;
    let alice = setup.account("alice").await;
    let mail = &setup.mail;
    mail.ensure_account(alice).await.unwrap();
    let trash = mail.mailbox_with_role(alice, Role::Trash).await.unwrap();
    let into = |mailbox| NewEmail { mailbox_ids: vec![mailbox], ..NewEmail::default() };
    let old = mail.import_email(alice, message("Old", "b@x", None, "Gone soon"), into(trash)).await.unwrap();
    sqlx::query!("UPDATE email_mailboxes SET added_at = now() - interval '10 days' WHERE email_id = $1", old.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query!("UPDATE tenants SET trash_retention_days = 30 WHERE id = $1", setup.tenant)
        .execute(&pool)
        .await
        .unwrap();

    // The tenant's 30 days: kept.
    let settings = mail.settings(alice).await.unwrap();
    assert_eq!((settings.trash_retention_days, settings.tenant_trash_retention_days), (None, Some(30)));
    assert_eq!(mail.apply_retention(100).await.unwrap(), 0);
    // The account's own 7 days: gone.
    mail.set_settings(alice, Some(7), None, 0).await.unwrap();
    assert_eq!(mail.apply_retention(100).await.unwrap(), 1);
    assert!(matches!(mail.email(alice, old.id).await, Err(MailError::NotFound(_))));
    assert!(matches!(mail.set_settings(alice, Some(0), None, 0).await, Err(MailError::Invalid(_))));

    // Sending from: only an address the account may send from.
    let (_, own) = mail.account_addresses(alice).await.unwrap();
    let address = own[0].to_uppercase();
    mail.set_settings(alice, None, Some(&address), 10).await.unwrap();
    let settings = mail.settings(alice).await.unwrap();
    assert_eq!((settings.default_from, settings.undo_send_seconds), (Some(own[0].to_lowercase()), 10));
    assert!(matches!(mail.set_settings(alice, None, None, 31).await, Err(MailError::Invalid(_))));
    assert!(matches!(
        mail.set_settings(alice, None, Some("ceo@elsewhere.example"), 0).await,
        Err(MailError::Invalid(_))
    ));
    mail.set_settings(alice, None, None, 0).await.unwrap();
    assert_eq!(
        mail.settings(alice).await.unwrap(),
        kernoid_mail::MailSettings { tenant_trash_retention_days: Some(30), ..Default::default() }
    );

    // Names for the mailboxes one reaches – only those, for oneself.
    mail.set_mailbox_name(alice, alice, "  Privat  ").await.unwrap();
    assert_eq!(mail.settings(alice).await.unwrap().mailbox_names.get(&alice).map(String::as_str), Some("Privat"));
    assert!(matches!(mail.set_mailbox_name(alice, uuid::Uuid::now_v7(), "Fremd").await, Err(MailError::NotFound(_))));
    assert!(matches!(mail.set_mailbox_name(alice, alice, &"x".repeat(65)).await, Err(MailError::Invalid(_))));
    mail.set_mailbox_name(alice, alice, "").await.unwrap();
    assert!(mail.settings(alice).await.unwrap().mailbox_names.is_empty());
}
