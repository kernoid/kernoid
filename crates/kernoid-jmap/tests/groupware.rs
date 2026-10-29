// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP for Contacts and Calendars against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use kernoid_events::EventStore;
use kernoid_groupware::Groupware;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_jmap::{Caller, Jmap};
use kernoid_mail::{Limits, Mail};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const WHO: &str = "operator";
const USING: [&str; 3] =
    ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars", "urn:ietf:params:jmap:contacts"];

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

struct Setup {
    identity: Identity,
    jmap: Jmap,
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
    let jmap = Jmap::new(mail.clone(), 1_000_000, chrono::Duration::days(5)).with_groupware(Groupware::new(mail, keys));
    Setup { identity, jmap, tenant }
}

impl Setup {
    async fn caller(&self, local: &str) -> Caller {
        let address = format!("{local}@firma.example");
        let account =
            self.identity.add_account(self.tenant, &Address::parse(&address).unwrap(), local, WHO).await.unwrap();
        Caller { account, tenant: self.tenant, username: address, mail: true, files: false }
    }

    async fn one(&self, caller: &Caller, name: &str, args: Value) -> Value {
        let request = json!({ "using": USING, "methodCalls": [[name, args, "0"]] });
        let response = self.jmap.api(caller, request.to_string().as_bytes()).await.unwrap();
        let entry = &response["methodResponses"][0];
        assert_eq!(entry[0], name, "{entry}");
        entry[1].clone()
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn contacts_through_jmap(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let account = alice.account.to_string();

    let session = setup.jmap.session(&alice, "https://login.firma.example").await.unwrap();
    assert!(session["accounts"][&account]["accountCapabilities"]["urn:ietf:params:jmap:contacts"].is_object());
    assert_eq!(session["primaryAccounts"]["urn:ietf:params:jmap:calendars"], account);

    let books = setup.one(&alice, "AddressBook/get", json!({ "accountId": account })).await;
    assert_eq!(books["list"][0]["isDefault"], true);
    let state = books["state"].as_str().unwrap().to_owned();

    let created = setup
        .one(
            &alice,
            "ContactCard/set",
            json!({ "accountId": account, "create": { "c1": {
                "@type": "Card", "version": "1.0",
                "name": { "full": "Carol Example" },
                "emails": { "e1": { "address": "carol@example.org" } }
            } } }),
        )
        .await;
    let id = created["created"]["c1"]["id"].as_str().unwrap().to_owned();

    let found =
        setup.one(&alice, "ContactCard/query", json!({ "accountId": account, "filter": { "email": "carol@" } })).await;
    assert_eq!(found["ids"], json!([id]));

    setup
        .one(&alice, "ContactCard/set", json!({ "accountId": account, "update": { &id: { "name/full": "Carol E." } } }))
        .await;
    let got = setup.one(&alice, "ContactCard/get", json!({ "accountId": account, "ids": [id] })).await;
    assert_eq!(got["list"][0]["name"]["full"], "Carol E.", "{got}");
    assert!(got["list"][0]["addressBookIds"].is_object());

    let changes = setup.one(&alice, "ContactCard/changes", json!({ "accountId": account, "sinceState": state })).await;
    assert_eq!(changes["created"], json!([id]));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn calendars_through_jmap(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let account = alice.account.to_string();

    let calendars = setup.one(&alice, "Calendar/get", json!({ "accountId": account })).await;
    let calendar = calendars["list"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(calendars["list"][0]["myRights"]["mayAdmin"], true);

    let created = setup
        .one(
            &alice,
            "CalendarEvent/set",
            json!({ "accountId": account, "create": { "e1": {
                "@type": "Event", "title": "Standup",
                "calendarIds": { &calendar: true },
                "start": "2026-11-02T09:00:00", "timeZone": "Europe/Berlin", "duration": "PT15M",
                "recurrenceRule": { "frequency": "daily", "count": 5 }
            } } }),
        )
        .await;
    let id = created["created"]["e1"]["id"].as_str().unwrap_or_else(|| panic!("{created}")).to_owned();

    // Expanded: three instances in the window, in order; the second as an object of its own.
    let found = setup
        .one(
            &alice,
            "CalendarEvent/query",
            json!({ "accountId": account, "expandRecurrences": true,
                    "filter": { "after": "2026-11-03T00:00:00Z", "before": "2026-11-06T00:00:00Z" } }),
        )
        .await;
    let ids = found["ids"].as_array().unwrap().clone();
    assert_eq!(ids.len(), 3, "{found}");
    let instance = setup.one(&alice, "CalendarEvent/get", json!({ "accountId": account, "ids": [ids[1]] })).await;
    let object = &instance["list"][0];
    assert_eq!(object["baseEventId"], id);
    assert_eq!(object["recurrenceId"], "2026-11-04T09:00:00");
    assert_eq!(object["utcStart"], "2026-11-04T08:00:00Z", "{object}");
    assert!(object.get("recurrenceRule").is_none());

    // Not expanded: the event once; text search.
    let found = setup
        .one(&alice, "CalendarEvent/query", json!({ "accountId": account, "filter": { "text": "standup" } }))
        .await;
    assert_eq!(found["ids"], json!([id]));

    setup
        .one(&alice, "CalendarEvent/set", json!({ "accountId": account, "update": { &id: { "title": "Daily" } } }))
        .await;
    let got = setup.one(&alice, "CalendarEvent/get", json!({ "accountId": account, "ids": [id] })).await;
    assert_eq!(got["list"][0]["title"], "Daily", "{got}");
    assert_eq!(got["list"][0]["utcStart"], "2026-11-02T08:00:00Z");

    let identities = setup.one(&alice, "ParticipantIdentity/get", json!({ "accountId": account })).await;
    assert_eq!(identities["list"][0]["calendarAddress"], "mailto:alice@firma.example");

    let gone = setup.one(&alice, "CalendarEvent/set", json!({ "accountId": account, "destroy": [id] })).await;
    assert_eq!(gone["destroyed"], json!([id]));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn single_instances_of_a_series_change_through_overrides(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let account = alice.account.to_string();
    let calendars = setup.one(&alice, "Calendar/get", json!({ "accountId": account })).await;
    let calendar = calendars["list"][0]["id"].as_str().unwrap().to_owned();
    let created = setup
        .one(
            &alice,
            "CalendarEvent/set",
            json!({ "accountId": account, "create": { "s": {
                "@type": "Event", "title": "Weekly",
                "calendarIds": { &calendar: true },
                "start": "2026-11-02T10:00:00", "timeZone": "Europe/Berlin", "duration": "PT1H",
                "recurrenceRule": { "frequency": "weekly", "count": 4 }
            } } }),
        )
        .await;
    let id = created["created"]["s"]["id"].as_str().unwrap().to_owned();

    // One instance moved and renamed, one left out (RFC 8984, 4.3.5).
    let overrides = json!({
        "2026-11-09T10:00:00": { "title": "Moved", "start": "2026-11-10T11:00:00" },
        "2026-11-16T10:00:00": { "excluded": true },
    });
    let updated = setup
        .one(
            &alice,
            "CalendarEvent/set",
            json!({ "accountId": account, "update": { &id: { "recurrenceOverrides": overrides } } }),
        )
        .await;
    assert_eq!(updated["notUpdated"], json!({}), "{updated}");
    let found = setup
        .one(
            &alice,
            "CalendarEvent/query",
            json!({ "accountId": account, "expandRecurrences": true,
                    "filter": { "after": "2026-11-01T00:00:00Z", "before": "2026-12-01T00:00:00Z" } }),
        )
        .await;
    let got = setup
        .one(
            &alice,
            "CalendarEvent/get",
            json!({ "accountId": account, "ids": found["ids"],
                    "properties": ["title", "start", "recurrenceId", "utcStart", "utcEnd"] }),
        )
        .await;
    // A moved instance lasts as long as the others.
    assert_eq!(got["list"][1]["utcStart"], "2026-11-10T10:00:00Z", "{got}");
    assert_eq!(got["list"][1]["utcEnd"], "2026-11-10T11:00:00Z", "{got}");
    let instances: Vec<(String, String, String)> = got["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            let text = |key: &str| event[key].as_str().unwrap_or_default().to_owned();
            (text("title"), text("start"), text("recurrenceId"))
        })
        .collect();
    let expected = [
        ("Weekly", "2026-11-02T10:00:00", "2026-11-02T10:00:00"),
        ("Moved", "2026-11-10T11:00:00", "2026-11-09T10:00:00"),
        ("Weekly", "2026-11-23T10:00:00", "2026-11-23T10:00:00"),
    ];
    let expected: Vec<(String, String, String)> =
        expected.iter().map(|(a, b, c)| ((*a).into(), (*b).into(), (*c).into())).collect();
    assert_eq!(instances, expected);
}
