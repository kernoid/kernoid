// SPDX-License-Identifier: AGPL-3.0-or-later
//! CalDAV and CardDAV as clients use them, against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use http::{HeaderMap, HeaderValue, Method, StatusCode};
use kernoid_dav::{Dav, DavRequest, DavResponse};
use kernoid_events::EventStore;
use kernoid_groupware::Groupware;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup, role::Principal};
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
    dav: Dav,
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
    Setup { identity, dav: Dav::new(Groupware::new(mail, keys)), tenant }
}

impl Setup {
    async fn account(&self, local: &str) -> Uuid {
        let address = Address::parse(&format!("{local}@firma.example")).unwrap();
        self.identity.add_account(self.tenant, &address, local, WHO).await.unwrap()
    }

    async fn request(
        &self,
        account: Uuid,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> DavResponse {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(http::HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        self.dav
            .handle(DavRequest {
                method: Method::from_bytes(method.as_bytes()).unwrap(),
                path: path.into(),
                headers: map,
                body: body.as_bytes().to_vec(),
                account,
            })
            .await
    }
}

fn text(response: &DavResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn event(uid: &str, start: &str, rule: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20261001T080000Z\r\n\
         DTSTART:{start}\r\nDURATION:PT1H\r\n{rule}SUMMARY:{summary}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

const PROPFIND_DISCOVERY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:A="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:current-user-principal/><C:calendar-home-set/><A:addressbook-home-set/><C:calendar-user-address-set/></D:prop>
</D:propfind>"#;

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_client_discovers_creates_writes_queries_and_syncs(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let home = format!("/dav/calendars/{alice}/");

    // Discovery: the root names the principal, the principal the homes.
    let response = setup.request(alice, "PROPFIND", "/dav/", &[("depth", "0")], PROPFIND_DISCOVERY).await;
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    assert!(text(&response).contains(&format!("/dav/principals/{alice}/")), "{}", text(&response));
    let response = setup
        .request(alice, "PROPFIND", &format!("/dav/principals/{alice}/"), &[("depth", "0")], PROPFIND_DISCOVERY)
        .await;
    let body = text(&response);
    assert!(body.contains(&home), "{body}");
    assert!(body.contains("mailto:alice@firma.example"), "{body}");

    // The home lists the default calendar, inbox and outbox.
    let response = setup
        .request(alice, "PROPFIND", &home, &[("depth", "1")], r#"<propfind xmlns="DAV:"><prop><resourcetype/><displayname/><getctag xmlns="http://calendarserver.org/ns/"/></prop></propfind>"#)
        .await;
    let body = text(&response);
    assert!(body.contains("Calendar") && body.contains("inbox/") && body.contains("schedule-outbox"), "{body}");

    // MKCALENDAR with Apple's colour.
    let work = format!("{home}work/");
    let response = setup
        .request(
            alice,
            "MKCALENDAR",
            &work,
            &[],
            r#"<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:A="http://apple.com/ns/ical/">
                 <D:set><D:prop><D:displayname>Work</D:displayname><A:calendar-color>#3DDC97FF</A:calendar-color>
                 <C:calendar-timezone-id>Europe/Berlin</C:calendar-timezone-id></D:prop></D:set></C:mkcalendar>"#,
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED, "{}", text(&response));
    let response = setup
        .request(alice, "PROPFIND", &work, &[("depth", "0")], r#"<propfind xmlns="DAV:" xmlns:A="http://apple.com/ns/ical/"><prop><displayname/><A:calendar-color/></prop></propfind>"#)
        .await;
    let body = text(&response);
    assert!(body.contains("Work") && body.contains("#3DDC97FF"), "{body}");

    // PUT: created with an ETag, If-None-Match refuses a second time.
    let weekly = event("weekly@firma", "20261005T090000Z", "RRULE:FREQ=WEEKLY\r\n", "Weekly");
    let response = setup.request(alice, "PUT", &format!("{work}weekly.ics"), &[("if-none-match", "*")], &weekly).await;
    assert_eq!(response.status(), StatusCode::CREATED, "{}", text(&response));
    let etag = response.headers().get("etag").unwrap().to_str().unwrap().to_owned();
    let response = setup.request(alice, "PUT", &format!("{work}weekly.ics"), &[("if-none-match", "*")], &weekly).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let response = setup.request(alice, "PUT", &format!("{work}other.ics"), &[], &weekly).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(text(&response).contains("no-uid-conflict"), "{}", text(&response));
    let once = event("once@firma", "20261102T140000Z", "", "Once");
    setup.request(alice, "PUT", &format!("{work}once.ics"), &[], &once).await;

    let response = setup.request(alice, "GET", &format!("{work}weekly.ics"), &[], "").await;
    assert_eq!(text(&response), weekly);
    assert_eq!(response.headers().get("etag").unwrap().to_str().unwrap(), etag);

    // calendar-query with a time range in December: only the weekly event, expanded on request.
    let query = r#"<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
      <D:prop><D:getetag/><C:calendar-data><C:expand start="20261201T000000Z" end="20261215T000000Z"/></C:calendar-data></D:prop>
      <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
        <C:time-range start="20261201T000000Z" end="20261215T000000Z"/></C:comp-filter></C:comp-filter></C:filter>
    </C:calendar-query>"#;
    let response = setup.request(alice, "REPORT", &work, &[("depth", "1")], query).await;
    let body = text(&response);
    assert!(body.contains("weekly.ics") && !body.contains("once.ics"), "{body}");
    assert_eq!(body.matches("RECURRENCE-ID").count(), 2, "{body}");

    // A text match on SUMMARY.
    let query = r#"<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/></D:prop>
      <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
        <C:prop-filter name="SUMMARY"><C:text-match>onc</C:text-match></C:prop-filter></C:comp-filter></C:comp-filter></C:filter>
    </C:calendar-query>"#;
    let body = text(&setup.request(alice, "REPORT", &work, &[("depth", "1")], query).await);
    assert!(body.contains("once.ics") && !body.contains("weekly.ics"), "{body}");

    // multiget, with an unknown href.
    let multiget = format!(
        r#"<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/><C:calendar-data/></D:prop>
        <D:href>{work}once.ics</D:href><D:href>{work}missing.ics</D:href></C:calendar-multiget>"#
    );
    let body = text(&setup.request(alice, "REPORT", &work, &[], &multiget).await);
    assert!(body.contains("SUMMARY:Once") && body.contains("404"), "{body}");

    // sync-collection: everything first, then only the change.
    let sync = |token: &str| {
        format!(
            r#"<D:sync-collection xmlns:D="DAV:"><D:sync-token>{token}</D:sync-token><D:sync-level>1</D:sync-level>
            <D:prop><D:getetag/></D:prop></D:sync-collection>"#
        )
    };
    let body = text(&setup.request(alice, "REPORT", &work, &[], &sync("")).await);
    assert!(body.contains("weekly.ics") && body.contains("once.ics"), "{body}");
    let token = body.split("<D:sync-token>").nth(1).and_then(|rest| rest.split('<').next()).unwrap().to_owned();
    let response = setup.request(alice, "DELETE", &format!("{work}once.ics"), &[], "").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let body = text(&setup.request(alice, "REPORT", &work, &[], &sync(&token)).await);
    assert!(body.contains("once.ics") && body.contains("404") && !body.contains("weekly.ics"), "{body}");
    let body = text(&setup.request(alice, "REPORT", &work, &[], &sync("urn:kernoid:sync:999999")).await);
    assert!(body.contains("valid-sync-token"), "{body}");

    // free-busy-query: the weekly event's December instances.
    let freebusy = r#"<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
      <C:time-range start="20261207T000000Z" end="20261208T000000Z"/></C:free-busy-query>"#;
    let body = text(&setup.request(alice, "REPORT", &work, &[], freebusy).await).replace("\r\n ", "");
    assert!(body.contains("FREEBUSY;FBTYPE=BUSY:20261207T090000Z/20261207T100000Z"), "{body}");

    // Another account sees nothing of Alice's home.
    let bob = setup.account("bob").await;
    let response = setup.request(bob, "PROPFIND", &home, &[("depth", "0")], "").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn contacts_and_shared_calendars(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let bob = setup.account("bob").await;
    let books = format!("/dav/addressbooks/{alice}/");

    // The default address book, a contact, a query.
    let body = text(&setup.request(alice, "PROPFIND", &books, &[("depth", "1")], "").await);
    let book = body
        .split("<D:href>")
        .filter_map(|part| part.split('<').next())
        .find(|href| href.len() > books.len() && href.starts_with(&books))
        .unwrap()
        .to_owned();
    let card =
        "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:carol\r\nFN:Carol Example\r\nEMAIL:carol@example.org\r\nEND:VCARD\r\n";
    let response = setup.request(alice, "PUT", &format!("{book}carol.vcf"), &[], card).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let query = r#"<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
      <D:prop><D:getetag/><C:address-data><C:prop name="FN"/></C:address-data></D:prop>
      <C:filter><C:prop-filter name="EMAIL"><C:text-match match-type="starts-with">carol</C:text-match></C:prop-filter></C:filter>
    </C:addressbook-query>"#;
    let body = text(&setup.request(alice, "REPORT", &book, &[("depth", "1")], query).await);
    assert!(body.contains("FN:Carol Example") && !body.contains("EMAIL"), "{body}");
    let response = setup.request(alice, "PUT", &format!("{book}bad.vcf"), &[], "not a card").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Alice shares her default calendar with Bob for reading: it appears in his home, read-only.
    let groupware = &setup.dav;
    let _ = groupware;
    let calendars = format!("/dav/calendars/{alice}/");
    let body = text(&setup.request(alice, "PROPFIND", &calendars, &[("depth", "1")], "").await);
    let default = body
        .split("<D:href>")
        .filter_map(|part| part.split('<').next())
        .find(|href| {
            href.starts_with(&calendars)
                && href.len() > calendars.len()
                && !href.ends_with("inbox/")
                && !href.ends_with("outbox/")
        })
        .unwrap()
        .to_owned();
    let calendar_id = default.trim_end_matches('/').rsplit('/').next().unwrap().parse::<Uuid>().unwrap();
    setup
        .request(alice, "PUT", &format!("{default}a.ics"), &[], &event("a@firma", "20261110T100000Z", "", "Shared"))
        .await;
    setup.identity.share_collection(alice, alice, calendar_id, Principal::Account(bob), "read").await.unwrap();

    let bob_home = format!("/dav/calendars/{bob}/");
    let body = text(&setup.request(bob, "PROPFIND", &bob_home, &[("depth", "1")], "").await);
    let shared = format!("{bob_home}shared-{calendar_id}/");
    assert!(body.contains(&shared), "{body}");
    let response = setup.request(bob, "GET", &format!("{shared}a.ics"), &[], "").await;
    assert!(text(&response).contains("SUMMARY:Shared"));
    let response = setup
        .request(bob, "PUT", &format!("{shared}b.ics"), &[], &event("b@firma", "20261111T100000Z", "", "No"))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Free/busy through Bob's outbox for Alice: allowed, since he may read her calendar.
    let request = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nMETHOD:REQUEST\r\nBEGIN:VFREEBUSY\r\nUID:fb1\r\n\
         DTSTAMP:20261001T080000Z\r\nDTSTART:20261110T000000Z\r\nDTEND:20261111T000000Z\r\n\
         ORGANIZER:mailto:bob@firma.example\r\nATTENDEE:mailto:alice@firma.example\r\nATTENDEE:mailto:nobody@else.example\r\n\
         END:VFREEBUSY\r\nEND:VCALENDAR\r\n";
    let response = setup.request(bob, "POST", &format!("{bob_home}outbox/"), &[], request).await;
    let body = text(&response).replace("\r\n ", "");
    assert!(body.contains("2.0;Success") && body.contains("20261110T100000Z/20261110T110000Z"), "{body}");
    assert!(body.contains("3.7;Invalid calendar user"), "{body}");
}
