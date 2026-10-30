// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end encryption over JMAP (RFC 0006): a client makes a key and stores it with a protected copy, switches
//! encrypted mail on, and what arrives afterwards is stored encrypted to that key – readable with the secret key, not
//! by kernoid. Against PostgreSQL, with object storage in memory; set `DATABASE_URL` as for the other tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use kernoid_e2e::{Kind, SecretKey, mime};
use kernoid_events::EventStore;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_jmap::{Caller, Jmap};
use kernoid_mail::{Delivered, Delivery, Limits, Mail};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use serde_json::{Value, json};
use sqlx::PgPool;

const WHO: &str = "operator";
const USING: [&str; 3] = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "https://kernoid.dev/jmap/openpgp"];
const MAIL: &[u8] = b"From: Eve <eve@elsewhere.example>\r\nTo: alice@firma.example\r\nSubject: The plan\r\n\
Message-ID: <plan@elsewhere.example>\r\nContent-Type: text/plain\r\n\r\nMeet at noon.\r\n";

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

struct Directory;

impl kernoid_jmap::KeyDirectory for Directory {
    fn lookup<'a>(
        &'a self,
        address: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            match address {
                "bob@elsewhere.example" => {
                    let key = SecretKey::generate(Kind::Compatible, &["bob@elsewhere.example"]).unwrap();
                    let other = SecretKey::generate(Kind::Pqc, &["someone@else.example"]).unwrap();
                    vec![key.public().to_bytes().unwrap(), other.public().to_bytes().unwrap()]
                }
                _ => Vec::new(),
            }
        })
    }
}

async fn call(jmap: &Jmap, caller: &Caller, name: &str, args: Value) -> Value {
    let request = json!({ "using": USING, "methodCalls": [[name, args, "0"]] });
    let response = jmap.api(caller, request.to_string().as_bytes()).await.unwrap();
    let entry = &response["methodResponses"][0];
    assert_eq!(entry[0], name, "{entry}");
    entry[1].clone()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_arrives_encrypted_to_the_key_the_client_made(pool: PgPool) {
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
    let mail = Mail::new(pool.clone(), BlobStore::new(Arc::new(InMemory::new()), keys), Limits::default());
    let jmap = Jmap::new(mail.clone(), 1_000_000, chrono::Duration::days(5))
        .with_identity(identity.clone())
        .with_key_directory(Arc::new(Directory));
    let address = "alice@firma.example";
    let account = identity.add_account(tenant, &Address::parse(address).unwrap(), "Alice", WHO).await.unwrap();
    let alice = Caller { account, tenant, username: address.into(), mail: true, files: false };
    let id = account.to_string();

    let session = jmap.session(&alice, "https://login.firma.example").await.unwrap();
    assert_eq!(session["primaryAccounts"]["https://kernoid.dev/jmap/openpgp"], json!(id));

    // Mail stored before the switch, in plain text.
    let earlier = String::from_utf8_lossy(MAIL).replace("<plan@", "<earlier@");
    let delivery = Delivery { from: "eve@elsewhere.example", to: address, junk: false };
    let Delivered::Stored(before) = mail.deliver(account, Bytes::from(earlier), delivery).await.unwrap() else {
        panic!("not stored");
    };
    mail.set_keywords(account, before.id, &[kernoid_mail::Keyword::parse("$flagged").unwrap()]).await.unwrap();

    // Before a key there is nothing to encrypt to.
    let set =
        call(&jmap, &alice, "E2eSettings/set", json!({ "accountId": id, "update": { "singleton": { "mail": true } } }))
            .await;
    assert_eq!(set["notUpdated"]["singleton"]["type"], "invalidProperties");

    // The client makes the key and keeps a copy protected with a recovery code.
    let secret = SecretKey::generate(Kind::Pqc, &[address]).unwrap();
    let copy = secret.protect("RECOVERY-CODE").unwrap();
    let set = call(
        &jmap,
        &alice,
        "OpenPgpKey/set",
        json!({ "accountId": id, "create": { "k": {
            "publicKey": STANDARD.encode(secret.public().to_bytes().unwrap()),
            "copies": { "recovery": { "protected": STANDARD.encode(&copy) } },
        } } }),
    )
    .await;
    assert_eq!(set["created"]["k"]["id"], secret.fingerprint(), "{set}");
    let got = call(&jmap, &alice, "OpenPgpKey/get", json!({ "accountId": id })).await;
    let stored = STANDARD.decode(got["list"][0]["copies"]["recovery"]["protected"].as_str().unwrap()).unwrap();
    assert_eq!(SecretKey::unlock(&stored, "RECOVERY-CODE").unwrap().fingerprint(), secret.fingerprint());
    let destroyed =
        call(&jmap, &alice, "OpenPgpKey/set", json!({ "accountId": id, "destroy": [secret.fingerprint()] })).await;
    assert_eq!(destroyed["notDestroyed"][secret.fingerprint()]["type"], "forbidden");

    let set =
        call(&jmap, &alice, "E2eSettings/set", json!({ "accountId": id, "update": { "singleton": { "mail": true } } }))
            .await;
    assert!(set["updated"]["singleton"].is_null() && set["notUpdated"].is_null(), "{set}");
    let settings = call(&jmap, &alice, "E2eSettings/get", json!({ "accountId": id })).await;
    assert_eq!(settings["list"][0]["mail"], true);
    assert_eq!(settings["list"][0]["policy"]["mail"], "allowed");

    // Others find the key; outside addresses come from their Web Key Directory, only keys that name them.
    let lookup = call(
        &jmap,
        &alice,
        "OpenPgpKey/lookup",
        json!({ "accountId": id, "emails": [address, "bob@elsewhere.example", "nobody@elsewhere.example"] }),
    )
    .await;
    assert_eq!(lookup["list"][0]["keys"][0]["id"], secret.fingerprint());
    assert_eq!(lookup["list"][0]["keys"][0]["source"], "local");
    assert_eq!(lookup["list"][1]["keys"].as_array().unwrap().len(), 1);
    assert_eq!(
        (lookup["list"][1]["keys"][0]["kind"].as_str(), lookup["list"][1]["keys"][0]["source"].as_str()),
        (Some("compatible"), Some("wkd"))
    );
    assert_eq!(lookup["list"][2]["keys"], json!([]));

    // What arrives now is encrypted before it is stored.
    let delivery = Delivery { from: "eve@elsewhere.example", to: address, junk: false };
    let Delivered::Stored(imported) = mail.deliver(account, Bytes::from_static(MAIL), delivery).await.unwrap() else {
        panic!("not stored");
    };
    let raw = mail.raw_email(account, imported.id).await.unwrap();
    assert!(mime::is_encrypted(&raw));
    let text = String::from_utf8_lossy(&raw);
    assert!(!text.contains("The plan") && !text.contains("noon"));
    let opened = mime::decrypt_message(&raw, &[&secret], &[]).unwrap();
    assert!(String::from_utf8(opened.data).unwrap().contains("Subject: The plan"));

    let got = call(
        &jmap,
        &alice,
        "Email/get",
        json!({ "accountId": id, "ids": [imported.id.to_string()],
                "properties": ["subject", "preview", "kernoid:encrypted", "kernoid:encryptedSummary"] }),
    )
    .await;
    let email = &got["list"][0];
    assert_eq!((email["subject"].clone(), email["preview"].clone()), (Value::Null, json!("")));
    assert_eq!(email["kernoid:encrypted"], true);
    let summary = STANDARD.decode(email["kernoid:encryptedSummary"].as_str().unwrap()).unwrap();
    let summary = mime::decrypt_summary(&summary, &[&secret]).unwrap();
    assert_eq!((summary.subject.as_deref(), summary.preview.as_str()), (Some("The plan"), "Meet at noon."));

    // The worker encrypts what was stored before: a new email in its place, with its keywords.
    assert_eq!(mail.encrypt_stored(10).await.unwrap(), 1);
    assert_eq!(mail.encrypt_stored(10).await.unwrap(), 0);
    assert!(mail.email(account, before.id).await.is_err());
    let query = call(&jmap, &alice, "Email/query", json!({ "accountId": id })).await;
    let ids: Vec<&str> = query["ids"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert_eq!(ids.len(), 2);
    let all = mail.emails(account, &ids.iter().map(|i| i.parse().unwrap()).collect::<Vec<_>>()).await.unwrap();
    assert!(all.iter().all(|email| email.encrypted));
    assert!(all.iter().any(|email| email.keywords == ["$flagged"]));

    // Mail that came encrypted already is stored as it came.
    let other = String::from_utf8_lossy(MAIL).replace("<plan@", "<plan-2@");
    let sealed = mime::encrypt_message(other.as_bytes(), &[&secret.public()], None).unwrap();
    let Delivered::Stored(again) = mail
        .deliver(
            account,
            Bytes::from(sealed.clone()),
            Delivery { from: "eve@elsewhere.example", to: address, junk: false },
        )
        .await
        .unwrap()
    else {
        panic!("not stored");
    };
    assert_eq!(mail.raw_email(account, again.id).await.unwrap(), Bytes::from(sealed));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn sent_mail_announces_a_compatible_key(pool: PgPool) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let domain = DomainName::parse("firma.example").unwrap();
    identity.add_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    let keys = Arc::new(TenantKeys::with_main_keys(pool.clone(), MainKeys::new(Key::random().unwrap(), Vec::new())));
    let mail = Mail::new(pool.clone(), BlobStore::new(Arc::new(InMemory::new()), keys), Limits::default());
    let copy =
        || vec![kernoid_identity::openpgp::KeyCopy { label: "recovery".into(), protected: b"p".to_vec(), salt: None }];

    let mut sent = Vec::new();
    for (local, kind) in [("bob", Kind::Compatible), ("carol", Kind::Pqc)] {
        let address = format!("{local}@firma.example");
        let account = identity.add_account(tenant, &Address::parse(&address).unwrap(), local, WHO).await.unwrap();
        let key = SecretKey::generate(kind, &[&address]).unwrap().public().to_bytes().unwrap();
        identity.add_openpgp_key(account, &key, copy(), WHO).await.unwrap();
        let raw = format!("From: {address}\r\nTo: x@elsewhere.example\r\nSubject: Hi\r\n\r\nHello\r\n");
        let id = mail
            .enqueue(kernoid_mail::Outgoing {
                tenant,
                account: Some(account),
                from: &address,
                recipients: &["x@elsewhere.example".to_owned()],
                raw: Bytes::from(raw),
                lifetime: chrono::Duration::days(1),
            })
            .await
            .unwrap();
        sent.push(String::from_utf8(mail.outbound_message(tenant, id).await.unwrap().to_vec()).unwrap());
    }
    assert!(sent[0].starts_with("Autocrypt: addr=bob@firma.example; keydata=\r\n "), "{}", sent[0]);
    assert!(sent[0].contains("\r\nFrom: bob@firma.example\r\n"));
    assert!(!sent[1].contains("Autocrypt:"), "post-quantum keys wait for Autocrypt's next version");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn encrypted_calendars_hold_only_what_the_apps_encrypted(pool: PgPool) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let domain = DomainName::parse("firma.example").unwrap();
    identity.add_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    let keys = Arc::new(TenantKeys::with_main_keys(pool.clone(), MainKeys::new(Key::random().unwrap(), Vec::new())));
    let mail = Mail::new(pool.clone(), BlobStore::new(Arc::new(InMemory::new()), keys.clone()), Limits::default());
    let groupware = kernoid_groupware::Groupware::new(mail.clone(), keys);
    let jmap = Jmap::new(mail, 1_000_000, chrono::Duration::days(5))
        .with_identity(identity.clone())
        .with_groupware(groupware.clone());
    let address = "alice@firma.example";
    let account = identity.add_account(tenant, &Address::parse(address).unwrap(), "Alice", WHO).await.unwrap();
    let alice = Caller { account, tenant, username: address.into(), mail: true, files: false };
    let id = account.to_string();
    let using = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars", "https://kernoid.dev/jmap/openpgp"];
    let call = |name: &'static str, args: Value| {
        let (jmap, alice) = (&jmap, &alice);
        async move {
            let request = json!({ "using": using, "methodCalls": [[name, args, "0"]] });
            let response = jmap.api(alice, request.to_string().as_bytes()).await.unwrap();
            response["methodResponses"][0][1].clone()
        }
    };

    // The calendar's key, made by the app; its secret wrapped for Alice.
    let own = SecretKey::generate(Kind::Pqc, &[address]).unwrap();
    let calendar_key = SecretKey::generate(Kind::Pqc, &["calendar@vault.invalid"]).unwrap();
    let wrapped =
        kernoid_e2e::message::encrypt(calendar_key.export().unwrap().as_bytes(), &[&own.public()], None, false)
            .unwrap();
    let created = call(
        "Calendar/set",
        json!({ "accountId": id, "create": { "c": { "name": "Private", "kernoid:newEncrypted": {
            "publicKey": STANDARD.encode(calendar_key.public().to_bytes().unwrap()), "sealed": STANDARD.encode(&wrapped) } } } }),
    )
    .await;
    let calendar = created["created"]["c"]["id"].as_str().unwrap_or_else(|| panic!("{created}")).to_owned();
    let got = call("Calendar/get", json!({ "accountId": id, "ids": [calendar] })).await;
    assert!(got["list"][0]["kernoid:collectionKey"].is_string());

    // Plain events are refused; encrypted entries are kept as they came.
    let plain = call(
        "CalendarEvent/set",
        json!({ "accountId": id, "create": { "e": { "@type": "Event", "title": "Leak", "calendarIds": { &calendar: true },
            "start": "2026-11-02T09:00:00", "duration": "PT1H" } } }),
    )
    .await;
    assert!(plain["notCreated"]["e"].is_object(), "{plain}");
    let event = br#"{"@type":"Event","title":"Doctor","start":"2026-11-03T10:00:00"}"#;
    let sealed = kernoid_e2e::message::encrypt(event, &[&calendar_key.public()], Some(&own), false).unwrap();
    let set = call(
        "SealedItem/set",
        json!({ "accountId": id, "collectionId": calendar, "create": { "i": { "data": STANDARD.encode(&sealed) } } }),
    )
    .await;
    let item = set["created"]["i"]["id"].as_str().unwrap_or_else(|| panic!("{set}")).to_owned();
    let items = call("SealedItem/get", json!({ "accountId": id, "collectionId": calendar })).await;
    let data = STANDARD.decode(items["list"][0]["data"].as_str().unwrap()).unwrap();
    assert_eq!(kernoid_e2e::message::decrypt(&data, &[&calendar_key], &[]).unwrap().data, event);

    // The key comes back to its member, unwrapped by her own key.
    let key = call("CollectionKey/get", json!({ "accountId": id, "ids": [calendar] })).await;
    let back = STANDARD.decode(key["list"][0]["sealed"].as_str().unwrap()).unwrap();
    let secret = kernoid_e2e::message::decrypt(&back, &[&own], &[]).unwrap().data;
    assert_eq!(SecretKey::import(&secret).unwrap().fingerprint(), calendar_key.fingerprint());
    assert_eq!(key["list"][0]["members"], json!([id]));

    // Not in a plain calendar; destroying the calendar takes its entries with it.
    let plain_calendar = groupware.default_calendar(account).await.unwrap().id.to_string();
    let wrong = call(
        "SealedItem/set",
        json!({ "accountId": id, "collectionId": plain_calendar, "create": { "i": { "data": "AAAA" } } }),
    )
    .await;
    assert!(wrong["notCreated"]["i"].is_object(), "{wrong}");
    let destroyed =
        call("SealedItem/set", json!({ "accountId": id, "collectionId": calendar, "destroy": [item] })).await;
    assert_eq!(destroyed["destroyed"], json!([item]));
    let gone =
        call("Calendar/set", json!({ "accountId": id, "destroy": [calendar], "onDestroyRemoveEvents": true })).await;
    assert_eq!(gone["destroyed"], json!([calendar]), "{gone}");
}
