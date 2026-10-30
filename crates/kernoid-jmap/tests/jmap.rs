// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP requests against PostgreSQL, with object storage in memory; set `DATABASE_URL` as for the other crates' tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use kernoid_events::EventStore;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_jmap::{Caller, Jmap, RequestError};
use kernoid_mail::{Limits, Mail, Role};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const WHO: &str = "operator";
const USING: [&str; 3] = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"];

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

struct Setup {
    pool: PgPool,
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
    let blobs = BlobStore::new(Arc::new(InMemory::new()), keys);
    let mail = Mail::new(pool.clone(), blobs, Limits::default());
    Setup { pool, identity, jmap: Jmap::new(mail, 1_000_000, chrono::Duration::days(5)), tenant }
}

impl Setup {
    async fn caller(&self, local: &str) -> Caller {
        let address = format!("{local}@firma.example");
        let account =
            self.identity.add_account(self.tenant, &Address::parse(&address).unwrap(), local, WHO).await.unwrap();
        Caller { account, tenant: self.tenant, username: address, mail: true, files: false }
    }

    /// Runs one request; the method responses by call id.
    async fn call(&self, caller: &Caller, calls: Value) -> HashMap<String, Vec<(String, Value)>> {
        let request = json!({ "using": USING, "methodCalls": calls });
        let response = self.jmap.api(caller, request.to_string().as_bytes()).await.unwrap();
        let mut out: HashMap<String, Vec<(String, Value)>> = HashMap::new();
        for entry in response["methodResponses"].as_array().unwrap() {
            out.entry(entry[2].as_str().unwrap().to_owned())
                .or_default()
                .push((entry[0].as_str().unwrap().to_owned(), entry[1].clone()));
        }
        out
    }

    async fn one(&self, caller: &Caller, name: &str, args: Value) -> (String, Value) {
        self.call(caller, json!([[name, args, "0"]])).await.remove("0").unwrap().remove(0)
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn session_mailboxes_and_errors(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let id = alice.account.to_string();

    let session = setup.jmap.session(&alice, "https://login.firma.example").await.unwrap();
    assert_eq!(session["primaryAccounts"]["urn:ietf:params:jmap:mail"], json!(id));
    assert_eq!(session["apiUrl"], "https://login.firma.example/jmap/api");
    assert_eq!(session["accounts"][&id]["isPersonal"], true);

    // A mailbox and its child in one request: the child refers to its parent by creation id.
    let responses = setup
        .call(
            &alice,
            json!([
                ["Mailbox/set", { "accountId": id, "create": {
                    "p": { "name": "Projects" },
                    "c": { "name": "kernoid", "parentId": "#p" },
                    "bad": { "name": "a/b" },
                } }, "s"],
                ["Mailbox/query", { "accountId": id, "filter": { "role": "inbox" } }, "q"],
                ["Mailbox/get", { "accountId": id, "#ids": { "resultOf": "q", "name": "Mailbox/query", "path": "/ids" }, "properties": ["name", "role", "totalEmails"] }, "g"],
            ]),
        )
        .await;
    let set = &responses["s"][0].1;
    assert!(set["created"]["p"]["id"].is_string() && set["created"]["c"]["id"].is_string());
    assert_eq!(set["notCreated"]["bad"]["type"], "invalidProperties");
    let inbox = &responses["g"][0].1["list"][0];
    assert_eq!(
        (inbox["name"].as_str(), inbox["role"].as_str(), inbox["totalEmails"].as_u64()),
        (Some("Inbox"), Some("inbox"), Some(0))
    );
    let state = set["oldState"].as_str().unwrap().to_owned();

    let (_, changes) = setup.one(&alice, "Mailbox/changes", json!({ "accountId": id, "sinceState": state })).await;
    assert_eq!(changes["created"].as_array().unwrap().len(), 2);
    assert_eq!(changes["newState"], set["newState"]);

    // Errors of single calls, and of whole requests.
    assert_eq!(setup.one(&alice, "Mailbox/frobnicate", json!({ "accountId": id })).await.1["type"], "unknownMethod");
    assert_eq!(
        setup.one(&alice, "Mailbox/get", json!({ "accountId": Uuid::now_v7().to_string() })).await.1["type"],
        "accountNotFound"
    );
    let (_, error) = setup
        .one(
            &alice,
            "Mailbox/get",
            json!({ "accountId": id, "#ids": { "resultOf": "nope", "name": "Mailbox/query", "path": "/ids" } }),
        )
        .await;
    assert_eq!(error["type"], "invalidResultReference");
    assert_eq!(setup.jmap.api(&alice, b"{").await.unwrap_err(), RequestError::NotJson);
    let unknown = json!({ "using": ["urn:example:nothing"], "methodCalls": [] }).to_string();
    assert!(matches!(setup.jmap.api(&alice, unknown.as_bytes()).await, Err(RequestError::UnknownCapability(_))));
    let (_, echo) = setup.one(&alice, "Core/echo", json!({ "hello": true })).await;
    assert_eq!(echo, json!({ "hello": true }));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn emails_are_written_read_queried_and_changed(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let id = alice.account.to_string();
    let mail = setup.jmap.mail();
    let drafts = mail.mailbox_with_role(alice.account, Role::Drafts).await.unwrap().to_string();
    let inbox = mail.mailbox_with_role(alice.account, Role::Inbox).await.unwrap().to_string();

    let (_, set) = setup
        .one(
            &alice,
            "Email/set",
            json!({ "accountId": id, "create": { "d": {
                "mailboxIds": { &drafts: true },
                "keywords": { "$draft": true },
                "from": [{ "name": "Alice", "email": "alice@firma.example" }],
                "to": [{ "email": "bob@firma.example" }],
                "subject": "Lunch?",
                "bodyValues": { "1": { "value": "Shall we meet at noon?" } },
                "textBody": [{ "partId": "1", "type": "text/plain" }],
            } } }),
        )
        .await;
    let draft = set["created"]["d"]["id"].as_str().unwrap().to_owned();

    // Query and get in one request, by reference.
    let responses = setup
        .call(
            &alice,
            json!([
                ["Email/query", { "accountId": id, "filter": { "inMailbox": &drafts, "hasKeyword": "$draft" }, "calculateTotal": true }, "q"],
                ["Email/get", {
                    "accountId": id,
                    "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" },
                    "properties": ["subject", "from", "keywords", "mailboxIds", "textBody", "bodyValues", "header:Subject:asText", "blobId"],
                    "fetchTextBodyValues": true,
                }, "g"],
            ]),
        )
        .await;
    assert_eq!(responses["q"][0].1["ids"], json!([draft]));
    assert_eq!(responses["q"][0].1["total"], 1);
    let email = &responses["g"][0].1["list"][0];
    assert_eq!(email["subject"], "Lunch?");
    assert_eq!(email["header:Subject:asText"], "Lunch?");
    assert_eq!(email["from"][0]["email"], "alice@firma.example");
    let part = email["textBody"][0]["partId"].as_str().unwrap();
    assert_eq!(email["bodyValues"][part]["value"].as_str().unwrap().trim(), "Shall we meet at noon?");
    let part_blob = email["textBody"][0]["blobId"].as_str().unwrap();
    let content = setup.jmap.download(&alice, &id, part_blob, None).await.unwrap().collect().await.unwrap();
    assert_eq!(String::from_utf8_lossy(&content).trim(), "Shall we meet at noon?");

    // Keywords and mailboxes by patch.
    let (_, set) = setup
        .one(
            &alice,
            "Email/set",
            json!({ "accountId": id, "update": { &draft: { format!("mailboxIds/{drafts}"): null } } }),
        )
        .await;
    assert_eq!(set["notUpdated"][&draft]["type"], "invalidProperties", "an email is in at least one mailbox");
    let (_, set) = setup
        .one(&alice, "Email/set", json!({ "accountId": id, "update": { &draft: {
            "keywords/$draft": null, "keywords/$seen": true, format!("mailboxIds/{drafts}"): null, format!("mailboxIds/{inbox}"): true,
        } } }))
        .await;
    assert!(set["updated"].as_object().unwrap().contains_key(&draft), "{set}");
    let (_, got) = setup
        .one(
            &alice,
            "Email/get",
            json!({ "accountId": id, "ids": [&draft], "properties": ["keywords", "mailboxIds", "threadId"] }),
        )
        .await;
    assert_eq!(got["list"][0]["keywords"], json!({ "$seen": true }));
    assert_eq!(got["list"][0]["mailboxIds"], json!({ &inbox: true }));
    let thread = got["list"][0]["threadId"].as_str().unwrap().to_owned();
    let (_, threads) = setup.one(&alice, "Thread/get", json!({ "accountId": id, "ids": [&thread] })).await;
    assert_eq!(threads["list"][0]["emailIds"], json!([draft]));

    // Uploaded, parsed, imported.
    let raw = "From: carol@other.example\r\nTo: alice@firma.example\r\nSubject: Report\r\nMessage-ID: <r1@other.example>\r\n\
               Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n\
               --b\r\nContent-Type: text/csv; name=\"report.csv\"\r\nContent-Disposition: attachment; filename=\"report.csv\"\r\n\r\na,b\r\n1,2\r\n--b--\r\n";
    let upload = setup.jmap.upload_bytes(&alice, &id, "message/rfc822", Bytes::from(raw)).await.unwrap();
    let blob = upload["blobId"].as_str().unwrap().to_owned();
    let (_, parsed) = setup
        .one(
            &alice,
            "Email/parse",
            json!({ "accountId": id, "blobIds": [&blob], "properties": ["subject", "attachments"] }),
        )
        .await;
    assert_eq!(parsed["parsed"][&blob]["subject"], "Report");
    assert_eq!(parsed["parsed"][&blob]["attachments"][0]["name"], "report.csv");
    let (_, imported) = setup
        .one(&alice, "Email/import", json!({ "accountId": id, "emails": { "i": { "blobId": &blob, "mailboxIds": { &inbox: true }, "keywords": {} } } }))
        .await;
    let report = imported["created"]["i"]["id"].as_str().unwrap().to_owned();
    let (_, got) = setup
        .one(
            &alice,
            "Email/get",
            json!({ "accountId": id, "ids": [&report], "properties": ["hasAttachment", "attachments"] }),
        )
        .await;
    assert_eq!(got["list"][0]["hasAttachment"], true);
    let attachment = got["list"][0]["attachments"][0]["blobId"].as_str().unwrap();
    let content = setup.jmap.download(&alice, &id, attachment, None).await.unwrap().collect().await.unwrap();
    assert_eq!(String::from_utf8_lossy(&content).replace("\r\n", "\n").trim(), "a,b\n1,2");

    // Sorted and filtered by address; changes since a state.
    let (_, query) = setup.one(&alice, "Email/query", json!({ "accountId": id, "filter": { "from": "carol" } })).await;
    assert_eq!(query["ids"], json!([report]));
    let (_, query) = setup
        .one(&alice, "Email/query", json!({ "accountId": id, "filter": { "operator": "NOT", "conditions": [{ "from": "carol" }] }, "sort": [{ "property": "subject" }] }))
        .await;
    assert_eq!(query["ids"], json!([draft]));
    // Text through the full-text index: words and word beginnings, attachment names included.
    let (_, query) = setup.one(&alice, "Email/query", json!({ "accountId": id, "filter": { "body": "repo" } })).await;
    assert_eq!(query["ids"], json!([report]), "{query}");
    let (_, query) = setup.one(&alice, "Email/query", json!({ "accountId": id, "filter": { "body": "port" } })).await;
    assert_eq!(query["ids"], json!([]));
    assert_eq!(
        setup.one(&alice, "Email/query", json!({ "accountId": id, "filter": { "header": ["X-Spam"] } })).await.1["type"],
        "unsupportedFilter"
    );
    let state = got["state"].as_str().unwrap().to_owned();
    let (_, set) = setup.one(&alice, "Email/set", json!({ "accountId": id, "destroy": [&report] })).await;
    assert_eq!(set["destroyed"], json!([report]));
    let (_, changes) = setup.one(&alice, "Email/changes", json!({ "accountId": id, "sinceState": state })).await;
    assert_eq!(changes["destroyed"], json!([report]));
    let _ = setup.pool;
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn submissions_send_stored_emails(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let alice = setup.caller("alice").await;
    let bob = setup.caller("bob").await;
    let id = alice.account.to_string();
    let mail = setup.jmap.mail();
    let drafts = mail.mailbox_with_role(alice.account, Role::Drafts).await.unwrap().to_string();
    let sent = mail.mailbox_with_role(alice.account, Role::Sent).await.unwrap().to_string();

    let (_, identities) = setup.one(&alice, "Identity/get", json!({ "accountId": id })).await;
    let identity = identities["list"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(identities["list"][0]["email"], "alice@firma.example");

    let responses = setup
        .call(
            &alice,
            json!([
                ["Email/set", { "accountId": id, "create": { "e": {
                    "mailboxIds": { &drafts: true }, "keywords": { "$draft": true },
                    "from": [{ "email": "alice@firma.example" }],
                    "to": [{ "email": "bob@firma.example" }, { "email": "carol@remote.example" }],
                    "bcc": [{ "email": "dave@remote.example" }],
                    "subject": "Hello",
                    "bodyValues": { "1": { "value": "Hi" } }, "textBody": [{ "partId": "1" }],
                } } }, "c"],
                ["EmailSubmission/set", { "accountId": id,
                    "create": { "s": { "identityId": &identity, "emailId": "#e" } },
                    "onSuccessUpdateEmail": { "#s": { format!("mailboxIds/{drafts}"): null, format!("mailboxIds/{sent}"): true, "keywords/$draft": null } },
                }, "s"],
            ]),
        )
        .await;
    let submission = &responses["s"][0].1;
    assert!(submission["created"]["s"]["id"].is_string(), "{submission}");
    // The implicit Email/set moved the email to Sent.
    let (name, moved) = &responses["s"][1];
    assert_eq!(name, "Email/set");
    assert_eq!(moved["updated"].as_object().unwrap().len(), 1, "{moved}");

    // Bob has it at once, without the Bcc; the others wait in the queue.
    let bob_inbox = mail.mailbox_with_role(bob.account, Role::Inbox).await.unwrap();
    let query = kernoid_mail::EmailQuery { in_mailbox: Some(bob_inbox), ..Default::default() };
    let (ids, _) = mail.query(bob.account, &query, 0, 10).await.unwrap();
    let raw = String::from_utf8(mail.raw_email(bob.account, ids[0]).await.unwrap().to_vec()).unwrap();
    assert!(!raw.contains("dave@remote.example"), "{raw}");
    let queued =
        sqlx::query_scalar!("SELECT address FROM outbound_recipients ORDER BY address").fetch_all(&pool).await.unwrap();
    assert_eq!(queued, ["carol@remote.example", "dave@remote.example"]);

    // Sending as someone else is refused.
    let (_, set) = setup
        .one(&alice, "Email/set", json!({ "accountId": id, "create": { "f": {
            "mailboxIds": { &drafts: true }, "from": [{ "email": "bob@firma.example" }], "to": [{ "email": "x@remote.example" }], "subject": "Forged",
        } } }))
        .await;
    let forged = set["created"]["f"]["id"].as_str().unwrap();
    let (_, refused) = setup
        .one(
            &alice,
            "EmailSubmission/set",
            json!({ "accountId": id, "create": { "s": { "identityId": &identity, "emailId": forged } } }),
        )
        .await;
    assert_eq!(refused["notCreated"]["s"]["type"], "forbiddenFrom");
    let (_, listed) = setup.one(&alice, "EmailSubmission/get", json!({ "accountId": id })).await;
    assert_eq!(listed["list"].as_array().unwrap().len(), 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn held_submissions_wait_and_may_be_taken_back(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let alice = setup.caller("alice").await;
    let bob = setup.caller("bob").await;
    let id = alice.account.to_string();
    let mail = setup.jmap.mail();
    let drafts = mail.mailbox_with_role(alice.account, Role::Drafts).await.unwrap().to_string();
    let bob_inbox = mail.mailbox_with_role(bob.account, Role::Inbox).await.unwrap();
    let in_bobs_inbox = || async {
        let query = kernoid_mail::EmailQuery { in_mailbox: Some(bob_inbox), ..Default::default() };
        mail.query(bob.account, &query, 0, 10).await.unwrap().0.len()
    };
    let (_, identities) = setup.one(&alice, "Identity/get", json!({ "accountId": id })).await;
    let identity = identities["list"][0]["id"].as_str().unwrap().to_owned();
    let send = |subject: &'static str| {
        let (drafts, identity, id) = (drafts.clone(), identity.clone(), id.clone());
        let alice = &alice;
        let setup = &setup;
        async move {
            let responses = setup
                .call(
                    alice,
                    json!([
                        ["Email/set", { "accountId": id, "create": { "e": {
                            "mailboxIds": { &drafts: true }, "from": [{ "email": "alice@firma.example" }],
                            "to": [{ "email": "bob@firma.example" }, { "email": "carol@remote.example" }], "subject": subject,
                        } } }, "c"],
                        ["EmailSubmission/set", { "accountId": id, "create": { "s": {
                            "identityId": identity, "emailId": "#e",
                            "envelope": {
                                "mailFrom": { "email": "alice@firma.example", "parameters": { "HOLDFOR": "10" } },
                                "rcptTo": [{ "email": "bob@firma.example" }, { "email": "carol@remote.example" }],
                            },
                        } } }, "s"],
                    ]),
                )
                .await;
            responses["s"][0].1["created"]["s"].clone()
        }
    };

    // Held: pending, and nothing has gone anywhere yet.
    let first = send("Taken back").await;
    assert_eq!(first["undoStatus"], "pending", "{first}");
    assert_eq!(in_bobs_inbox().await, 0);
    assert!(sqlx::query_scalar!("SELECT address FROM outbound_recipients").fetch_all(&pool).await.unwrap().is_empty());
    // The held message belongs to its submission: nothing marks it as left behind.
    let marks = || async {
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM blob_garbage WHERE key LIKE 'submissions/%'"#)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert_eq!(marks().await, 0);

    // Taken back: canceled, and never sent – once due either.
    let (_, canceled) = setup
        .one(
            &alice,
            "EmailSubmission/set",
            json!({ "accountId": id, "update": { first["id"].as_str().unwrap(): { "undoStatus": "canceled" } } }),
        )
        .await;
    assert!(canceled["updated"].as_object().unwrap().contains_key(first["id"].as_str().unwrap()), "{canceled}");
    let second = send("Sent later").await;
    sqlx::query!("UPDATE email_submissions SET send_at = now() - interval '1 second'").execute(&pool).await.unwrap();
    assert_eq!(mail.release_held(10).await.unwrap(), 1);
    assert_eq!(in_bobs_inbox().await, 1);
    let queued = sqlx::query_scalar!("SELECT address FROM outbound_recipients").fetch_all(&pool).await.unwrap();
    assert_eq!(queued, ["carol@remote.example"]);
    // What was taken back and what was sent are garbage now.
    assert_eq!(marks().await, 2);

    // Once sent, it cannot be taken back.
    let (_, late) = setup
        .one(
            &alice,
            "EmailSubmission/set",
            json!({ "accountId": id, "update": { second["id"].as_str().unwrap(): { "undoStatus": "canceled" } } }),
        )
        .await;
    assert_eq!(late["notUpdated"][second["id"].as_str().unwrap()]["type"], "cannotUnsend");
    let (_, listed) = setup.one(&alice, "EmailSubmission/get", json!({ "accountId": id })).await;
    let statuses: Vec<&str> =
        listed["list"].as_array().unwrap().iter().map(|entry| entry["undoStatus"].as_str().unwrap()).collect();
    assert_eq!(statuses.len(), 2);
    assert!(statuses.contains(&"canceled") && statuses.contains(&"final"), "{statuses:?}");
    assert_eq!(mail.release_held(10).await.unwrap(), 0);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn shared_accounts_follow_the_grants(pool: PgPool) {
    use kernoid_identity::role::Principal;
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let bob = setup.caller("bob").await;
    let info = setup
        .identity
        .add_shared_mailbox(setup.tenant, &Address::parse("info@firma.example").unwrap(), "Info", WHO)
        .await
        .unwrap();
    let mail = setup.jmap.mail();
    mail.ensure_account(info).await.unwrap();
    let inbox = mail.mailbox_with_role(info, Role::Inbox).await.unwrap();
    let archive = mail.mailbox_with_role(info, Role::Archive).await.unwrap();
    let new = |mailbox| kernoid_mail::NewEmail { mailbox_ids: vec![mailbox], ..Default::default() };
    let question = mail
        .import_email(
            info,
            Bytes::from_static(b"From: x@remote.example\r\nSubject: Question\r\n\r\nHi\r\n"),
            new(inbox),
        )
        .await
        .unwrap()
        .id;
    mail.import_email(info, Bytes::from_static(b"From: y@remote.example\r\nSubject: Old\r\n\r\nOld\r\n"), new(archive))
        .await
        .unwrap();
    // Alice reads and flags the inbox and may send as info@; Bob has nothing.
    setup
        .identity
        .set_mail_access(info, Principal::Account(alice.account), Some(inbox), "lrsw", false, WHO)
        .await
        .unwrap();
    setup.identity.set_mail_access(info, Principal::Account(alice.account), None, "l", true, WHO).await.unwrap();
    let id = info.to_string();

    let session = setup.jmap.session(&alice, "https://login.firma.example").await.unwrap();
    let shared = &session["accounts"][&id];
    assert_eq!(
        (shared["name"].as_str(), shared["isPersonal"].as_bool(), shared["isReadOnly"].as_bool()),
        (Some("info@firma.example"), Some(false), Some(false))
    );
    assert!(shared["accountCapabilities"]["urn:ietf:params:jmap:submission"].is_object());
    let bob_session = setup.jmap.session(&bob, "https://login.firma.example").await.unwrap();
    assert!(bob_session["accounts"].get(&id).is_none());
    let (name, error) = setup.one(&bob, "Mailbox/get", json!({ "accountId": id })).await;
    assert_eq!((name.as_str(), error["type"].as_str()), ("error", Some("accountNotFound")));

    // Alice sees every mailbox (`l` on the store) but reads only the inbox.
    let (_, mailboxes) = setup.one(&alice, "Mailbox/get", json!({ "accountId": id })).await;
    assert_eq!(mailboxes["list"].as_array().unwrap().len(), 6);
    let rights =
        mailboxes["list"].as_array().unwrap().iter().find(|m| m["role"] == "inbox").unwrap()["myRights"].clone();
    assert_eq!(
        (rights["mayReadItems"].as_bool(), rights["mayRemoveItems"].as_bool(), rights["maySubmit"].as_bool()),
        (Some(true), Some(false), Some(true))
    );
    let (_, query) = setup.one(&alice, "Email/query", json!({ "accountId": id })).await;
    assert_eq!(query["ids"], json!([question.to_string()]), "the archive is not readable");
    let (_, set) = setup
        .one(&alice, "Email/set", json!({ "accountId": id, "update": { question.to_string(): { "keywords/$seen": true } }, "destroy": [question.to_string()] }))
        .await;
    assert!(set["updated"].as_object().unwrap().contains_key(&question.to_string()), "{set}");
    assert_eq!(set["notDestroyed"][question.to_string()]["type"], "forbidden", "{set}");
    let (_, set) =
        setup.one(&alice, "Mailbox/set", json!({ "accountId": id, "create": { "m": { "name": "Mine" } } })).await;
    assert_eq!(set["notCreated"]["m"]["type"], "forbidden", "{set}");
    let (_, identities) = setup.one(&alice, "Identity/get", json!({ "accountId": id })).await;
    assert_eq!(identities["list"][0]["email"], "info@firma.example");
}

/// What the web app sends: the email moved to Sent with `mailboxIds` as a whole, `$draft` removed by a patch.
#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn submissions_move_the_email_to_sent(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let alice = setup.caller("alice").await;
    let id = alice.account.to_string();
    let mail = setup.jmap.mail();
    let drafts = mail.mailbox_with_role(alice.account, Role::Drafts).await.unwrap().to_string();
    let sent = mail.mailbox_with_role(alice.account, Role::Sent).await.unwrap().to_string();
    let (_, identities) = setup.one(&alice, "Identity/get", json!({ "accountId": id })).await;
    let identity = identities["list"][0]["id"].as_str().unwrap().to_owned();

    let responses = setup
        .call(
            &alice,
            json!([
                ["Email/set", { "accountId": id, "create": { "draft": {
                    "mailboxIds": { &drafts: true }, "keywords": { "$draft": true, "$seen": true },
                    "from": [{ "name": null, "email": "alice@firma.example" }],
                    "to": [{ "email": "carol@remote.example" }],
                    "subject": "Hello",
                    "bodyValues": { "body": { "value": "Hi" } }, "textBody": [{ "partId": "body", "type": "text/plain" }],
                } } }, "e"],
                ["EmailSubmission/set", { "accountId": id,
                    "create": { "send": { "identityId": &identity, "emailId": "#draft" } },
                    "onSuccessUpdateEmail": { "#send": { "keywords/$draft": null, "mailboxIds": { &sent: true } } },
                }, "s"],
            ]),
        )
        .await;
    let (name, moved) = &responses["s"][1];
    assert_eq!(name, "Email/set");
    assert_eq!(moved["updated"].as_object().map(|updated| updated.len()), Some(1), "{moved}");
    let email = responses["e"][0].1["created"]["draft"]["id"].as_str().unwrap().to_owned();
    let (_, got) = setup
        .one(&alice, "Email/get", json!({ "accountId": id, "ids": [&email], "properties": ["mailboxIds", "keywords"] }))
        .await;
    assert_eq!(got["list"][0]["mailboxIds"], json!({ &sent: true }), "{got}");
    assert_eq!(got["list"][0]["keywords"], json!({ "$seen": true }), "{got}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_vacation_response_is_a_singleton_of_the_own_account(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice").await;
    let session = setup.jmap.session(&alice, "https://login.firma.example").await.unwrap();
    assert_eq!(session["primaryAccounts"][kernoid_jmap::VACATION], json!(alice.account.to_string()));
    let request =
        |calls: Value| json!({ "using": ["urn:ietf:params:jmap:core", kernoid_jmap::VACATION], "methodCalls": calls });
    let account = alice.account.to_string();
    let (jmap, caller) = (&setup.jmap, &alice);
    let run = |calls: Value| {
        let body = request(calls).to_string();
        async move { jmap.api(caller, body.as_bytes()).await }
    };

    let got = run(json!([["VacationResponse/get", { "accountId": account, "ids": null }, "g"]])).await.unwrap();
    let off = &got["methodResponses"][0][1];
    assert_eq!(
        off["list"][0],
        json!({ "id": "singleton", "isEnabled": false, "fromDate": null, "toDate": null,
        "subject": null, "textBody": null, "htmlBody": null })
    );
    let set = run(json!([["VacationResponse/set", { "accountId": account, "update": { "singleton": {
        "isEnabled": true, "toDate": "2026-11-09T00:00:00Z", "subject": "Away", "textBody": "Back on Monday." } },
        "create": { "x": {} }, "destroy": ["singleton"] }, "s"]]))
    .await
    .unwrap();
    let set = &set["methodResponses"][0][1];
    assert!(set["updated"].get("singleton").is_some(), "{set}");
    assert_eq!(
        (set["notCreated"]["x"]["type"].as_str(), set["notDestroyed"]["singleton"]["type"].as_str()),
        (Some("singleton"), Some("singleton"))
    );
    assert_ne!(set["oldState"], set["newState"]);
    let got = run(json!([["VacationResponse/get", { "accountId": account, "ids": ["singleton", "other"] }, "g"]]))
        .await
        .unwrap();
    let on = &got["methodResponses"][0][1];
    assert_eq!(
        (on["list"][0]["isEnabled"].as_bool(), on["list"][0]["toDate"].as_str()),
        (Some(true), Some("2026-11-09T00:00:00Z"))
    );
    assert_eq!(on["notFound"], json!(["other"]));
    let wrong = run(json!([["VacationResponse/set", { "accountId": account, "update": { "singleton": { "toDate": "monday" } } }, "s"]])).await.unwrap();
    assert_eq!(wrong["methodResponses"][0][1]["notUpdated"]["singleton"]["type"], "invalidProperties");
}
