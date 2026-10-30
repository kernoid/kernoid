// SPDX-License-Identifier: MIT
//! End-to-end encrypted mail against a server that records what it is sent (RFC 0006, 4–5): unlocking the key with
//! the recovery code, the summaries of the list, reading an encrypted email, and sending one encrypted. The keys are
//! made here with kernoid-e2e, as the web app makes them.

mod support;

use std::sync::{Arc, OnceLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use kernoid_e2e::{
    Kind, PublicKey, SecretKey, compose,
    keys::{normalize_recovery_code, recovery_code},
    mime,
};
use kernoid_tui::jmap::{
    self, Client, Options,
    e2e::{E2e, OPENPGP, Outgoing, Plan},
    mail::{self, Draft, Identity, parse_addresses},
};
use serde_json::{Value, json};
use support::{Answer, Request, Server};

/// Alice's key in use, a retired one of hers, Bob's – made once, as Argon2 and the keys take a while.
struct Keys {
    alice: SecretKey,
    retired: SecretKey,
    bob: SecretKey,
    code: String,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        alice: SecretKey::generate(Kind::Pqc, &["alice@firma.example"]).unwrap(),
        retired: SecretKey::generate(Kind::Compatible, &["alice@firma.example"]).unwrap(),
        bob: SecretKey::generate(Kind::Compatible, &["bob@x.example"]).unwrap(),
        code: recovery_code(),
    })
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn session() -> Value {
    let all = json!({ "urn:ietf:params:jmap:mail": {}, "urn:ietf:params:jmap:submission": {}, OPENPGP: {} });
    json!({
        "capabilities": { "urn:ietf:params:jmap:core": {}, "urn:ietf:params:jmap:mail": {},
                          "urn:ietf:params:jmap:submission": {}, OPENPGP: {} },
        "accounts": { "A": { "name": "alice@firma.example", "isPersonal": true, "accountCapabilities": all } },
        "primaryAccounts": { "urn:ietf:params:jmap:mail": "A", "urn:ietf:params:jmap:submission": "A", OPENPGP: "A" },
        "username": "alice@firma.example",
        "apiUrl": "/jmap/api",
        "downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
        "uploadUrl": "/jmap/upload/{accountId}/",
        "eventSourceUrl": "/jmap/eventsource",
        "state": "s1",
    })
}

/// Bob's message to Alice, encrypted to her key and signed by his – as kernoid stores it after encrypting it on
/// arrival, or as Bob's app sends it.
fn message() -> Vec<u8> {
    let draft = compose::Draft {
        from: Some(compose::Mailbox { name: Some("Bob".into()), email: "bob@x.example".into() }),
        to: vec![compose::Mailbox { name: None, email: "alice@firma.example".into() }],
        subject: "The secret plan".into(),
        message_id: "m1@x.example".into(),
        date: "Fri, 30 Oct 2026 10:00:00 +0100".into(),
        text: "Meet at noon.".into(),
        attachments: vec![compose::Attachment {
            name: "plan.txt".into(),
            media_type: "text/plain".into(),
            data: b64(b"step one"),
        }],
        ..compose::Draft::default()
    };
    let raw = compose::build(&draft).unwrap();
    let keys = keys();
    mime::encrypt_message(&raw, &[&keys.alice.public()], Some(&keys.bob)).unwrap()
}

/// The summary of `message`, encrypted to `key`.
fn summary(key: &PublicKey) -> String {
    let raw = compose::build(&compose::Draft {
        from: Some(compose::Mailbox { name: None, email: "bob@x.example".into() }),
        subject: "The secret plan".into(),
        message_id: "m1@x.example".into(),
        date: "Fri, 30 Oct 2026 10:00:00 +0100".into(),
        text: "Meet at noon.".into(),
        ..compose::Draft::default()
    })
    .unwrap();
    b64(&mime::encrypted_summary(&raw, &[key]).unwrap())
}

fn method(name: &str, arguments: &Value, stored: &Stored) -> Value {
    let account = arguments["accountId"].clone();
    let keys = keys();
    match name {
        "OpenPgpKey/get" => json!({ "accountId": account, "list": [
            { "id": keys.alice.fingerprint(), "kind": "pqc", "publicKey": b64(&keys.alice.public().to_bytes().unwrap()),
              "created": "2026-10-30T09:00:00Z", "retired": null, "copies": { "recovery": stored.alice_copy } },
            { "id": keys.retired.fingerprint(), "kind": "compatible", "publicKey": b64(&keys.retired.public().to_bytes().unwrap()),
              "created": "2026-10-01T09:00:00Z", "retired": "2026-10-30T09:00:00Z", "copies": { "recovery": stored.retired_copy } },
        ] }),
        "OpenPgpKey/lookup" => {
            let list: Vec<Value> = arguments["emails"]
                .as_array()
                .unwrap()
                .iter()
                .map(|email| {
                    let found = match email.as_str().unwrap() {
                        "bob@x.example" => vec![json!({ "id": keys.bob.fingerprint(), "kind": "compatible",
                            "publicKey": b64(&keys.bob.public().to_bytes().unwrap()), "source": "wkd" })],
                        "alice@firma.example" => vec![json!({ "id": keys.alice.fingerprint(), "kind": "pqc",
                            "publicKey": b64(&keys.alice.public().to_bytes().unwrap()), "source": "directory" })],
                        _ => Vec::new(),
                    };
                    json!({ "email": email, "keys": found })
                })
                .collect();
            json!({ "accountId": account, "list": list })
        }
        "Mailbox/get" => json!({ "accountId": account, "list": [
            { "id": "m1", "name": "Inbox", "role": "inbox" },
            { "id": "m2", "name": "Drafts", "role": "drafts" },
            { "id": "m3", "name": "Sent", "role": "sent" },
        ] }),
        "Email/query" => json!({ "accountId": account, "ids": ["e1", "e2", "e3"], "total": 3 }),
        // e1 encrypted to the key in use, e2 to the retired key, e3 plain. The server knows only `[...]`.
        "Email/get" => json!({ "accountId": account, "list": [
            { "id": "e1", "threadId": "t1", "mailboxIds": { "m1": true }, "keywords": {}, "subject": "[...]",
              "from": [{ "name": "Bob", "email": "bob@x.example" }], "receivedAt": "2026-10-30T09:00:00Z",
              "preview": "This is an OpenPGP/MIME encrypted message", "hasAttachment": true, "blobId": "R1",
              "kernoid:encrypted": true, "kernoid:encryptedSummary": stored.summary_current,
              "textBody": [{ "partId": "1", "type": "text/plain" }], "bodyValues": { "1": { "value": "This is an OpenPGP/MIME encrypted message" } },
              "attachments": [{ "partId": "3", "blobId": "B3", "type": "application/octet-stream", "name": "encrypted.asc" }] },
            { "id": "e2", "threadId": "t2", "mailboxIds": { "m1": true }, "keywords": {}, "subject": "[...]",
              "receivedAt": "2026-10-01T09:00:00Z", "kernoid:encrypted": true,
              "kernoid:encryptedSummary": stored.summary_retired },
            { "id": "e3", "threadId": "t3", "mailboxIds": { "m1": true }, "keywords": {}, "subject": "Plain",
              "receivedAt": "2026-09-01T09:00:00Z", "kernoid:encrypted": false, "kernoid:encryptedSummary": null },
        ] }),
        "Email/import" => json!({ "accountId": account, "created": { "draft": { "id": "e9" } } }),
        "EmailSubmission/set" => json!({ "accountId": account, "created": { "send": { "id": "s1" } } }),
        _ => json!({ "type": "unknownMethod" }),
    }
}

/// What the server answers with, made once per test: copies and summaries cost an Argon2 or an encryption each.
struct Stored {
    alice_copy: Value,
    retired_copy: Value,
    summary_current: String,
    summary_retired: String,
    message: Vec<u8>,
}

fn server() -> Server {
    let keys = keys();
    let copy = |key: &SecretKey| json!({ "protected": b64(&key.protect(&normalize_recovery_code(&keys.code)).unwrap()), "salt": null });
    let stored = Arc::new(Stored {
        alice_copy: copy(&keys.alice),
        retired_copy: copy(&keys.retired),
        summary_current: summary(&keys.alice.public()),
        summary_retired: summary(&keys.retired.public()),
        message: message(),
    });
    Server::start(move |request: &Request| match (request.method.as_str(), request.path.split('?').next().unwrap()) {
        ("GET", "/.well-known/jmap") => Answer::redirect("/jmap/session"),
        ("GET", "/jmap/session") => Answer::json(200, session()),
        ("POST", "/jmap/api") => {
            let responses: Vec<Value> = request
                .calls()
                .iter()
                .zip(request.json()["methodCalls"].as_array().unwrap())
                .map(|((name, arguments), call)| {
                    let mut answer = method(name, arguments, &stored);
                    if let (Some(ids), Some(list)) = (arguments["ids"].as_array(), answer["list"].as_array().cloned()) {
                        answer["list"] = json!(list.into_iter().filter(|o| ids.contains(&o["id"])).collect::<Vec<_>>());
                    }
                    let name = if answer.get("type").is_some() { "error" } else { name.as_str() };
                    json!([name, answer, call[2]])
                })
                .collect();
            Answer::json(200, json!({ "methodResponses": responses, "sessionState": "s1" }))
        }
        ("GET", "/jmap/download/A/R1/message.eml") => Answer::bytes(&stored.message),
        ("POST", "/jmap/upload/A/") => Answer::json(
            201,
            json!({ "accountId": "A", "blobId": "U1", "type": request.header("content-type"), "size": request.body.len() }),
        ),
        _ => Answer::json(404, json!({ "type": "about:blank", "status": 404 })),
    })
}

fn connect(server: &Server) -> Client {
    let url = jmap::session_url(Some(&server.origin), "alice@firma.example").unwrap();
    Client::connect(&url, "alice@firma.example", "app-password", &Options::default()).unwrap()
}

fn identity() -> Identity {
    Identity { id: "i1".into(), name: "Alice".into(), email: "alice@firma.example".into() }
}

#[test]
fn unlocking_with_the_recovery_code() {
    let server = server();
    let client = connect(&server);
    let mut e2e = E2e::load(&client).unwrap();
    assert!(e2e.available && e2e.has_key() && !e2e.is_unlocked());
    assert_eq!(e2e.current_key().unwrap().id, keys().alice.fingerprint());
    let error = e2e.unlock("0000-0000-0000-0000-0000-0000-0000-0000").unwrap_err();
    assert!(error.to_string().contains("wrong passphrase"), "{error}");
    assert!(!e2e.is_unlocked());
    // As people type it: lower case, without the dashes.
    e2e.unlock(&keys().code.to_lowercase().replace('-', " ")).unwrap();
    assert!(e2e.is_unlocked());
    assert!(!format!("{e2e:?}").contains("BEGIN"), "no key in Debug");
    e2e.lock();
    assert!(!e2e.is_unlocked());
}

#[test]
fn the_list_shows_decrypted_summaries() {
    let server = server();
    let client = connect(&server);
    let (mut list, _) = mail::emails(&client, "A", Some("m1"), "", 0, 50).unwrap();
    let request = server.api_requests().pop().unwrap();
    assert_eq!(request.json()["using"], json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", OPENPGP]));
    let properties = &request.calls()[1].1["properties"];
    assert!(properties.as_array().unwrap().contains(&json!("kernoid:encryptedSummary")), "{properties}");
    let mut e2e = E2e::load(&client).unwrap();
    // Locked: as the server has them.
    for email in &mut list {
        e2e.open_summary(email);
    }
    assert!(list[0].encrypted && !list[0].opened);
    assert_eq!(list[0].subject.as_deref(), Some("[...]"));
    e2e.unlock(&keys().code).unwrap();
    for email in &mut list {
        e2e.open_summary(email);
    }
    assert!(list[0].opened);
    assert_eq!(list[0].subject.as_deref(), Some("The secret plan"));
    assert_eq!(list[0].preview, "Meet at noon.");
    // Encrypted to the retired key, which the same code opened.
    assert!(list[1].opened, "the retired key decrypts its mail");
    assert!(!list[2].encrypted && !list[2].opened);
    assert_eq!(list[2].subject.as_deref(), Some("Plain"));
}

#[test]
fn reading_an_encrypted_email() {
    let server = server();
    let client = connect(&server);
    let mut e2e = E2e::load(&client).unwrap();
    let email = mail::email(&client, "A", "e1").unwrap().unwrap();
    // Locked: nothing of the outer message is shown, nothing downloaded.
    let locked = e2e.open(&client, "A", email.clone()).unwrap();
    assert!(locked.sealed.unwrap().locked);
    assert!(locked.attachments.is_empty() && locked.text(80).is_empty());
    assert!(!server.requests().iter().any(|r| r.path.starts_with("/jmap/download/")));

    e2e.unlock(&keys().code).unwrap();
    let read = e2e.open(&client, "A", email).unwrap();
    let sealed = read.sealed.unwrap();
    assert!(!sealed.locked && sealed.signed && sealed.verified, "{sealed:?}");
    assert_eq!(read.summary.subject.as_deref(), Some("The secret plan"));
    assert_eq!(read.text(80), "Meet at noon.");
    assert_eq!(read.message_id.as_deref(), Some(&["m1@x.example".to_owned()][..]));
    assert_eq!(read.attachments.len(), 1);
    let part = &read.attachments[0];
    assert_eq!(part.name.as_deref(), Some("plan.txt"));
    assert!(part.blob_id.is_none());
    assert_eq!(read.part(part).unwrap().unwrap(), b"step one");
    // The raw message was downloaded; nothing went to Email/parse.
    assert!(server.requests().iter().any(|r| r.path.starts_with("/jmap/download/A/R1/")));
    assert!(!server.api_requests().iter().flat_map(|r| r.calls()).any(|(name, _)| name == "Email/parse"));
}

#[test]
fn sending_encrypted_to_recipients_with_keys() {
    let server = server();
    let client = connect(&server);
    let boxes = mail::mailboxes(&client, "A").unwrap();
    let mut e2e = E2e::load(&client).unwrap();
    let draft = Draft {
        to: parse_addresses("Bob <bob@x.example>"),
        subject: "Re: The secret plan".into(),
        body: "Noon it is.".into(),
        in_reply_to: vec!["m1@x.example".into()],
        ..Draft::default()
    };
    let identity = identity();
    // Locked: plain, and why.
    let Plan::Plain(reason) = e2e.plan(&client, "A", &identity, &draft) else { panic!("sealed while locked") };
    assert!(reason.contains("locked"), "{reason}");
    e2e.unlock(&keys().code).unwrap();
    // A recipient without a key, or Bcc: plain.
    let carol = Draft { cc: parse_addresses("carol@y.example"), ..draft.clone() };
    let Plan::Plain(reason) = e2e.plan(&client, "A", &identity, &carol) else { panic!("sealed without Carol's key") };
    assert!(reason.contains("carol@y.example has no key"), "{reason}");
    let hidden = Draft { bcc: parse_addresses("dave@x.example"), ..draft.clone() };
    assert!(matches!(e2e.plan(&client, "A", &identity, &hidden), Plan::Plain(_)));
    let Plan::Sealed(recipients) = e2e.plan(&client, "A", &identity, &draft) else { panic!("not sealed") };
    assert_eq!(recipients.len(), 2, "Bob's key and Alice's own");

    let directory = std::env::temp_dir().join(format!("kernoid-tui-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join("notes.txt");
    std::fs::write(&file, "bring cake").unwrap();
    let files = [file];
    let outgoing = Outgoing { account: "A", identity: &identity, draft: &draft, files: &files, boxes: &boxes };
    e2e.send(&client, outgoing, &recipients).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();

    // The upload is the PGP/MIME message; Bob reads it, signed by Alice; the file is inside.
    let upload = server.requests().into_iter().find(|r| r.path == "/jmap/upload/A/").unwrap();
    assert_eq!(upload.header("content-type"), Some("message/rfc822"));
    assert!(mime::is_encrypted(&upload.body));
    let text = String::from_utf8_lossy(&upload.body);
    assert!(!text.contains("Noon it is") && !text.contains("bring cake") && text.contains("Subject: [...]"));
    let keys = keys();
    let opened = mime::decrypt_message(&upload.body, &[&keys.bob], &[&keys.alice.public()]).unwrap();
    assert!(opened.verified_by.is_some());
    let parsed = compose::parse(&opened.data).unwrap();
    assert_eq!(parsed.subject.as_deref(), Some("Re: The secret plan"));
    assert_eq!(parsed.in_reply_to, ["m1@x.example"]);
    assert_eq!(parsed.text.as_deref().map(str::trim), Some("Noon it is."));
    assert_eq!(compose::part(&opened.data, parsed.attachments[0].index).unwrap(), b"bring cake");
    // Alice can read her copy in Sent.
    assert!(mime::decrypt_message(&upload.body, &[&keys.alice], &[]).is_ok());

    let calls = server.api_requests().pop().unwrap().calls();
    let imported = &calls[0].1["emails"]["draft"];
    assert_eq!(calls[0].0, "Email/import");
    assert_eq!(imported["blobId"], "U1");
    assert_eq!(imported["mailboxIds"], json!({ "m2": true }));
    assert_eq!(imported["keywords"], json!({ "$draft": true, "$seen": true }));
    let summary = STANDARD.decode(imported["kernoid:encryptedSummary"].as_str().unwrap()).unwrap();
    assert_eq!(
        mime::decrypt_summary(&summary, &[&keys.alice]).unwrap().subject.as_deref(),
        Some("Re: The secret plan")
    );
    assert!(mime::decrypt_summary(&summary, &[&keys.bob]).is_err(), "the summary is for the sender only");
    assert_eq!(calls[1].0, "EmailSubmission/set");
    assert_eq!(
        calls[1].1["create"]["send"],
        json!({ "identityId": "i1", "emailId": "#draft", "envelope": {
            "mailFrom": { "email": "alice@firma.example", "parameters": null },
            "rcptTo": [{ "email": "bob@x.example", "parameters": null }],
        } })
    );
    assert_eq!(
        calls[1].1["onSuccessUpdateEmail"]["#send"],
        json!({ "keywords/$draft": null, "mailboxIds": { "m3": true } })
    );
    // No Email/set: the server never saw the text.
    assert!(!server.api_requests().iter().flat_map(|r| r.calls()).any(|(name, _)| name == "Email/set"));
}

#[test]
fn drafts_kept_encrypted_to_the_own_key() {
    let server = server();
    let client = connect(&server);
    let boxes = mail::mailboxes(&client, "A").unwrap();
    let mut e2e = E2e::load(&client).unwrap();
    e2e.unlock(&keys().code).unwrap();
    let draft = Draft { to: parse_addresses("carol@y.example"), subject: "Later".into(), ..Draft::default() };
    let Plan::Sealed(own) = e2e.draft_plan(&client, "A", &identity(), &draft) else { panic!("not sealed") };
    let outgoing = Outgoing { account: "A", identity: &identity(), draft: &draft, files: &[], boxes: &boxes };
    e2e.keep(&client, outgoing, &own).unwrap();
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls.len(), 1, "kept, not submitted");
    let upload = server.requests().into_iter().find(|r| r.path == "/jmap/upload/A/").unwrap();
    assert!(mime::decrypt_message(&upload.body, &[&keys().alice], &[]).is_ok());
    // Not from the own account: plain.
    assert!(matches!(e2e.draft_plan(&client, "S", &identity(), &draft), Plan::Plain(_)));
}
