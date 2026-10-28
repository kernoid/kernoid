// SPDX-License-Identifier: MIT
//! The JMAP layer against a server that records what it is sent: logging in, method calls and their errors, mail,
//! files with downloads, uploads and versions, calendars, contacts.

mod support;

use std::{collections::BTreeSet, io::Cursor};

use kernoid_tui::jmap::{
    self, Client, Error, Options, calendars, contacts, files,
    mail::{self, Draft, Identity, parse_addresses},
    push::{Events, changed_types},
};
use serde_json::{Value, json};
use support::{Answer, Request, Server};

const PASSWORD: &str = "app-password";

fn session() -> Value {
    let all = json!({
        "urn:ietf:params:jmap:mail": {}, "urn:ietf:params:jmap:submission": {},
        "urn:ietf:params:jmap:filenode": {}, "urn:ietf:params:jmap:calendars": {},
        "urn:ietf:params:jmap:contacts": {}, "urn:ietf:params:jmap:principals": {},
    });
    // The URLs name the instance's public host, as kernoid builds them; the client keeps to the origin it used.
    json!({
        "capabilities": { "urn:ietf:params:jmap:core": {} },
        "accounts": {
            "A": { "name": "alice@firma.example", "isPersonal": true, "isReadOnly": false, "accountCapabilities": all },
            "D": { "name": "Team", "isPersonal": false, "isReadOnly": false, "kernoid:drive": true,
                   "accountCapabilities": { "urn:ietf:params:jmap:filenode": {} } },
            "S": { "name": "bob@firma.example", "isPersonal": false, "isReadOnly": false,
                   "accountCapabilities": { "urn:ietf:params:jmap:filenode": {}, "urn:ietf:params:jmap:calendars": {} } },
        },
        "primaryAccounts": {
            "urn:ietf:params:jmap:mail": "A", "urn:ietf:params:jmap:submission": "A",
            "urn:ietf:params:jmap:filenode": "A", "urn:ietf:params:jmap:calendars": "A",
            "urn:ietf:params:jmap:contacts": "A", "urn:ietf:params:jmap:principals": "A",
        },
        "username": "alice@firma.example",
        "apiUrl": "http://login.firma.example/jmap/api",
        "downloadUrl": "http://login.firma.example/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
        "uploadUrl": "http://login.firma.example/jmap/upload/{accountId}/",
        "eventSourceUrl": "http://login.firma.example/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
        "state": "s1",
    })
}

fn authorized(request: &Request) -> bool {
    use base64::Engine;
    let expected = base64::engine::general_purpose::STANDARD.encode(format!("alice@firma.example:{PASSWORD}"));
    request.header("authorization") == Some(&format!("Basic {expected}"))
}

/// The answer of a method call, as the tests' server gives it.
fn method(name: &str, arguments: &Value) -> Value {
    let account = arguments["accountId"].clone();
    match name {
        "Mailbox/get" => json!({ "accountId": account, "state": "1", "notFound": [], "list": [
            { "id": "m9", "name": "Archive", "role": null, "sortOrder": 0, "totalEmails": 0, "unreadEmails": 0 },
            { "id": "m2", "name": "Drafts", "role": "drafts", "sortOrder": 0, "totalEmails": 0, "unreadEmails": 0 },
            { "id": "m1", "name": "Inbox", "role": "inbox", "sortOrder": 0, "totalEmails": 2, "unreadEmails": 1 },
            { "id": "m3", "name": "Sent", "role": "sent", "sortOrder": 0, "totalEmails": 0, "unreadEmails": 0 },
        ] }),
        "Email/query" => {
            json!({ "accountId": account, "ids": ["e1", "e2"], "position": 0, "total": 2, "queryState": "q" })
        }
        "Email/get" => json!({ "accountId": account, "state": "1", "notFound": [], "list": [
            { "id": "e1", "threadId": "t1", "mailboxIds": { "m1": true }, "keywords": { "$seen": true },
              "from": [{ "name": "Bob", "email": "bob@firma.example" }], "subject": "Hello",
              "receivedAt": "2026-10-28T09:00:00Z", "preview": "Hi", "hasAttachment": false,
              "messageId": ["m1@firma.example"], "textBody": [{ "partId": "1", "type": "text/plain" }],
              "htmlBody": [{ "partId": "1", "type": "text/plain" }], "attachments": [],
              "bodyValues": { "1": { "value": "Hi Alice" } } },
            { "id": "e2", "threadId": "t2", "mailboxIds": { "m1": true }, "keywords": {}, "subject": null,
              "receivedAt": "2026-10-27T09:00:00Z", "preview": "", "hasAttachment": true },
            // The reply in Sent: a member of thread t1, asked for through Thread/get only.
            { "id": "e3", "threadId": "t1", "mailboxIds": { "m3": true }, "keywords": { "$seen": true },
              "from": [{ "name": "Alice", "email": "alice@firma.example" }], "subject": "Re: Hello",
              "receivedAt": "2026-10-28T10:00:00Z", "preview": "Thanks", "hasAttachment": false },
        ] }),
        "Thread/get" => json!({ "accountId": account, "list": [
            { "id": "t1", "emailIds": ["e1", "e3"] }, { "id": "t2", "emailIds": ["e2"] },
        ] }),
        "Email/set" if arguments.get("create").is_some() => {
            json!({ "accountId": account, "newState": "2", "created": { "draft": { "id": "e9" } } })
        }
        "Email/set" if arguments["update"].get("forbidden").is_some() => json!({ "accountId": account, "newState": "2",
            "notUpdated": { "forbidden": { "type": "forbidden", "description": "not yours" } } }),
        "Email/set" => json!({ "accountId": account, "newState": "2", "updated": {}, "destroyed": [] }),
        "EmailSubmission/set" => {
            json!({ "accountId": account, "newState": "2", "created": { "send": { "id": "s1" } } })
        }
        "Identity/get" => {
            json!({ "accountId": account, "list": [{ "id": "i1", "name": "Alice", "email": "alice@firma.example" }] })
        }
        "FileNode/query" => json!({ "accountId": account, "ids": ["n1", "n2", "n3"] }),
        "FileNode/get" => json!({ "accountId": account, "list": [
            { "@type": "File", "id": "n1", "parentId": null, "name": "b.txt", "blobId": "F1", "size": 5,
              "mediaType": "text/plain", "myRights": { "mayRead": true } },
            { "@type": "Directory", "id": "n2", "parentId": null, "name": "Projects", "shareWith": { "p2": { "mayRead": true } } },
            { "@type": "File", "id": "n3", "parentId": null, "name": "a.pdf", "blobId": "F3", "size": 9 },
        ] }),
        "FileNode/set" => {
            json!({ "accountId": account, "newState": "2", "created": { "f": { "id": "n4" } }, "updated": {} })
        }
        "FileVersion/get" => json!({ "accountId": account, "list": [
            { "id": "v2", "blobId": "V2", "size": 5, "modified": "2026-10-28T10:00:00Z", "created": "2026-10-28T10:00:00Z", "isCurrent": true },
            { "id": "v1", "blobId": "V1", "size": 3, "modified": "2026-10-27T10:00:00Z", "created": "2026-10-27T10:00:00Z", "isCurrent": false },
        ] }),
        "Calendar/get" => {
            json!({ "accountId": account, "list": [{ "id": format!("c-{}", account.as_str().unwrap()), "name": "Calendar" }] })
        }
        "CalendarEvent/query" => json!({ "accountId": account, "ids": ["x"] }),
        "CalendarEvent/get" if account == "A" => json!({ "accountId": account, "list": [
            { "id": "ev2.1", "calendarIds": { "c-A": true }, "title": "Later", "start": "2026-11-02T10:00:00",
              "utcStart": "2026-11-02T09:00:00Z", "utcEnd": "2026-11-02T10:00:00Z", "locations": { "l": { "name": "Room 1" } } },
        ] }),
        "CalendarEvent/get" => json!({ "accountId": account, "list": [
            { "id": "ev1", "calendarIds": { "c-S": true }, "title": "Sooner", "start": "2026-11-01T00:00:00",
              "showWithoutTime": true, "duration": "P1D" },
        ] }),
        "ContactCard/query" => json!({ "accountId": account, "ids": ["k1", "k2"] }),
        "ContactCard/get" => json!({ "accountId": account, "list": [
            { "id": "k1", "name": { "components": [{ "kind": "given", "value": "Zoe" }, { "kind": "surname", "value": "Z" }] } },
            { "id": "k2", "name": { "full": "Anna A" }, "emails": { "e": { "address": "anna@x.example" } },
              "phones": { "p": { "number": "+49 1" } } },
        ] }),
        "AddressBook/get" => json!({ "accountId": account, "list": [
            { "id": "b2", "name": "Work", "isDefault": false, "myRights": { "mayWrite": false } },
            { "id": "b1", "name": "Contacts", "isDefault": true, "myRights": { "mayWrite": true } },
        ] }),
        "ContactCard/set" | "CalendarEvent/set" if arguments.get("create").is_some() => {
            json!({ "accountId": account, "newState": "2", "created": { "c": { "id": "k9" }, "e": { "id": "ev9" } } })
        }
        "ContactCard/set" | "CalendarEvent/set" => {
            json!({ "accountId": account, "newState": "2", "updated": {}, "destroyed": [] })
        }
        "Principal/query" => json!({ "accountId": account, "ids": ["p2"] }),
        "Principal/get" => {
            json!({ "accountId": account, "list": [{ "id": "p2", "type": "individual", "name": "Bob", "email": "bob@firma.example" }] })
        }
        "Fail/now" => json!({ "type": "invalidArguments", "description": "no" }),
        _ => json!({ "type": "unknownMethod" }),
    }
}

fn server() -> Server {
    Server::start(|request| {
        if !authorized(request) {
            return Answer {
                status: 401,
                headers: vec![("www-authenticate".into(), "Basic".into())],
                body: Vec::new(),
            };
        }
        match (request.method.as_str(), request.path.split('?').next().unwrap_or_default()) {
            ("GET", "/.well-known/jmap") => Answer::redirect("/jmap/session"),
            ("GET", "/jmap/session") => Answer::json(200, session()),
            ("POST", "/jmap/api") => {
                let responses: Vec<Value> = request
                    .calls()
                    .iter()
                    .zip(request.json()["methodCalls"].as_array().unwrap())
                    .map(|((name, arguments), call)| {
                        let mut answer = method(name, arguments);
                        // A get with ids gives only those; one with a result reference gives all.
                        if let (Some(ids), Some(list)) =
                            (arguments["ids"].as_array(), answer["list"].as_array().cloned())
                        {
                            let wanted: Vec<_> = list.into_iter().filter(|o| ids.contains(&o["id"])).collect();
                            answer["list"] = json!(wanted);
                        } else if name == "Email/get" && arguments["#ids"]["resultOf"] != "t" {
                            let list: Vec<Value> = answer["list"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|o| o["id"] != "e3")
                                .cloned()
                                .collect();
                            answer["list"] = json!(list);
                        }
                        let name = if answer.get("type").is_some() { "error" } else { name.as_str() };
                        json!([name, answer, call[2]])
                    })
                    .collect();
                Answer::json(200, json!({ "methodResponses": responses, "sessionState": "s1" }))
            }
            ("GET", path) if path.starts_with("/jmap/download/") => Answer::bytes(b"hello"),
            ("POST", "/jmap/upload/A/") | ("POST", "/jmap/upload/D/") => Answer::json(
                201,
                json!({ "accountId": "A", "blobId": "U1", "type": request.header("content-type"), "size": request.body.len() }),
            ),
            _ => Answer::json(404, json!({ "type": "about:blank", "status": 404, "detail": "no such thing" })),
        }
    })
}

fn connect(server: &Server) -> Client {
    let url = jmap::session_url(Some(&server.origin), "alice@firma.example").unwrap();
    Client::connect(&url, "alice@firma.example", PASSWORD, &Options::default()).unwrap()
}

#[test]
fn logs_in_through_the_well_known_redirect() {
    let server = server();
    let client = connect(&server);
    assert_eq!(client.session.username, "alice@firma.example");
    assert_eq!(client.primary(jmap::MAIL).unwrap(), "A");
    // The redirect kept the credentials (same host), and both requests were made.
    let paths: Vec<_> = server.requests().iter().map(|r| r.path.clone()).collect();
    assert_eq!(paths, ["/.well-known/jmap", "/jmap/session"]);
    // The session's URLs name another host; the client stays on the one it logged in to.
    assert!(client.download_url("A", "B", "x y.txt", "text/plain").starts_with(&server.origin));
    assert!(
        client
            .download_url("A", "B", "x y.txt", "text/plain")
            .ends_with("/jmap/download/A/B/x%20y.txt?accept=text%2Fplain")
    );
}

#[test]
fn a_wrong_password_is_unauthorized() {
    let server = server();
    let url = format!("{}/.well-known/jmap", server.origin);
    let error = Client::connect(&url, "alice@firma.example", "wrong", &Options::default()).unwrap_err();
    assert!(matches!(error, Error::Unauthorized), "{error}");
}

#[test]
fn plain_http_only_to_this_machine() {
    let error = Client::connect("http://example.org/.well-known/jmap", "a", "b", &Options::default()).unwrap_err();
    assert!(error.to_string().contains("not HTTPS"), "{error}");
}

#[test]
fn method_errors_and_set_errors() {
    let server = server();
    let client = connect(&server);
    let error = client.call(&[], "Fail/now", json!({})).unwrap_err();
    assert!(matches!(&error, Error::Method { kind, .. } if kind == "invalidArguments"), "{error}");
    let error = mail::move_to(&client, "A", "forbidden", "m1").unwrap_err();
    assert!(matches!(&error, Error::Set { kind, .. } if kind == "forbidden"), "{error}");
    assert_eq!(error.to_string(), "forbidden: not yours");
    // Every request says which capabilities it uses, core first.
    let request = server.api_requests().pop().unwrap();
    assert_eq!(request.json()["using"], json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]));
}

#[test]
fn mailboxes_emails_and_one_email() {
    let server = server();
    let client = connect(&server);
    let boxes = mail::mailboxes(&client, "A").unwrap();
    let names: Vec<_> = boxes.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["Inbox", "Drafts", "Sent", "Archive"]);
    let (emails, total) = mail::emails(&client, "A", Some("m1"), " plans ", 0, 50).unwrap();
    assert_eq!(total, 2);
    assert_eq!(emails.len(), 2);
    assert!(emails[0].is_seen() && !emails[1].is_seen());
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls[0].0, "Email/query");
    assert_eq!(calls[0].1["filter"], json!({ "inMailbox": "m1", "text": "plans" }));
    assert_eq!(calls[0].1["limit"], 50);
    assert_eq!(calls[1].1["#ids"], json!({ "resultOf": "q", "name": "Email/query", "path": "/ids" }));
    let email = mail::email(&client, "A", "e1").unwrap().unwrap();
    assert_eq!(email.text(80), "Hi Alice");
    assert_eq!(email.message_id.as_deref(), Some(&["m1@firma.example".to_owned()][..]));
    mail::set_keyword(&client, "A", "e2", "$seen", true).unwrap();
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls[0].1["update"], json!({ "e2": { "keywords/$seen": true } }));
    mail::destroy(&client, "A", "e2").unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["destroy"], json!(["e2"]));
}

#[test]
fn sending_goes_through_drafts_to_sent() {
    let server = server();
    let client = connect(&server);
    let boxes = mail::mailboxes(&client, "A").unwrap();
    let identity = Identity { id: "i1".into(), name: "Alice".into(), email: "alice@firma.example".into() };
    let draft = Draft {
        to: parse_addresses("Bob <bob@firma.example>"),
        subject: "Re: Hello".into(),
        body: "Hi Bob".into(),
        in_reply_to: vec!["m1@firma.example".into()],
        references: vec!["m1@firma.example".into()],
        ..Draft::default()
    };
    mail::send(&client, "A", &identity, &draft, &boxes).unwrap();
    let calls = server.api_requests().pop().unwrap().calls();
    let email = &calls[0].1["create"]["draft"];
    assert_eq!(email["mailboxIds"], json!({ "m2": true }));
    assert_eq!(email["from"], json!([{ "name": "Alice", "email": "alice@firma.example" }]));
    assert_eq!(email["to"], json!([{ "name": "Bob", "email": "bob@firma.example" }]));
    assert_eq!(email["inReplyTo"], json!(["m1@firma.example"]));
    assert_eq!(calls[1].0, "EmailSubmission/set");
    assert_eq!(calls[1].1["create"]["send"], json!({ "identityId": "i1", "emailId": "#draft" }));
    assert_eq!(
        calls[1].1["onSuccessUpdateEmail"]["#send"],
        json!({ "keywords/$draft": null, "mailboxIds": { "m3": true } })
    );
    assert_eq!(mail::save_draft(&client, "A", &draft, &boxes).unwrap(), "e9");
}

#[test]
fn stores_directories_and_downloads() {
    let server = server();
    let client = connect(&server);
    let stores = files::stores(&client);
    let kinds: Vec<_> = stores.iter().map(|s| (s.id.as_str(), s.kind)).collect();
    assert_eq!(kinds, [("A", files::StoreKind::Own), ("D", files::StoreKind::Drive), ("S", files::StoreKind::Shared)]);
    let nodes = files::children(&client, "D", None).unwrap();
    let names: Vec<_> = nodes.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["Projects", "a.pdf", "b.txt"]);
    assert!(nodes[0].is_directory() && nodes[2].rights().may_read);
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls[0].1["filter"], json!({ "isTopLevel": true }));
    assert_eq!(calls[0].1["accountId"], "D");
    files::children(&client, "D", Some("n2")).unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["filter"], json!({ "parentId": "n2" }));

    let mut out = Vec::new();
    let mut seen = Vec::new();
    let size = client
        .download("D", "F1", "b.txt", "text/plain", &mut out, &mut |done, total| seen.push((done, total)))
        .unwrap();
    assert_eq!((size, out.as_slice()), (5, &b"hello"[..]));
    assert_eq!(seen.last(), Some(&(5, Some(5))));
    let download = server.requests().into_iter().find(|r| r.path.starts_with("/jmap/download/")).unwrap();
    assert_eq!(download.path, "/jmap/download/D/F1/b.txt?accept=text%2Fplain");
    assert!(authorized(&download));

    let people = files::principals(&client, &["p2"]).unwrap();
    assert_eq!(people[0].email.as_deref(), Some("bob@firma.example"));
}

#[test]
fn uploads_new_files_and_new_versions() {
    let server = server();
    let client = connect(&server);
    let dir = std::env::temp_dir().join(format!("kernoid-tui-upload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("notes.txt");
    std::fs::write(&path, "some notes").unwrap();

    let mut progress = Vec::new();
    files::upload_file(&client, "D", Some("n2"), &path, None, &mut |done, total| progress.push((done, total))).unwrap();
    let upload = server.requests().into_iter().find(|r| r.path == "/jmap/upload/D/").unwrap();
    assert_eq!(upload.body, b"some notes");
    assert_eq!(upload.header("content-type"), Some("text/plain"));
    assert_eq!(upload.header("content-length"), Some("10"));
    assert_eq!(progress.last(), Some(&(10, 10)));
    let calls = server.api_requests().pop().unwrap().calls();
    let created = &calls[0].1["create"]["f"];
    assert_eq!(created["@type"], "File");
    assert_eq!(
        (created["parentId"].as_str(), created["name"].as_str(), created["blobId"].as_str()),
        (Some("n2"), Some("notes.txt"), Some("U1"))
    );
    assert_eq!(calls[0].1["onExists"], "rename");

    // A file of that name gets the upload as its new content.
    let existing = files::children(&client, "D", None).unwrap().into_iter().find(|n| n.name == "b.txt").unwrap();
    files::upload_file(&client, "D", None, &path, Some(&existing), &mut |_, _| {}).unwrap();
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls[0].1["update"]["n1"]["blobId"], "U1");
    std::fs::remove_dir_all(&dir).unwrap();

    let versions = files::versions(&client, "D", "n1").unwrap();
    assert_eq!(versions.len(), 2);
    assert!(versions[0].is_current);
    let using = server.api_requests().pop().unwrap().json()["using"].clone();
    assert!(using.as_array().unwrap().contains(&json!("https://kernoid.dev/jmap/file-versions")));
    files::restore(&client, "D", "n1", &versions[1]).unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["update"], json!({ "n1": { "blobId": "V1" } }));
    files::destroy(&client, "D", "n2").unwrap();
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(
        (calls[0].1["destroy"].clone(), calls[0].1["onDestroyRemoveChildren"].clone()),
        (json!(["n2"]), json!(true))
    );
    files::create_directory(&client, "D", None, "New").unwrap();
    assert_eq!(
        server.api_requests().pop().unwrap().calls()[0].1["create"]["d"],
        json!({ "@type": "Directory", "parentId": null, "name": "New" })
    );
}

#[test]
fn calendars_and_contacts_of_all_accounts() {
    let server = server();
    let client = connect(&server);
    let list = calendars::calendars(&client).unwrap();
    assert_eq!(list.len(), 2);
    let shared = list.iter().find(|c| c.account == "S").unwrap();
    assert_eq!(shared.shared.as_deref(), Some("bob@firma.example"));
    let after = chrono::DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z").unwrap().to_utc();
    let events = calendars::instances(&client, &list, after, after + chrono::Duration::days(14)).unwrap();
    let titles: Vec<_> = events.iter().map(|e| e.title.as_deref().unwrap_or_default()).collect();
    assert_eq!(titles, ["Sooner", "Later"]);
    assert_eq!(events[1].location().as_deref(), Some("Room 1"));
    let query =
        server.api_requests().into_iter().flat_map(|r| r.calls()).find(|(n, _)| n == "CalendarEvent/query").unwrap();
    assert_eq!(query.1["filter"], json!({ "after": "2026-11-01T00:00:00Z", "before": "2026-11-15T00:00:00Z" }));
    assert_eq!(query.1["expandRecurrences"], true);

    let cards = contacts::cards(&client, "ann").unwrap();
    let names: Vec<_> = cards.iter().map(|c| c.full_name()).collect();
    assert_eq!(names, ["Anna A", "Zoe Z"]);
    assert_eq!(cards[0].phones(), ["+49 1"]);
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["filter"], json!({ "text": "ann" }));
}

#[test]
fn push_events() {
    let stream = "event: state\ndata: {\"@type\":\"StateChange\",\"changed\":{\"A\":{\"FileNode\":\"7\"}}}\n\n";
    let (name, data) = Events::new(Cursor::new(stream)).next().unwrap().unwrap();
    assert_eq!(name, "state");
    assert_eq!(changed_types(&data), BTreeSet::from(["FileNode".to_owned()]));
}

#[test]
fn conversations_through_threads() {
    let server = server();
    let client = connect(&server);
    let (rows, total) = mail::conversations(&client, "A", Some("m1"), "", 0, 50).unwrap();
    assert_eq!((rows.len(), total), (2, 2));
    let first = &rows[0];
    let ids: Vec<_> = first.emails.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, ["e1", "e3"]);
    // Moving or deleting the conversation in the Inbox leaves the reply in Sent alone.
    assert_eq!(first.ids_in("m1"), ["e1"]);
    assert!(!first.unread() && rows[1].unread());
    let calls = server.api_requests().pop().unwrap().calls();
    let names: Vec<_> = calls.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["Email/query", "Email/get", "Thread/get", "Email/get"]);
    assert_eq!(calls[0].1["collapseThreads"], true);
    assert_eq!(calls[2].1["#ids"]["path"], "/list/*/threadId");
    assert_eq!(calls[3].1["#ids"]["path"], "/list/*/emailIds");
    let emails = mail::full(&client, "A", &["e3", "e1"]).unwrap();
    let order: Vec<_> = emails.iter().map(|e| e.summary.id.as_str()).collect();
    assert_eq!(order, ["e1", "e3"]);
    mail::set_keywords(&client, "A", &["e1".into(), "e3".into()], "$flagged", true).unwrap();
    let update = &server.api_requests().pop().unwrap().calls()[0].1["update"];
    assert_eq!(update, &json!({ "e1": { "keywords/$flagged": true }, "e3": { "keywords/$flagged": true } }));
    mail::move_all(&client, "A", &["e1".into()], "m9").unwrap();
    assert_eq!(
        server.api_requests().pop().unwrap().calls()[0].1["update"],
        json!({ "e1": { "mailboxIds": { "m9": true } } })
    );
}

#[test]
fn sharing_a_directory() {
    let server = server();
    let client = connect(&server);
    let found = files::find_principals(&client, " bo ").unwrap();
    assert_eq!(found[0].name, "Bob");
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!((calls[0].0.as_str(), calls[0].1["filter"].clone()), ("Principal/query", json!({ "text": "bo" })));
    let with = vec![("p2".to_owned(), files::Level::Edit), ("g1".to_owned(), files::Level::Full)];
    files::share(&client, "A", "n2", &with).unwrap();
    let update = &server.api_requests().pop().unwrap().calls()[0].1["update"]["n2"]["shareWith"];
    assert_eq!(update["p2"]["mayModifyContent"], true);
    assert_eq!(update["p2"]["mayShare"], false);
    assert_eq!(update["g1"]["mayShare"], true);
    files::share(&client, "A", "n2", &[]).unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["update"]["n2"]["shareWith"], json!({}));
    assert_eq!(files::Level::of(&files::Level::Edit.rights()), files::Level::Edit);
}

#[test]
fn events_made_changed_answered_and_removed() {
    let server = server();
    let client = connect(&server);
    let list = calendars::calendars(&client).unwrap();
    let calendar = list.iter().find(|c| c.account == "A").unwrap();
    let at = |s: &str| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap();
    let form = calendars::EventForm {
        title: "Plans".into(),
        all_day: false,
        start: at("2026-11-03 10:00"),
        end: at("2026-11-03 11:00"),
        time_zone: Some("Europe/Berlin".into()),
        location: String::new(),
        description: String::new(),
        participants: vec!["bob@firma.example".into()],
        repeat: None,
        answers: Vec::new(),
        was: None,
    };
    assert_eq!(calendars::create(&client, calendar, &form, "alice@firma.example").unwrap(), "ev9");
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls[0].1["sendSchedulingMessages"], true);
    let created = &calls[0].1["create"]["e"];
    assert_eq!(created["calendarIds"], json!({ "c-A": true }));
    assert_eq!(created["participants"]["p1"]["calendarAddress"], "mailto:bob@firma.example");
    calendars::update(&client, calendar, "ev9", &form, "alice@firma.example").unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["update"]["ev9"]["title"], "Plans");
    calendars::answer(&client, "A", "ev2", "p3", "accepted").unwrap();
    let calls = server.api_requests().pop().unwrap().calls();
    assert_eq!(calls[0].1["update"], json!({ "ev2": { "participants/p3/participationStatus": "accepted" } }));
    assert_eq!(calls[0].1["sendSchedulingMessages"], true);
    calendars::destroy(&client, "A", "ev2").unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["destroy"], json!(["ev2"]));
    let event = calendars::event(&client, "A", "ev2.1").unwrap().unwrap();
    assert_eq!(event.title.as_deref(), Some("Later"));
}

#[test]
fn contacts_made_changed_and_removed() {
    let server = server();
    let client = connect(&server);
    let books = contacts::address_books(&client).unwrap();
    let names: Vec<_> = books.iter().map(|b| (b.name.as_str(), b.writable())).collect();
    assert_eq!(names, [("Contacts", true), ("Work", false)]);
    let form = contacts::CardForm { name: "Dora".into(), email: "dora@x.example".into(), ..Default::default() };
    contacts::create(&client, &books[0], &form).unwrap();
    let created = &server.api_requests().pop().unwrap().calls()[0].1["create"]["c"];
    assert_eq!(created["@type"], "Card");
    assert_eq!(created["addressBookIds"], json!({ "b1": true }));
    assert_eq!(created["emails"]["e1"]["address"], "dora@x.example");
    assert_eq!(created["phones"], Value::Null);
    contacts::update(&client, &books[0], "k2", &form).unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["update"]["k2"]["name"], json!({ "full": "Dora" }));
    contacts::destroy(&client, "A", "k2").unwrap();
    assert_eq!(server.api_requests().pop().unwrap().calls()[0].1["destroy"], json!(["k2"]));
}
