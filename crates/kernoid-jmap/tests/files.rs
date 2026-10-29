// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP for files (RFC 0005, 8) against PostgreSQL, with object storage in memory; set `DATABASE_URL` as for the
//! other crates' tests.

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use bytes::Bytes;
use kernoid_events::EventStore;
use kernoid_files::Files;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup, role::Principal, services::Service};
use kernoid_jmap::{Caller, FILE_VERSIONS, FILENODE, Jmap, PRINCIPALS};
use kernoid_mail::{Limits, Mail};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const WHO: &str = "operator";
const USING: [&str; 4] = ["urn:ietf:params:jmap:core", FILENODE, FILE_VERSIONS, PRINCIPALS];

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
    let mail = Mail::new(pool.clone(), blobs.clone(), Limits::default());
    let files = Files::new(pool.clone(), blobs, kernoid_files::Limits::default());
    let jmap = Jmap::new(mail, 20_000_000, chrono::Duration::days(5))
        .with_files(files)
        .with_identity(Identity::new(EventStore::new(pool.clone())));
    Setup { pool, identity, jmap, tenant }
}

impl Setup {
    /// An account with files and – if `mail` – mail.
    async fn caller(&self, local: &str, mail: bool) -> Caller {
        let address = format!("{local}@firma.example");
        let account =
            self.identity.add_account(self.tenant, &Address::parse(&address).unwrap(), local, WHO).await.unwrap();
        self.identity.grant_service(account, Service::Files, WHO).await.unwrap();
        if !mail {
            self.identity.revoke_service(account, Service::Mail, WHO).await.unwrap();
        }
        Caller { account, tenant: self.tenant, username: address, mail, files: true }
    }

    async fn one(&self, caller: &Caller, name: &str, args: Value) -> (String, Value) {
        self.in_account(caller, caller.account, name, args).await
    }

    /// One call on the store of `account`.
    async fn in_account(&self, caller: &Caller, account: Uuid, name: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(account.to_string());
        let request = json!({ "using": USING, "methodCalls": [[name, args, "c"]] });
        let response = self.jmap.api(caller, request.to_string().as_bytes()).await.unwrap();
        let entry = &response["methodResponses"][0];
        (entry[0].as_str().unwrap().to_owned(), entry[1].clone())
    }

    async fn upload(&self, caller: &Caller, content: &'static [u8]) -> String {
        self.upload_to(caller, caller.account, content).await
    }

    async fn upload_to(&self, caller: &Caller, account: Uuid, content: &'static [u8]) -> String {
        let answer = self
            .jmap
            .upload_bytes(caller, &account.to_string(), "text/plain", Bytes::from_static(content))
            .await
            .unwrap();
        answer["blobId"].as_str().unwrap().to_owned()
    }

    async fn download(&self, caller: &Caller, account: Uuid, blob: &str) -> Vec<u8> {
        let download = self.jmap.download(caller, &account.to_string(), blob, None).await.unwrap();
        download.collect().await.unwrap().to_vec()
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_account_without_mail_has_files_only(pool: PgPool) {
    let setup = setup(pool).await;
    let carol = setup.caller("carol", false).await;

    let session = setup.jmap.session(&carol, "https://login.firma.example").await.unwrap();
    let own = carol.account.to_string();
    assert_eq!(session["primaryAccounts"][FILENODE], json!(own));
    assert!(session["primaryAccounts"].get("urn:ietf:params:jmap:mail").is_none());
    let capabilities = &session["accounts"][&own]["accountCapabilities"];
    assert_eq!(capabilities[FILENODE]["maxFileNodeDepth"], 64);
    assert_eq!(capabilities[FILENODE]["mayCreateTopLevelFileNode"], true);
    assert!(session["capabilities"].get("urn:ietf:params:jmap:mail").is_none());

    // Mail methods are not for this account, and no mail store was made for it.
    let (name, error) = setup.one(&carol, "Mailbox/get", json!({})).await;
    assert_eq!((name.as_str(), error["type"].as_str()), ("error", Some("accountNotSupportedByMethod")));
    let stores = sqlx::query_scalar!("SELECT count(*) FROM mail_accounts WHERE account_id = $1", carol.account)
        .fetch_one(&setup.pool)
        .await
        .unwrap();
    assert_eq!(stores, Some(0));

    // Uploads work all the same, and a file takes one.
    let blob = setup.upload(&carol, b"notes").await;
    let (_, set) = setup
        .one(
            &carol,
            "FileNode/set",
            json!({ "create": { "f": { "@type": "File", "parentId": null, "name": "notes.txt", "blobId": blob } } }),
        )
        .await;
    let file = &set["created"]["f"];
    assert_eq!((file["size"].as_u64(), file["mediaType"].as_str()), (Some(5), Some("application/octet-stream")));
    let content = file["blobId"].as_str().unwrap();
    assert_eq!(setup.download(&carol, carol.account, content).await, b"notes");
    // A range of it.
    let part = setup.jmap.download(&carol, &own, content, Some((1, Some(2)))).await.unwrap();
    assert_eq!((part.start, part.end, part.size), (1, 3, 5));
    assert_eq!(&part.collect().await.unwrap()[..], b"ot");

    // Another account does not reach them.
    let dave = setup.caller("dave", true).await;
    assert!(setup.jmap.download(&dave, &own, content, None).await.is_err());
    let (_, error) = setup.in_account(&dave, carol.account, "FileNode/get", json!({})).await;
    assert_eq!(error["type"], "accountNotFound");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn file_nodes_are_created_queried_changed_and_destroyed(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice", true).await;

    let (_, get) = setup.one(&alice, "FileNode/get", json!({ "ids": null })).await;
    let start = get["state"].as_str().unwrap().to_owned();
    let trash = &get["list"][0];
    assert_eq!((trash["@type"].as_str(), trash["role"].as_str()), (Some("Directory"), Some("trash")));
    assert_eq!(trash["myRights"]["mayShare"], true);

    let blob = setup.upload(&alice, b"hello").await;
    let (_, set) = setup
        .one(
            &alice,
            "FileNode/set",
            json!({ "create": {
                "f": { "@type": "File", "parentId": "#d", "name": "a.txt", "blobId": blob, "mediaType": "text/plain",
                       "modified": "2026-01-02T03:04:05.123Z" },
                "d": { "@type": "Directory", "parentId": null, "name": "Docs" },
            } }),
        )
        .await;
    let docs = set["created"]["d"]["id"].as_str().unwrap().to_owned();
    let file = set["created"]["f"]["id"].as_str().unwrap().to_owned();
    assert_eq!(set["created"]["f"]["modified"], "2026-01-02T03:04:05.123Z");

    let create = json!({ "x": { "@type": "File", "parentId": docs, "name": "a.txt", "blobId": blob } });
    let (_, set) = setup.one(&alice, "FileNode/set", json!({ "create": create })).await;
    assert_eq!(set["notCreated"]["x"]["existingId"], json!(file));
    let (_, set) = setup.one(&alice, "FileNode/set", json!({ "create": create, "onExists": "rename" })).await;
    assert_eq!(set["created"]["x"]["name"], "a (2).txt");

    let (_, query) = setup
        .one(&alice, "FileNode/query", json!({ "filter": { "parentId": docs }, "sort": [{ "property": "name" }] }))
        .await;
    // By code point: "a (2).txt" before "a.txt".
    assert_eq!(query["ids"][1], json!(file));
    let (_, error) = setup.one(&alice, "FileNode/query", json!({ "filter": { "body": "x" } })).await;
    assert_eq!(error["type"], "unsupportedFilter");

    // New content keeps the old as a version, which restores by its blob.
    let second = setup.upload(&alice, b"hello, world").await;
    let (_, set) = setup.one(&alice, "FileNode/set", json!({ "update": { file.clone(): { "blobId": second } } })).await;
    assert_eq!(set["updated"][&file]["size"], 12);
    let (_, versions) = setup.one(&alice, "FileVersion/get", json!({ "nodeId": file })).await;
    let list = versions["list"].as_array().unwrap();
    assert_eq!((list.len(), list[0]["isCurrent"].as_bool(), list[1]["size"].as_u64()), (2, Some(true), Some(5)));
    let old = list[1]["blobId"].as_str().unwrap().to_owned();
    assert_eq!(setup.download(&alice, alice.account, &old).await, b"hello");
    let (_, set) = setup.one(&alice, "FileNode/set", json!({ "update": { file.clone(): { "blobId": old } } })).await;
    assert_eq!(set["updated"][&file]["size"], 5);

    let trash_id = trash["id"].as_str().unwrap();
    let (_, set) = setup
        .one(&alice, "FileNode/set", json!({ "update": { trash_id: { "name": "Bin" } }, "destroy": [trash_id] }))
        .await;
    assert_eq!(set["notUpdated"][trash_id]["type"], "forbidden");
    let (_, set) =
        setup.one(&alice, "FileNode/set", json!({ "destroy": [docs], "onDestroyRemoveChildren": true })).await;
    assert_eq!(set["destroyed"].as_array().unwrap().len(), 3);
    let (_, changes) = setup.one(&alice, "FileNode/changes", json!({ "sinceState": start })).await;
    assert!(changes["created"].as_array().unwrap().is_empty());

    // Large content streams in and comes back in ranges.
    let piece = Bytes::from(vec![1u8; 1024 * 1024]);
    let pieces = futures_util::stream::iter((0..9).map(move |_| Ok::<_, std::io::Error>(piece.clone())));
    let answer = setup.jmap.upload(&alice, &alice.account.to_string(), "application/zip", pieces).await.unwrap();
    assert_eq!(answer["size"], 9 * 1024 * 1024);
    let create = json!({ "z": { "@type": "File", "parentId": null, "name": "big.zip", "blobId": answer["blobId"] } });
    let (_, set) = setup.one(&alice, "FileNode/set", json!({ "create": create })).await;
    let big = set["created"]["z"]["blobId"].as_str().unwrap().to_owned();
    let tail = setup.jmap.download(&alice, &alice.account.to_string(), &big, Some((9 * 1024 * 1024 - 2, None))).await;
    assert_eq!(&tail.unwrap().collect().await.unwrap()[..], &[1, 1]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn directories_are_shared_with_share_with(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice", true).await;
    let bob = setup.caller("bob", true).await;

    // Bob is found among the principals.
    let (_, found) = setup.one(&alice, "Principal/query", json!({ "filter": { "email": "bob@" } })).await;
    assert_eq!(found["ids"], json!([bob.account.to_string()]));

    let blob = setup.upload(&alice, b"plan").await;
    let (_, set) = setup
        .one(
            &alice,
            "FileNode/set",
            json!({ "create": {
                "p": { "@type": "Directory", "parentId": null, "name": "Project",
                       "shareWith": { bob.account.to_string(): { "mayRead": true } } },
                "f": { "@type": "File", "parentId": "#p", "name": "plan.txt", "blobId": blob },
                "x": { "@type": "Directory", "parentId": null, "name": "Private" },
            } }),
        )
        .await;
    let project = set["created"]["p"]["id"].as_str().unwrap().to_owned();
    let plan = set["created"]["f"]["id"].as_str().unwrap().to_owned();
    assert_eq!(set["created"]["p"]["shareWith"][bob.account.to_string()]["mayRead"], true);

    // Bob's session has Alice's store; Bob sees Project and what it holds, not Private.
    let session = setup.jmap.session(&bob, "https://login.firma.example").await.unwrap();
    let shared = &session["accounts"][alice.account.to_string()];
    assert_eq!((shared["isPersonal"].as_bool(), shared["isReadOnly"].as_bool()), (Some(false), Some(true)));
    assert_eq!(shared["accountCapabilities"][FILENODE]["mayCreateTopLevelFileNode"], false);
    let (_, get) = setup.in_account(&bob, alice.account, "FileNode/get", json!({ "ids": null })).await;
    let names: Vec<&str> = get["list"].as_array().unwrap().iter().map(|node| node["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"Project") && names.contains(&"plan.txt"));
    let (_, get) = setup.in_account(&bob, alice.account, "FileNode/get", json!({ "ids": [project] })).await;
    assert_eq!(get["list"][0]["myRights"]["mayAddChildren"], false);
    assert_eq!(get["list"][0]["shareWith"], Value::Null);

    // Bob may not change or share what he only reads.
    let (_, set) = setup
        .in_account(&bob, alice.account, "FileNode/set", json!({ "update": { plan.clone(): { "name": "mine.txt" } } }))
        .await;
    assert_eq!(set["notUpdated"][&plan]["type"], "forbidden");
    let share = json!({ "update": { project.clone(): { format!("shareWith/{}", bob.account): { "mayRead": true, "mayShare": true } } } });
    let (_, set) = setup.in_account(&bob, alice.account, "FileNode/set", share).await;
    assert_eq!(set["notUpdated"][&project]["type"], "forbidden");

    // Alice gives Bob more; he writes – into Alice's quota – and may upload to her store.
    let more = json!({ "update": { project.clone(): { format!("shareWith/{}", bob.account): {
        "mayRead": true, "mayAddChildren": true, "mayModifyContent": true } } } });
    let (_, before) = setup.in_account(&bob, alice.account, "FileNode/get", json!({ "ids": [] })).await;
    let (_, set) = setup.one(&alice, "FileNode/set", more).await;
    assert!(set["updated"].get(&project).is_some());
    let since = before["state"].as_str().unwrap();
    let (_, changes) = setup.in_account(&bob, alice.account, "FileNode/changes", json!({ "sinceState": since })).await;
    assert_eq!(changes["updated"].as_array().unwrap().len(), 2);
    let blob = setup.upload_to(&bob, alice.account, b"notes").await;
    let create = json!({ "n": { "@type": "File", "parentId": project, "name": "notes.txt", "blobId": blob } });
    let (_, set) = setup.in_account(&bob, alice.account, "FileNode/set", json!({ "create": create })).await;
    assert!(set["created"]["n"]["id"].is_string());

    // Taking the grant away: everything is gone for Bob.
    let (_, before) = setup.in_account(&bob, alice.account, "FileNode/get", json!({ "ids": [] })).await;
    let (_, set) =
        setup.one(&alice, "FileNode/set", json!({ "update": { project.clone(): { "shareWith": null } } })).await;
    assert!(set["updated"].get(&project).is_some());
    let session = setup.jmap.session(&bob, "https://login.firma.example").await.unwrap();
    assert!(session["accounts"].get(alice.account.to_string()).is_none());
    let _ = before;
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_drive_is_shared_by_its_members(pool: PgPool) {
    let setup = setup(pool).await;
    let one = setup.caller("one", true).await;
    let two = setup.caller("two", false).await;
    let drive = setup.identity.add_drive(setup.tenant, "falkOSS", WHO).await.unwrap();
    for member in [&one, &two] {
        setup.identity.set_file_access(drive, None, Principal::Account(member.account), "randws", WHO).await.unwrap();
    }

    for member in [&one, &two] {
        let session = setup.jmap.session(member, "https://login.firma.example").await.unwrap();
        let account = &session["accounts"][drive.to_string()];
        assert_eq!((account["name"].as_str(), account["kernoid:drive"].as_bool()), (Some("falkOSS"), Some(true)));
        assert_eq!(account["accountCapabilities"][FILENODE]["mayCreateTopLevelFileNode"], true);
    }
    let blob = setup.upload_to(&one, drive, b"minutes").await;
    let create = json!({
        "d": { "@type": "Directory", "parentId": null, "name": "Board" },
        "f": { "@type": "File", "parentId": "#d", "name": "minutes.txt", "blobId": blob },
    });
    let (_, set) = setup.in_account(&one, drive, "FileNode/set", json!({ "create": create })).await;
    let minutes = set["created"]["f"]["blobId"].as_str().unwrap().to_owned();
    // The other member reads and changes it just as well.
    assert_eq!(setup.download(&two, drive, &minutes).await, b"minutes");
    let file = set["created"]["f"]["id"].as_str().unwrap().to_owned();
    let (_, set) = setup
        .in_account(&two, drive, "FileNode/set", json!({ "update": { file.clone(): { "name": "minutes-2026.txt" } } }))
        .await;
    assert!(set["updated"].get(&file).is_some());
}

/// Mailboxes are shared the same way (RFC 9670, 4): `shareWith` on Mailbox, by the owner.
#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mailboxes_are_shared_with_share_with(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.caller("alice", true).await;
    let bob = setup.caller("bob", true).await;
    let using = json!(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]);
    let call = |caller: &Caller, account: Uuid, name: &str, mut args: Value| {
        args["accountId"] = json!(account.to_string());
        let request = json!({ "using": using, "methodCalls": [[name, args, "c"]] });
        let jmap = setup.jmap.clone();
        let caller = caller.clone();
        async move { jmap.api(&caller, request.to_string().as_bytes()).await.unwrap()["methodResponses"][0][1].clone() }
    };
    let created =
        call(&alice, alice.account, "Mailbox/set", json!({ "create": { "p": { "name": "Projects" } } })).await;
    let projects = created["created"]["p"]["id"].as_str().unwrap().to_owned();
    let bob_id = bob.account.to_string();

    // Bob may not share Alice's mailbox; Alice may.
    let refused = call(
        &bob,
        alice.account,
        "Mailbox/set",
        json!({ "update": { &projects: { format!("shareWith/{bob_id}"): { "mayReadItems": true } } } }),
    )
    .await;
    assert!(refused["notUpdated"][&projects].is_object() || refused["type"].is_string(), "{refused}");
    let shared = call(&alice, alice.account, "Mailbox/set",
        json!({ "update": { &projects: { format!("shareWith/{bob_id}"): { "mayReadItems": true, "maySetSeen": true } } } })).await;
    assert!(
        shared["updated"][&projects].is_null() && shared["notUpdated"].as_object().is_none_or(|map| map.is_empty()),
        "{shared}"
    );
    let got = call(
        &alice,
        alice.account,
        "Mailbox/get",
        json!({ "ids": [&projects], "properties": ["shareWith", "myRights"] }),
    )
    .await;
    let rights = &got["list"][0]["shareWith"][&bob_id];
    assert_eq!(
        (rights["mayReadItems"].as_bool(), rights["maySetSeen"].as_bool(), rights["mayAddItems"].as_bool()),
        (Some(true), Some(true), Some(false))
    );
    assert_eq!(got["list"][0]["myRights"]["mayShare"], true);

    // Bob sees the mailbox in Alice's store, without whom else it is shared with.
    let seen = call(&bob, alice.account, "Mailbox/get", json!({ "properties": ["name", "shareWith"] })).await;
    let list = seen["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{seen}");
    assert_eq!((list[0]["name"].as_str(), &list[0]["shareWith"]), (Some("Projects"), &Value::Null));

    // shareWith null takes everything back.
    call(&alice, alice.account, "Mailbox/set", json!({ "update": { &projects: { "shareWith": null } } })).await;
    let gone = call(&bob, alice.account, "Mailbox/get", json!({})).await;
    assert!(gone["type"].is_string() || gone["list"].as_array().is_some_and(Vec::is_empty), "{gone}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn large_files_are_uploaded_in_pieces_and_joined(pool: PgPool) {
    let setup = setup(pool).await;
    let dana = setup.caller("dana", false).await;
    // Three pieces, as a client sends them; the second broke off once and came again.
    let first = setup.upload(&dana, b"Hello, ").await;
    let _broken = setup.upload(&dana, b"wor").await;
    let second = setup.upload(&dana, b"world").await;
    let third = setup.upload(&dana, b"!! and more").await;

    let (name, joined) = setup
        .one(
            &dana,
            "Blob/upload",
            json!({ "create": { "j": { "type": "text/plain", "data": [
                { "blobId": first },
                { "blobId": second },
                { "blobId": third, "length": 1 },
                { "data:asText": " – " },
                { "data:asBase64": "QnllLg==" },
            ] } } }),
        )
        .await;
    assert_eq!(name, "Blob/upload", "{joined}");
    let blob = joined["created"]["j"]["id"].as_str().unwrap().to_owned();
    assert_eq!(joined["created"]["j"]["size"], 22);
    assert_eq!(setup.download(&dana, dana.account, &blob).await, "Hello, world! – Bye.".as_bytes());

    // A piece that is not there, or a range outside one, makes nothing.
    let (_, refused) = setup
        .one(
            &dana,
            "Blob/upload",
            json!({ "create": {
                "a": { "data": [{ "blobId": "u-0190a3d6-0000-7000-8000-000000000000" }] },
                "b": { "data": [{ "blobId": first, "offset": 3, "length": 10 }] },
            } }),
        )
        .await;
    assert_eq!(refused["notCreated"]["a"]["type"], "blobNotFound", "{refused}");
    assert_eq!(refused["notCreated"]["b"]["type"], "invalidProperties", "{refused}");

    // Blob/get: size, digest and data of a range.
    let (_, got) = setup
        .one(
            &dana,
            "Blob/get",
            json!({ "ids": [blob], "properties": ["size", "data:asText", "digest:sha-256"], "offset": 7, "length": 5 }),
        )
        .await;
    assert_eq!(got["list"][0]["size"], 22);
    assert_eq!(got["list"][0]["data:asText"], "world");
    use base64::Engine;
    use sha2::Digest;
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(b"world"));
    assert_eq!(got["list"][0]["digest:sha-256"], digest);

    // The joined blob becomes a file; Blob/lookup finds it.
    let (_, created) = setup
        .one(
            &dana,
            "FileNode/set",
            json!({ "create": { "f": { "@type": "File", "parentId": null, "name": "big.txt", "blobId": blob } } }),
        )
        .await;
    let node = created["created"]["f"]["id"].as_str().unwrap().to_owned();
    let file_blob = created["created"]["f"]["blobId"].as_str().unwrap_or_default().to_owned();
    let (_, found) =
        setup.one(&dana, "Blob/lookup", json!({ "typeNames": ["FileNode", "Email"], "ids": [file_blob, blob] })).await;
    assert_eq!(found["list"][0]["matchedIds"]["FileNode"], json!([node]), "{found}");
    assert_eq!(found["list"][1]["matchedIds"]["FileNode"], json!([]));
    let (name, _) = setup.one(&dana, "Blob/lookup", json!({ "typeNames": ["Calendar"], "ids": [blob] })).await;
    assert_eq!(name, "error");
}
