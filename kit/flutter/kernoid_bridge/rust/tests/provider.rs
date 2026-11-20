// SPDX-License-Identifier: MIT
//! The core of the file shells (`kernoid_bridge::provider`) against a real kernoid, as `tests/server.rs`: the same
//! variables, nothing without them. A folder and a file are made, listed, seen in the changes, changed, fetched and
//! deleted – what Finder, Android's Files and Explorer will ask.

use kernoid_bridge::provider::call;
use serde_json::{Value, json};

fn ask(request: Value) -> Value {
    let answer: Value = serde_json::from_str(&call(&request.to_string())).unwrap();
    assert!(answer.get("error").is_none(), "{request} → {answer}");
    answer["ok"].clone()
}

#[test]
fn the_core_answers_what_a_file_manager_asks() {
    let (Ok(server), Ok(address), Ok(password)) = (
        std::env::var("KERNOID_TEST_SERVER"),
        std::env::var("KERNOID_TEST_ADDRESS"),
        std::env::var("KERNOID_TEST_PASSWORD"),
    ) else {
        return;
    };
    let session = ask(json!({ "op": "open", "server": server, "address": address, "password": password }))["session"]
        .as_u64()
        .unwrap();
    let stores = ask(json!({ "op": "stores", "session": session }));
    let store = stores["stores"].as_array().unwrap().iter().find(|s| s["kind"] == "own").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let start = ask(json!({ "op": "changes", "session": session, "store": store }));
    assert_eq!(start["reset"], true);
    let anchor = start["anchor"].as_str().unwrap().to_owned();

    let stamp = std::process::id();
    let folder = ask(json!({ "op": "create", "session": session, "store": store, "parent": null,
        "name": format!("Provider {stamp}"), "directory": true }))["item"]
        .clone();
    let dir = std::env::temp_dir().join(format!("kernoid-provider-{stamp}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("staged"), "first").unwrap();
    let file = ask(json!({ "op": "create", "session": session, "store": store, "parent": folder["id"],
        "name": "notes.txt", "directory": false, "from": dir.join("staged") }))["item"]
        .clone();
    assert_eq!((file["name"].as_str(), file["size"].as_u64()), (Some("notes.txt"), Some(5)));

    // Seen in the changes since the start, and listed.
    let changed = ask(json!({ "op": "changes", "session": session, "store": store, "since": anchor }));
    let ids: Vec<&str> = changed["items"].as_array().unwrap().iter().filter_map(|i| i["id"].as_str()).collect();
    assert!(ids.contains(&folder["id"].as_str().unwrap()) && ids.contains(&file["id"].as_str().unwrap()));
    let listed = ask(json!({ "op": "list", "session": session, "store": store, "parent": folder["id"] }));
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    // kernoid gives rights on directories only: a file takes its directory's, in every answer of the core.
    let writable = |item: &Value| item["rights"]["write"] == true && item["rights"]["rename"] == true;
    assert!(writable(&file), "{file}");
    assert!(writable(&listed["items"][0]), "{listed}");
    assert!(changed["items"].as_array().unwrap().iter().filter(|i| i["id"] == file["id"]).all(writable), "{changed}");

    // Renamed and given new content: a new version; fetched with it.
    std::fs::write(dir.join("changed"), "second, longer").unwrap();
    let modified = ask(json!({ "op": "modify", "session": session, "store": store, "id": file["id"],
        "name": "renamed.txt", "from": dir.join("changed") }))["item"]
        .clone();
    assert_eq!(modified["name"], "renamed.txt");
    assert_ne!(modified["version"], file["version"]);
    let target = dir.join("fetched");
    ask(json!({ "op": "fetch", "session": session, "store": store, "id": file["id"], "to": target }));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "second, longer");

    // Deleted: into the Trash, gone from where it was.
    ask(json!({ "op": "delete", "session": session, "store": store, "id": folder["id"] }));
    let top = ask(json!({ "op": "list", "session": session, "store": store, "parent": null }));
    assert!(top["items"].as_array().unwrap().iter().all(|i| i["id"] != folder["id"]));
    // Deleted from the Trash: gone for good.
    ask(json!({ "op": "delete", "session": session, "store": store, "id": folder["id"], "forever": true }));
    let gone: Value = serde_json::from_str(&call(
        &json!({ "op": "item", "session": session, "store": store, "id": folder["id"] }).to_string(),
    ))
    .unwrap();
    assert_eq!(gone["error"]["message"], "no such item");
    ask(json!({ "op": "close", "session": session }));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Vaults on spaces in the file manager (RFC 0010, 5): the app makes a vault and hands the shell its code; the shell,
/// a device of its own, lists, fetches, makes, renames and deletes in it, and the app sees what it did.
#[test]
fn a_vault_on_a_space_in_the_file_manager() {
    let (Ok(server), Ok(address), Ok(password)) = (
        std::env::var("KERNOID_TEST_SERVER"),
        std::env::var("KERNOID_TEST_SHELL_ADDRESS"),
        std::env::var("KERNOID_TEST_PASSWORD"),
    ) else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let work = std::env::temp_dir().join(format!("kernoid-shell-vaults-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let key = [5u8; 32];
    let (store, vault, file) = runtime.block_on(async {
        use kernoid_client::{
            Client, FILENODE, Options,
            e2e::{E2e, Vaults},
        };
        // The app: logged in by token, its key made here, a vault with a letter in it.
        let host = url::Url::parse(&server).unwrap();
        let http = reqwest::Client::builder()
            .resolve(host.host_str().unwrap(), std::net::SocketAddr::from(([127, 0, 0, 1], host.port().unwrap())))
            .build()
            .unwrap();
        let session: Value = http
            .post(format!("{server}/v1/sessions"))
            .json(&json!({ "address": address, "password": password }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let url = kernoid_client::session_url(Some(&server), &address).unwrap();
        let client =
            Client::connect_with_token(&url, session["token"].as_str().unwrap(), &Options::default()).await.unwrap();
        let mut e2e = E2e::load(&client).await.unwrap();
        if !e2e.has_key() {
            e2e.setup(&client, kernoid_e2e::Kind::Pqc).await.unwrap();
        }
        let store = client.primary(FILENODE).unwrap();
        let app = Vaults::in_memory("app").unwrap();
        let id = app.create(&client, &mut e2e, &store, None, "Hülle").await.unwrap();
        let node = kernoid_client::files::get(&client, &store, &id).await.unwrap();
        let file = app.put_file(&node, None, "brief.txt", b"aus der App".to_vec(), None, None, None).await.unwrap();
        // The codes the app hands the shell.
        let code = Vaults::code(&client, &mut e2e, &store, &node).await.unwrap().unwrap();
        let hex: String = code.iter().map(|b| format!("{b:02x}")).collect();
        let codes = json!({ id.clone(): [node.space.clone().unwrap(), hex] });
        let sealed = kernoid_vault::sealed::seal(&key, codes.to_string().as_bytes());
        std::fs::write(work.join("shell-codes.sealed"), sealed).unwrap();
        (store, id, file)
    });
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let vaults = json!({
        "store": work.join("shell.sealed").to_string_lossy(),
        "codes": work.join("shell-codes.sealed").to_string_lossy(),
        "key": hex_key,
    });
    let session = ask(json!({ "op": "open", "server": server, "address": address, "password": password,
        "vaults": vaults }))["session"]
        .as_u64()
        .unwrap();

    // The vault by its name, open; in it the app's letter.
    let top = ask(json!({ "op": "list", "session": session, "store": store, "parent": null }));
    let shown = top["items"].as_array().unwrap().iter().find(|i| i["id"] == vault.as_str()).unwrap().clone();
    assert_eq!((shown["name"].as_str(), shown["locked"].as_bool()), (Some("Hülle"), Some(false)), "{shown}");
    let inside = ask(json!({ "op": "list", "session": session, "store": store, "parent": vault }));
    let letter = inside["items"].as_array().unwrap().iter().find(|i| i["name"] == "brief.txt").unwrap().clone();
    assert_eq!(letter["id"].as_str().unwrap(), format!("s|{vault}|{file}"));
    let to = work.join("fetched.txt");
    ask(json!({ "op": "fetch", "session": session, "store": store, "id": letter["id"], "to": to.to_string_lossy() }));
    assert_eq!(std::fs::read(&to).unwrap(), b"aus der App");

    // Made, renamed and deleted from the file manager.
    let from = work.join("neu.txt");
    std::fs::write(&from, "aus dem Finder").unwrap();
    let made = ask(json!({ "op": "create", "session": session, "store": store, "parent": vault, "name": "neu.txt",
        "directory": false, "from": from.to_string_lossy() }))["item"]
        .clone();
    let folder = ask(json!({ "op": "create", "session": session, "store": store, "parent": vault, "name": "Akten",
        "directory": true }))["item"]
        .clone();
    let moved = ask(json!({ "op": "modify", "session": session, "store": store, "id": made["id"],
        "name": "Neu.txt", "parent": folder["id"] }))["item"]
        .clone();
    assert_eq!((moved["name"].as_str(), &moved["parent"]), (Some("Neu.txt"), &folder["id"]));
    let item = ask(json!({ "op": "item", "session": session, "store": store, "id": moved["id"] }))["item"].clone();
    assert_eq!(item["size"], 14);
    let changes = ask(json!({ "op": "changes", "session": session, "store": store }));
    assert!(changes["anchor"].as_str().unwrap().contains('~'));
    assert!(changes["items"].as_array().unwrap().iter().any(|i| i["id"] == moved["id"]));
    let anchor = changes["anchor"].as_str().unwrap().to_owned();
    ask(json!({ "op": "delete", "session": session, "store": store, "id": letter["id"] }));
    let after = ask(json!({ "op": "changes", "session": session, "store": store, "since": anchor }));
    assert_eq!(after["reset"], true, "what is in the vault changed");
    assert!(!after["items"].as_array().unwrap().iter().any(|i| i["id"] == letter["id"]), "into the vault's trash");
    ask(json!({ "op": "close", "session": session }));
    std::fs::remove_dir_all(&work).unwrap();
}
