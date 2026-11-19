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
