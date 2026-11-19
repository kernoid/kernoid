// SPDX-License-Identifier: MIT
//! Two devices and kernoid's relay, end to end (`scripts/client-check.sh` starts a kernoid with an open relay and names
//! it in `KERNOID_TEST_RELAY`, e.g. `http://127.0.0.1:18380/relay/kernoid`): found a space, write offline, invite and
//! add a device, sync both ways, remove a member, and bring the space back with the recovery code when every device is
//! lost. Without `KERNOID_TEST_RELAY` the test does nothing. The case of aktujo's core (aktujo 0.4.1), taken over with
//! it.

use std::sync::Arc;

use kernoid_blob::MemoryBlobs;
use kernoid_crypt::{Domain, Rights};
use kernoid_replica::{Replica, SyncError};
use kernoid_space_store::Store;
use serde_json::json;

const D: Domain = Domain::KERNOID;

/// The relay the script started, if any.
fn relay() -> Option<String> {
    std::env::var("KERNOID_TEST_RELAY").ok()
}

fn replica(device: &str) -> Replica {
    Replica::open(D, device.parse().unwrap(), Store::in_memory().unwrap(), Arc::new(MemoryBlobs::new())).unwrap()
}

fn titles<S: kernoid_space_store::Backend>(replica: &Replica<S>, space: &kernoid_base::SpaceId) -> Vec<String> {
    let log = replica.log(space).unwrap();
    log.ordered().iter().filter_map(|(_, e)| e.members.get("title")?.as_str().map(str::to_owned)).collect()
}

#[test]
fn two_devices_a_relay_a_removal_and_a_recovery() {
    let Some(url) = relay() else { return };
    let (mut laptop, mut phone) = (replica("laptop"), replica("phone"));

    // The laptop writes offline, then starts to synchronise.
    let space = laptop.new_space();
    laptop.write(&space, &json!({"kind": "document_added", "title": "Lease"})).unwrap();
    let scan = laptop.put_original(&space, b"%PDF-1.7 lease").unwrap();
    let code = laptop.start_sync(&space, &url, Some("Laptop")).unwrap();

    // The phone joins with an invitation; it waits until the laptop adds it.
    let invitation = laptop.invite(&space, Rights::Manage).unwrap();
    assert_eq!(phone.join(&invitation, Some("Phone")).unwrap(), space);
    assert!(phone.sync(&space).unwrap().waiting);
    assert_eq!(laptop.sync(&space).unwrap().added, vec!["Phone".to_owned()]);
    let report = phone.sync(&space).unwrap();
    assert_eq!(report.received, 2, "the event and the original");
    assert_eq!(titles(&phone, &space), ["Lease"]);
    assert_eq!(phone.original(&scan).unwrap().as_deref(), Some(&b"%PDF-1.7 lease"[..]));

    // Both write; both see both.
    phone.write(&space, &json!({"kind": "document_added", "title": "Receipt"})).unwrap();
    laptop.write(&space, &json!({"kind": "document_added", "title": "Notice"})).unwrap();
    phone.sync(&space).unwrap();
    laptop.sync(&space).unwrap();
    phone.sync(&space).unwrap();
    assert_eq!(laptop.log(&space).unwrap().state(), phone.log(&space).unwrap().state());
    assert_eq!(titles(&laptop, &space).len(), 3);
    assert!(laptop.log(&space).unwrap().verify().is_empty());

    // The laptop removes the phone: the phone learns it, and the laptop goes on with a new key.
    assert_eq!(laptop.remove_member(&space, "phone").unwrap(), "Phone");
    assert!(matches!(phone.sync(&space), Err(SyncError::State(_))));
    laptop.write(&space, &json!({"kind": "document_added", "title": "After"})).unwrap();
    laptop.sync(&space).unwrap();

    // Every device is lost: a new one comes back with the recovery code and receives everything.
    let mut tablet = replica("tablet");
    let report = tablet.recover(&url, &space, &code, Some("Tablet")).unwrap();
    assert_eq!(report.received, 5, "four events and the original");
    assert_eq!(tablet.log(&space).unwrap().state(), laptop.log(&space).unwrap().state());
    assert_eq!(tablet.original(&scan).unwrap().as_deref(), Some(&b"%PDF-1.7 lease"[..]));
    let mut members: Vec<_> = tablet.members(&space).unwrap().into_iter().filter_map(|m| m.name).collect();
    members.sort();
    assert_eq!(members, ["Laptop", "Recovery code", "Tablet"]);
}
