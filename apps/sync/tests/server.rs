// SPDX-License-Identifier: MIT
//! Two folders kept in step with one store of a real kernoid (`scripts/client-check.sh` starts one and names it): a
//! file made in one reaches the other, a change comes back, a change on both sides keeps both, a deletion carries over.
//! Without `KERNOID_TEST_SERVER` the test does nothing.

use std::path::{Path, PathBuf};

use kernoid_client::{Client, FILENODE, Options};
use kernoid_sync::Folder;

async fn client() -> Option<Client> {
    let server = std::env::var("KERNOID_TEST_SERVER").ok()?;
    let address = std::env::var("KERNOID_TEST_ADDRESS").expect("KERNOID_TEST_ADDRESS");
    let password = std::env::var("KERNOID_TEST_PASSWORD").expect("KERNOID_TEST_PASSWORD");
    let url = kernoid_client::session_url(Some(&server), &address).unwrap();
    Some(Client::connect(&url, &address, &password, &Options::default()).await.unwrap())
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// Waits a moment, so that a file written again gets another modification time on every file system.
async fn tick() {
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_folders_kept_in_step() {
    let Some(client) = client().await else { return };
    let store = client.primary(FILENODE).unwrap();
    let work: PathBuf = std::env::temp_dir().join(format!("kernoid-sync-server-{}", std::process::id()));
    let (a, b) = (work.join("a"), work.join("b"));
    let mut one = Folder::open(&a, &store, &work.join("a.db")).unwrap();
    let mut two = Folder::open(&b, &store, &work.join("b.db")).unwrap();
    one.sync(&client).await.unwrap();
    two.sync(&client).await.unwrap();

    // Made in one, it reaches the other – a directory with a file in it.
    std::fs::create_dir_all(a.join("Sync test")).unwrap();
    std::fs::write(a.join("Sync test/notes.txt"), "first").unwrap();
    let report = one.sync(&client).await.unwrap();
    assert_eq!((report.uploaded, report.directories, report.failed.len()), (1, 1, 0), "{report:?}");
    let report = two.sync(&client).await.unwrap();
    assert_eq!((report.downloaded, report.failed.len()), (1, 0), "{report:?}");
    assert_eq!(read(&b.join("Sync test/notes.txt")), "first");
    // Nothing changed since: nothing to do on either side.
    assert_eq!(one.sync(&client).await.unwrap(), Default::default());
    assert_eq!(two.sync(&client).await.unwrap(), Default::default());

    // Changed in the other, it comes back.
    tick().await;
    std::fs::write(b.join("Sync test/notes.txt"), "second, longer").unwrap();
    assert_eq!(two.sync(&client).await.unwrap().uploaded, 1);
    assert_eq!(one.sync(&client).await.unwrap().downloaded, 1);
    assert_eq!(read(&a.join("Sync test/notes.txt")), "second, longer");

    // Changed on both sides: the server's version keeps the name, the local one a copy beside it – uploaded next.
    tick().await;
    std::fs::write(a.join("Sync test/notes.txt"), "from a").unwrap();
    std::fs::write(b.join("Sync test/notes.txt"), "from b, longer").unwrap();
    one.sync(&client).await.unwrap();
    let report = two.sync(&client).await.unwrap();
    assert_eq!(report.conflicts, ["Sync test/notes.txt"], "{report:?}");
    assert_eq!(read(&b.join("Sync test/notes.txt")), "from a");
    let copy = std::fs::read_dir(b.join("Sync test"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.to_string_lossy().contains("(conflict "))
        .expect("a conflict copy");
    assert_eq!(read(&copy), "from b, longer");
    assert_eq!(two.sync(&client).await.unwrap().uploaded, 1);
    one.sync(&client).await.unwrap();
    assert!(a.join("Sync test").join(copy.file_name().unwrap()).exists(), "the copy reached the other folder");

    // Deleted in one, gone in the other – the directory with what is in it, to the store's trash.
    std::fs::remove_dir_all(a.join("Sync test")).unwrap();
    assert_eq!(one.sync(&client).await.unwrap().deleted_there, 1);
    assert_eq!(two.sync(&client).await.unwrap().deleted_here, 1);
    assert!(!b.join("Sync test").exists());
    std::fs::remove_dir_all(&work).unwrap();
}
