// SPDX-License-Identifier: MIT
//! Two folders kept in step with one store of a real kernoid (`scripts/client-check.sh` starts one and names it): a
//! file made in one reaches the other, a change comes back, a change on both sides keeps both, a deletion carries over;
//! moves stay moves, large files go in pieces and transfers that broke off go on, vaults are kept in step with the
//! key. Without `KERNOID_TEST_SERVER` the tests do nothing.

use std::path::{Path, PathBuf};

use kernoid_client::{Client, FILENODE, Options, files};
use kernoid_sync::{
    Folder, PIECE, Report,
    state::{Pieces, State},
};

async fn client() -> Option<Client> {
    login("KERNOID_TEST_ADDRESS", "KERNOID_TEST_PASSWORD").await
}

async fn login(address: &str, password: &str) -> Option<Client> {
    let server = std::env::var("KERNOID_TEST_SERVER").ok()?;
    let address = std::env::var(address).ok()?;
    let password = std::env::var(password).expect("a password beside the address");
    let url = kernoid_client::session_url(Some(&server), &address).unwrap();
    Some(Client::connect(&url, &address, &password, &Options::default()).await.unwrap())
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// A round that did nothing – vaults of the account whose key is not at hand aside (the SDK's test leaves one).
fn nothing(report: Report) {
    assert_eq!(Report { locked: Vec::new(), ..report }, Report::default());
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
    nothing(one.sync(&client).await.unwrap());
    nothing(two.sync(&client).await.unwrap());

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

/// The ids of the store's nodes by name, for what keeps its node.
async fn ids(client: &Client, store: &str) -> std::collections::BTreeMap<String, String> {
    let snapshot = files::snapshot(client, store).await.unwrap();
    snapshot.nodes.into_iter().map(|node| (node.name, node.id)).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn moves_stay_moves() {
    let Some(client) = client().await else { return };
    let store = client.primary(FILENODE).unwrap();
    let work: PathBuf = std::env::temp_dir().join(format!("kernoid-sync-moves-{}", std::process::id()));
    let (a, b) = (work.join("a"), work.join("b"));
    let mut one = Folder::open(&a, &store, &work.join("a.db")).unwrap();
    let mut two = Folder::open(&b, &store, &work.join("b.db")).unwrap();
    std::fs::create_dir_all(a.join("Move test/Inner")).unwrap();
    std::fs::write(a.join("Move test/Inner/deep.txt"), "deep").unwrap();
    std::fs::write(a.join("Move test/loose.txt"), "loose").unwrap();
    one.sync(&client).await.unwrap();
    two.sync(&client).await.unwrap();
    let before = ids(&client, &store).await;

    // Moved here: on the server the same nodes, at the new paths; nothing sent again.
    std::fs::rename(a.join("Move test/Inner"), a.join("Move test/Renamed")).unwrap();
    std::fs::rename(a.join("Move test/loose.txt"), a.join("Move test/Renamed/loose.txt")).unwrap();
    let report = one.sync(&client).await.unwrap();
    assert_eq!((report.moved, report.uploaded, report.deleted_there, report.failed.len()), (2, 0, 0, 0), "{report:?}");
    let after = ids(&client, &store).await;
    assert_eq!(after["Renamed"], before["Inner"]);
    assert_eq!(after["loose.txt"], before["loose.txt"]);

    // In the other folder, a move from the server: nothing downloaded.
    let report = two.sync(&client).await.unwrap();
    assert_eq!((report.moved, report.downloaded, report.deleted_here), (2, 0, 0), "{report:?}");
    assert_eq!(read(&b.join("Move test/Renamed/deep.txt")), "deep");
    assert_eq!(read(&b.join("Move test/Renamed/loose.txt")), "loose");
    assert!(!b.join("Move test/Inner").exists());
    nothing(one.sync(&client).await.unwrap());
    nothing(two.sync(&client).await.unwrap());

    std::fs::remove_dir_all(a.join("Move test")).unwrap();
    one.sync(&client).await.unwrap();
    std::fs::remove_dir_all(&work).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn large_files_go_in_pieces_and_transfers_go_on() {
    let Some(client) = client().await else { return };
    let store = client.primary(FILENODE).unwrap();
    let work: PathBuf = std::env::temp_dir().join(format!("kernoid-sync-pieces-{}", std::process::id()));
    let (a, b) = (work.join("a"), work.join("b"));
    std::fs::create_dir_all(a.join("Pieces")).unwrap();
    // Two and a half pieces, not repeating, so that a piece out of place shows.
    let content: Vec<u8> = (0..(PIECE * 5 / 2)).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(a.join("Pieces/large.bin"), &content).unwrap();

    // The first piece sent before, as by a round that broke off: the round sends only the others.
    let meta = std::fs::metadata(a.join("Pieces/large.bin")).unwrap();
    let modified = meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i128;
    let first = client
        .upload(
            &store,
            "application/octet-stream",
            std::io::Cursor::new(content[..PIECE as usize].to_vec()),
            PIECE,
            |_, _| {},
        )
        .await
        .unwrap();
    {
        let state = State::open(&work.join("a.db")).unwrap();
        state.set_meta("store", &store).unwrap();
        let started = jiff::Timestamp::now().as_second();
        let pieces = Pieces { size: meta.len(), modified, blobs: vec![first.blob_id], started };
        state.set_upload("Pieces/large.bin", Some(&pieces)).unwrap();
    }
    let mut one = Folder::open(&a, &store, &work.join("a.db")).unwrap();
    let report = one.sync(&client).await.unwrap();
    assert_eq!((report.uploaded, report.failed.len()), (1, 0), "{report:?}");
    assert!(State::open(&work.join("a.db")).unwrap().upload("Pieces/large.bin").unwrap().is_none());

    // A download that broke off after the first piece goes on from there.
    let snapshot = files::snapshot(&client, &store).await.unwrap();
    let blob = snapshot.nodes.iter().find(|n| n.name == "large.bin").unwrap().blob_id.clone().unwrap();
    std::fs::create_dir_all(b.join("Pieces")).unwrap();
    std::fs::write(b.join("Pieces/large.bin.kernoid-part"), &content[..PIECE as usize]).unwrap();
    {
        let state = State::open(&work.join("b.db")).unwrap();
        state.set_meta("store", &store).unwrap();
        state.set_download("Pieces/large.bin", Some(&blob)).unwrap();
    }
    let mut two = Folder::open(&b, &store, &work.join("b.db")).unwrap();
    let report = two.sync(&client).await.unwrap();
    assert_eq!((report.downloaded, report.failed.len()), (1, 0), "{report:?}");
    assert!(std::fs::read(b.join("Pieces/large.bin")).unwrap() == content, "the whole file, in order");
    assert!(!b.join("Pieces/large.bin.kernoid-part").exists());

    std::fs::remove_dir_all(a.join("Pieces")).unwrap();
    one.sync(&client).await.unwrap();
    std::fs::remove_dir_all(&work).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vault_is_kept_in_step_with_the_key() {
    use kernoid_client::e2e::E2e;
    let Some(client) = login("KERNOID_TEST_VAULT_ADDRESS", "KERNOID_TEST_VAULT_PASSWORD").await else { return };
    let mut e2e = E2e::load(&client).await.unwrap();
    if !e2e.vaults_allowed() || e2e.has_key() {
        return;
    }
    let code = e2e.setup(&client, kernoid_e2e::Kind::Pqc).await.unwrap();
    let store = client.primary(FILENODE).unwrap();
    let vault = e2e.create_vault(&client, &store, None, "Tresor").await.unwrap();
    let work: PathBuf = std::env::temp_dir().join(format!("kernoid-sync-vault-{}", std::process::id()));
    let (a, b) = (work.join("a"), work.join("b"));
    let mut one = Folder::open(&a, &store, &work.join("a.db")).unwrap();
    let mut two = Folder::open(&b, &store, &work.join("b.db")).unwrap();
    one.sync_with(&client, Some(&mut e2e)).await.unwrap();
    assert!(a.join("Tresor").is_dir(), "the vault by its real name");

    // Made here, encrypted on the server: ids and ciphertext only.
    std::fs::create_dir_all(a.join("Tresor/Akten")).unwrap();
    std::fs::write(a.join("Tresor/Akten/brief.txt"), "nur für Mitglieder").unwrap();
    let report = one.sync_with(&client, Some(&mut e2e)).await.unwrap();
    assert_eq!((report.uploaded, report.directories, report.failed.len()), (1, 1, 0), "{report:?}");
    let snapshot = files::snapshot(&client, &store).await.unwrap();
    assert!(snapshot.nodes.iter().all(|n| n.name != "Akten" && n.name != "brief.txt"));
    let blob = snapshot.nodes.iter().find(|n| n.in_vault() && !n.is_directory()).unwrap().blob_id.clone().unwrap();
    let mut raw = Vec::new();
    client.download(&store, &blob, "x", "application/octet-stream", &mut raw, &mut |_, _| {}).await.unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("Mitglieder"));

    // Without the key: a folder that knows the names already keeps them, and nothing is deleted on either side…
    nothing(one.sync(&client).await.unwrap());
    assert!(a.join("Tresor/Akten/brief.txt").exists());
    // …and one that never had the key leaves the vault out.
    let report = two.sync(&client).await.unwrap();
    assert!(!b.join("Tresor").exists() && report.locked == [vault.clone()], "{report:?}");

    // With it, the other folder gets the real names and the content; a move stays within the vault.
    e2e.lock();
    e2e.unlock(&code).unwrap();
    let report = two.sync_with(&client, Some(&mut e2e)).await.unwrap();
    assert_eq!((report.downloaded, report.failed.len()), (1, 0), "{report:?}");
    assert_eq!(read(&b.join("Tresor/Akten/brief.txt")), "nur für Mitglieder");
    std::fs::rename(b.join("Tresor/Akten/brief.txt"), b.join("Tresor/brief.txt")).unwrap();
    let report = two.sync_with(&client, Some(&mut e2e)).await.unwrap();
    assert_eq!((report.moved, report.uploaded, report.failed.len()), (1, 0, 0), "{report:?}");
    let report = one.sync_with(&client, Some(&mut e2e)).await.unwrap();
    assert_eq!((report.moved, report.downloaded), (1, 0), "{report:?}");
    assert_eq!(read(&a.join("Tresor/brief.txt")), "nur für Mitglieder");

    std::fs::remove_dir_all(&work).unwrap();
}
