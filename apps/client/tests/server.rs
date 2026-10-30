// SPDX-License-Identifier: MIT
//! The SDK against a real kernoid (`scripts/client-check.sh` starts one and names it): logging in, mail, files with
//! an upload, a download, versions and the changes of the store, push. Without `KERNOID_TEST_SERVER` the tests do
//! nothing.

use std::time::Duration;

use kernoid_client::{Client, FILENODE, MAIL, Options, files, mail, push};

async fn client() -> Option<Client> {
    let server = std::env::var("KERNOID_TEST_SERVER").ok()?;
    let address = std::env::var("KERNOID_TEST_ADDRESS").expect("KERNOID_TEST_ADDRESS");
    let password = std::env::var("KERNOID_TEST_PASSWORD").expect("KERNOID_TEST_PASSWORD");
    let url = kernoid_client::session_url(Some(&server), &address).unwrap();
    Some(Client::connect(&url, &address, &password, &Options::default()).await.unwrap())
}

#[tokio::test]
async fn mail_of_the_account() {
    let Some(client) = client().await else { return };
    let account = client.primary(MAIL).unwrap();
    let boxes = mail::mailboxes(&client, &account).await.unwrap();
    for role in ["inbox", "drafts", "sent", "trash"] {
        assert!(boxes.iter().any(|b| b.role.as_deref() == Some(role)), "no {role} in {boxes:?}");
    }
}

#[tokio::test]
async fn a_file_up_down_changed_and_seen_by_push() {
    let Some(client) = client().await else { return };
    let account = client.primary(FILENODE).unwrap();
    let before = files::snapshot(&client, &account).await.unwrap();

    let (sender, mut heard) = tokio::sync::mpsc::unbounded_channel();
    let listening = push::listen(client.clone(), move |event| sender.send(event).is_ok());

    let dir = std::env::temp_dir().join(format!("kernoid-client-server-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("hello.txt");
    tokio::fs::write(&path, "hello, kernoid").await.unwrap();
    files::upload_file(&client, &account, None, &path, None, |_, _| {}).await.unwrap();
    let node = files::children(&client, &account, None).await.unwrap().into_iter().find(|n| n.name == "hello.txt").unwrap();
    let mut out = Vec::new();
    let size = client
        .download(&account, node.blob_id.as_deref().unwrap(), "hello.txt", "text/plain", &mut out, &mut |_, _| {})
        .await
        .unwrap();
    assert_eq!((size, out.as_slice()), (14, &b"hello, kernoid"[..]));

    // New content: the old one stays as a version.
    tokio::fs::write(&path, "hello again").await.unwrap();
    files::upload_file(&client, &account, None, &path, Some(&node), |_, _| {}).await.unwrap();
    assert_eq!(files::versions(&client, &account, &node.id).await.unwrap().len(), 2);

    let changes = files::changes(&client, &account, &before.state, 100).await.unwrap();
    assert!(changes.changed.iter().any(|n| n.id == node.id), "{changes:?}");

    // Push told that files changed.
    let told = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(event) = heard.recv().await {
            if let push::Push::Changed(types) = event
                && types.contains("FileNode")
            {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    listening.abort();
    files::destroy(&client, &account, &node.id).await.unwrap();
    tokio::fs::remove_dir_all(&dir).await.unwrap();
    assert!(told, "push told nothing of FileNode");
}
