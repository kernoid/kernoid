// SPDX-License-Identifier: MIT
//! The SDK against a real kernoid (`scripts/client-check.sh` starts one and names it): logging in, mail, files with
//! an upload, a download, versions and the changes of the store, push. Without `KERNOID_TEST_SERVER` the tests do
//! nothing.

use std::time::Duration;

use kernoid_client::{Client, FILENODE, MAIL, Options, account, files, mail, push};

async fn client() -> Option<Client> {
    let server = std::env::var("KERNOID_TEST_SERVER").ok()?;
    let address = std::env::var("KERNOID_TEST_ADDRESS").expect("KERNOID_TEST_ADDRESS");
    let password = std::env::var("KERNOID_TEST_PASSWORD").expect("KERNOID_TEST_PASSWORD");
    let url = kernoid_client::session_url(Some(&server), &address).unwrap();
    Some(Client::connect(&url, &address, &password, &Options::default()).await.unwrap())
}

#[tokio::test]
async fn an_app_password_changes_no_settings() {
    let Some(client) = client().await else { return };
    assert!(matches!(account::language(&client).await, Err(kernoid_client::Error::Unauthorized)));
    assert!(matches!(account::set_name(&client, "Mallory").await, Err(kernoid_client::Error::Unauthorized)));
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
    let node =
        files::children(&client, &account, None).await.unwrap().into_iter().find(|n| n.name == "hello.txt").unwrap();
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

/// What the browser does in a login: kernoid's login page logs in (here: `/v1/sessions` with the password) and
/// finishes the auth request `authorize` parked; the callback URL comes back.
async fn browser(login_url: &str, server: &str, address: &str, password: &str) -> String {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(
            url::Url::parse(server).unwrap().host_str().unwrap(),
            std::net::SocketAddr::from(([127, 0, 0, 1], url::Url::parse(server).unwrap().port().unwrap_or(443))),
        )
        .build()
        .unwrap();
    let session: serde_json::Value = http
        .post(format!("{server}/v1/sessions"))
        .json(&serde_json::json!({ "address": address, "password": password }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = session["token"].as_str().expect("a session").to_owned();
    let to_login = http.get(login_url).send().await.unwrap();
    let location = to_login.headers()["location"].to_str().unwrap().to_owned();
    let request = location.split("authRequest=").nth(1).expect("an auth request").to_owned();
    let finished: serde_json::Value = http
        .post(format!("{server}/v1/auth-requests/{request}"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    finished["callback_url"].as_str().unwrap_or_else(|| panic!("{finished}")).to_owned()
}

#[tokio::test]
async fn an_app_logs_in_with_openid_connect() {
    let Ok(server) = std::env::var("KERNOID_TEST_SERVER") else { return };
    let address = std::env::var("KERNOID_TEST_ADDRESS").unwrap();
    let password = std::env::var("KERNOID_TEST_PASSWORD").unwrap();
    let options = Options::default();
    // A loopback redirect on a port of the app's choosing, as a desktop app listens.
    let login =
        kernoid_client::oidc::begin(&server, "http://127.0.0.1:47613/oauth", Some(&address), &options).await.unwrap();
    assert!(login.url.contains("code_challenge_method=S256") && login.url.contains("urn%3Akernoid%3Adata"));
    let callback = browser(&login.url, &server, &address, &password).await;
    assert!(callback.starts_with("http://127.0.0.1:47613/oauth?"), "{callback}");
    let tokens = kernoid_client::oidc::finish(&login, &callback, &options).await.unwrap();
    assert!(tokens.refresh_token.is_some());

    // The access token reaches JMAP; renewed, the client keeps working with the new one.
    let url = kernoid_client::session_url(Some(&server), &address).unwrap();
    let client = Client::connect_with_token(&url, &tokens.access_token, &options).await.unwrap();
    assert_eq!(client.session.username, address);
    let account = client.primary(MAIL).unwrap();
    mail::mailboxes(&client, &account).await.unwrap();
    // The everyday settings take the app's token: name, language, mail settings, picture.
    account::set_name(&client, "Alice A.").await.unwrap();
    account::set_language(&client, Some("de")).await.unwrap();
    let language = account::language(&client).await.unwrap();
    assert_eq!((language.language.as_deref(), language.used.as_str()), (Some("de"), "de"));
    account::set_language(&client, None).await.unwrap();
    let mut settings = account::mail_settings(&client).await.unwrap();
    settings.undo_send_seconds = 10;
    settings.trash_retention_days = Some(14);
    account::set_mail_settings(&client, &settings).await.unwrap();
    assert_eq!(account::mail_settings(&client).await.unwrap(), settings);
    account::set_mail_settings(&client, &account::MailSettings::default()).await.unwrap();
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1,
        8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0, 1, 0, 0, 5,
        0, 1, 0x0d, 0x0a, 0x2d, 0xb4, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];
    account::set_avatar(&client, PNG.to_vec(), "image/png").await.unwrap();
    assert_eq!(account::avatar(&client, &account).await.unwrap().as_deref(), Some(PNG));
    account::remove_avatar(&client).await.unwrap();
    assert_eq!(account::avatar(&client, &account).await.unwrap(), None);
    let renewed = kernoid_client::oidc::refresh(&tokens, &options).await.unwrap();
    assert_ne!(renewed.access_token, tokens.access_token);
    client.set_access_token(&renewed.access_token);
    mail::mailboxes(&client, &account).await.unwrap();
    // Kept and resumed, as after a restart; revoked, the login is over.
    let saved = renewed.saved().unwrap();
    let text = serde_json::to_string(&saved).unwrap();
    assert!(!text.contains(&renewed.access_token), "the access token is never kept");
    let resumed = kernoid_client::oidc::refresh(
        &serde_json::from_str::<kernoid_client::oidc::Saved>(&text).unwrap().tokens(),
        &options,
    )
    .await
    .unwrap();
    client.set_access_token(&resumed.access_token);
    mail::mailboxes(&client, &account).await.unwrap();
    kernoid_client::oidc::revoke(&resumed, &options).await.unwrap();
    assert!(matches!(
        kernoid_client::oidc::refresh(&resumed, &options).await,
        Err(kernoid_client::Error::Unauthorized)
    ));
    assert!(mail::mailboxes(&client, &account).await.is_err(), "its access token ends with it");
    // A refresh token used before is used up (and presenting it again would end the login, were it still on).
    assert!(matches!(kernoid_client::oidc::refresh(&tokens, &options).await, Err(kernoid_client::Error::Unauthorized)));
    // A callback for another request is refused.
    let other = kernoid_client::oidc::begin(&server, "http://127.0.0.1:47613/oauth", None, &options).await.unwrap();
    assert!(kernoid_client::oidc::finish(&other, &callback, &options).await.is_err());
}

#[tokio::test]
async fn folders_made_renamed_moved_emptied_and_removed() {
    let Some(client) = client().await else { return };
    let account = client.primary(MAIL).unwrap();
    let stamp = std::process::id();
    let parent = mail::create_mailbox(&client, &account, &format!("SDK {stamp}"), None).await.unwrap();
    let child = mail::create_mailbox(&client, &account, "Kind", Some(&parent)).await.unwrap();
    let find = async |id: &str| mail::mailboxes(&client, &account).await.unwrap().into_iter().find(|b| b.id == id);
    assert_eq!(find(&child).await.unwrap().parent_id.as_deref(), Some(parent.as_str()));

    mail::rename_mailbox(&client, &account, &child, "Umbenannt").await.unwrap();
    mail::move_mailbox(&client, &account, &child, None).await.unwrap();
    let moved = find(&child).await.unwrap();
    assert_eq!((moved.name.as_str(), moved.parent_id), ("Umbenannt", None));

    // A message in it: emptied, then the folder goes; one with a message is refused unless its emails go too.
    let message =
        format!("From: a@x.example\r\nSubject: Ordner {stamp}\r\nMessage-ID: <o{stamp}@x.example>\r\n\r\nHallo\r\n");
    let upload = client
        .upload(
            &account,
            "message/rfc822",
            std::io::Cursor::new(message.clone().into_bytes()),
            message.len() as u64,
            |_, _| {},
        )
        .await
        .unwrap();
    client
        .call(
            &[MAIL],
            "Email/import",
            serde_json::json!({ "accountId": account, "emails": { "e": {
            "blobId": upload.blob_id, "mailboxIds": { child.as_str(): true } } } }),
        )
        .await
        .unwrap();
    assert!(mail::destroy_mailbox(&client, &account, &child, false).await.is_err(), "it holds an email");
    assert_eq!(mail::empty_mailbox(&client, &account, &child).await.unwrap(), 1);
    mail::destroy_mailbox(&client, &account, &child, false).await.unwrap();
    mail::destroy_mailbox(&client, &account, &parent, true).await.unwrap();
    assert!(find(&child).await.is_none() && find(&parent).await.is_none());
}
