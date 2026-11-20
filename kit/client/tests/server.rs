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

#[tokio::test]
async fn a_vault_keeps_names_and_contents_from_the_server() {
    use kernoid_client::e2e::E2e;
    let Some(client) = client().await else { return };
    let mut e2e = E2e::load(&client).await.unwrap();
    // The account's own key is made here once; with one from before, its recovery code is not known.
    if !e2e.vaults_allowed() || e2e.has_key() {
        return;
    }
    let code = e2e.setup(&client, kernoid_e2e::Kind::Pqc).await.unwrap();
    let account = client.primary(FILENODE).unwrap();

    let vault = e2e.create_vault(&client, &account, None, "Geheim").await.unwrap();
    e2e.create_directory_in(&client, &account, &vault, &vault, "Verträge").await.unwrap();
    let dir = std::env::temp_dir().join(format!("kernoid-client-vault-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("Brief.txt");
    tokio::fs::write(&path, "nur für Mitglieder").await.unwrap();
    e2e.upload_into(&client, &account, &vault, &vault, &path, None, |_, _| {}).await.unwrap();

    // The server sees ids and ciphertext only.
    let mut top = files::children(&client, &account, None).await.unwrap();
    let mut inside = files::children(&client, &account, Some(&vault)).await.unwrap();
    assert!(top.iter().chain(&inside).all(|n| n.name != "Geheim" && n.name != "Verträge" && n.name != "Brief.txt"));
    let file = inside.iter().find(|n| !n.is_directory()).unwrap().clone();
    let mut raw = Vec::new();
    let blob = file.blob_id.as_deref().unwrap();
    client.download(&account, blob, "x", "application/octet-stream", &mut raw, &mut |_, _| {}).await.unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("Mitglieder"));

    // With the key: the real names and the content.
    e2e.open_names(&client, &account, &mut top).await;
    e2e.open_names(&client, &account, &mut inside).await;
    assert!(top.iter().any(|n| n.name == "Geheim" && n.vault.as_deref() == Some(vault.as_str()) && !n.locked));
    let mut names: Vec<_> = inside.iter().map(|n| n.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["Brief.txt", "Verträge"]);
    let file = inside.iter().find(|n| n.name == "Brief.txt").unwrap();
    assert_eq!(e2e.download_from(&client, &account, file).await.unwrap(), "nur für Mitglieder".as_bytes());

    // Renamed; locked, the names are ids again – and come back with the recovery code.
    e2e.rename_in(&client, &account, file, "Antwort.txt").await.unwrap();
    e2e.lock();
    let mut again = files::children(&client, &account, Some(&vault)).await.unwrap();
    e2e.open_names(&client, &account, &mut again).await;
    assert!(again.iter().all(|n| n.locked));
    e2e.unlock(&code).unwrap();
    e2e.open_names(&client, &account, &mut again).await;
    assert!(again.iter().any(|n| n.name == "Antwort.txt" && !n.locked));

    // Nothing moves out of a vault.
    let moved = files::move_to(&client, &account, &file.id, None).await;
    assert!(moved.is_err(), "{moved:?}");
    tokio::fs::remove_dir_all(&dir).await.unwrap();

    let old = top.into_iter().find(|n| n.id == vault).unwrap();
    vaults_on_spaces(&mut e2e, &account, &old).await;
}

/// A client logged in by a session token – what the relay takes to found a space.
async fn by_token(address: &str) -> Client {
    session(address).await.0
}

/// The same, with the token – for kernoid's own REST API.
async fn session(address: &str) -> (Client, String) {
    let server = std::env::var("KERNOID_TEST_SERVER").unwrap();
    let password = std::env::var("KERNOID_TEST_PASSWORD").unwrap();
    let http = reqwest::Client::builder()
        .resolve(
            url::Url::parse(&server).unwrap().host_str().unwrap(),
            std::net::SocketAddr::from(([127, 0, 0, 1], url::Url::parse(&server).unwrap().port().unwrap_or(443))),
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
    let token = session["token"].as_str().unwrap_or_else(|| panic!("no session: {session}")).to_owned();
    let url = kernoid_client::session_url(Some(&server), address).unwrap();
    (Client::connect_with_token(&url, &token, &Options::default()).await.unwrap(), token)
}

/// A request to kernoid's REST API with a session token.
async fn rest(token: &str, method: reqwest::Method, path: &str, body: Option<serde_json::Value>) -> serde_json::Value {
    let server = std::env::var("KERNOID_TEST_SERVER").unwrap();
    let host = url::Url::parse(&server).unwrap();
    let http = reqwest::Client::builder()
        .resolve(host.host_str().unwrap(), std::net::SocketAddr::from(([127, 0, 0, 1], host.port().unwrap_or(443))))
        .build()
        .unwrap();
    let mut request = http.request(method, format!("{server}{path}")).bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    assert!(response.status().is_success(), "{path}: {}", response.status());
    response.json().await.unwrap_or(serde_json::Value::Null)
}

/// Vaults on spaces (RFC 0010, 5): the OpenPGP vault moves onto a space, Alice's second device comes in with her
/// code, Carol is made a member and removed again.
async fn vaults_on_spaces(e2e: &mut kernoid_client::e2e::E2e, account: &str, old: &files::FileNode) {
    use kernoid_client::e2e::{E2e, Vaults, relay_url};
    let address = std::env::var("KERNOID_TEST_ADDRESS").unwrap();
    let Ok(carol_address) = std::env::var("KERNOID_TEST_SPACE_ADDRESS") else { return };
    let alice = by_token(&address).await;
    assert!(relay_url(&alice).is_some(), "the server names the relay of vaults");
    let laptop = Vaults::in_memory("Alice's laptop").unwrap();

    // The OpenPGP vault, copied onto a space beside it: names, directories, contents.
    let moved = laptop.move_vault(&alice, e2e, account, old).await.unwrap();
    let node = files::children(&alice, account, None).await.unwrap().into_iter().find(|n| n.id == moved).unwrap();
    assert!(node.space.is_some() && node.name.starts_with("k-") && node.encrypted_name.is_none(), "{node:?}");
    assert_eq!(laptop.name(&node).await.unwrap().as_deref(), Some("Geheim"));
    let top = laptop.list(&node, None).await.unwrap();
    let names: Vec<(&str, bool)> = top.iter().map(|e| (e.name.as_str(), e.directory)).collect();
    assert_eq!(names, [("Verträge", true), ("Antwort.txt", false)]);
    let letter = top.iter().find(|e| !e.directory).unwrap().clone();
    assert_eq!(laptop.read_file(&node, &letter.id).await.unwrap(), "nur für Mitglieder".as_bytes());
    assert!(files::children(&alice, account, Some(&node.id)).await.unwrap().is_empty(), "the store sees nothing in it");

    // Directories, a move, a rename, a new version, the trash.
    let archive = laptop.make_directory(&node, None, "Archiv").await.unwrap();
    laptop.move_to(&node, None, &letter.id, Some(&archive)).await.unwrap();
    laptop.rename(&node, Some(&archive), &letter.id, "Brief 2026.txt").await.unwrap();
    laptop
        .put_file(&node, Some(&archive), "", b"neu".to_vec(), Some("text/plain"), None, Some(&letter.id))
        .await
        .unwrap();
    let note = laptop.put_file(&node, None, "Notiz.md", b"# Notiz".to_vec(), None, None, None).await.unwrap();
    laptop.set_trashed(&node, None, &note, true).await.unwrap();

    // Alice's phone: in with her code, sealed to her key; its vaults kept sealed in a file.
    let sealed = std::env::temp_dir().join(format!("kernoid-vaults-{}.sealed", std::process::id()));
    let phone = Vaults::open_sealed(&sealed, [9u8; 32], "Alice's phone").unwrap();
    assert!(phone.enter(&alice, e2e, account, &node).await.unwrap());
    let in_archive = phone.list(&node, Some(&archive)).await.unwrap();
    assert_eq!((in_archive[0].name.as_str(), in_archive[0].size), ("Brief 2026.txt", 3));
    assert_eq!(phone.read_file(&node, &letter.id).await.unwrap(), b"neu");
    assert!(phone.list(&node, None).await.unwrap().iter().any(|e| e.name == "Notiz.md" && e.trashed));
    // Opened again from its file – with the key only.
    assert!(Vaults::open_sealed(&sealed, [8u8; 32], "x").is_err());
    let again = Vaults::open_sealed(&sealed, [9u8; 32], "x").unwrap();
    assert_eq!(again.name(&node).await.unwrap().as_deref(), Some("Geheim"));
    drop(again);

    // Carol: shared with in the store, then made a member with a code sealed to her new key.
    let carol = by_token(&carol_address).await;
    let mut carol_e2e = E2e::load(&carol).await.unwrap();
    if !carol_e2e.has_key() {
        carol_e2e.setup(&carol, kernoid_e2e::Kind::Pqc).await.unwrap();
    }
    let principal =
        files::find_principals(&alice, "carol").await.unwrap().into_iter().find(|p| p.kind == "individual").unwrap();
    files::share(&alice, account, &node.id, &[(principal.id.clone(), files::Level::Edit)]).await.unwrap();
    let people = [(principal.clone(), kernoid_client::e2e::Level::Edit)];
    let waiting = laptop.share(&alice, e2e, account, &node, &people).await.unwrap();
    assert!(waiting.is_empty());
    assert!(laptop.members(&node).await.unwrap().contains(&principal.id));
    let carols = Vaults::in_memory("Carol's laptop").unwrap();
    let seen = files::children(&carol, account, None).await.unwrap();
    let shared = seen.into_iter().find(|n| n.id == node.id).expect("the vault, shared");
    assert!(carols.enter(&carol, &mut carol_e2e, account, &shared).await.unwrap());
    assert_eq!(carols.read_file(&shared, &letter.id).await.unwrap(), b"neu");
    carols.make_directory(&shared, None, "Von Carol").await.unwrap();
    laptop.sync(&node).await.unwrap();
    assert!(laptop.list(&node, None).await.unwrap().iter().any(|e| e.name == "Von Carol"));

    // Carol's level goes down to reading: she comes in again with a new code, and may no longer write.
    let read = [(principal.clone(), kernoid_client::e2e::Level::Read)];
    assert!(laptop.share(&alice, e2e, account, &node, &read).await.unwrap().is_empty());
    assert!(carols.enter(&carol, &mut carol_e2e, account, &shared).await.unwrap());
    assert_eq!(carols.read_file(&shared, &letter.id).await.unwrap(), b"neu");
    assert!(carols.make_directory(&shared, None, "Nicht mehr").await.is_err(), "reading only");

    // The vault renamed: the phone reads the new name.
    laptop.rename_vault(&node, "Geheim 2").await.unwrap();
    phone.sync(&node).await.unwrap();
    assert_eq!(phone.name(&node).await.unwrap().as_deref(), Some("Geheim 2"));

    // A grant changed elsewhere – in the store, the vault untouched –: reconciling brings Carol back to editing.
    files::share(&alice, account, &node.id, &[(principal.id.clone(), files::Level::Edit)]).await.unwrap();
    laptop.reconcile(&alice, e2e, account, &node).await.unwrap();
    assert!(carols.enter(&carol, &mut carol_e2e, account, &shared).await.unwrap());
    carols.make_directory(&shared, None, "Wieder da").await.unwrap();

    // A group: Dave, in the group "Team", becomes a member through it at its level.
    if let Ok(dave_address) = std::env::var("KERNOID_TEST_GROUP_ADDRESS") {
        let (_, token) = session(&address).await;
        let dave = by_token(&dave_address).await;
        let mut dave_e2e = E2e::load(&dave).await.unwrap();
        if !dave_e2e.has_key() {
            dave_e2e.setup(&dave, kernoid_e2e::Kind::Pqc).await.unwrap();
        }
        let dave_id = dave.primary(FILENODE).unwrap();
        let group =
            rest(&token, reqwest::Method::POST, "/v1/groups", Some(serde_json::json!({ "name": "Team" }))).await;
        let group = group["id"].as_str().unwrap().to_owned();
        rest(&token, reqwest::Method::PUT, &format!("/v1/groups/{group}/members/{dave_id}"), None).await;
        let shares = [(principal.id.clone(), files::Level::Edit), (group.clone(), files::Level::Read)];
        files::share(&alice, account, &node.id, &shares).await.unwrap();
        assert!(laptop.reconcile(&alice, e2e, account, &node).await.unwrap().is_empty(), "nobody waits");
        assert!(laptop.members(&node).await.unwrap().contains(&dave_id));
        let daves = Vaults::in_memory("Dave's laptop").unwrap();
        let seen = files::children(&dave, account, None).await.unwrap().into_iter().find(|n| n.id == node.id);
        let seen = seen.expect("the vault, shared with the group");
        assert!(daves.enter(&dave, &mut dave_e2e, account, &seen).await.unwrap());
        assert_eq!(daves.level(&seen).await.unwrap(), kernoid_client::e2e::Level::Read);
        assert_eq!(daves.read_file(&seen, &letter.id).await.unwrap(), b"neu");
    }

    // Carol leaves: the relay serves her nothing more.
    laptop.remove_member(&alice, account, &node, &principal.id).await.unwrap();
    assert!(carols.sync(&shared).await.is_err());
    laptop.put_file(&node, None, "Danach.txt", b"ohne Carol".to_vec(), None, None, None).await.unwrap();
    phone.sync(&node).await.unwrap();
    assert!(phone.list(&node, None).await.unwrap().iter().any(|e| e.name == "Danach.txt"));

    // Removed for good: the store's directory goes, its space with it (by the worker).
    files::destroy(&alice, account, &node.id).await.unwrap();
}
