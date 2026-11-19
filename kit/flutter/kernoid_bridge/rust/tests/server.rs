// SPDX-License-Identifier: MIT
//! Against a real kernoid, when one is named: `KERNOID_TEST_SERVER` (e.g. `http://apps.localhost:18190`),
//! `KERNOID_TEST_ADDRESS` and `KERNOID_TEST_PASSWORD` (an app password). Without them the test does nothing. The
//! protocols are kernoid's Rust SDK (`kernoid-client`), tested in kernoid's repository as well; these tests check what
//! the apps rely on.
//!
//! Sent mail goes through the queue and the recipient's MX, which a development server's domain does not have – so the
//! test sends to itself and finds the message in Sent, and puts a message into the inbox with `Email/import`.

use kernoid_client::{
    Client, FILENODE, MAIL, Options,
    e2e::{E2e, Outgoing, Plan},
    files,
    mail::{self, Draft, EmailAddress, Identity},
    set_error,
};
use serde_json::json;

async fn login(server: &str, address: &str, password: &str) -> kernoid_client::Result<Client> {
    let url = kernoid_client::session_url(Some(server), address)?;
    Client::connect(&url, address, password, &Options::default()).await
}

fn draft(to: &str, subject: &str, text: &str) -> Draft {
    Draft {
        from: None,
        to: vec![EmailAddress { name: None, email: to.to_owned() }],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: subject.to_owned(),
        body: text.to_owned(),
        in_reply_to: Vec::new(),
        references: Vec::new(),
        attachments: Vec::new(),
    }
}

async fn identity(client: &Client, account: &str) -> Identity {
    mail::identities(client, account).await.expect("identities").into_iter().next().expect("an identity")
}

#[tokio::test]
async fn mail_is_sent_and_read_and_files_are_listed() {
    let (Ok(server), Ok(address), Ok(password)) = (
        std::env::var("KERNOID_TEST_SERVER"),
        std::env::var("KERNOID_TEST_ADDRESS"),
        std::env::var("KERNOID_TEST_PASSWORD"),
    ) else {
        eprintln!("no KERNOID_TEST_SERVER: skipped");
        return;
    };
    assert!(login(&server, &address, "wrong").await.is_err());
    let client = login(&server, &address, &password).await.expect("login");
    assert_eq!(client.session.username, address);
    let account = client.primary(MAIL).expect("mail");
    let boxes = mail::mailboxes(&client, &account).await.expect("mailboxes");
    let by_role = |role: &str| boxes.iter().find(|b| b.role.as_deref() == Some(role)).expect(role).id.clone();

    let subject = format!("Sent {}", std::process::id());
    let identity = identity(&client, &account).await;
    mail::send(&client, &account, &identity, &draft(&address, &subject, "Hallo von der App."), &boxes)
        .await
        .expect("send");
    let (sent, _) = mail::emails(&client, &account, Some(&by_role("sent")), "", 0, 50).await.expect("sent");
    assert!(sent.iter().any(|e| e.subject.as_deref() == Some(subject.as_str())));

    let subject = format!("Imported {}", std::process::id());
    let raw = format!(
        "From: Bob <bob@example.org>\r\nTo: {address}\r\nSubject: {subject}\r\nDate: Thu, 29 Oct 2026 10:00:00 +0000\r\n\
         Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hallo&nbsp;Alice</p>\r\n"
    );
    let size = raw.len() as u64;
    let blob = client
        .upload(&account, "message/rfc822", std::io::Cursor::new(raw.into_bytes()), size, |_, _| {})
        .await
        .expect("upload");
    let inbox = by_role("inbox");
    let responses = client
        .request(
            &[MAIL],
            vec![(
                "Email/import",
                json!({ "accountId": account, "emails": { "m": { "blobId": blob.blob_id, "mailboxIds": { &inbox: true } } } }),
                "i",
            )],
        )
        .await
        .expect("import");
    set_error(responses.get("i").expect("import")).expect("imported");
    let (page, total) = mail::emails(&client, &account, Some(&inbox), "", 0, 50).await.expect("page");
    assert!(total >= 1);
    let found = page.into_iter().find(|e| e.subject.as_deref() == Some(subject.as_str())).expect("imported");
    let email = mail::full(&client, &account, &[found.id.as_str()]).await.expect("email").remove(0);
    // HTML as text; `&nbsp;` stays a non-breaking space.
    assert_eq!(email.text(10_000).trim().replace('\u{a0}', " "), "Hallo Alice");

    let stores = files::stores(&client);
    let own = stores.iter().find(|s| Some(s.id.as_str()) == client.session.primary(FILENODE)).expect("files");
    files::children(&client, &own.id, None).await.expect("files");
}

/// End-to-end encrypted mail (RFC 0006, 5): the account's key made here – or, if it has one, unlocked with the recovery
/// code kept in `KERNOID_TEST_RECOVERY_FILE` by an earlier run –, a message sent to itself encrypted and signed, found
/// in Sent with its summary, decrypted and verified; locked again, it stays closed.
#[tokio::test]
async fn mail_is_encrypted_end_to_end() {
    let (Ok(server), Ok(address), Ok(password), Ok(file)) = (
        std::env::var("KERNOID_TEST_SERVER"),
        std::env::var("KERNOID_TEST_ADDRESS"),
        std::env::var("KERNOID_TEST_PASSWORD"),
        std::env::var("KERNOID_TEST_RECOVERY_FILE"),
    ) else {
        eprintln!("no KERNOID_TEST_SERVER or KERNOID_TEST_RECOVERY_FILE: skipped");
        return;
    };
    let client = login(&server, &address, &password).await.expect("login");
    let account = client.primary(MAIL).expect("mail");
    let mut e2e = E2e::load(&client).await.expect("keys");
    assert!(e2e.available, "the server has no end-to-end extension");
    if e2e.current_key().is_none() {
        let code = e2e.setup(&client, kernoid_e2e::Kind::Pqc).await.expect("setup");
        std::fs::write(&file, code).expect("recovery file");
    } else {
        let code = std::fs::read_to_string(&file).expect("the account has a key: its recovery code in the file");
        e2e.unlock(&code).expect("unlock");
    }
    assert!(e2e.is_unlocked());

    let identity = identity(&client, &account).await;
    let subject = format!("Sealed {}", std::process::id());
    let message = draft(&address, &subject, "Nur für mich.");
    let Plan::Sealed(keys) = e2e.plan(&client, &account, &identity, &message).await else { panic!("not sealed") };
    let boxes = mail::mailboxes(&client, &account).await.expect("mailboxes");
    let outgoing = Outgoing { account: &account, identity: &identity, draft: &message, files: &[], boxes: &boxes };
    e2e.send(&client, outgoing, &keys).await.expect("send");

    let sent = boxes.iter().find(|b| b.role.as_deref() == Some("sent")).expect("sent").id.clone();
    let (page, _) = mail::emails(&client, &account, Some(&sent), "", 0, 50).await.expect("page");
    let mut found = None;
    for mut summary in page.into_iter().filter(|e| e.encrypted) {
        e2e.open_summary(&mut summary);
        if summary.opened && summary.subject.as_deref() == Some(subject.as_str()) {
            found = Some(summary);
        }
    }
    let found = found.expect("the encrypted message in Sent, its summary decrypted");
    let email = mail::full(&client, &account, &[found.id.as_str()]).await.expect("email").remove(0);
    assert!(email.summary.encrypted);
    let opened = e2e.open(&client, &account, email.clone()).await.expect("open");
    let sealed = opened.sealed.expect("sealed");
    assert!(!sealed.locked && sealed.signed && sealed.verified);
    assert_eq!(opened.text(10_000).trim(), "Nur für mich.");

    e2e.lock();
    let locked = e2e.open(&client, &account, email).await.expect("open locked");
    assert!(locked.sealed.expect("sealed").locked && locked.text_body.is_empty());
}

/// Writing as the app does (`api::kernoid`): a message with a file of the device and a copy, sent to the account
/// itself; a reply to it in the user's words, keeping the thread; a forward carrying its attachment along.
#[tokio::test]
async fn messages_are_written_replied_to_and_forwarded() {
    use kernoid_bridge::api::kernoid::{EmailDraft, Kernoid, ReplyPhrases};

    let (Ok(server), Ok(address), Ok(password)) = (
        std::env::var("KERNOID_TEST_SERVER"),
        std::env::var("KERNOID_TEST_ADDRESS"),
        std::env::var("KERNOID_TEST_PASSWORD"),
    ) else {
        eprintln!("no KERNOID_TEST_SERVER: skipped");
        return;
    };
    let app = Kernoid::login(server, address.clone(), password).await.expect("login");
    let sent_box = app
        .mailboxes(None)
        .await
        .expect("mailboxes")
        .into_iter()
        .find(|b| b.role.as_deref() == Some("sent"))
        .expect("sent")
        .id;
    let in_sent = async |subject: &str| {
        let page = app.emails(None, Some(sent_box.clone()), String::new(), 0, 50).await.expect("sent");
        let found = page.emails.into_iter().find(|e| e.subject == subject).expect(subject);
        app.email(None, found.id).await.expect("email")
    };

    let file = std::env::temp_dir().join(format!("kernoid-plan-{}.txt", std::process::id()));
    std::fs::write(&file, "Der Plan.\n").expect("file");
    let subject = format!("Written {}", std::process::id());
    let draft = EmailDraft {
        to: format!("Ich <{address}>"),
        cc: "carol@example.org".into(),
        bcc: String::new(),
        subject: subject.clone(),
        text: "Mit Anhang.".into(),
        in_reply_to: Vec::new(),
        references: Vec::new(),
        attachments: Vec::new(),
        parts: Vec::new(),
        files: vec![file.to_string_lossy().into_owned()],
    };
    assert!(!app.send_draft(draft).await.expect("send"), "the key is locked: plain");
    let written = in_sent(&subject).await;
    assert_eq!(written.cc.first().map(|a| a.email.as_str()), Some("carol@example.org"));
    let attached = written.attachments.first().expect("the file");
    assert!(attached.name.starts_with("kernoid-plan-"), "{}", attached.name);

    let phrases = ReplyPhrases {
        wrote: "Am {date} schrieb {who}:".into(),
        forwarded: "---------- Weitergeleitete Nachricht ----------".into(),
        from: "Von".into(),
        date: "Datum".into(),
        subject: "Betreff".into(),
        to: "An".into(),
        date_format: "%d.%m.%Y %H:%M".into(),
    };
    let reply = app.reply_draft(None, written.id.clone(), "replyAll".into(), phrases.clone()).await.expect("reply");
    assert_eq!(reply.subject, format!("Re: {subject}"));
    assert!(reply.to.contains(&address), "{}", reply.to);
    assert_eq!(reply.cc, "carol@example.org", "the user is not asked twice");
    assert!(reply.text.contains(&format!("<{address}>:\n> Mit Anhang.")), "{}", reply.text);
    assert!(reply.text.contains(" schrieb "), "{}", reply.text);
    assert_eq!(reply.in_reply_to.len(), 1);
    assert!(reply.attachments.is_empty());

    let forward = app.reply_draft(None, written.id.clone(), "forward".into(), phrases).await.expect("forward");
    assert_eq!(forward.subject, format!("Fwd: {subject}"));
    assert!(forward.text.contains("Weitergeleitete Nachricht ----------\nVon: "), "{}", forward.text);
    assert_eq!(forward.attachments.len(), 1);
    let forward = EmailDraft { to: address.clone(), cc: String::new(), ..forward };
    app.send_draft(forward).await.expect("forward");
    let forwarded = in_sent(&format!("Fwd: {subject}")).await;
    assert_eq!(forwarded.attachments.first().map(|a| a.name.as_str()), Some(attached.name.as_str()));
    assert!(app.reply_draft(None, written.id, "sideways".into(), reply_phrases()).await.is_err());
    let _ = std::fs::remove_file(file);
}

/// Forwarding an end-to-end encrypted message with its attachment, as the app does: the key unlocked (or made) as in
/// `mail_is_encrypted_end_to_end`, a message with a file sent to the account itself encrypted, forwarded – the file
/// decrypted in memory and put inside the encrypted forward –, and read again from the forward.
#[tokio::test]
async fn an_encrypted_message_is_forwarded_with_its_attachment() {
    use kernoid_bridge::api::kernoid::{EmailDraft, Kernoid};

    let (Ok(server), Ok(address), Ok(password), Ok(recovery)) = (
        std::env::var("KERNOID_TEST_SERVER"),
        std::env::var("KERNOID_TEST_ADDRESS"),
        std::env::var("KERNOID_TEST_PASSWORD"),
        std::env::var("KERNOID_TEST_RECOVERY_FILE"),
    ) else {
        eprintln!("no KERNOID_TEST_SERVER or KERNOID_TEST_RECOVERY_FILE: skipped");
        return;
    };
    let app = Kernoid::login(server, address.clone(), password).await.expect("login");
    if app.key_status().await.has_key {
        let code = std::fs::read_to_string(&recovery).expect("the account has a key: its recovery code in the file");
        app.unlock_key(code).await.expect("unlock");
    } else {
        let code = app.make_key().await.expect("key");
        std::fs::write(&recovery, &code).expect("recovery file");
        app.unlock_key(code).await.expect("unlock");
    }
    let sent_box = app
        .mailboxes(None)
        .await
        .expect("mailboxes")
        .into_iter()
        .find(|b| b.role.as_deref() == Some("sent"))
        .expect("sent")
        .id;
    let in_sent = async |subject: &str| {
        let page = app.emails(None, Some(sent_box.clone()), String::new(), 0, 50).await.expect("sent");
        let found = page.emails.into_iter().find(|e| e.subject == subject).expect(subject);
        app.email(None, found.id).await.expect("email")
    };

    let file = std::env::temp_dir().join(format!("kernoid-sealed-{}.txt", std::process::id()));
    std::fs::write(&file, "Nur für uns.\n").expect("file");
    let subject = format!("Sealed with a file {}", std::process::id());
    let draft = EmailDraft {
        to: address.clone(),
        cc: String::new(),
        bcc: String::new(),
        subject: subject.clone(),
        text: "Siehe Anhang.".into(),
        in_reply_to: Vec::new(),
        references: Vec::new(),
        attachments: Vec::new(),
        parts: Vec::new(),
        files: vec![file.to_string_lossy().into_owned()],
    };
    assert!(app.send_draft(draft).await.expect("send"), "sent encrypted");
    let _ = std::fs::remove_file(&file);
    let written = in_sent(&subject).await;
    assert!(written.encrypted && !written.locked);
    assert_eq!(written.attachments.len(), 1);
    assert!(written.attachments[0].blob_id.is_none(), "inside the encrypted message only");

    let forward = app.reply_draft(None, written.id.clone(), "forward".into(), reply_phrases()).await.expect("forward");
    assert!(forward.attachments.is_empty(), "nothing to name by blob");
    assert_eq!(forward.parts.len(), 1);
    assert_eq!(forward.parts[0].name, written.attachments[0].name);
    let forward = EmailDraft { to: address.clone(), ..forward };
    assert!(app.send_draft(forward).await.expect("send forward"), "forwarded encrypted");

    let forwarded = in_sent(&format!("Fwd: {subject}")).await;
    assert!(forwarded.encrypted);
    let part = forwarded.attachments.first().expect("the file in the forward");
    assert_eq!(part.name, written.attachments[0].name);
    let directory = std::env::temp_dir().join(format!("kernoid-forwarded-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("directory");
    let saved = app
        .save_part(
            forwarded.id,
            part.part_index.expect("decrypted part"),
            part.name.clone(),
            directory.to_string_lossy().into_owned(),
        )
        .await
        .expect("save");
    assert_eq!(std::fs::read_to_string(saved).expect("saved"), "Nur für uns.\n");
    let _ = std::fs::remove_dir_all(directory);
}

fn reply_phrases() -> kernoid_bridge::api::kernoid::ReplyPhrases {
    kernoid_bridge::api::kernoid::ReplyPhrases {
        wrote: String::new(),
        forwarded: String::new(),
        from: String::new(),
        date: String::new(),
        subject: String::new(),
        to: String::new(),
        date_format: String::new(),
    }
}
