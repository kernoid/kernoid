// SPDX-License-Identifier: MIT
//! Keys, messages and PGP/MIME as RFC 0006 describes them – both kinds of key, signatures, protected copies, header
//! protection.

use kernoid_e2e::{
    Error, Kind, PublicKey, SecretKey,
    keys::{normalize_recovery_code, recovery_code},
    message::{decrypt, encrypt},
    mime::{OBSCURED_SUBJECT, decrypt_message, decrypt_summary, encrypt_message, encrypted_summary, is_encrypted},
};

const MAIL: &[u8] = b"From: Ada <ada@example.org>\r\nTo: Bob <bob@example.org>\r\nSubject: The plan\r\n\
Date: Thu, 29 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\nMeet at noon.\r\n";

fn key(kind: Kind, address: &str) -> SecretKey {
    SecretKey::generate(kind, &[address]).unwrap()
}

#[test]
fn keys_have_the_kind_they_were_made_as() {
    let pqc = key(Kind::Pqc, "ada@example.org").public();
    let compatible = key(Kind::Compatible, "ada@example.org").public();
    assert_eq!(pqc.kind(), Some(Kind::Pqc));
    assert_eq!(compatible.kind(), Some(Kind::Compatible));
    assert_eq!(pqc.addresses(), ["ada@example.org"]);
    let parsed = PublicKey::parse(pqc.armored().unwrap().as_bytes()).unwrap();
    assert_eq!(parsed.fingerprint(), pqc.fingerprint());
    assert_eq!(pqc.fingerprint().len(), 64, "v6 fingerprints are SHA-256");
    assert_eq!(compatible.fingerprint().len(), 40);
}

#[test]
fn a_protected_copy_opens_only_with_its_passphrase() {
    let secret = key(Kind::Pqc, "ada@example.org");
    let copy = secret.protect("correct horse").unwrap();
    assert!(matches!(SecretKey::unlock(&copy, "wrong horse"), Err(Error::Unlock)));
    let unlocked = SecretKey::unlock(&copy, "correct horse").unwrap();
    assert_eq!(unlocked.fingerprint(), secret.fingerprint());
    let sealed = encrypt(b"hello", &[&secret.public()], None, false).unwrap();
    assert_eq!(decrypt(&sealed, &[&unlocked], &[]).unwrap().data, b"hello");
}

#[test]
fn messages_are_encrypted_signed_and_verified_with_both_kinds() {
    for kind in [Kind::Pqc, Kind::Compatible] {
        let ada = key(kind, "ada@example.org");
        let bob = key(kind, "bob@example.org");
        let sealed = encrypt(b"Meet at noon.", &[&bob.public()], Some(&ada), true).unwrap();
        assert!(sealed.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        let opened = decrypt(&sealed, &[&bob], &[&ada.public()]).unwrap();
        assert_eq!(opened.data, b"Meet at noon.");
        assert!(opened.signed);
        assert_eq!(opened.verified_by, Some(ada.fingerprint()));
        assert!(matches!(decrypt(&sealed, &[&ada], &[]), Err(Error::Decrypt)), "{kind:?}: only the recipient");
        let stranger = key(kind, "eve@example.org");
        assert_eq!(decrypt(&sealed, &[&bob], &[&stranger.public()]).unwrap().verified_by, None);
    }
}

#[test]
fn a_message_reaches_recipients_of_both_kinds() {
    let pqc = key(Kind::Pqc, "ada@example.org");
    let compatible = key(Kind::Compatible, "bob@example.org");
    let sealed = encrypt(b"both", &[&pqc.public(), &compatible.public()], None, false).unwrap();
    assert_eq!(decrypt(&sealed, &[&pqc], &[]).unwrap().data, b"both");
    assert_eq!(decrypt(&sealed, &[&compatible], &[]).unwrap().data, b"both");
}

#[test]
fn pgp_mime_hides_the_subject_and_keeps_what_delivery_needs() {
    let bob = key(Kind::Pqc, "bob@example.org");
    let encrypted = encrypt_message(MAIL, &[&bob.public()], None).unwrap();
    let text = String::from_utf8(encrypted.clone()).unwrap();
    assert!(is_encrypted(&encrypted));
    assert!(!is_encrypted(MAIL));
    assert!(text.contains(&format!("Subject: {OBSCURED_SUBJECT}\r\n")));
    assert!(!text.contains("The plan") && !text.contains("noon"));
    for kept in ["From: Ada <ada@example.org>", "To: Bob <bob@example.org>", "Message-ID: <1@example.org>"] {
        assert!(text.contains(kept), "{kept}");
    }
    assert!(text.contains("multipart/encrypted; protocol=\"application/pgp-encrypted\""));
    assert!(!text.contains("charset=utf-8"), "the inner content type stays inside");

    let inner = String::from_utf8(decrypt_message(&encrypted, &[&bob], &[]).unwrap().data).unwrap();
    assert!(inner.contains("Subject: The plan\r\n"));
    assert!(inner.contains("Content-Type: text/plain; charset=utf-8; protected-headers=\"v1\"\r\n"));
    assert!(inner.contains(&format!("HP-Outer: Subject: {OBSCURED_SUBJECT}\r\n")));
    assert!(inner.ends_with("\r\n\r\nMeet at noon.\r\n"));
}

#[test]
fn mail_with_bare_line_feeds_is_encrypted_too() {
    let bob = key(Kind::Compatible, "bob@example.org");
    let mail = b"From: a@example.org\nSubject: Hi\n  there\n\nBody\n";
    let encrypted = encrypt_message(mail, &[&bob.public()], None).unwrap();
    let inner = String::from_utf8(decrypt_message(&encrypted, &[&bob], &[]).unwrap().data).unwrap();
    assert!(inner.starts_with("From: a@example.org\r\nSubject: Hi\r\n  there\r\n"));
    assert!(inner.ends_with("\r\n\r\nBody\n"));
}

#[test]
fn the_summary_travels_encrypted() {
    let bob = key(Kind::Pqc, "bob@example.org");
    let sealed = encrypted_summary(MAIL, &[&bob.public()]).unwrap();
    let summary = decrypt_summary(&sealed, &[&bob]).unwrap();
    assert_eq!(summary.subject.as_deref(), Some("The plan"));
    assert_eq!(summary.preview, "Meet at noon.");
    assert!(!summary.has_attachment);
}

#[test]
fn recovery_codes_read_back_as_typed() {
    let code = recovery_code();
    assert_eq!(code.len(), 39);
    assert_eq!(normalize_recovery_code(&code.to_lowercase().replace('-', " ")), code);
    assert_eq!(normalize_recovery_code("o1il-abcd"), "0111-ABCD");
}

#[test]
fn drafts_are_built_and_read_back() {
    use kernoid_e2e::compose::{Attachment, Draft, Mailbox, build, parse, part};
    let mailbox = |name: Option<&str>, email: &str| Mailbox { name: name.map(str::to_owned), email: email.to_owned() };
    let draft = Draft {
        from: Some(mailbox(Some("Ada Lovelace"), "ada@example.org")),
        to: vec![mailbox(Some("Jürgen Müller"), "j@example.org"), mailbox(None, "bob@example.org")],
        cc: vec![mailbox(Some("Doe, John"), "john@example.org")],
        subject: "Grüße aus München – ein recht langer Betreff, der in mehrere Wörter muss".to_owned(),
        message_id: "1@example.org".to_owned(),
        in_reply_to: vec!["0@example.org".to_owned()],
        references: vec!["0@example.org".to_owned()],
        date: "Thu, 29 Oct 2026 10:00:00 +0100".to_owned(),
        text: "Hallo,\nbis bald.".to_owned(),
        html: Some("<p>Hallo,<br>bis bald.</p>".to_owned()),
        attachments: vec![Attachment {
            name: "Plan für März.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            data: base64_encode(b"step one"),
        }],
        ..Draft::default()
    };
    let raw = build(&draft).unwrap();
    let text = String::from_utf8(raw.clone()).unwrap();
    assert!(text.is_ascii(), "{text}");
    assert!(text.lines().all(|line| line.len() <= 998));
    let parsed = parse(&raw).unwrap();
    assert_eq!(parsed.subject.as_deref(), Some(draft.subject.as_str()));
    assert_eq!(parsed.from, vec![mailbox(Some("Ada Lovelace"), "ada@example.org")]);
    assert_eq!(parsed.to[0], mailbox(Some("Jürgen Müller"), "j@example.org"));
    assert_eq!(parsed.cc[0], mailbox(Some("Doe, John"), "john@example.org"));
    assert_eq!(parsed.in_reply_to, ["0@example.org"]);
    assert_eq!(parsed.message_id.as_deref(), Some("1@example.org"));
    assert_eq!(parsed.text.as_deref().map(str::trim_end), Some("Hallo,\nbis bald."));
    assert!(parsed.html.unwrap().contains("<p>Hallo,"));
    assert_eq!(parsed.attachments.len(), 1);
    assert_eq!(parsed.attachments[0].name.as_deref(), Some("Plan für März.txt"));
    assert_eq!(part(&raw, parsed.attachments[0].index).unwrap(), b"step one");

    // Encrypted and decrypted, it reads the same.
    let bob = key(Kind::Pqc, "bob@example.org");
    let encrypted = encrypt_message(&raw, &[&bob.public()], None).unwrap();
    let inner = decrypt_message(&encrypted, &[&bob], &[]).unwrap().data;
    assert_eq!(parse(&inner).unwrap().subject, parsed.subject);
    assert!(build(&Draft { from: Some(mailbox(None, "a\r\nBcc: x@y")), ..draft }).is_err());
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
