// SPDX-License-Identifier: MIT
//! Mail as PGP/MIME (RFC 3156) with header protection (RFC 9788), and the summary the apps show in lists (RFC 0006,
//! 5.2). The whole original message becomes the cryptographic payload; its `Content-Type` gets
//! `protected-headers="v1"`, and the outer message keeps the header fields delivery, threads and sorting need – with
//! the subject replaced by `[...]` and recorded in `HP-Outer`.

use mail_parser::{MessageParser, MimeHeaders};
use rand::{Rng, rngs::OsRng};

use crate::{
    Error, PublicKey, Result, SecretKey,
    message::{self, Decrypted},
};

/// The subject outside an encrypted message (RFC 9788, 2.2).
pub const OBSCURED_SUBJECT: &str = "[...]";

/// Encrypts a mail message (RFC 5322, as received or as built by an app) to `recipients`: the result is a PGP/MIME
/// message to store or send.
pub fn encrypt_message(raw: &[u8], recipients: &[&PublicKey], signer: Option<&SecretKey>) -> Result<Vec<u8>> {
    let (header, body) = split(raw).ok_or(Error::NotMail)?;
    let fields = fields(header);
    let mut inner = Vec::with_capacity(raw.len() + 256);
    let mut outer = Vec::with_capacity(header.len() + 256);
    let mut content_type = false;
    for field in &fields {
        let name = field_name(field);
        if name.eq_ignore_ascii_case("content-type") {
            content_type = true;
            inner.extend_from_slice(trim_newline(field));
            inner.extend_from_slice(b"; protected-headers=\"v1\"\r\n");
            continue;
        }
        inner.extend_from_slice(field);
        if name.to_ascii_lowercase().starts_with("content-") || name.eq_ignore_ascii_case("mime-version") {
            continue;
        }
        if name.eq_ignore_ascii_case("subject") {
            outer.extend_from_slice(format!("Subject: {OBSCURED_SUBJECT}\r\n").as_bytes());
        } else {
            outer.extend_from_slice(field);
        }
    }
    if !content_type {
        inner.extend_from_slice(b"Content-Type: text/plain; charset=us-ascii; protected-headers=\"v1\"\r\n");
    }
    if fields.iter().any(|f| field_name(f).eq_ignore_ascii_case("subject")) {
        inner.extend_from_slice(format!("HP-Outer: Subject: {OBSCURED_SUBJECT}\r\n").as_bytes());
    }
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(body);

    let armored = crlf(&message::encrypt(&inner, recipients, signer, true)?);
    let boundary = boundary();
    outer.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; \
             boundary=\"{boundary}\"\r\n\r\nThis is an OpenPGP/MIME encrypted message (RFC 3156 and 9580).\r\n\
             --{boundary}\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version \
             identification\r\n\r\nVersion: 1\r\n\r\n--{boundary}\r\nContent-Type: application/octet-stream; \
             name=\"encrypted.asc\"\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: \
             inline; filename=\"encrypted.asc\"\r\n\r\n"
        )
        .as_bytes(),
    );
    outer.extend_from_slice(&armored);
    if !armored.ends_with(b"\r\n") {
        outer.extend_from_slice(b"\r\n");
    }
    outer.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(outer)
}

/// Whether a mail message is PGP/MIME encrypted.
pub fn is_encrypted(raw: &[u8]) -> bool {
    encrypted_payload(raw).is_some()
}

/// Decrypts a PGP/MIME message: `data` is the inner message, with its protected header fields.
pub fn decrypt_message(raw: &[u8], keys: &[&SecretKey], senders: &[&PublicKey]) -> Result<Decrypted> {
    let payload = encrypted_payload(raw).ok_or(Error::NotEncrypted)?;
    message::decrypt(&payload, keys, senders)
}

/// What an app shows of a message in a list (RFC 0006, 5.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub subject: Option<String>,
    pub preview: String,
    pub has_attachment: bool,
}

/// The summary of a mail message in plain text.
pub fn summary(raw: &[u8]) -> Result<Summary> {
    let message = MessageParser::default().parse(raw).ok_or(Error::NotMail)?;
    let preview = message.body_preview(256).map(|p| p.into_owned()).unwrap_or_default();
    Ok(Summary {
        subject: message.subject().map(str::to_owned),
        preview: preview.split_whitespace().collect::<Vec<_>>().join(" "),
        has_attachment: message.attachment_count() > 0,
    })
}

/// The summary of a message, encrypted to `recipients` (binary) – the property `kernoid:encryptedSummary`.
pub fn encrypted_summary(raw: &[u8], recipients: &[&PublicKey]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(&summary(raw)?).map_err(|e| Error::Pgp(e.to_string()))?;
    message::encrypt(&json, recipients, None, false)
}

/// Decrypts an encrypted summary.
pub fn decrypt_summary(data: &[u8], keys: &[&SecretKey]) -> Result<Summary> {
    let decrypted = message::decrypt(data, keys, &[])?;
    serde_json::from_slice(&decrypted.data).map_err(|_| Error::Decrypt)
}

/// The armored OpenPGP message of a PGP/MIME message: the second part of a `multipart/encrypted` with the protocol
/// `application/pgp-encrypted`.
fn encrypted_payload(raw: &[u8]) -> Option<Vec<u8>> {
    let message = MessageParser::default().parse(raw)?;
    let root = message.content_type()?;
    let encrypted = root.ctype().eq_ignore_ascii_case("multipart")
        && root.subtype().is_some_and(|s| s.eq_ignore_ascii_case("encrypted"))
        && root.attribute("protocol").is_some_and(|p| p.eq_ignore_ascii_case("application/pgp-encrypted"));
    if !encrypted {
        return None;
    }
    let mail_parser::PartType::Multipart(children) = &message.root_part().body else { return None };
    let part = message.part(*children.get(1)?)?;
    let contents = part.contents();
    message::is_armored(contents).then(|| contents.to_vec())
}

/// The header section (with its last line break) and the body.
fn split(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(i) = find(raw, b"\r\n\r\n") {
        return Some((&raw[..i + 2], &raw[i + 4..]));
    }
    find(raw, b"\n\n").map(|i| (&raw[..i + 1], &raw[i + 2..]))
}

/// The header fields, each with its continuation lines and line break; bare `\n` become `\r\n`.
fn fields(header: &[u8]) -> Vec<Vec<u8>> {
    let mut fields: Vec<Vec<u8>> = Vec::new();
    for line in header.split_inclusive(|b| *b == b'\n') {
        let mut line = trim_newline(line).to_vec();
        line.extend_from_slice(b"\r\n");
        match fields.last_mut() {
            Some(field) if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') => field.extend_from_slice(&line),
            _ => fields.push(line),
        }
    }
    fields
}

fn field_name(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == b':').unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).trim().to_owned()
}

fn trim_newline(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32);
    for line in data.split_inclusive(|b| *b == b'\n') {
        out.extend_from_slice(trim_newline(line));
        if line.ends_with(b"\n") {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn boundary() -> String {
    let bytes: [u8; 16] = OsRng.r#gen();
    format!("kernoid-{}", crate::keys::hex(&bytes))
}
