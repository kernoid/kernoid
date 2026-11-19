// SPDX-License-Identifier: MIT
//! Mail the apps write and read when kernoid must not see it (RFC 0006, 5.3–5.4): a message built from its parts –
//! here, because the server builds it otherwise (JMAP `Email/set`) and must not see the text –, and an encrypted
//! message's inner message read into its parts for display, with mail-parser (never sent back to the server's
//! `Email/parse`). Building is plain RFC 5322 and MIME: header fields with RFC 2047 encoded words where they are not
//! ASCII, file names after RFC 2231, every body in base64.

use base64::{Engine, engine::general_purpose::STANDARD};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, keys::hex};

/// An address: a name (may be empty) and the address itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    #[serde(default)]
    pub name: Option<String>,
    pub email: String,
}

/// A file to attach, its content base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub name: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub data: String,
}

/// What a message is built from. `bcc` is not written – it is the envelope's.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    pub from: Option<Mailbox>,
    #[serde(default)]
    pub to: Vec<Mailbox>,
    #[serde(default)]
    pub cc: Vec<Mailbox>,
    #[serde(default)]
    pub reply_to: Vec<Mailbox>,
    #[serde(default)]
    pub subject: String,
    /// The `Message-ID` without angle brackets.
    pub message_id: String,
    #[serde(default)]
    pub in_reply_to: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    /// `Date`, as written (RFC 5322, 3.3) – the client knows the time and its zone.
    pub date: String,
    #[serde(default)]
    pub text: String,
    pub html: Option<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// One part of a message as an app shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    /// The part's index, for [`part`].
    pub index: usize,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub media_type: String,
    pub size: usize,
    pub cid: Option<String>,
    pub inline: bool,
}

/// A message read into what an app shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parsed {
    pub subject: Option<String>,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    /// RFC 3339, UTC.
    pub sent_at: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<Part>,
}

/// Builds the message of a draft.
pub fn build(draft: &Draft) -> Result<Vec<u8>> {
    let from = draft.from.as_ref().ok_or(Error::NotMail)?;
    let mut out = String::new();
    header(&mut out, "From", &addresses(std::slice::from_ref(from))?);
    if !draft.to.is_empty() {
        header(&mut out, "To", &addresses(&draft.to)?);
    }
    if !draft.cc.is_empty() {
        header(&mut out, "Cc", &addresses(&draft.cc)?);
    }
    if !draft.reply_to.is_empty() {
        header(&mut out, "Reply-To", &addresses(&draft.reply_to)?);
    }
    header(&mut out, "Subject", &words(&draft.subject));
    header(&mut out, "Date", &plain(&draft.date)?);
    header(&mut out, "Message-ID", &format!("<{}>", plain(&draft.message_id)?));
    if !draft.in_reply_to.is_empty() {
        header(&mut out, "In-Reply-To", &ids(&draft.in_reply_to)?);
    }
    if !draft.references.is_empty() {
        header(&mut out, "References", &ids(&draft.references)?);
    }
    out.push_str("MIME-Version: 1.0\r\n");

    let text = body("text/plain; charset=utf-8", None, draft.text.as_bytes());
    let content = match &draft.html {
        Some(html) => multipart("alternative", &[text, body("text/html; charset=utf-8", None, html.as_bytes())]),
        None => text,
    };
    let message = if draft.attachments.is_empty() {
        content
    } else {
        let mut parts = vec![content];
        for attachment in &draft.attachments {
            let data = STANDARD.decode(&attachment.data).map_err(|_| Error::NotMail)?;
            let kind = plain(&attachment.media_type)?;
            parts.push(body(&kind, Some(&attachment.name), &data));
        }
        multipart("mixed", &parts)
    };
    out.push_str(&message);
    Ok(out.into_bytes())
}

/// Reads a message into its parts.
pub fn parse(raw: &[u8]) -> Result<Parsed> {
    let message = MessageParser::default().parse(raw).ok_or(Error::NotMail)?;
    let list = |address: Option<&mail_parser::Address<'_>>| -> Vec<Mailbox> {
        address
            .map(|a| {
                a.iter()
                    .filter_map(|m| {
                        m.address().map(|email| Mailbox {
                            name: m.name().map(str::to_owned).filter(|n| !n.is_empty()),
                            email: email.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let ids = |value: &mail_parser::HeaderValue<'_>| -> Vec<String> {
        value.as_text_list().map(|l| l.iter().map(|s| s.to_string()).collect()).unwrap_or_default()
    };
    let attachments = message
        .attachments()
        .map(|part| Part {
            index: message.parts.iter().position(|p| std::ptr::eq(p, part)).unwrap_or(0),
            name: part.attachment_name().map(str::to_owned),
            media_type: part
                .content_type()
                .map(|t| format!("{}/{}", t.ctype(), t.subtype().unwrap_or("octet-stream")))
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
            size: part.contents().len(),
            cid: part.content_id().map(str::to_owned),
            inline: part.content_disposition().is_some_and(|d| d.ctype().eq_ignore_ascii_case("inline")),
        })
        .collect();
    Ok(Parsed {
        subject: message.subject().map(str::to_owned),
        from: list(message.from()),
        to: list(message.to()),
        cc: list(message.cc()),
        reply_to: list(message.reply_to()),
        sent_at: message.date().map(|d| d.to_rfc3339()),
        message_id: message.message_id().map(str::to_owned),
        in_reply_to: ids(message.in_reply_to()),
        references: ids(message.references()),
        text: message.body_text(0).map(|t| t.into_owned()),
        html: message.body_html(0).filter(|_| !message.html_body.is_empty()).map(|h| h.into_owned()),
        attachments,
    })
}

/// The decoded content of a part of a message (an index of [`Part`]).
pub fn part(raw: &[u8], index: usize) -> Result<Vec<u8>> {
    let message = MessageParser::default().parse(raw).ok_or(Error::NotMail)?;
    let part = message.parts.get(index).ok_or(Error::NotMail)?;
    match &part.body {
        PartType::Multipart(_) => Err(Error::NotMail),
        _ => Ok(part.contents().to_vec()),
    }
}

/// A header field, folded where its value has spaces and lines would be long.
fn header(out: &mut String, name: &str, value: &str) {
    let mut line = format!("{name}:");
    let mut length = line.len();
    for word in value.split(' ') {
        if length + 1 + word.len() > 76 && length > name.len() + 1 {
            line.push_str("\r\n");
            length = 0;
        }
        line.push(' ');
        line.push_str(word);
        length += 1 + word.len();
    }
    out.push_str(&line);
    out.push_str("\r\n");
}

/// Text that must be ASCII without line breaks (dates, ids, media types).
fn plain(text: &str) -> Result<String> {
    if text.is_ascii() && !text.contains(['\r', '\n']) && !text.trim().is_empty() {
        Ok(text.trim().to_owned())
    } else {
        Err(Error::NotMail)
    }
}

/// Unstructured text: as it is if it is printable ASCII, else RFC 2047 encoded words (UTF-8, base64), each at most
/// 75 characters.
fn words(text: &str) -> String {
    let text = text.replace(['\r', '\n'], " ");
    if text.bytes().all(|b| (0x20..0x7f).contains(&b)) && !text.contains("=?") {
        return text;
    }
    // 45 bytes become 60 characters of base64, plus `=?utf-8?b?` and `?=`: 72.
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(&chunk)));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(&chunk)));
    }
    words.join(" ")
}

fn addresses(list: &[Mailbox]) -> Result<String> {
    let mut out = Vec::new();
    for mailbox in list {
        let email = plain(&mailbox.email)?;
        if !email.contains('@') || email.contains([' ', '<', '>', ',', '"']) {
            return Err(Error::NotMail);
        }
        match mailbox.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            Some(name) if name.bytes().all(|b| b.is_ascii_alphanumeric() || b" !#$%&'*+-/=?^_`{|}~".contains(&b)) => {
                out.push(format!("{name} <{email}>"));
            }
            Some(name) if name.is_ascii() && !name.contains(['\r', '\n']) => {
                out.push(format!("\"{}\" <{email}>", name.replace('\\', "\\\\").replace('"', "\\\"")));
            }
            Some(name) => out.push(format!("{} <{email}>", words(name))),
            None => out.push(email),
        }
    }
    Ok(out.join(", "))
}

fn ids(list: &[String]) -> Result<String> {
    list.iter().map(|id| plain(id).map(|id| format!("<{id}>"))).collect::<Result<Vec<_>>>().map(|l| l.join(" "))
}

/// A leaf part: its content type, a file name if it is an attachment, the content in base64 lines of 76.
fn body(content_type: &str, file: Option<&str>, data: &[u8]) -> String {
    let mut out = format!("Content-Type: {content_type}");
    // A name that is not ASCII: RFC 2231 in the disposition, an encoded word in `name` for older readers.
    if let Some(name) = file {
        if name.is_ascii() {
            out.push_str(&format!("; name=\"{}\"", ascii_name(name)));
        } else {
            out.push_str(&format!("; name=\"{}\"", words(name)));
        }
    }
    out.push_str("\r\nContent-Transfer-Encoding: base64\r\n");
    if let Some(name) = file {
        if name.is_ascii() {
            out.push_str(&format!("Content-Disposition: attachment; filename=\"{}\"\r\n", ascii_name(name)));
        } else {
            out.push_str(&format!("Content-Disposition: attachment; filename*=utf-8''{}\r\n", percent(name)));
        }
    }
    out.push_str("\r\n");
    let encoded = STANDARD.encode(data);
    for line in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

fn multipart(subtype: &str, parts: &[String]) -> String {
    let mut random = [0u8; 12];
    OsRng.fill_bytes(&mut random);
    let boundary = format!("kernoid-{}", hex(&random));
    let mut out = format!("Content-Type: multipart/{subtype}; boundary=\"{boundary}\"\r\n\r\n");
    for part in parts {
        out.push_str(&format!("--{boundary}\r\n{part}"));
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

/// A file name for the plain `name`/`filename` parameters: ASCII, quotes and backslashes replaced.
fn ascii_name(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii() && !matches!(c, '"' | '\\' | '\r' | '\n') { c } else { '_' }).collect()
}

/// RFC 2231's percent-encoding of UTF-8.
fn percent(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
