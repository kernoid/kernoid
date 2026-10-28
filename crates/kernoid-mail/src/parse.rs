// SPDX-License-Identifier: AGPL-3.0-or-later
//! What kernoid keeps of a message in PostgreSQL (RFC 0002, 4), read with mail-parser.

use chrono::{DateTime, Utc};
use mail_parser::{Address, HeaderValue, MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};

/// Length of the preview, in characters (JMAP `preview` has at most 256).
const PREVIEW: usize = 256;

/// How much text is indexed for search, in bytes (RFC 0002, 13.1); a `tsvector` holds at most 1 MiB.
const SEARCH_TEXT: usize = 512 * 1024;

/// A name and an address, as JMAP's `EmailAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Summary {
    pub sent_at: Option<DateTime<Utc>>,
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub resent_message_ids: Vec<String>,
    pub subject: Option<String>,
    /// The subject without `Re:`, `Fwd:` and the like (RFC 5256, 2.1), for threading.
    pub base_subject: String,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub sender: Vec<Mailbox>,
    pub preview: String,
    pub has_attachment: bool,
    /// The text parts (HTML as text) and attachment names, for the search index.
    pub search_text: String,
}

fn ids(value: &HeaderValue<'_>) -> Vec<String> {
    match value {
        HeaderValue::Text(id) => vec![id.to_string()],
        HeaderValue::TextList(list) => list.iter().map(ToString::to_string).collect(),
        _ => Vec::new(),
    }
    .into_iter()
    .filter(|id| !id.is_empty())
    .collect()
}

fn mailboxes(address: Option<&Address<'_>>) -> Vec<Mailbox> {
    address
        .map(|address| {
            address
                .iter()
                .filter_map(|addr| {
                    Some(Mailbox {
                        name: addr.name().map(str::to_owned).filter(|name| !name.is_empty()),
                        email: addr.address()?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Reads the headers and a preview; `None` if the input is not a message at all.
pub(crate) fn summarize(raw: &[u8]) -> Option<Summary> {
    let message = MessageParser::default().parse(raw)?;
    let preview = message
        .body_preview(PREVIEW)
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
        .map(|text| text.chars().take(PREVIEW).collect())
        .unwrap_or_default();
    Some(Summary {
        sent_at: message.date().and_then(|date| DateTime::from_timestamp(date.to_timestamp(), 0)),
        message_id: message.message_id().filter(|id| !id.is_empty()).map(str::to_owned),
        in_reply_to: ids(message.in_reply_to()),
        references: ids(message.references()),
        resent_message_ids: ids(message.resent_message_id()),
        subject: message.subject().map(str::to_owned),
        base_subject: message.thread_name().unwrap_or_default().to_owned(),
        from: mailboxes(message.from()),
        to: mailboxes(message.to()),
        cc: mailboxes(message.cc()),
        bcc: mailboxes(message.bcc()),
        reply_to: mailboxes(message.reply_to()),
        sender: mailboxes(message.sender()),
        preview,
        has_attachment: message.attachment_count() > 0,
        search_text: search_text(&message),
    })
}

/// What the search index reads of a message: its text bodies and the names of its attachments, cut at
/// [`SEARCH_TEXT`] bytes.
pub(crate) fn search_text(message: &mail_parser::Message<'_>) -> String {
    let mut text = String::new();
    for index in 0..message.text_body.len() {
        if let Some(body) = message.body_text(index) {
            text.push_str(&body);
            text.push('\n');
        }
    }
    for attachment in message.attachments() {
        if let Some(name) = attachment.attachment_name() {
            text.push_str(name);
            text.push('\n');
        }
    }
    if text.len() > SEARCH_TEXT {
        let mut end = SEARCH_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The search text of a raw message (for emails stored before the index).
pub(crate) fn search_text_of(raw: &[u8]) -> String {
    MessageParser::default().parse(raw).map(|message| search_text(&message)).unwrap_or_default()
}

/// A full-text query (RFC 0002, 13.1): every word of `text`, matched as a word or a word's beginning; `None` if it
/// has no words. Only letters and digits reach PostgreSQL.
pub fn search_query(text: &str) -> Option<String> {
    let words: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| format!("'{}':*", word.to_lowercase()))
        .collect();
    (!words.is_empty()).then(|| words.join(" & "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_preview() {
        let raw = b"From: Alice <alice@firma.example>\r\nTo: bob@firma.example, \"Carol\" <carol@firma.example>\r\n\
                    Subject: Re: Fwd: Lunch\r\nDate: Sat, 24 Oct 2026 10:00:00 +0200\r\nMessage-ID: <a1@firma.example>\r\n\
                    In-Reply-To: <a0@firma.example>\r\nReferences: <z@firma.example> <a0@firma.example>\r\n\r\n\
                    Shall we\r\n  meet at noon?\r\n";
        let summary = summarize(raw).expect("a message");
        assert_eq!(summary.subject.as_deref(), Some("Re: Fwd: Lunch"));
        assert_eq!(summary.base_subject, "Lunch");
        assert_eq!(summary.message_id.as_deref(), Some("a1@firma.example"));
        assert_eq!(summary.in_reply_to, ["a0@firma.example"]);
        assert_eq!(summary.references, ["z@firma.example", "a0@firma.example"]);
        assert_eq!(summary.from, [Mailbox { name: Some("Alice".into()), email: "alice@firma.example".into() }]);
        assert_eq!(summary.to.len(), 2);
        assert_eq!(summary.sent_at.map(|at| at.to_rfc3339()).as_deref(), Some("2026-10-24T08:00:00+00:00"));
        assert_eq!(summary.preview, "Shall we meet at noon?");
        assert!(!summary.has_attachment);
        assert_eq!(summary.search_text, "Shall we\r\n  meet at noon?\r\n\n");
    }

    #[test]
    fn queries_are_words() {
        assert_eq!(search_query("Lunch, noo!").as_deref(), Some("'lunch':* & 'noo':*"));
        assert_eq!(search_query("x' | y").as_deref(), Some("'x':* & 'y':*"));
        assert_eq!(search_query(" -- "), None);
    }
}
