// SPDX-License-Identifier: MIT
//! Replies and forwards, as every one of kernoid's clients writes them: `Re: `/`Fwd: ` before the subject (once), the
//! text quoted, the thread kept (`In-Reply-To`, `References`), "reply to all" without the user's own addresses, and a
//! forward carrying the attachments along. The words around the quote are the caller's ([`Phrases`]).

use crate::mail::{Attachment, Draft, Email, EmailAddress, Identity, format_addresses};

/// How a message refers to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    New,
    Reply,
    ReplyAll,
    Forward,
}

/// The words around a quote, in the user's language. `{date}` and `{who}` are filled in.
#[derive(Debug, Clone)]
pub struct Phrases {
    /// Above a quoted reply: `On {date}, {who} wrote:`.
    pub wrote: String,
    /// The line that begins a forwarded message.
    pub forwarded: String,
    pub from: String,
    pub date: String,
    pub subject: String,
    pub to: String,
    /// How a date is written (chrono's format), in the local time zone.
    pub date_format: String,
}

impl Default for Phrases {
    fn default() -> Self {
        Self {
            wrote: "On {date}, {who} wrote:".into(),
            forwarded: "---------- Forwarded message ----------".into(),
            from: "From".into(),
            date: "Date".into(),
            subject: "Subject".into(),
            to: "To".into(),
            date_format: "%a, %d %b %Y %H:%M".into(),
        }
    }
}

/// `Re: ` or `Fwd: ` before a subject, unless it is there already (in any case).
pub fn prefixed(prefix: &str, subject: &str) -> String {
    let subject = subject.trim();
    if subject.to_lowercase().starts_with(&prefix.to_lowercase()) {
        subject.to_owned()
    } else {
        format!("{prefix}{subject}")
    }
}

/// Each line with `> ` before it.
pub fn quote(text: &str) -> String {
    text.lines()
        .map(|line| if line.is_empty() { ">".to_owned() } else { format!("> {line}") })
        .collect::<Vec<_>>()
        .join("\n")
}

fn mine(address: &EmailAddress, identities: &[Identity]) -> bool {
    identities.iter().any(|identity| identity.email.eq_ignore_ascii_case(&address.email))
}

/// The identity to write from: the one the original was sent to, or the first.
pub fn identity_for<'a>(original: Option<&Email>, identities: &'a [Identity]) -> Option<&'a Identity> {
    let addressed = original.into_iter().flat_map(|email| {
        email.summary.to.iter().flatten().chain(email.cc.iter().flatten()).cloned().collect::<Vec<_>>()
    });
    for address in addressed {
        if let Some(identity) = identities.iter().find(|i| i.email.eq_ignore_ascii_case(&address.email)) {
            return Some(identity);
        }
    }
    identities.first()
}

/// A new message, or a reply to or a forward of `original` (with `text`, its text as read); `identities` are the
/// user's, left out of "reply to all".
pub fn start(kind: Kind, original: Option<(&Email, &str)>, identities: &[Identity], phrases: &Phrases) -> Draft {
    let mut draft = Draft::default();
    let Some((email, text)) = original.filter(|_| kind != Kind::New) else { return draft };
    let subject = email.summary.subject.clone().unwrap_or_default();
    let sender = email.summary.from.clone().unwrap_or_default();
    let date = email.sent_at.clone().unwrap_or_else(|| email.summary.received_at.clone());
    let date = chrono::DateTime::parse_from_rfc3339(&date)
        .map(|time| time.with_timezone(&chrono::Local).format(&phrases.date_format).to_string())
        .unwrap_or(date);
    match kind {
        Kind::Reply | Kind::ReplyAll => {
            let reply_to = email.reply_to.clone().filter(|list| !list.is_empty()).unwrap_or_else(|| sender.clone());
            draft.to = reply_to;
            if kind == Kind::ReplyAll {
                let mut cc: Vec<EmailAddress> = Vec::new();
                for address in email.summary.to.iter().flatten().chain(email.cc.iter().flatten()) {
                    let known = draft.to.iter().chain(cc.iter()).any(|a| a.email.eq_ignore_ascii_case(&address.email));
                    if !known && !mine(address, identities) {
                        cc.push(address.clone());
                    }
                }
                draft.cc = cc;
            }
            draft.subject = prefixed("Re: ", &subject);
            let wrote = phrases.wrote.replace("{date}", &date).replace("{who}", &format_addresses(&sender));
            draft.body = format!("\n\n{wrote}\n{}\n", quote(text));
            draft.in_reply_to = email.message_id.clone().unwrap_or_default();
            draft.references = email.references.clone().unwrap_or_default();
            draft.references.extend(draft.in_reply_to.iter().cloned());
        }
        Kind::Forward => {
            draft.subject = prefixed("Fwd: ", &subject);
            draft.body = format!(
                "\n\n{}\n{}: {}\n{}: {date}\n{}: {subject}\n{}: {}\n\n{text}\n",
                phrases.forwarded,
                phrases.from,
                format_addresses(&sender),
                phrases.date,
                phrases.subject,
                phrases.to,
                format_addresses(email.summary.to.as_deref().unwrap_or_default()),
            );
            // Parts on the server; those of an encrypted message are in the decrypted one only (OPEN: forwarding them).
            draft.attachments = email
                .attachments
                .iter()
                .filter_map(|part| {
                    Some(Attachment {
                        blob_id: part.blob_id.clone()?,
                        kind: part.kind.clone(),
                        name: part.name.clone().unwrap_or_else(|| "attachment".into()),
                        size: part.size,
                    })
                })
                .collect();
        }
        Kind::New => {}
    }
    draft
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::mail::{BodyPart, EmailSummary};

    fn identities() -> Vec<Identity> {
        vec![Identity { id: "i1".into(), name: "Alice".into(), email: "alice@firma.example".into() }]
    }

    fn original() -> Email {
        let address = |email: &str| EmailAddress { name: None, email: email.into() };
        Email {
            summary: EmailSummary {
                id: "e1".into(),
                thread_id: "t".into(),
                mailbox_ids: BTreeMap::new(),
                keywords: BTreeMap::new(),
                from: Some(vec![EmailAddress { name: Some("Bob".into()), email: "bob@x.example".into() }]),
                to: Some(vec![address("alice@firma.example"), address("carol@x.example")]),
                subject: Some("Plans".into()),
                received_at: "2026-10-28T10:00:00Z".into(),
                preview: String::new(),
                has_attachment: true,
                size: 0,
                encrypted: false,
                encrypted_summary: None,
                opened: false,
            },
            cc: Some(vec![address("dave@x.example"), address("bob@x.example")]),
            reply_to: None,
            message_id: Some(vec!["m2@x".into()]),
            references: Some(vec!["m1@x".into()]),
            sent_at: None,
            text_body: Vec::new(),
            html_body: Vec::new(),
            attachments: vec![BodyPart {
                part_id: Some("2".into()),
                blob_id: Some("B".into()),
                kind: "application/pdf".into(),
                name: Some("plan.pdf".into()),
                size: 10,
                inner: None,
            }],
            body_values: BTreeMap::new(),
            blob_id: None,
            sealed: None,
            inner: None,
        }
    }

    #[test]
    fn reply_to_all_without_the_user() {
        let email = original();
        let ids = identities();
        assert_eq!(identity_for(Some(&email), &ids).map(|i| i.id.as_str()), Some("i1"));
        let draft = start(Kind::ReplyAll, Some((&email, "Hi\n\nBye")), &ids, &Phrases::default());
        assert_eq!(format_addresses(&draft.to), "Bob <bob@x.example>");
        assert_eq!(format_addresses(&draft.cc), "carol@x.example, dave@x.example");
        assert_eq!(draft.subject, "Re: Plans");
        assert_eq!(draft.in_reply_to, ["m2@x"]);
        assert_eq!(draft.references, ["m1@x", "m2@x"]);
        assert!(draft.body.contains("Bob <bob@x.example> wrote:\n> Hi\n>\n> Bye"), "{}", draft.body);
        assert!(draft.attachments.is_empty());
    }

    #[test]
    fn a_forward_carries_the_attachments_in_the_users_words() {
        let phrases = Phrases {
            forwarded: "---------- Weitergeleitete Nachricht ----------".into(),
            from: "Von".into(),
            ..Phrases::default()
        };
        let draft = start(Kind::Forward, Some((&original(), "Hi")), &[], &phrases);
        assert_eq!(draft.subject, "Fwd: Plans");
        assert_eq!(draft.attachments.len(), 1);
        assert!(
            draft.body.contains("Weitergeleitete Nachricht ----------\nVon: Bob <bob@x.example>"),
            "{}",
            draft.body
        );
        assert_eq!(prefixed("Re: ", "RE: x"), "RE: x");
    }
}
