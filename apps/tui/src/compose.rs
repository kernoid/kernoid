// SPDX-License-Identifier: MIT
//! Writing messages in the user's editor: a template with header lines, a blank line and the text; replies quote
//! the text they answer and keep the thread (`In-Reply-To`, `References`), forwards carry the attachments along.

use std::path::PathBuf;

use crate::jmap::mail::{Attachment, Draft, Email, EmailAddress, Identity, format_addresses, parse_addresses};

/// How a message refers to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    New,
    Reply,
    ReplyAll,
    Forward,
}

/// A message being written, as the editor shows it; files named in `Attach:` lines are uploaded when it is sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub from: String,
    pub draft: Draft,
    pub files: Vec<PathBuf>,
}

/// `Re: ` or `Fwd: ` before a subject, unless it is there already.
fn prefixed(prefix: &str, subject: &str) -> String {
    let subject = subject.trim();
    if subject.to_lowercase().starts_with(&prefix.to_lowercase()) {
        subject.to_owned()
    } else {
        format!("{prefix}{subject}")
    }
}

fn quote(text: &str) -> String {
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

/// A new message, a reply or a forward of `original`, from `identity`; `text` is the original's text.
pub fn start(
    kind: Kind,
    original: Option<(&Email, &str)>,
    identity: Option<&Identity>,
    identities: &[Identity],
) -> Message {
    let from = identity
        .map(|identity| {
            EmailAddress {
                name: (!identity.name.is_empty()).then(|| identity.name.clone()),
                email: identity.email.clone(),
            }
            .to_string()
        })
        .unwrap_or_default();
    let mut draft = Draft::default();
    let Some((email, text)) = original.filter(|_| kind != Kind::New) else {
        return Message { from, draft, files: Vec::new() };
    };
    let subject = email.summary.subject.clone().unwrap_or_default();
    let sender = email.summary.from.clone().unwrap_or_default();
    let date = email.sent_at.clone().unwrap_or_else(|| email.summary.received_at.clone());
    // As people read it, in local time: `Wed, 28 Oct 2026 19:24`.
    let date = chrono::DateTime::parse_from_rfc3339(&date)
        .map(|time| time.with_timezone(&chrono::Local).format("%a, %d %b %Y %H:%M").to_string())
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
            let who = format_addresses(&sender);
            draft.body = format!("\n\nOn {date}, {who} wrote:\n{}\n", quote(text));
            draft.in_reply_to = email.message_id.clone().unwrap_or_default();
            draft.references = email.references.clone().unwrap_or_default();
            draft.references.extend(draft.in_reply_to.iter().cloned());
        }
        Kind::Forward => {
            draft.subject = prefixed("Fwd: ", &subject);
            draft.body = format!(
                "\n\n---------- Forwarded message ----------\nFrom: {}\nDate: {date}\nSubject: {subject}\nTo: {}\n\n{text}\n",
                format_addresses(&sender),
                format_addresses(email.summary.to.as_deref().unwrap_or_default()),
            );
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
    Message { from, draft, files: Vec::new() }
}

/// The text the editor opens with.
pub fn render(message: &Message) -> String {
    let draft = &message.draft;
    let mut out = String::new();
    out.push_str(&format!("From: {}\n", message.from));
    out.push_str(&format!("To: {}\n", format_addresses(&draft.to)));
    out.push_str(&format!("Cc: {}\n", format_addresses(&draft.cc)));
    out.push_str(&format!("Bcc: {}\n", format_addresses(&draft.bcc)));
    out.push_str(&format!("Subject: {}\n", draft.subject));
    for file in &draft.attachments {
        out.push_str(&format!("Attached: {}\n", file.name));
    }
    for file in &message.files {
        out.push_str(&format!("Attach: {}\n", file.display()));
    }
    if draft.attachments.is_empty() && message.files.is_empty() {
        out.push_str("Attach: \n");
    }
    out.push('\n');
    out.push_str(&draft.body);
    out
}

/// Reads back what the user wrote, on top of what `message` was. The header ends at the first blank line;
/// `Attached:` lines that were removed drop that attachment, `Attach:` lines name local files (`~` is the home).
pub fn parse(text: &str, message: &Message) -> Result<Message, String> {
    let mut out = message.clone();
    out.files.clear();
    let mut kept = Vec::new();
    let (header, body) = match text.split_once("\n\n") {
        Some((header, body)) => (header, body),
        None => (text, ""),
    };
    for line in header.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("not a header line: {line}"));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "from" => out.from = value.to_owned(),
            "to" => out.draft.to = parse_addresses(value),
            "cc" => out.draft.cc = parse_addresses(value),
            "bcc" => out.draft.bcc = parse_addresses(value),
            "subject" => out.draft.subject = value.to_owned(),
            "attached" => kept.push(value.to_owned()),
            "attach" if !value.is_empty() => out.files.push(expand(value)),
            "attach" => {}
            other => return Err(format!("unknown header: {other}")),
        }
    }
    out.draft.attachments.retain(|file| kept.contains(&file.name));
    out.draft.body = body.to_owned();
    for address in out.draft.to.iter().chain(&out.draft.cc).chain(&out.draft.bcc) {
        if !address.email.contains('@') {
            return Err(format!("not an address: {}", address.email));
        }
    }
    Ok(out)
}

fn expand(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

/// The identity the `From:` line names, if the account may send as it.
pub fn chosen<'a>(from: &str, identities: &'a [Identity]) -> Option<&'a Identity> {
    let address = parse_addresses(from).into_iter().next()?;
    identities.iter().find(|identity| identity.email.eq_ignore_ascii_case(&address.email))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::jmap::mail::{BodyPart, EmailSummary};

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
    fn reply_all() {
        let email = original();
        let ids = identities();
        let identity = identity_for(Some(&email), &ids);
        assert_eq!(identity.map(|i| i.id.as_str()), Some("i1"));
        let message = start(Kind::ReplyAll, Some((&email, "Hi\n\nBye")), identity, &ids);
        assert_eq!(message.from, "Alice <alice@firma.example>");
        assert_eq!(format_addresses(&message.draft.to), "Bob <bob@x.example>");
        assert_eq!(format_addresses(&message.draft.cc), "carol@x.example, dave@x.example");
        assert_eq!(message.draft.subject, "Re: Plans");
        assert_eq!(message.draft.in_reply_to, ["m2@x"]);
        assert_eq!(message.draft.references, ["m1@x", "m2@x"]);
        assert!(message.draft.body.contains("> Hi\n>\n> Bye"));
        assert!(message.draft.attachments.is_empty());
    }

    #[test]
    fn forward_keeps_attachments() {
        let email = original();
        let message = start(Kind::Forward, Some((&email, "Hi")), None, &[]);
        assert_eq!(message.draft.subject, "Fwd: Plans");
        assert_eq!(message.draft.attachments.len(), 1);
        let text = render(&message);
        assert!(text.contains("Attached: plan.pdf\n"));
        // Removing the line drops the attachment; an Attach: line adds a file.
        let edited =
            text.replace("Attached: plan.pdf\n", "Attach: ~/notes.txt\n").replace("To: \n", "To: x@y.example\n");
        let parsed = parse(&edited, &message).unwrap();
        assert!(parsed.draft.attachments.is_empty());
        assert_eq!(parsed.files.len(), 1);
        assert!(parsed.files[0].ends_with("notes.txt"));
        assert_eq!(parsed.draft.to[0].email, "x@y.example");
        assert!(parsed.draft.body.contains("Forwarded message"));
    }

    #[test]
    fn round_trip_and_errors() {
        let ids = identities();
        let message = start(Kind::New, None, ids.first(), &ids);
        let text =
            render(&message).replace("To: \n", "To: Bob <bob@x.example>\n").replace("Subject: \n", "Subject: Hi\n")
                + "Hello";
        let parsed = parse(&text, &message).unwrap();
        assert_eq!(parsed.draft.subject, "Hi");
        assert_eq!(parsed.draft.body, "Hello");
        assert_eq!(chosen(&parsed.from, &ids).map(|i| i.id.as_str()), Some("i1"));
        assert!(parse("To: nobody\n\nx", &message).is_err());
        assert!(parse("X-Other: 1\n\nx", &message).is_err());
        assert_eq!(prefixed("Re: ", "RE: x"), "RE: x");
    }
}
