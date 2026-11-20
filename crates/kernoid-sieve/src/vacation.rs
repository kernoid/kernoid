// SPDX-License-Identifier: AGPL-3.0-or-later
//! `vacation` (RFC 5230, RFC 6131): whether to answer – never an empty sender, the user themselves, lists, automatic
//! mail (RFC 3834), nor mail that is not addressed to the user – and the reply.

use mail_builder::{
    MessageBuilder,
    headers::raw::Raw,
    mime::{BodyPart, MimePart},
};
use sha2::{Digest, Sha256};

use crate::{
    Context,
    message::{Mail, domain, local_part, single_address},
    run::Vacation,
};

/// A `vacation` with its strings filled in.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub reason: String,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub addresses: Vec<String>,
    pub mime: bool,
    pub handle: Option<String>,
    pub seconds: u64,
}

/// An address without its subaddress (RFC 5233), in lower case.
fn base(address: &str) -> String {
    let address = address.to_lowercase();
    match address.rsplit_once('@') {
        Some((local, domain)) => match local.split_once('+') {
            Some((user, _)) if !user.is_empty() => format!("{user}@{domain}"),
            _ => address,
        },
        None => address,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The reply to send, if one is to be sent; whether it was sent within `seconds` before is the caller's to know, by
/// the reply's key.
pub(crate) fn respond(mail: &Mail<'_>, context: &Context<'_>, request: Request) -> Option<Vacation> {
    let sender = context.envelope_from.trim();
    if sender.is_empty() || !sender.contains('@') {
        return None;
    }
    let mut own: Vec<String> = if context.user_addresses.is_empty() {
        vec![context.envelope_to.to_owned()]
    } else {
        context.user_addresses.clone()
    };
    own.extend(request.addresses.iter().cloned());
    let own_bases: Vec<String> = own.iter().map(|address| base(address)).collect();
    if own_bases.contains(&base(sender)) {
        return None;
    }
    // Lists and their robots (RFC 5230, 4.6).
    let local = local_part(sender).to_ascii_lowercase();
    if local.starts_with("owner-")
        || local.ends_with("-request")
        || matches!(local.as_str(), "mailer-daemon" | "listserv" | "majordomo")
    {
        return None;
    }
    let automatic = mail
        .header_values("auto-submitted", None)
        .iter()
        .any(|value| !value.split(';').next().unwrap_or_default().trim().eq_ignore_ascii_case("no"));
    let bulk = mail
        .header_values("precedence", None)
        .iter()
        .any(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "bulk" | "list" | "junk"));
    let list =
        ["list-id", "list-help", "list-subscribe", "list-unsubscribe", "list-post", "list-owner", "list-archive"]
            .iter()
            .any(|name| mail.exists(name));
    if automatic || bulk || list {
        return None;
    }
    // Only to mail addressed to the user (RFC 5230, 4.5).
    let addressed = ["to", "cc", "bcc", "resent-to", "resent-cc", "resent-bcc"]
        .iter()
        .flat_map(|name| mail.addresses(name, None))
        .any(|address| own_bases.contains(&base(&address)));
    if !addressed {
        return None;
    }

    let mut hash = Sha256::new();
    match &request.handle {
        Some(handle) => hash.update(handle.as_bytes()),
        None => {
            for part in [Some(request.reason.as_str()), request.subject.as_deref(), request.from.as_deref()] {
                hash.update(part.unwrap_or_default().as_bytes());
                hash.update([0]);
            }
            hash.update([u8::from(request.mime)]);
        }
    }
    let key = format!("vacation:{}:{}", hex(&hash.finalize()[..16]), sender.to_lowercase());

    let (name, from) = request
        .from
        .as_deref()
        .and_then(single_address)
        .unwrap_or_else(|| (None, own.first().cloned().unwrap_or_default()));
    let subject = request.subject.clone().unwrap_or_else(|| match mail.subject().filter(|s| !s.trim().is_empty()) {
        Some(original) => format!("Auto: {original}"),
        None => "Automatic reply".to_owned(),
    });
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("the system's random source");
    let host = match domain(&from) {
        "" => "localhost",
        host => host,
    };
    let mut builder = MessageBuilder::new()
        .from(match &name {
            Some(name) => mail_builder::headers::address::Address::from((name.clone(), from.clone())),
            None => mail_builder::headers::address::Address::from(from.clone()),
        })
        .to(sender.to_owned())
        .subject(subject)
        .date(context.now)
        .message_id(format!("{}@{host}", hex(&id)))
        .header("Auto-Submitted", Raw::new("auto-replied"));
    if let Some(original) = mail.message_id() {
        let mut references = mail.references();
        references.push(original.clone());
        builder = builder.in_reply_to(original).references(references);
    }
    builder = if request.mime {
        let mut entity = request.reason.replace("\r\n", "\n").replace('\n', "\r\n");
        if !entity.contains("\r\n\r\n") {
            // Without headers, the entity is its body.
            entity.insert_str(0, "\r\n");
        }
        builder.body(MimePart::raw(BodyPart::Binary(entity.into_bytes().into())))
    } else {
        builder.text_body(request.reason)
    };
    let message = builder.write_to_vec().unwrap_or_default();
    Some(Vacation { to: sender.to_owned(), key, seconds: request.seconds, message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MessageParser;

    fn request() -> Request {
        Request {
            reason: "I am away.".into(),
            subject: None,
            from: None,
            addresses: Vec::new(),
            mime: false,
            handle: None,
            seconds: 7 * 86_400,
        }
    }

    fn context<'a>(from: &'a str) -> Context<'a> {
        Context {
            envelope_from: from,
            envelope_to: "alice+box@firma.example",
            user_addresses: vec!["alice@firma.example".into()],
            now: 1_700_000_000,
            zone: 0,
        }
    }

    const MAIL: &[u8] = b"From: Carol <carol@other.example>\r\nTo: alice@firma.example\r\nSubject: Lunch\r\n\
Message-ID: <m1@other.example>\r\nReferences: <m0@other.example>\r\n\r\nHi\r\n";

    #[test]
    fn it_answers_with_a_reply_to_the_message() {
        let mail = Mail::new(MAIL);
        let reply = respond(&mail, &context("carol@other.example"), request()).unwrap();
        assert_eq!(reply.to, "carol@other.example");
        assert!(reply.key.ends_with(":carol@other.example"));
        let parsed = MessageParser::new().parse(&reply.message).unwrap();
        assert_eq!(parsed.subject(), Some("Auto: Lunch"));
        assert_eq!(parsed.from().unwrap().first().unwrap().address(), Some("alice@firma.example"));
        assert_eq!(parsed.in_reply_to().unwrap().first(), Some("m1@other.example"));
        assert_eq!(parsed.references().unwrap().iter().collect::<Vec<_>>(), ["m0@other.example", "m1@other.example"]);
        assert_eq!(parsed.headers().get("auto-submitted").unwrap().raw_value(), b" auto-replied\r\n");
        assert!(parsed.body_text(0).unwrap().contains("I am away."));
        assert!(parsed.message_id().unwrap().ends_with("@firma.example"));

        // Its own subject, sender and a MIME body.
        let custom = Request {
            subject: Some("Away".into()),
            from: Some("Alice <alice@firma.example>".into()),
            mime: true,
            reason: "Content-Type: text/html\n\n<p>Away</p>\n".into(),
            ..request()
        };
        let reply = respond(&mail, &context("carol@other.example"), custom).unwrap();
        let parsed = MessageParser::new().parse(&reply.message).unwrap();
        assert_eq!(parsed.subject(), Some("Away"));
        assert_eq!(parsed.from().unwrap().first().unwrap().name(), Some("Alice"));
        assert!(parsed.body_html(0).unwrap().contains("<p>Away</p>"));
    }

    #[test]
    fn the_key_follows_the_handle_or_the_arguments() {
        let mail = Mail::new(MAIL);
        let key = |request| respond(&mail, &context("carol@other.example"), request).unwrap().key;
        assert_eq!(key(request()), key(request()));
        assert_ne!(key(request()), key(Request { subject: Some("x".into()), ..request() }));
        let handled = |reason: &str| Request { reason: reason.into(), handle: Some("h".into()), ..request() };
        assert_eq!(key(handled("one")), key(handled("two")));
    }

    #[test]
    fn it_does_not_answer_lists_robots_itself_or_mail_not_to_the_user() {
        let mail = Mail::new(MAIL);
        assert!(respond(&mail, &context(""), request()).is_none());
        assert!(respond(&mail, &context("alice@firma.example"), request()).is_none());
        assert!(respond(&mail, &context("Alice+x@Firma.example"), request()).is_none());
        for robot in ["owner-dev@x.example", "dev-request@x.example", "MAILER-DAEMON@x.example", "listserv@x.example"] {
            assert!(respond(&mail, &context(robot), request()).is_none(), "{robot}");
        }
        for header in ["Auto-Submitted: auto-generated", "Precedence: bulk", "List-Id: <dev.x.example>"] {
            let raw = format!("{header}\r\n{}", String::from_utf8_lossy(MAIL));
            assert!(respond(&Mail::new(raw.as_bytes()), &context("carol@other.example"), request()).is_none());
        }
        let raw = format!("Auto-Submitted: no\r\n{}", String::from_utf8_lossy(MAIL));
        assert!(respond(&Mail::new(raw.as_bytes()), &context("carol@other.example"), request()).is_some());

        let elsewhere = Mail::new(b"From: carol@other.example\r\nTo: team@firma.example\r\n\r\nHi\r\n");
        assert!(respond(&elsewhere, &context("carol@other.example"), request()).is_none());
        let with = Request { addresses: vec!["team@firma.example".into()], ..request() };
        assert!(respond(&elsewhere, &context("carol@other.example"), with).is_some());
        let subaddressed = Mail::new(b"From: carol@other.example\r\nCc: alice+news@firma.example\r\n\r\nHi\r\n");
        let reply = respond(&subaddressed, &context("carol@other.example"), request()).unwrap();
        let parsed = MessageParser::new().parse(&reply.message).unwrap();
        assert_eq!(parsed.subject(), Some("Automatic reply"));
    }
}
