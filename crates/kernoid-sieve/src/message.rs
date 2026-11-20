// SPDX-License-Identifier: AGPL-3.0-or-later
//! What tests read from the message, through kernoid-mime: header fields decoded (RFC 2047) and unfolded, the
//! addresses in them, their dates, and the body (RFC 5173).

use kernoid_mime::{DateTime, Header, Message};

pub(crate) struct Mail<'m> {
    raw: &'m [u8],
    message: Option<Message<'m>>,
}

/// How `body` looks at the message (RFC 5173, 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyTransform {
    Raw,
    /// Content types: `""` for every part, `type` for all of a type, `type/subtype` for one.
    Content(Vec<String>),
    Text,
}

/// The local part of an address: what comes before its last `@`; without one, the whole.
pub(crate) fn local_part(address: &str) -> &str {
    address.rsplit_once('@').map_or(address, |(local, _)| local)
}

pub(crate) fn domain(address: &str) -> &str {
    address.rsplit_once('@').map_or("", |(_, domain)| domain)
}

/// Parses one address as in a header field; `None` unless it is one address with an `@`.
pub(crate) fn single_address(text: &str) -> Option<(Option<String>, String)> {
    let list = kernoid_mime::address::parse(text);
    let mut mailboxes = list.mailboxes();
    let first = mailboxes.next()?;
    if mailboxes.next().is_some() {
        return None;
    }
    let address = first.address()?.trim();
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || address.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some((first.name().map(str::to_owned), address.to_owned()))
}

impl<'m> Mail<'m> {
    pub(crate) fn new(raw: &'m [u8]) -> Self {
        Mail { raw, message: Message::parse(raw) }
    }

    pub(crate) fn size(&self) -> usize {
        self.raw.len()
    }

    /// The fields called `name` of the message's own header, in order.
    fn fields(&self, name: &str) -> Vec<Header<'_>> {
        match &self.message {
            Some(message) if !name.is_empty() => message.root().headers().all(name).collect(),
            _ => Vec::new(),
        }
    }

    /// The fields called `name`, or only the `index`th of them (from 1; from the end with `last`) – RFC 5260, 4.
    fn indexed(&self, name: &str, index: Option<(usize, bool)>) -> Vec<Header<'_>> {
        let mut fields = self.fields(name);
        if let Some((n, last)) = index {
            let at = if last { fields.len().checked_sub(n) } else { n.checked_sub(1) };
            fields = at.and_then(|at| fields.get(at).copied()).into_iter().collect();
        }
        fields
    }

    pub(crate) fn exists(&self, name: &str) -> bool {
        !self.fields(name).is_empty()
    }

    /// The decoded, unfolded values of the fields called `name`.
    pub(crate) fn header_values(&self, name: &str, index: Option<(usize, bool)>) -> Vec<String> {
        self.indexed(name, index).iter().map(|field| field.text()).collect()
    }

    /// The addresses in the fields called `name`, group members included; what is no address is left out.
    pub(crate) fn addresses(&self, name: &str, index: Option<(usize, bool)>) -> Vec<String> {
        let mut out = Vec::new();
        for field in self.indexed(name, index) {
            out.extend(field.addresses().mailboxes().filter_map(|mailbox| mailbox.address().map(str::to_owned)));
        }
        out
    }

    /// The dates of the fields called `name`; a `Received` field's is after its last `;` (RFC 5260, 4.1).
    pub(crate) fn dates(&self, name: &str, index: Option<(usize, bool)>) -> Vec<DateTime> {
        self.indexed(name, index)
            .iter()
            .filter_map(|field| {
                let raw = field.raw_value();
                let raw = if name.eq_ignore_ascii_case("received") {
                    raw.iter().rposition(|b| *b == b';').map_or(raw, |at| &raw[at + 1..])
                } else {
                    raw
                };
                kernoid_mime::date::parse(&String::from_utf8_lossy(raw)).filter(DateTime::is_valid)
            })
            .collect()
    }

    pub(crate) fn subject(&self) -> Option<String> {
        self.message.as_ref().and_then(|message| message.subject())
    }

    pub(crate) fn message_id(&self) -> Option<String> {
        self.message.as_ref().and_then(|message| message.message_id())
    }

    pub(crate) fn references(&self) -> Vec<String> {
        self.message.as_ref().map(|message| message.references()).unwrap_or_default()
    }

    /// What `body` compares (RFC 5173, 5): the raw body, the decoded parts of the given types, or the text parts.
    pub(crate) fn body(&self, transform: &BodyTransform) -> Vec<String> {
        let Some(message) = &self.message else {
            let body = match self.raw.windows(4).position(|w| w == b"\r\n\r\n") {
                Some(at) => &self.raw[at + 4..],
                None => &[][..],
            };
            return vec![String::from_utf8_lossy(body).into_owned()];
        };
        let root = message.root();
        match transform {
            BodyTransform::Raw => vec![String::from_utf8_lossy(root.root_part().raw_body()).into_owned()],
            BodyTransform::Text => {
                let types = ["text".to_owned()];
                self.parts(message, &types)
            }
            BodyTransform::Content(types) => self.parts(message, types),
        }
    }

    fn parts(&self, message: &Message<'_>, types: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for part in message.all_parts() {
            if part.is_multipart() {
                continue;
            }
            let (ctype, subtype) = match part.media_type().split_once('/') {
                Some((ctype, subtype)) => (ctype.to_owned(), Some(subtype.to_owned())),
                None => (part.media_type().to_owned(), None),
            };
            let wanted = types.iter().any(|wanted| match wanted.split_once('/') {
                _ if wanted.is_empty() => true,
                Some((t, s)) => t.eq_ignore_ascii_case(&ctype) && Some(s.to_ascii_lowercase()) == subtype,
                None => wanted.eq_ignore_ascii_case(&ctype),
            });
            if !wanted {
                continue;
            }
            let text = if part.is_message() {
                String::from_utf8_lossy(part.raw_headers()).into_owned()
            } else if ctype == "text" {
                match part.text() {
                    Some(text) if subtype.as_deref() == Some("html") => kernoid_mime::html_to_text(&text),
                    Some(text) => text.into_owned(),
                    None => String::new(),
                }
            } else {
                String::from_utf8_lossy(&part.decoded()).into_owned()
            };
            out.push(text);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"Received: from a by b; Tue, 1 Apr 1997 09:06:31 -0800\r\n\
From: \"Coyote\" <coyote@desert.example.org>, Road <roadrunner@acme.example.com>\r\n\
To: friends: a@x.example, b@y.example;\r\n\
Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\n\
\x20and more\r\n\
X-Caffeine: C8H10N4O2\r\n\
X-Caffeine: second\r\n\
Date: Tue, 1 Apr 1997 09:06:31 -0800\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Sch=C3=B6n\r\n\
--b\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>Hello <b>you</b></p>\r\n\
--b\r\n\
Content-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
YmluYXJ5\r\n\
--b--\r\n";

    #[test]
    fn headers_are_decoded_unfolded_and_indexed() {
        let mail = Mail::new(MESSAGE);
        assert_eq!(mail.header_values("subject", None), ["Grüße and more"]);
        assert_eq!(mail.header_values("x-caffeine", None), ["C8H10N4O2", "second"]);
        assert_eq!(mail.header_values("X-Caffeine", Some((2, false))), ["second"]);
        assert_eq!(mail.header_values("X-Caffeine", Some((1, true))), ["second"]);
        assert_eq!(mail.header_values("X-Caffeine", Some((3, false))), Vec::<String>::new());
        assert!(mail.exists("FROM") && !mail.exists("Cc") && !mail.exists(""));
        assert_eq!(mail.subject().as_deref(), Some("Grüße and more"));
    }

    #[test]
    fn addresses_and_their_parts() {
        let mail = Mail::new(MESSAGE);
        assert_eq!(mail.addresses("from", None), ["coyote@desert.example.org", "roadrunner@acme.example.com"]);
        assert_eq!(mail.addresses("to", None), ["a@x.example", "b@y.example"]);
        assert!(mail.addresses("x-caffeine", Some((1, false))).is_empty());
        assert_eq!(local_part("a@b@c"), "a@b");
        assert_eq!(domain("a@b@c"), "c");
        assert_eq!(domain("nobody"), "");
        assert_eq!(single_address("Me <me@example.org>"), Some((Some("Me".into()), "me@example.org".into())));
        assert_eq!(single_address("me@example.org"), Some((None, "me@example.org".into())));
        assert_eq!(single_address("a@x, b@y"), None);
        assert_eq!(single_address("not an address"), None);
    }

    #[test]
    fn dates_of_fields() {
        let mail = Mail::new(MESSAGE);
        let date = mail.dates("date", None);
        assert_eq!(date.len(), 1);
        assert_eq!(date[0].to_timestamp(), 859_914_391);
        assert_eq!(date[0].offset, -480);
        assert_eq!(mail.dates("received", None)[0].to_timestamp(), 859_914_391);
        assert!(mail.dates("subject", None).is_empty());
    }

    #[test]
    fn body_transforms() {
        let mail = Mail::new(MESSAGE);
        assert_eq!(mail.body(&BodyTransform::Text), ["Schön", "Hello you\n"]);
        let octets = mail.body(&BodyTransform::Content(vec!["application/octet-stream".into()]));
        assert_eq!(octets, ["binary"]);
        assert_eq!(mail.body(&BodyTransform::Content(vec!["".into()])).len(), 3);
        assert_eq!(mail.body(&BodyTransform::Content(vec!["text/html".into()])).len(), 1);
        assert!(mail.body(&BodyTransform::Raw)[0].starts_with("--b\r\n"));
        let plain = Mail::new(b"Subject: x\r\n\r\nJust text\r\n");
        assert_eq!(plain.body(&BodyTransform::Text), ["Just text\r\n"]);
    }
}
