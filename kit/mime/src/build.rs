// SPDX-License-Identifier: MIT
//! Writing messages (RFC 5322, MIME): header fields folded at 78 characters, text that is not ASCII in encoded words
//! (RFC 2047) and parameters after RFC 2231, bodies in 7bit, quoted-printable or base64 as their content needs,
//! multiparts with boundaries that do not occur in them. A message without `Date` gets the present time, one without
//! `Message-ID` an id of its own.

use std::hash::{BuildHasher, Hasher};

use crate::{date::DateTime, transfer, words};

/// An address to write: a name, if any, and the address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub name: Option<String>,
    pub email: String,
}

impl Address {
    pub fn new(name: Option<impl Into<String>>, email: impl Into<String>) -> Self {
        Self { name: name.map(Into::into).filter(|name: &String| !name.trim().is_empty()), email: email.into() }
    }
}

impl From<&str> for Address {
    fn from(email: &str) -> Self {
        Self { name: None, email: email.to_owned() }
    }
}

impl From<String> for Address {
    fn from(email: String) -> Self {
        Self { name: None, email }
    }
}

impl From<(&str, &str)> for Address {
    fn from((name, email): (&str, &str)) -> Self {
        Self::new(Some(name), email)
    }
}

impl From<(String, String)> for Address {
    fn from((name, email): (String, String)) -> Self {
        Self::new(Some(name), email)
    }
}

#[derive(Debug, Clone)]
enum Value {
    Raw(String),
    Text(String),
    Addresses(Vec<Address>),
    Ids(Vec<String>),
    Date(DateTime),
}

/// The content of a part.
#[derive(Debug, Clone)]
pub enum Body {
    /// Text, written with CRLF line breaks in the encoding it needs.
    Text(String),
    Binary(Vec<u8>),
    Multipart(Vec<Part>),
}

/// A MIME part to write.
#[derive(Debug, Clone)]
pub struct Part {
    media_type: String,
    parameters: Vec<(String, String)>,
    disposition: Option<(String, Option<String>)>,
    content_id: Option<String>,
    encoding: Option<transfer::Encoding>,
    body: Body,
}

impl Part {
    /// A part of `media_type` (`type/subtype`).
    pub fn new(media_type: impl Into<String>, body: Body) -> Self {
        Self {
            media_type: media_type.into(),
            parameters: Vec::new(),
            disposition: None,
            content_id: None,
            encoding: None,
            body,
        }
    }

    /// Text of `media_type`, in UTF-8.
    pub fn text(media_type: impl Into<String>, text: impl Into<String>) -> Self {
        Self::new(media_type, Body::Text(text.into()))
    }

    pub fn binary(media_type: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self::new(media_type, Body::Binary(data.into()))
    }

    /// `multipart/subtype` of `parts`.
    pub fn multipart(subtype: &str, parts: Vec<Part>) -> Self {
        Self::new(format!("multipart/{subtype}"), Body::Multipart(parts))
    }

    /// A parameter of the content type.
    pub fn parameter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.push((name.into(), value.into()));
        self
    }

    /// An attachment named `name` (in the content type's `name` too).
    pub fn attachment(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !self.parameters.iter().any(|(n, _)| n.eq_ignore_ascii_case("name")) {
            self.parameters.push(("name".into(), name.clone()));
        }
        self.disposition = Some(("attachment".into(), Some(name)));
        self
    }

    /// Inline, with a `Content-ID` (without angle brackets) to refer to it by.
    pub fn inline(mut self, content_id: impl Into<String>) -> Self {
        self.disposition = Some(("inline".into(), None));
        self.content_id = Some(content_id.into());
        self
    }

    /// The transfer encoding to write the content in, as it is (`7bit`, `8bit`) or encoded.
    pub fn transfer_encoding(mut self, encoding: transfer::Encoding) -> Self {
        self.encoding = Some(encoding);
        self
    }

    fn write(&self, bytes: &mut Vec<u8>) {
        let mut header = String::new();
        let mut content_type = self.media_type.clone();
        let mut parameters = self.parameters.clone();
        let boundary = matches!(self.body, Body::Multipart(_)).then(boundary);
        if let Some(boundary) = &boundary {
            parameters.push(("boundary".into(), boundary.clone()));
        }
        let is_text = matches!(self.body, Body::Text(_));
        if is_text && !parameters.iter().any(|(n, _)| n.eq_ignore_ascii_case("charset")) {
            parameters.push(("charset".into(), "utf-8".into()));
        }
        for (name, value) in &parameters {
            content_type.push_str(&parameter(name, value, name.eq_ignore_ascii_case("name")));
        }
        fold_into(&mut header, "Content-Type", &content_type);
        let (encoding, content): (Option<&str>, Vec<u8>) = match &self.body {
            Body::Multipart(_) => (None, Vec::new()),
            Body::Text(text) => {
                let text = crlf(text);
                match self.encoding {
                    Some(transfer::Encoding::Base64) => (Some("base64"), base64_body(text.as_bytes())),
                    Some(transfer::Encoding::QuotedPrintable) => {
                        (Some("quoted-printable"), transfer::qp_encode(text.as_bytes()).into_bytes())
                    }
                    Some(encoding @ (transfer::Encoding::SevenBit | transfer::Encoding::EightBit)) => (
                        Some(if encoding == transfer::Encoding::SevenBit { "7bit" } else { "8bit" }),
                        text.into_bytes(),
                    ),
                    _ => text_encoding(text),
                }
            }
            Body::Binary(data) => match self.encoding {
                Some(transfer::Encoding::SevenBit) => (Some("7bit"), data.clone()),
                Some(transfer::Encoding::EightBit) => (Some("8bit"), data.clone()),
                Some(transfer::Encoding::QuotedPrintable) => {
                    (Some("quoted-printable"), transfer::qp_encode(data).into_bytes())
                }
                _ => (Some("base64"), base64_body(data)),
            },
        };
        if let Some(encoding) = encoding {
            header.push_str(&format!("Content-Transfer-Encoding: {encoding}\r\n"));
        }
        if let Some((kind, filename)) = &self.disposition {
            let mut value = kind.clone();
            if let Some(filename) = filename {
                value.push_str(&parameter("filename", filename, false));
            }
            fold_into(&mut header, "Content-Disposition", &value);
        }
        if let Some(id) = &self.content_id {
            header.push_str(&format!("Content-ID: <{}>\r\n", id.trim_matches(['<', '>'])));
        }
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        match &self.body {
            Body::Multipart(parts) => {
                let boundary = boundary.unwrap_or_default();
                for part in parts {
                    bytes.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                    part.write(bytes);
                    bytes.extend_from_slice(b"\r\n");
                }
                bytes.extend_from_slice(format!("--{boundary}--").as_bytes());
            }
            _ => bytes.extend_from_slice(&content),
        }
    }
}

/// Line breaks as CRLF.
fn crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 32);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\r\n");
            }
            '\n' => out.push_str("\r\n"),
            c => out.push(c),
        }
    }
    out
}

/// Base64 in lines, without the last line break (the delimiter or the message's end brings its own).
fn base64_body(data: &[u8]) -> Vec<u8> {
    let mut lines = transfer::base64_lines(data);
    if lines.ends_with("\r\n") {
        lines.truncate(lines.len() - 2);
    }
    lines.into_bytes()
}

/// The encoding text needs: none for short lines of ASCII, quoted-printable for text mostly ASCII, base64 otherwise.
fn text_encoding(text: String) -> (Option<&'static str>, Vec<u8>) {
    let long = text.split("\r\n").any(|line| line.len() > 76);
    if text.is_ascii() && !long && !text.contains(['\0']) {
        return (Some("7bit"), text.into_bytes());
    }
    let other = text.bytes().filter(|b| !b.is_ascii()).count();
    if other * 4 < text.len() {
        (Some("quoted-printable"), transfer::qp_encode(text.as_bytes()).into_bytes())
    } else {
        (Some("base64"), base64_body(text.as_bytes()))
    }
}

fn is_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b))
}

/// `; name=value`: a token, a quoted string, or RFC 2231 for what is not ASCII – for `name`, an encoded word too.
fn parameter(name: &str, value: &str, words_too: bool) -> String {
    let value = value.replace(['\r', '\n'], " ");
    if is_token(&value) {
        return format!("; {name}={value}");
    }
    if value.is_ascii() {
        return format!("; {name}=\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""));
    }
    if words_too {
        return format!("; {name}=\"{}\"", words::encode(&value));
    }
    let encoded: String = value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("; {name}*=utf-8''{encoded}")
}

/// A field folded at white space so that lines stay within 78 characters where they can.
fn fold_into(out: &mut String, name: &str, value: &str) {
    let mut line_length = name.len() + 1;
    out.push_str(name);
    out.push(':');
    let mut first = true;
    for word in value.split(' ') {
        if word.is_empty() && !first {
            continue;
        }
        // A first word too long for the line of the name goes to the next line.
        let breakable = !first || word.len() < 78;
        if breakable && line_length + 1 + word.len() > 78 && (line_length > name.len() + 1 || first) {
            out.push_str("\r\n");
            line_length = 0;
        }
        out.push(' ');
        out.push_str(word);
        line_length += 1 + word.len();
        first = false;
    }
    out.push_str("\r\n");
}

/// A display name: as it is if it is atoms, quoted if it is other ASCII, encoded words otherwise.
fn display_name(name: &str) -> String {
    let name = name.trim().replace(['\r', '\n'], " ");
    if name.bytes().all(|b| b.is_ascii_alphanumeric() || b" !#$%&'*+-/=?^_`{|}~".contains(&b)) && !name.contains("=?") {
        name
    } else if words::is_plain(&name) {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        words::encode(&name)
    }
}

fn address(address: &Address) -> String {
    let email = address.email.trim().replace(['\r', '\n', ' '], "");
    match address.name.as_deref().map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => format!("{} <{email}>", display_name(name)),
        None => email,
    }
}

/// A random boundary.
fn boundary() -> String {
    format!("kernoid-{}", unique())
}

/// 128 bits that are not the same twice: two hashers seeded at random by the standard library, a counter and the time.
fn unique() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let half = |salt: u64| {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(salt);
        hasher.write_u64(count);
        hasher.write_u128(nanos);
        hasher.finish()
    };
    format!("{:016x}{:016x}", half(1), half(2))
}

/// A message to write.
#[derive(Debug, Clone, Default)]
pub struct MessageBuilder {
    headers: Vec<(String, Value)>,
    body: Option<Part>,
    raw_entity: Option<Vec<u8>>,
    text: Option<String>,
    html: Option<String>,
    attachments: Vec<Part>,
    inline: Vec<Part>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn set(mut self, name: &str, value: Value) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value));
        self
    }

    fn addresses(self, name: &str, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        let list: Vec<Address> = list.into_iter().map(Into::into).collect();
        if list.is_empty() { self } else { self.set(name, Value::Addresses(list)) }
    }

    pub fn from(self, address: impl Into<Address>) -> Self {
        self.addresses("From", [address.into()])
    }

    pub fn from_list(self, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        self.addresses("From", list)
    }

    pub fn sender(self, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        self.addresses("Sender", list)
    }

    pub fn reply_to(self, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        self.addresses("Reply-To", list)
    }

    pub fn to(self, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        self.addresses("To", list)
    }

    pub fn cc(self, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        self.addresses("Cc", list)
    }

    pub fn bcc(self, list: impl IntoIterator<Item = impl Into<Address>>) -> Self {
        self.addresses("Bcc", list)
    }

    pub fn subject(self, subject: impl Into<String>) -> Self {
        self.set("Subject", Value::Text(subject.into()))
    }

    pub fn date(self, date: DateTime) -> Self {
        self.set("Date", Value::Date(date))
    }

    /// `Message-ID`, without angle brackets.
    pub fn message_id(self, id: impl Into<String>) -> Self {
        self.set("Message-ID", Value::Ids(vec![id.into()]))
    }

    pub fn in_reply_to(self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let ids: Vec<String> = ids.into_iter().map(Into::into).collect();
        if ids.is_empty() { self } else { self.set("In-Reply-To", Value::Ids(ids)) }
    }

    pub fn references(self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let ids: Vec<String> = ids.into_iter().map(Into::into).collect();
        if ids.is_empty() { self } else { self.set("References", Value::Ids(ids)) }
    }

    /// A field written as it is (ASCII, no line breaks).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), Value::Raw(value.into().replace(['\r', '\n'], " "))));
        self
    }

    /// A field of unstructured text, encoded where it needs to be.
    pub fn text_header(mut self, name: impl Into<String>, text: impl Into<String>) -> Self {
        self.headers.push((name.into(), Value::Text(text.into())));
        self
    }

    pub fn text_body(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    pub fn html_body(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    pub fn attachment(
        mut self,
        media_type: impl Into<String>,
        name: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        self.attachments.push(Part::binary(media_type, data).attachment(name));
        self
    }

    /// A part the HTML body shows (`cid:`).
    pub fn inline(
        mut self,
        media_type: impl Into<String>,
        content_id: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        self.inline.push(Part::binary(media_type, data).inline(content_id));
        self
    }

    /// The body as one part (in place of text, HTML and attachments).
    pub fn body(mut self, part: Part) -> Self {
        self.body = Some(part);
        self
    }

    /// The body as a MIME entity written as it is: its header fields join the message's, then its body.
    pub fn raw_entity(mut self, entity: impl Into<Vec<u8>>) -> Self {
        self.raw_entity = Some(entity.into());
        self
    }

    /// The body from text, HTML, inline parts and attachments.
    fn assembled(&mut self) -> Part {
        let html = self.html.take().map(|html| {
            let html = Part::text("text/html", html);
            if self.inline.is_empty() {
                html
            } else {
                let mut parts = vec![html];
                parts.append(&mut self.inline);
                Part::multipart("related", parts)
            }
        });
        let text = self.text.take().map(|text| Part::text("text/plain", text));
        let content = match (text, html) {
            (Some(text), Some(html)) => Some(Part::multipart("alternative", vec![text, html])),
            (text, html) => text.or(html),
        };
        let mut attachments = std::mem::take(&mut self.attachments);
        attachments.append(&mut self.inline);
        match (content, attachments.is_empty()) {
            (Some(content), true) => content,
            (None, true) => Part::text("text/plain", ""),
            (content, false) => Part::multipart("mixed", content.into_iter().chain(attachments).collect()),
        }
    }

    /// The message.
    pub fn write(mut self) -> Vec<u8> {
        let mut header = String::new();
        let has = |headers: &[(String, Value)], name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        if !has(&self.headers, "Date") {
            self.headers.push(("Date".into(), Value::Date(DateTime::now())));
        }
        if !has(&self.headers, "Message-ID") {
            let domain = self
                .headers
                .iter()
                .find_map(|(name, value)| match value {
                    Value::Addresses(list) if name.eq_ignore_ascii_case("From") => {
                        list.first().and_then(|a| a.email.rsplit_once('@')).map(|(_, domain)| domain.to_owned())
                    }
                    _ => None,
                })
                .filter(|domain| !domain.is_empty())
                .unwrap_or_else(|| "kernoid".into());
            self.headers.push(("Message-ID".into(), Value::Ids(vec![format!("{}@{domain}", unique())])));
        }
        for (name, value) in &self.headers {
            match value {
                Value::Raw(raw) => header.push_str(&format!("{name}: {raw}\r\n")),
                Value::Text(text) => fold_into(&mut header, name, &words::encode(text)),
                Value::Addresses(list) => {
                    let joined = list.iter().map(address).collect::<Vec<_>>().join(", ");
                    fold_into(&mut header, name, &joined);
                }
                Value::Ids(ids) => {
                    let joined = ids
                        .iter()
                        .map(|id| format!("<{}>", id.trim().trim_matches(['<', '>']).replace([' ', '\r', '\n'], "")))
                        .collect::<Vec<_>>()
                        .join(" ");
                    fold_into(&mut header, name, &joined);
                }
                Value::Date(date) => header.push_str(&format!("{name}: {}\r\n", date.to_rfc822())),
            }
        }
        header.push_str("MIME-Version: 1.0\r\n");
        let mut out = header.into_bytes();
        if let Some(entity) = self.raw_entity.take() {
            out.extend_from_slice(&entity);
            return out;
        }
        let body = match self.body.take() {
            Some(body) => body,
            None => self.assembled(),
        };
        body.write(&mut out);
        if !out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Kind, Message};

    #[test]
    fn a_message_with_everything() {
        let raw = MessageBuilder::new()
            .from(("Jürgen Müller", "juergen@firma.example"))
            .to(["bob@x.example", "carol@y.example"])
            .cc([Address::new(Some("Doe, John"), "john@x.example")])
            .subject("Grüße aus Köln – ein sehr langer Betreff, der gefaltet werden muss, weil er lang ist")
            .date(DateTime::from_timestamp(1_700_000_000))
            .message_id("m1@firma.example")
            .in_reply_to(["m0@x.example"])
            .references(["a@x", "m0@x.example"])
            .header("Auto-Submitted", "auto-replied")
            .text_body("Hallo,\nbis bald – Jürgen\n")
            .html_body("<p>Hallo,</p><img src=\"cid:logo@x\">")
            .inline("image/png", "logo@x", b"\x89PNG".to_vec())
            .attachment("application/pdf", "Plan für März.pdf", b"%PDF-1.4".to_vec())
            .write();
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.lines().all(|line| line.len() <= 78), "{text}");
        assert!(text.contains("Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n"), "{text}");
        assert!(text.contains("Auto-Submitted: auto-replied\r\n"));
        let message = Message::parse(&raw).unwrap();
        let root = message.root();
        assert_eq!(root.from().unwrap().first().unwrap().name(), Some("Jürgen Müller"));
        assert_eq!(root.to().unwrap().mailboxes().count(), 2);
        assert_eq!(root.cc().unwrap().first().unwrap().name(), Some("Doe, John"));
        assert_eq!(
            root.subject().as_deref(),
            Some("Grüße aus Köln – ein sehr langer Betreff, der gefaltet werden muss, weil er lang ist")
        );
        assert_eq!(root.message_id().as_deref(), Some("m1@firma.example"));
        assert_eq!(root.in_reply_to(), ["m0@x.example"]);
        assert_eq!(root.references(), ["a@x", "m0@x.example"]);
        assert_eq!(root.date().unwrap().to_timestamp(), 1_700_000_000);
        assert_eq!(root.body_text(0).as_deref(), Some("Hallo,\r\nbis bald – Jürgen\r\n"));
        assert_eq!(root.body_html(0).as_deref(), Some("<p>Hallo,</p><img src=\"cid:logo@x\">"));
        let attachments = root.attachments();
        assert_eq!(attachments.len(), 2);
        let pdf = attachments.iter().find(|p| p.media_type() == "application/pdf").unwrap();
        assert_eq!(pdf.attachment_name(), Some("Plan für März.pdf"));
        assert_eq!(pdf.decoded().as_ref(), b"%PDF-1.4");
        let png = attachments.iter().find(|p| p.media_type() == "image/png").unwrap();
        assert_eq!(png.kind(), Kind::InlineBinary);
        assert_eq!(png.content_id().as_deref(), Some("logo@x"));
        let types: Vec<&str> = root.parts().map(|p| p.media_type()).collect();
        assert_eq!(
            types,
            [
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "multipart/related",
                "text/html",
                "image/png",
                "application/pdf"
            ]
        );
    }

    #[test]
    fn defaults_and_raw_entities() {
        let raw = MessageBuilder::new().from("a@firma.example").to(["b@x.example"]).text_body("Hi").write();
        let message = Message::parse(&raw).unwrap();
        assert!(message.message_id().unwrap().ends_with("@firma.example"));
        assert!(message.date().is_some());
        assert_eq!(message.root().body_text(0).as_deref(), Some("Hi\r\n"));
        let raw = MessageBuilder::new()
            .from("a@x.example")
            .raw_entity(b"Content-Type: text/html\r\n\r\n<p>Away</p>\r\n".to_vec())
            .write();
        let message = Message::parse(&raw).unwrap();
        assert!(message.root().body_html(0).unwrap().contains("<p>Away</p>"));
        // An empty body.
        let raw = MessageBuilder::new().from("a@x.example").write();
        assert_eq!(Message::parse(&raw).unwrap().root().body_text(0).as_deref(), Some(""));
    }

    #[test]
    fn parts_with_parameters_and_encodings() {
        let report = Part::multipart(
            "report",
            vec![
                Part::text("text/plain", "Not delivered."),
                Part::binary("message/delivery-status", b"Reporting-MTA: dns; x\r\n".to_vec())
                    .transfer_encoding(transfer::Encoding::SevenBit),
            ],
        )
        .parameter("report-type", "delivery-status");
        let raw = MessageBuilder::new().from("a@x.example").subject("s").body(report).write();
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.contains("multipart/report; report-type=delivery-status;\r\n boundary="), "{text}");
        assert!(text.contains("Content-Transfer-Encoding: 7bit\r\n\r\nReporting-MTA: dns; x\r\n"), "{text}");
        let message = Message::parse(&raw).unwrap();
        assert_eq!(message.root().parts().count(), 3);
        let calendar =
            Part::text("text/calendar", "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").parameter("method", "REQUEST");
        let raw = MessageBuilder::new().from("a@x.example").body(calendar).write();
        let message = Message::parse(&raw).unwrap();
        let part = message.root().root_part();
        assert_eq!(part.content_type().unwrap().attribute("method"), Some("REQUEST"));
        assert_eq!(part.content_type().unwrap().attribute("charset"), Some("utf-8"));
        assert_eq!(part.text().as_deref(), Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"));
        // Long lines and much text that is not ASCII.
        for text in ["x".repeat(500), "日本語".repeat(100), format!("{}ü", "a".repeat(300))] {
            let raw = MessageBuilder::new().from("a@x.example").text_body(text.clone()).write();
            assert!(raw.split(|b| *b == b'\n').all(|line| line.len() <= 78));
            assert_eq!(Message::parse(&raw).unwrap().root().body_text(0).unwrap().trim_end_matches("\r\n"), text);
        }
    }
}
