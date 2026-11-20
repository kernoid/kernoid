// SPDX-License-Identifier: AGPL-3.0-or-later
//! What `FETCH` reads from a message, parsed by mail-parser: `ENVELOPE` and `BODYSTRUCTURE`/`BODY` (RFC 9051, 7.5.2),
//! the sections of `BODY[…]` (6.4.5) and the decoded content of `BINARY[…]` (RFC 3516). Sizes are those of the raw
//! message; line counts count line feeds. Without UTF-8 (RFC 6855), text the client gets in the envelope or the
//! structure is 7-bit: what is not ASCII goes into an RFC 2047 encoded word.

use std::borrow::Cow;

use base64::Engine;
use mail_parser::{Address, Message, MessagePart, MessageRef, PartKind};

use crate::proto::{
    request::{Section, SectionText},
    response::nstring,
};

/// How deep nested messages and multiparts are described; deeper ones are cut off.
const MAX_DEPTH: usize = 48;

/// Text for the client: as it is with UTF-8, else ASCII or an encoded word.
fn seven_bit(text: &str, utf8: bool) -> Cow<'_, str> {
    if utf8 || text.is_ascii() {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(format!("=?utf-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(text)))
    }
}

fn text(out: &mut Vec<u8>, value: Option<&str>, utf8: bool) {
    nstring(out, value.map(|value| seven_bit(value, utf8)).as_deref().map(str::as_bytes), utf8);
}

/// A header's value as written: unfolded and trimmed.
fn raw_header<'m>(headers: mail_parser::Headers<'m>, name: &str) -> Option<String> {
    let header = headers.get(name)?;
    let value = String::from_utf8_lossy(header.raw_value());
    let unfolded: String = value.split(['\r', '\n']).collect::<Vec<_>>().join("");
    let trimmed = unfolded.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// One address: `(name NIL mailbox host)`.
fn address(out: &mut Vec<u8>, name: Option<&str>, address: Option<&str>, utf8: bool) {
    out.push(b'(');
    text(out, name, utf8);
    out.extend_from_slice(b" NIL ");
    let (local, host) = match address {
        Some(address) => match address.rsplit_once('@') {
            Some((local, host)) => (Some(local), Some(host)),
            None => (Some(address), None),
        },
        None => (None, None),
    };
    text(out, local, utf8);
    out.push(b' ');
    text(out, host, utf8);
    out.push(b')');
}

/// An address list; groups between `(NIL NIL "name" NIL)` and `(NIL NIL NIL NIL)`.
fn addresses(out: &mut Vec<u8>, list: Option<mail_parser::AddressList<'_>>, utf8: bool) {
    let Some(list) = list.filter(|list| !list.is_empty()) else {
        out.extend_from_slice(b"NIL");
        return;
    };
    out.push(b'(');
    for item in list.iter() {
        match item {
            Address::Mailbox(mailbox) => address(out, mailbox.name(), mailbox.address(), utf8),
            Address::Group(group) => {
                out.extend_from_slice(b"(NIL NIL ");
                text(out, Some(group.name().unwrap_or_default()), utf8);
                out.extend_from_slice(b" NIL)");
                for mailbox in group.mailboxes() {
                    address(out, mailbox.name(), mailbox.address(), utf8);
                }
                out.extend_from_slice(b"(NIL NIL NIL NIL)");
            }
        }
    }
    out.push(b')');
}

/// `ENVELOPE`: date, subject, from, sender, reply-to, to, cc, bcc, in-reply-to, message-id. Sender and reply-to
/// default to from.
pub(crate) fn envelope(out: &mut Vec<u8>, message: MessageRef<'_>, utf8: bool) {
    let headers = message.headers();
    out.push(b'(');
    text(out, raw_header(headers, "Date").as_deref(), utf8);
    out.push(b' ');
    text(out, message.subject(), utf8);
    let from = message.from();
    for list in
        [from, message.sender().or(from), message.reply_to().or(from), message.to(), message.cc(), message.bcc()]
    {
        out.push(b' ');
        addresses(out, list, utf8);
    }
    for name in ["In-Reply-To", "Message-ID"] {
        out.push(b' ');
        text(out, raw_header(headers, name).as_deref(), utf8);
    }
    out.push(b')');
}

/// `("name" "value" …)`, or `NIL`.
fn parameters<'m>(out: &mut Vec<u8>, parameters: impl Iterator<Item = (&'m str, &'m str)>, utf8: bool) {
    let mut any = false;
    for (name, value) in parameters {
        out.push(if any { b' ' } else { b'(' });
        any = true;
        text(out, Some(name), utf8);
        out.push(b' ');
        text(out, Some(value), utf8);
    }
    out.extend_from_slice(if any { b")" } else { b"NIL" });
}

/// Disposition, language and location – the extension data every part ends with.
fn extension_tail(out: &mut Vec<u8>, part: &MessagePart<'_>, utf8: bool) {
    out.push(b' ');
    match part.content_disposition() {
        Some(disposition) => {
            out.push(b'(');
            text(out, Some(disposition.ctype()), utf8);
            out.push(b' ');
            parameters(out, disposition.attributes(), utf8);
            out.push(b')');
        }
        None => out.extend_from_slice(b"NIL"),
    }
    out.push(b' ');
    match part.content_language() {
        Some(languages) if languages.len() == 1 => text(out, languages.first(), utf8),
        Some(languages) if !languages.is_empty() => {
            out.push(b'(');
            for (index, language) in languages.iter().enumerate() {
                if index > 0 {
                    out.push(b' ');
                }
                text(out, Some(language), utf8);
            }
            out.push(b')');
        }
        _ => out.extend_from_slice(b"NIL"),
    }
    out.push(b' ');
    text(out, part.content_location(), utf8);
}

fn line_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b == b'\n').count()
}

/// The structure of a part and what it contains.
fn part_structure(out: &mut Vec<u8>, part: MessagePart<'_>, extended: bool, utf8: bool, depth: usize) {
    let content_type = part.content_type();
    let children: Vec<MessagePart<'_>> = part.children().collect();
    if part.is_multipart() && !children.is_empty() && depth < MAX_DEPTH {
        out.push(b'(');
        for child in children {
            part_structure(out, child, extended, utf8, depth + 1);
        }
        out.push(b' ');
        let subtype = content_type.and_then(|content_type| content_type.subtype()).unwrap_or("mixed");
        text(out, Some(&subtype.to_ascii_lowercase()), utf8);
        if extended {
            out.push(b' ');
            match content_type {
                Some(content_type) => parameters(out, content_type.attributes(), utf8),
                None => out.extend_from_slice(b"NIL"),
            }
            extension_tail(out, &part, utf8);
        }
        out.push(b')');
        return;
    }
    let nested = match part.kind() {
        PartKind::Message(nested) if depth < MAX_DEPTH => Some(nested),
        _ => None,
    };
    let (kind, subtype) = match (content_type, nested) {
        (Some(content_type), _) if !part.is_multipart() => (
            content_type.ctype().to_ascii_lowercase(),
            content_type.subtype().unwrap_or("octet-stream").to_ascii_lowercase(),
        ),
        (_, Some(_)) => ("message".to_owned(), "rfc822".to_owned()),
        _ => ("text".to_owned(), "plain".to_owned()),
    };
    out.push(b'(');
    text(out, Some(&kind), utf8);
    out.push(b' ');
    text(out, Some(&subtype), utf8);
    out.push(b' ');
    let mut parameter_list: Vec<(&str, &str)> = content_type
        .filter(|_| !part.is_multipart())
        .map(|content_type| content_type.attributes().collect())
        .unwrap_or_default();
    if kind == "text" && !parameter_list.iter().any(|(name, _)| name.eq_ignore_ascii_case("charset")) {
        parameter_list.push(("charset", "us-ascii"));
    }
    parameters(out, parameter_list.into_iter(), utf8);
    out.push(b' ');
    text(out, raw_header(part.headers(), "Content-ID").as_deref(), utf8);
    out.push(b' ');
    text(out, part.content_description(), utf8);
    out.push(b' ');
    let encoding = part.content_transfer_encoding().map(str::to_ascii_lowercase);
    text(out, Some(encoding.as_deref().unwrap_or("7bit")), utf8);
    let body = part.raw_body();
    out.extend_from_slice(format!(" {}", body.len()).as_bytes());
    if let Some(nested) = nested {
        out.push(b' ');
        envelope(out, nested, utf8);
        out.push(b' ');
        part_structure(out, nested.root_part(), extended, utf8, depth + 1);
        out.extend_from_slice(format!(" {}", line_count(body)).as_bytes());
    } else if kind == "text" {
        out.extend_from_slice(format!(" {}", line_count(body)).as_bytes());
    }
    if extended {
        out.push(b' ');
        text(out, raw_header(part.headers(), "Content-MD5").as_deref(), utf8);
        extension_tail(out, &part, utf8);
    }
    out.push(b')');
}

/// `BODYSTRUCTURE` (`extended`) or `BODY` of a message.
pub(crate) fn body_structure(out: &mut Vec<u8>, message: &Message<'_>, extended: bool, utf8: bool) {
    part_structure(out, message.root().root_part(), extended, utf8, 0);
}

/// Where section numbers lead: a message (the whole one, or one in a `message/rfc822` part) or a part.
#[derive(Clone, Copy)]
enum Node<'m> {
    Message(MessageRef<'m>),
    Part(MessagePart<'m>),
}

/// Follows part numbers (RFC 9051, 6.4.5): in a multipart the n-th child; in a message its body's parts, or – for a
/// body of one part – that part as number 1.
fn walk<'m>(message: MessageRef<'m>, numbers: &[u32]) -> Option<Node<'m>> {
    let mut node = Node::Message(message);
    for &number in numbers {
        let index = usize::try_from(number).ok()?.checked_sub(1)?;
        let parent = match node {
            Node::Message(message) => message.root_part(),
            Node::Part(part) => match part.nested() {
                Some(nested) => nested.root_part(),
                None if part.is_multipart() => part,
                None => return None,
            },
        };
        node = Node::Part(if parent.is_multipart() {
            parent.children().nth(index)?
        } else if index == 0 {
            parent
        } else {
            return None;
        });
    }
    Some(node)
}

/// The message a node stands for, if it is one.
fn as_message(node: Node<'_>) -> Option<MessageRef<'_>> {
    match node {
        Node::Message(message) => Some(message),
        Node::Part(part) => part.nested(),
    }
}

/// The header block split into fields, each with its continuation lines and line break; the blank line is left out.
fn fields(block: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut position = 0;
    while position < block.len() {
        let end = block[position..].iter().position(|&b| b == b'\n').map_or(block.len(), |i| position + i + 1);
        let line = &block[position..end];
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if position > start && !matches!(line.first(), Some(b' ' | b'\t')) {
            fields.push(&block[start..position]);
            start = position;
        }
        position = end;
    }
    if position > start {
        fields.push(&block[start..position]);
    }
    fields
}

/// The fields of a header block named (or, with `not`, not named) in `names`, and the blank line.
fn header_fields(block: &[u8], names: &[String], not: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields(block) {
        let name = field.split(|&b| b == b':').next().unwrap_or_default().trim_ascii();
        let named = names.iter().any(|wanted| wanted.as_bytes().eq_ignore_ascii_case(name));
        if named != not {
            out.extend_from_slice(field);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The text of a message: its body. The top message's runs to the end of what was stored.
fn message_text<'m>(raw: &'m [u8], message: MessageRef<'m>) -> &'m [u8] {
    let root = message.root_part();
    if message.container().is_none() {
        raw.get(root.offset_body() as usize..).unwrap_or_default()
    } else {
        root.raw_body()
    }
}

/// `BODY[section]`; `None` if the message has no such part.
pub(crate) fn section<'m>(message: &'m Message<'_>, section: &Section) -> Option<Cow<'m, [u8]>> {
    let raw = message.raw();
    let node = walk(message.root(), &section.part)?;
    Some(Cow::Borrowed(match (&section.text, node) {
        (None, Node::Message(_)) => raw,
        (None, Node::Part(part)) => part.raw_body(),
        (Some(SectionText::Mime), Node::Part(part)) => part.raw_headers(),
        (Some(SectionText::Mime), Node::Message(_)) => return None,
        (Some(SectionText::Header), node) => as_message(node)?.root_part().raw_headers(),
        (Some(SectionText::Text), node) => message_text(raw, as_message(node)?),
        (Some(SectionText::Fields { not, names }), node) => {
            let block = as_message(node)?.root_part().raw_headers();
            return Some(Cow::Owned(header_fields(block, names, *not)));
        }
    }))
}

/// `BINARY[part]` (RFC 3516): the content without its transfer encoding; `Ok(None)` if there is no such part,
/// `Err` if its transfer encoding is unknown.
pub(crate) fn binary<'m>(message: &'m Message<'_>, part: &[u32]) -> Result<Option<Cow<'m, [u8]>>, ()> {
    if part.is_empty() {
        return Ok(Some(Cow::Borrowed(message.raw())));
    }
    match walk(message.root(), part) {
        Some(Node::Part(part)) if part.is_multipart() || part.is_message() => Ok(Some(Cow::Borrowed(part.raw_body()))),
        Some(Node::Part(part)) if !part.has_known_transfer_encoding() => Err(()),
        Some(Node::Part(part)) => Ok(Some(part.decoded())),
        Some(Node::Message(_)) | None => Ok(None),
    }
}

/// `<start.length>` of content.
pub(crate) fn partial(content: &[u8], range: Option<(u32, u32)>) -> &[u8] {
    match range {
        Some((start, length)) => {
            let start = (start as usize).min(content.len());
            let end = start.saturating_add(length as usize).min(content.len());
            &content[start..end]
        }
        None => content,
    }
}

#[cfg(test)]
mod tests {
    use mail_parser::MessageParser;

    use super::*;

    const MESSAGE: &str = "From: =?UTF-8?Q?J=C3=BCrgen?= <juergen@remote.example>\r\n\
To: Team: anna@firma.example, \"Doe, John\" <john@firma.example>;, alice@firma.example\r\n\
Subject: Gr=?UTF-8?Q?=C3=BC=C3=9Fe?=\r\n\
Date: Sat, 24 Oct 2026 08:30:00\r\n +0200\r\n\
Message-ID: <multi@remote.example>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Gr=C3=BC=C3=9Fe!\r\n\
Zweite Zeile\r\n\
--inner\r\n\
Content-Type: text/html\r\n\
Content-Language: de, en\r\n\
\r\n\
<p>Hallo</p>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"report.pdf\"\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-ID: <pdf@remote.example>\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--outer\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
From: inner@remote.example\r\n\
Subject: Inner\r\n\
\r\n\
Inner body\r\n\
--outer\r\n\
Content-Type: application/x-odd\r\n\
Content-Transfer-Encoding: x-unknown\r\n\
\r\n\
odd\r\n\
--outer--\r\n";

    fn written(write: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut out = Vec::new();
        write(&mut out);
        String::from_utf8(out).unwrap()
    }

    fn section_of(message: &Message<'_>, part: &[u32], text: Option<SectionText>) -> Option<String> {
        let section = Section { part: part.to_vec(), text };
        super::section(message, &section).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn envelopes() {
        let message = MessageParser::new().parse(MESSAGE.as_bytes()).unwrap();
        assert_eq!(
            written(|out| envelope(out, message.root(), false)),
            "(\"Sat, 24 Oct 2026 08:30:00 +0200\" \"=?utf-8?B?R3LDvMOfZQ==?=\" \
             ((\"=?utf-8?B?SsO8cmdlbg==?=\" NIL \"juergen\" \"remote.example\")) \
             ((\"=?utf-8?B?SsO8cmdlbg==?=\" NIL \"juergen\" \"remote.example\")) \
             ((\"=?utf-8?B?SsO8cmdlbg==?=\" NIL \"juergen\" \"remote.example\")) \
             ((NIL NIL \"Team\" NIL)(NIL NIL \"anna\" \"firma.example\")(\"Doe, John\" NIL \"john\" \"firma.example\")\
             (NIL NIL NIL NIL)(NIL NIL \"alice\" \"firma.example\")) NIL NIL NIL \"<multi@remote.example>\")"
        );
        let utf8 = written(|out| envelope(out, message.root(), true));
        assert!(utf8.contains("\"Grüße\" ((\"Jürgen\" NIL"), "{utf8}");
    }

    #[test]
    fn structures() {
        let message = MessageParser::new().parse(MESSAGE.as_bytes()).unwrap();
        assert_eq!(
            written(|out| body_structure(out, &message, false, false)),
            "(((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"quoted-printable\" 30 1)\
             (\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 12 0) \"alternative\")\
             (\"application\" \"pdf\" (\"name\" \"report.pdf\") \"<pdf@remote.example>\" NIL \"base64\" 12)\
             (\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 56 (NIL \"Inner\" ((NIL NIL \"inner\" \"remote.example\")) \
             ((NIL NIL \"inner\" \"remote.example\")) ((NIL NIL \"inner\" \"remote.example\")) NIL NIL NIL NIL NIL) \
             (\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 10 0) 3)\
             (\"application\" \"x-odd\" NIL NIL NIL \"x-unknown\" 3) \"mixed\")"
        );
        let extended = written(|out| body_structure(out, &message, true, false));
        assert!(
            extended.contains(
                "\"7bit\" 12 0 NIL NIL (\"de\" \"en\") NIL) \"alternative\" (\"boundary\" \"inner\") NIL NIL NIL)"
            ),
            "{extended}"
        );
        assert!(
            extended.contains("\"base64\" 12 NIL (\"attachment\" (\"filename\" \"report.pdf\")) NIL NIL)"),
            "{extended}"
        );
        assert!(extended.ends_with("\"mixed\" (\"boundary\" \"outer\") NIL NIL NIL)"), "{extended}");
        let single = MessageParser::new().parse(b"Subject: x\r\n\r\nHello\r\nAlice\r\n".as_slice()).unwrap();
        assert_eq!(
            written(|out| body_structure(out, &single, false, false)),
            "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 14 2)"
        );
    }

    #[test]
    fn sections() {
        let message = MessageParser::new().parse(MESSAGE.as_bytes()).unwrap();
        assert_eq!(section_of(&message, &[], None).unwrap(), MESSAGE);
        assert_eq!(section_of(&message, &[1, 1], None).unwrap(), "Gr=C3=BC=C3=9Fe!\r\nZweite Zeile");
        assert_eq!(
            section_of(&message, &[1, 2], Some(SectionText::Mime)).unwrap(),
            "Content-Type: text/html\r\nContent-Language: de, en\r\n\r\n"
        );
        assert_eq!(section_of(&message, &[3], Some(SectionText::Text)).unwrap(), "Inner body");
        assert_eq!(section_of(&message, &[3, 1], None).unwrap(), "Inner body");
        assert_eq!(
            section_of(&message, &[3], Some(SectionText::Header)).unwrap(),
            "From: inner@remote.example\r\nSubject: Inner\r\n\r\n"
        );
        assert_eq!(
            section_of(
                &message,
                &[],
                Some(SectionText::Fields { not: false, names: vec!["subject".into(), "DATE".into()] })
            )
            .unwrap(),
            "Subject: Gr=?UTF-8?Q?=C3=BC=C3=9Fe?=\r\nDate: Sat, 24 Oct 2026 08:30:00\r\n +0200\r\n\r\n"
        );
        let not = section_of(&message, &[], Some(SectionText::Fields { not: true, names: vec!["To".into()] })).unwrap();
        assert!(not.starts_with("From: ") && !not.contains("To:") && not.ends_with("\"outer\"\r\n\r\n"), "{not}");
        assert!(section_of(&message, &[], Some(SectionText::Text)).unwrap().starts_with("--outer\r\n"));
        assert_eq!(section_of(&message, &[9], None), None);
        assert_eq!(section_of(&message, &[2, 1], None), None);
        assert_eq!(section_of(&message, &[], Some(SectionText::Mime)), None);
        assert_eq!(section_of(&message, &[2], Some(SectionText::Header)), None);
        let single = MessageParser::new().parse(b"Subject: x\r\n\r\nHello\r\n".as_slice()).unwrap();
        assert_eq!(section_of(&single, &[1], None).unwrap(), "Hello\r\n");
        assert_eq!(section_of(&single, &[2], None), None);
    }

    #[test]
    fn binaries() {
        let message = MessageParser::new().parse(MESSAGE.as_bytes()).unwrap();
        assert_eq!(binary(&message, &[2]).unwrap().unwrap().as_ref(), b"%PDF-1.4\n");
        assert_eq!(binary(&message, &[1, 1]).unwrap().unwrap().as_ref(), "Grüße!\r\nZweite Zeile".as_bytes());
        assert_eq!(binary(&message, &[4]), Err(()));
        assert_eq!(binary(&message, &[7]), Ok(None));
        assert_eq!(partial(b"0123456789", Some((2, 3))), b"234");
        assert_eq!(partial(b"0123456789", Some((8, 30))), b"89");
        assert_eq!(partial(b"0123456789", Some((80, 3))), b"");
    }

    #[test]
    fn broken_messages_do_not_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..300 {
            let mut bytes = MESSAGE.as_bytes().to_vec();
            for _ in 0..(random() % 12) {
                let position = (random() as usize) % bytes.len();
                bytes[position] = b"\r\n-:;\"=(){}<>@ ax"[(random() % 17) as usize];
            }
            let Some(message) = MessageParser::new().parse(bytes.as_slice()) else { continue };
            let mut out = Vec::new();
            body_structure(&mut out, &message, true, random() % 2 == 0);
            envelope(&mut out, message.root(), false);
            for part in [&[][..], &[1], &[1, 2], &[3, 1], &[4, 1, 1]] {
                for text in [None, Some(SectionText::Header), Some(SectionText::Text), Some(SectionText::Mime)] {
                    let _ = section(&message, &Section { part: part.to_vec(), text });
                }
                let _ = binary(&message, part);
            }
        }
        // Deeply nested messages.
        let mut deep = String::from("Subject: x\r\n\r\nend\r\n");
        for _ in 0..200 {
            deep = format!("Content-Type: message/rfc822\r\n\r\n{deep}");
        }
        let message = MessageParser::new().parse(deep.as_bytes()).unwrap();
        let mut out = Vec::new();
        body_structure(&mut out, &message, true, false);
    }
}
