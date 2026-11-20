// SPDX-License-Identifier: MIT
//! Messages (RFC 5322) and their MIME structure (RFC 2045, RFC 2046): every part with the byte ranges of its header
//! and body in the raw message, so that IMAP can serve sections and JMAP blobs exactly as they were received.
//!
//! The body of a part inside a multipart ends before the line break that precedes the next delimiter (RFC 2046,
//! 5.1.1: that line break belongs to the delimiter); the body of a message's top part, and of a nested message's,
//! runs to the end of what holds it. Parts are numbered as [`MessageRef::parts`] lists them: the top part first, then
//! every part in document order, containers before what they contain – the parts of nested messages not counted.
//!
//! Real mail is read as far as it goes: a multipart without its closing delimiter ends where its container ends, a
//! header without an empty line after it is all header, bare line feeds stand for CRLF, junk lines in a header are
//! skipped, and nesting deeper than [`MAX_DEPTH`] is kept as one part.

use std::borrow::Cow;

use crate::{
    address::AddressList,
    body, charset,
    date::DateTime,
    header::{self, Header, Headers, Span},
    params::{self, ContentType},
    subject,
    transfer::Encoding,
};

/// How deep multiparts and nested messages are read; deeper ones are one part.
pub const MAX_DEPTH: usize = 64;

/// What a part is, for what is done with its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `text/*` but HTML, and a part without a content type.
    Text,
    /// `text/html`.
    Html,
    /// Anything else, as an attachment …
    Binary,
    /// … or with the disposition `inline`.
    InlineBinary,
    /// A nested message (`message/rfc822`, `message/global`).
    Message,
    Multipart,
}

#[derive(Debug, Clone)]
enum Shape {
    Leaf,
    Multipart(Vec<usize>),
    /// The top part of the nested message.
    Message(usize),
}

#[derive(Debug, Clone)]
struct PartData {
    start: usize,
    body_start: usize,
    end: usize,
    fields: Vec<Span>,
    content_type: Option<ContentType>,
    /// `type/subtype` in lower case, the default where the part has none.
    media_type: String,
    disposition: Option<ContentType>,
    encoding: Encoding,
    shape: Shape,
    /// The top part of the message this part belongs to.
    root: usize,
    /// For a message's top part: the part holding the message (`None` for the outermost).
    container: Option<usize>,
}

/// A parsed message: the raw bytes and its parts.
#[derive(Debug, Clone)]
pub struct Message<'a> {
    raw: &'a [u8],
    parts: Vec<PartData>,
}

struct Parser<'a> {
    raw: &'a [u8],
    parts: Vec<PartData>,
}

/// The line break before `line`, if it is within `start..line`: where content before a delimiter ends.
fn before_break(raw: &[u8], start: usize, line: usize) -> usize {
    let mut end = line;
    if end > start && raw[end - 1] == b'\n' {
        end -= 1;
        if end > start && raw[end - 1] == b'\r' {
            end -= 1;
        }
    }
    end
}

/// The ranges of a multipart's body parts between `start` and `end`.
fn split(raw: &[u8], start: usize, end: usize, boundary: &[u8]) -> Vec<(usize, usize)> {
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;
    let mut line = start;
    while line < end {
        let line_end = raw[line..end].iter().position(|&b| b == b'\n').map_or(end, |i| line + i + 1);
        let text = &raw[line..line_end];
        if let Some(rest) = text.strip_prefix(b"--").and_then(|rest| rest.strip_prefix(boundary)) {
            let close = rest.starts_with(b"--");
            if close || rest.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) {
                if let Some(part) = current.take() {
                    parts.push((part, before_break(raw, part, line).max(part)));
                }
                if close {
                    return parts;
                }
                current = Some(line_end);
            }
        }
        line = line_end;
    }
    if let Some(part) = current {
        parts.push((part, end));
    }
    parts
}

impl Parser<'_> {
    fn field<'f>(&self, fields: &'f [Span], name: &str) -> Option<&'f Span> {
        fields.iter().find(|span| self.raw[span.name.0..span.name.1].eq_ignore_ascii_case(name.as_bytes()))
    }

    fn value(&self, span: &Span) -> Cow<'_, str> {
        header::text_of(&self.raw[span.value.0..span.value.1])
    }

    /// Reads the entity between `start` and `end`; returns its index.
    fn entity(
        &mut self,
        start: usize,
        end: usize,
        depth: usize,
        in_digest: bool,
        root: Option<usize>,
        container: Option<usize>,
    ) -> usize {
        let (fields, body_start) = header::read(self.raw, start, end);
        let content_type = self.field(&fields, "content-type").and_then(|span| params::parse(&self.value(span), true));
        let disposition =
            self.field(&fields, "content-disposition").and_then(|span| params::parse(&self.value(span), false));
        let encoding =
            Encoding::parse(self.field(&fields, "content-transfer-encoding").map(|s| self.value(s)).as_deref());
        let media_type = match &content_type {
            Some(content_type) if content_type.subtype().is_some() => content_type.media_type(),
            _ if in_digest => "message/rfc822".to_owned(),
            _ => "text/plain".to_owned(),
        };
        let index = self.parts.len();
        self.parts.push(PartData {
            start,
            body_start,
            end,
            fields,
            content_type,
            media_type,
            disposition,
            encoding,
            shape: Shape::Leaf,
            root: root.unwrap_or(index),
            container,
        });
        let root = root.unwrap_or(index);
        if depth >= MAX_DEPTH {
            return index;
        }
        let media_type = self.parts[index].media_type.clone();
        if let Some(subtype) = media_type.strip_prefix("multipart/") {
            let boundary = self.parts[index]
                .content_type
                .as_ref()
                .and_then(|content_type| content_type.attribute("boundary"))
                .map(|boundary| boundary.as_bytes().to_vec())
                .filter(|boundary| !boundary.is_empty());
            let mut children = Vec::new();
            if let Some(boundary) = boundary {
                for (part_start, part_end) in split(self.raw, body_start, end, &boundary) {
                    children.push(self.entity(part_start, part_end, depth + 1, subtype == "digest", Some(root), None));
                }
            }
            self.parts[index].shape = Shape::Multipart(children);
        } else if matches!(media_type.as_str(), "message/rfc822" | "message/global") && encoding.is_identity() {
            let nested = self.entity(body_start, end, depth + 1, false, None, Some(index));
            self.parts[index].shape = Shape::Message(nested);
        }
        index
    }
}

impl<'a> Message<'a> {
    /// Reads a message; `None` if it has no header field at all – then it is no message.
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        let mut parser = Parser { raw, parts: Vec::new() };
        parser.entity(0, raw.len(), 0, false, None, None);
        let message = Message { raw, parts: parser.parts };
        (!message.parts[0].fields.is_empty()).then_some(message)
    }

    /// Reads only the header of a message (its body stays one part); `None` without a header field.
    pub fn parse_headers(raw: &'a [u8]) -> Option<Self> {
        let (fields, body_start) = header::read(raw, 0, raw.len());
        if fields.is_empty() {
            return None;
        }
        let part = PartData {
            start: 0,
            body_start,
            end: raw.len(),
            fields,
            content_type: None,
            media_type: "text/plain".into(),
            disposition: None,
            encoding: Encoding::SevenBit,
            shape: Shape::Leaf,
            root: 0,
            container: None,
        };
        Some(Message { raw, parts: vec![part] })
    }

    /// The message as it was read.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The message itself (as opposed to messages nested in it).
    pub fn root(&self) -> MessageRef<'_> {
        MessageRef { message: self, root: 0 }
    }

    /// Every part, those of nested messages included, in document order.
    pub fn all_parts(&self) -> impl Iterator<Item = PartRef<'_>> {
        (0..self.parts.len()).map(move |index| PartRef { message: self, index })
    }

    /// The part with this [`PartRef::id`].
    pub fn part(&self, id: usize) -> Option<PartRef<'_>> {
        (id < self.parts.len()).then_some(PartRef { message: self, index: id })
    }

    pub fn headers(&self) -> Headers<'_> {
        self.root().headers()
    }

    pub fn subject(&self) -> Option<String> {
        self.root().subject()
    }

    pub fn from(&self) -> Option<AddressList> {
        self.root().from()
    }

    pub fn to(&self) -> Option<AddressList> {
        self.root().to()
    }

    pub fn cc(&self) -> Option<AddressList> {
        self.root().cc()
    }

    pub fn bcc(&self) -> Option<AddressList> {
        self.root().bcc()
    }

    pub fn reply_to(&self) -> Option<AddressList> {
        self.root().reply_to()
    }

    pub fn sender(&self) -> Option<AddressList> {
        self.root().sender()
    }

    pub fn date(&self) -> Option<DateTime> {
        self.root().date()
    }

    pub fn message_id(&self) -> Option<String> {
        self.root().message_id()
    }

    pub fn in_reply_to(&self) -> Vec<String> {
        self.root().in_reply_to()
    }

    pub fn references(&self) -> Vec<String> {
        self.root().references()
    }
}

/// A message: the outermost one or one nested in a part.
#[derive(Debug, Clone, Copy)]
pub struct MessageRef<'m> {
    message: &'m Message<'m>,
    root: usize,
}

impl<'m> MessageRef<'m> {
    /// The message's top part: its header and body.
    pub fn root_part(&self) -> PartRef<'m> {
        PartRef { message: self.message, index: self.root }
    }

    /// The part holding this message, unless it is the outermost.
    pub fn container(&self) -> Option<PartRef<'m>> {
        self.message.parts[self.root].container.map(|index| PartRef { message: self.message, index })
    }

    pub fn headers(&self) -> Headers<'m> {
        self.root_part().headers()
    }

    /// The first field called `name`.
    pub fn header(&self, name: &str) -> Option<Header<'m>> {
        self.headers().get(name)
    }

    pub fn subject(&self) -> Option<String> {
        self.header("Subject").map(|header| header.text())
    }

    /// The addresses of every field called `name`; `None` without one.
    pub fn addresses(&self, name: &str) -> Option<AddressList> {
        let mut fields = self.headers().all(name).peekable();
        fields.peek()?;
        Some(AddressList(fields.flat_map(|field| field.addresses().0).collect()))
    }

    pub fn from(&self) -> Option<AddressList> {
        self.addresses("From")
    }

    pub fn sender(&self) -> Option<AddressList> {
        self.addresses("Sender")
    }

    pub fn reply_to(&self) -> Option<AddressList> {
        self.addresses("Reply-To")
    }

    pub fn to(&self) -> Option<AddressList> {
        self.addresses("To")
    }

    pub fn cc(&self) -> Option<AddressList> {
        self.addresses("Cc")
    }

    pub fn bcc(&self) -> Option<AddressList> {
        self.addresses("Bcc")
    }

    pub fn date(&self) -> Option<DateTime> {
        self.header("Date").and_then(|header| header.date())
    }

    pub fn message_id(&self) -> Option<String> {
        self.header("Message-ID").and_then(|header| header.message_ids().into_iter().next())
    }

    pub fn in_reply_to(&self) -> Vec<String> {
        self.header("In-Reply-To").map(|header| header.message_ids()).unwrap_or_default()
    }

    pub fn references(&self) -> Vec<String> {
        self.header("References").map(|header| header.message_ids()).unwrap_or_default()
    }

    pub fn resent_message_id(&self) -> Vec<String> {
        self.header("Resent-Message-ID").map(|header| header.message_ids()).unwrap_or_default()
    }

    /// The subject without `Re:`, `Fwd:` and list tags (RFC 5256, 2.1), for threads.
    pub fn base_subject(&self) -> String {
        subject::base_subject(&self.subject().unwrap_or_default())
    }

    /// The message's parts: its top part first, then every part in document order – nested messages are one part.
    pub fn parts(&self) -> impl Iterator<Item = PartRef<'m>> + 'm {
        let message = self.message;
        let mut stack = vec![self.root];
        std::iter::from_fn(move || {
            let index = stack.pop()?;
            if let Shape::Multipart(children) = &message.parts[index].shape {
                stack.extend(children.iter().rev());
            }
            Some(PartRef { message, index })
        })
    }

    /// The parts to show as text (RFC 8621, 4.1.4).
    pub fn text_body(&self) -> Vec<PartRef<'m>> {
        self.bodies().0
    }

    /// The parts to show as HTML (RFC 8621, 4.1.4).
    pub fn html_body(&self) -> Vec<PartRef<'m>> {
        self.bodies().1
    }

    /// The attachments (RFC 8621, 4.1.4).
    pub fn attachments(&self) -> Vec<PartRef<'m>> {
        self.bodies().2
    }

    pub fn has_attachments(&self) -> bool {
        !self.attachments().is_empty()
    }

    /// The text, HTML and attachment parts.
    #[allow(clippy::type_complexity)]
    pub fn bodies(&self) -> (Vec<PartRef<'m>>, Vec<PartRef<'m>>, Vec<PartRef<'m>>) {
        let (text, html, attachments) = body::structure(*self);
        let refs = |list: Vec<usize>| list.into_iter().map(|index| PartRef { message: self.message, index }).collect();
        (refs(text), refs(html), refs(attachments))
    }

    /// The text of text body `index`, HTML turned into text.
    pub fn body_text(&self, index: usize) -> Option<String> {
        let part = *self.text_body().get(index)?;
        let text = part.text()?;
        Some(if part.kind() == Kind::Html { body::html_to_text(&text) } else { text.into_owned() })
    }

    /// The HTML of HTML body `index`, if it is HTML.
    pub fn body_html(&self, index: usize) -> Option<String> {
        let part = *self.html_body().get(index)?;
        (part.kind() == Kind::Html).then(|| part.text().map(Cow::into_owned)).flatten()
    }

    /// The first `length` characters of the first text body, HTML turned into text.
    pub fn body_preview(&self, length: usize) -> Option<String> {
        self.body_text(0).map(|text| text.chars().take(length).collect())
    }

    pub(crate) fn message(&self) -> &'m Message<'m> {
        self.message
    }

    pub(crate) fn root_index(&self) -> usize {
        self.root
    }
}

/// A part of a message.
#[derive(Debug, Clone, Copy)]
pub struct PartRef<'m> {
    message: &'m Message<'m>,
    index: usize,
}

impl<'m> PartRef<'m> {
    fn data(&self) -> &'m PartData {
        &self.message.parts[self.index]
    }

    /// The part's place among all parts of the message read ([`Message::part`]).
    pub fn id(&self) -> usize {
        self.index
    }

    pub fn headers(&self) -> Headers<'m> {
        Headers::new(self.message.raw, &self.data().fields)
    }

    fn header(&self, name: &str) -> Option<Header<'m>> {
        self.headers().get(name)
    }

    /// Where the part's header starts in the raw message.
    pub fn offset_header(&self) -> usize {
        self.data().start
    }

    /// Where its body starts.
    pub fn offset_body(&self) -> usize {
        self.data().body_start
    }

    /// Where it ends.
    pub fn offset_end(&self) -> usize {
        self.data().end
    }

    /// The header as written, with the empty line after it.
    pub fn raw_headers(&self) -> &'m [u8] {
        &self.message.raw[self.data().start..self.data().body_start]
    }

    /// The body as written.
    pub fn raw_body(&self) -> &'m [u8] {
        &self.message.raw[self.data().body_start..self.data().end]
    }

    /// The content type as written; `None` without one (or one that has no type).
    pub fn content_type(&self) -> Option<&'m ContentType> {
        self.data().content_type.as_ref()
    }

    /// `type/subtype` in lower case: the content type, or the default (`text/plain`, `message/rfc822` in a digest).
    pub fn media_type(&self) -> &'m str {
        &self.data().media_type
    }

    pub fn content_disposition(&self) -> Option<&'m ContentType> {
        self.data().disposition.as_ref()
    }

    /// `Content-ID` without angle brackets.
    pub fn content_id(&self) -> Option<String> {
        let header = self.header("Content-ID")?;
        header.message_ids().into_iter().next().or_else(|| Some(header.unfolded()).filter(|id| !id.is_empty()))
    }

    pub fn content_description(&self) -> Option<String> {
        self.header("Content-Description").map(|header| header.text())
    }

    pub fn content_location(&self) -> Option<String> {
        self.header("Content-Location").map(|header| header.text()).filter(|location| !location.is_empty())
    }

    pub fn content_language(&self) -> Vec<String> {
        self.header("Content-Language").map(|header| header.list()).unwrap_or_default()
    }

    /// `Content-Transfer-Encoding` as written, unfolded.
    pub fn content_transfer_encoding(&self) -> Option<String> {
        self.header("Content-Transfer-Encoding").map(|header| header.unfolded())
    }

    pub fn encoding(&self) -> Encoding {
        self.data().encoding
    }

    pub fn has_known_transfer_encoding(&self) -> bool {
        self.data().encoding != Encoding::Unknown
    }

    /// The file name: the disposition's `filename`, else the content type's `name`.
    pub fn attachment_name(&self) -> Option<&'m str> {
        self.content_disposition()
            .and_then(|disposition| disposition.attribute("filename"))
            .or_else(|| self.content_type().and_then(|content_type| content_type.attribute("name")))
            .filter(|name| !name.is_empty())
    }

    pub fn is_multipart(&self) -> bool {
        matches!(self.data().shape, Shape::Multipart(_))
    }

    pub fn is_message(&self) -> bool {
        matches!(self.data().shape, Shape::Message(_))
    }

    /// The parts of a multipart.
    pub fn children(&self) -> impl Iterator<Item = PartRef<'m>> + 'm {
        let message = self.message;
        let children: &'m [usize] = match &self.data().shape {
            Shape::Multipart(children) => children,
            _ => &[],
        };
        children.iter().map(move |&index| PartRef { message, index })
    }

    /// The message in a `message/rfc822` part.
    pub fn nested(&self) -> Option<MessageRef<'m>> {
        match self.data().shape {
            Shape::Message(root) => Some(MessageRef { message: self.message, root }),
            _ => None,
        }
    }

    /// The message this part belongs to.
    pub fn message(&self) -> MessageRef<'m> {
        MessageRef { message: self.message, root: self.data().root }
    }

    pub fn kind(&self) -> Kind {
        let data = self.data();
        match data.shape {
            Shape::Multipart(_) => Kind::Multipart,
            Shape::Message(_) => Kind::Message,
            Shape::Leaf if data.media_type == "text/html" => Kind::Html,
            Shape::Leaf if data.media_type.starts_with("text/") => Kind::Text,
            Shape::Leaf if data.disposition.as_ref().is_some_and(|d| d.ctype().eq_ignore_ascii_case("inline")) => {
                Kind::InlineBinary
            }
            Shape::Leaf => Kind::Binary,
        }
    }

    /// Whether the part is text (or HTML).
    pub fn is_text(&self) -> bool {
        matches!(self.kind(), Kind::Text | Kind::Html)
    }

    /// The content without its transfer encoding (containers as written).
    pub fn decoded(&self) -> Cow<'m, [u8]> {
        match self.data().shape {
            Shape::Leaf => self.data().encoding.decode(self.raw_body()),
            _ => Cow::Borrowed(self.raw_body()),
        }
    }

    /// The size of [`decoded`](Self::decoded).
    pub fn decoded_len(&self) -> usize {
        self.decoded().len()
    }

    /// A text part's content as UTF-8 (`None` for other parts), and whether its charset could not read all of it.
    pub fn text_checked(&self) -> Option<(Cow<'m, str>, bool)> {
        if !self.is_text() {
            return None;
        }
        let label = self.content_type().and_then(|content_type| content_type.attribute("charset"));
        let unknown = label.is_some_and(|label| !charset::is_known(label));
        Some(match self.decoded() {
            Cow::Borrowed(bytes) => {
                let (text, errors) = charset::decode(label, bytes);
                (text, errors || unknown)
            }
            Cow::Owned(bytes) => {
                let (text, errors) = charset::decode(label, &bytes);
                (Cow::Owned(text.into_owned()), errors || unknown)
            }
        })
    }

    /// A text part's content as UTF-8.
    pub fn text(&self) -> Option<Cow<'m, str>> {
        self.text_checked().map(|(text, _)| text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &str = "From: a@x.example\r\n\
Subject: Parts\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
preamble\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\
\r\n\
--inner\r\n\
\r\n\
plain\r\n\
--inner\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>html</p>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
Subject: Inner\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\
\r\n\
--b\r\n\
\r\n\
inner text\r\n\
--b--\r\n\
--outer \r\n\
Content-Type: multipart/digest; boundary=d\r\n\
\r\n\
--d\r\n\
\r\n\
Subject: Digested\r\n\
\r\n\
one\r\n\
--d--\r\n\
--outer--\r\n\
epilogue\r\n";

    #[test]
    fn parts_and_their_ranges() {
        let message = Message::parse(MESSAGE.as_bytes()).unwrap();
        let root = message.root();
        let parts: Vec<PartRef<'_>> = root.parts().collect();
        let types: Vec<&str> = parts.iter().map(|part| part.media_type()).collect();
        assert_eq!(
            types,
            [
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "text/html",
                "message/rfc822",
                "multipart/digest",
                "message/rfc822"
            ]
        );
        assert_eq!(parts[2].raw_body(), b"plain");
        assert_eq!(parts[2].raw_headers(), b"\r\n");
        assert_eq!(parts[3].raw_body(), b"<p>html</p>");
        assert!(parts[1].raw_body().ends_with(b"--inner--"));
        let nested = parts[4].nested().unwrap();
        assert_eq!(nested.subject().as_deref(), Some("Inner"));
        assert_eq!(nested.container().unwrap().id(), parts[4].id());
        assert_eq!(nested.parts().count(), 2);
        assert_eq!(nested.parts().nth(1).unwrap().raw_body(), b"inner text");
        assert!(nested.root_part().raw_body().ends_with(b"--b--"));
        let digested = parts[6].nested().unwrap();
        assert_eq!(digested.subject().as_deref(), Some("Digested"));
        assert_eq!(digested.root_part().raw_body(), b"one");
        assert_eq!(message.all_parts().count(), 10);
        assert_eq!(root.root_part().raw_body(), &MESSAGE.as_bytes()[root.root_part().offset_body()..]);
        for part in message.all_parts() {
            assert_eq!(part.raw_body(), &MESSAGE.as_bytes()[part.offset_body()..part.offset_end()]);
            assert!(part.offset_header() <= part.offset_body());
        }
    }

    #[test]
    fn broken_structures() {
        // No closing delimiter; bare line feeds.
        let raw = b"Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\none\n--x\n\ntwo\n";
        let message = Message::parse(raw).unwrap();
        let bodies: Vec<&[u8]> = message.root().parts().skip(1).map(|p| p.raw_body()).collect();
        assert_eq!(bodies, [&b"one"[..], b"two\n"]);
        // No boundary, no delimiter.
        let message = Message::parse(b"Content-Type: multipart/mixed\r\n\r\ntext").unwrap();
        assert!(message.root().root_part().is_multipart());
        assert_eq!(message.root().parts().count(), 1);
        let message = Message::parse(b"Content-Type: multipart/mixed; boundary=q\r\n\r\ntext").unwrap();
        assert_eq!(message.root().parts().count(), 1);
        // A boundary that is a prefix of another.
        let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\n--bb\r\n--b--\r\n";
        let message = Message::parse(raw).unwrap();
        assert_eq!(message.root().parts().nth(1).unwrap().raw_body(), b"--bb");
        // No header at all.
        assert!(Message::parse(b"").is_none());
        assert!(Message::parse(b"not a message at all\r\n").is_none());
        assert!(Message::parse(b"\r\nbody").is_none());
        // Header only.
        let message = Message::parse(b"Subject: x").unwrap();
        assert_eq!(message.root().root_part().raw_body(), b"");
    }

    #[test]
    fn decoding_and_kinds() {
        let raw = "Subject: x\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nGr=FC=DFe\r\n\
--b\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: base64\r\n\
Content-ID: <logo@x>\r\n\r\niVBORw0KGgo=\r\n\
--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Transfer-Encoding: x-weird\r\n\r\nraw\r\n\
--b\r\nContent-Type: text/plain; charset=x-nothing\r\n\r\n#\r\n--b--\r\n";
        let raw: Vec<u8> = raw.bytes().map(|b| if b == b'#' { 0xfc } else { b }).collect();
        let message = Message::parse(&raw).unwrap();
        let parts: Vec<PartRef<'_>> = message.root().parts().collect();
        assert_eq!(parts[1].text().as_deref(), Some("Grüße"));
        assert_eq!(parts[1].kind(), Kind::Text);
        assert_eq!(parts[2].kind(), Kind::InlineBinary);
        assert_eq!(parts[2].decoded().as_ref(), b"\x89PNG\r\n\x1a\n");
        assert_eq!(parts[2].content_id().as_deref(), Some("logo@x"));
        assert_eq!(parts[3].kind(), Kind::Binary);
        assert!(!parts[3].has_known_transfer_encoding());
        assert_eq!(parts[3].decoded().as_ref(), b"raw");
        assert_eq!(parts[3].attachment_name(), Some("a.pdf"));
        assert_eq!(parts[4].text_checked().map(|(_, problem)| problem), Some(true));
        assert_eq!(parts[0].kind(), Kind::Multipart);
    }

    #[test]
    fn deep_nesting_is_cut() {
        let mut deep = String::from("Subject: x\r\n\r\nend\r\n");
        for _ in 0..500 {
            deep = format!("Content-Type: message/rfc822\r\n\r\n{deep}");
        }
        let message = Message::parse(deep.as_bytes()).unwrap();
        assert_eq!(message.all_parts().count(), MAX_DEPTH + 1);
        let mut deep = String::from("x");
        for level in 0..500 {
            deep = format!(
                "Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n--b{level}\r\n{deep}\r\n--b{level}--\r\n"
            );
        }
        let message = Message::parse(deep.as_bytes()).unwrap();
        assert_eq!(message.all_parts().count(), MAX_DEPTH + 1);
    }
}
