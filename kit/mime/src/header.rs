// SPDX-License-Identifier: MIT
//! Header fields (RFC 5322, 2.2 and 3.6): a header section cut into fields with their byte ranges, and each field's
//! value read in the forms mail needs – unstructured text, addresses, message ids, a date, URLs, a list.

use std::borrow::Cow;

use crate::{address, charset, date, words};

/// Where a field lies in the message: its name, and its value from after the colon up to and with its line break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    pub name: (usize, usize),
    pub value: (usize, usize),
}

fn is_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&b| (33..=126).contains(&b) && b != b':')
}

/// The fields of the header section starting at `start`, and where the body starts: after the empty line, or at
/// `end` without one. Lines that are no field (no colon, no name) are skipped, as are continuation lines without a
/// field before them.
pub(crate) fn read(raw: &[u8], start: usize, end: usize) -> (Vec<Span>, usize) {
    let mut fields: Vec<Span> = Vec::new();
    let mut open = false;
    let mut position = start;
    while position < end {
        let line_end = raw[position..end].iter().position(|&b| b == b'\n').map_or(end, |i| position + i + 1);
        let line = &raw[position..line_end];
        if line == b"\r\n" || line == b"\n" || line == b"\r" {
            return (fields, line_end);
        }
        if matches!(line[0], b' ' | b'\t') {
            if open {
                fields.last_mut().expect("an open field").value.1 = line_end;
            }
        } else {
            open = false;
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let name = line[..colon].trim_ascii_end();
                if is_name(name) {
                    fields.push(Span {
                        name: (position, position + name.len()),
                        value: (position + colon + 1, line_end),
                    });
                    open = true;
                }
            }
        }
        position = line_end;
    }
    (fields, end)
}

/// Bytes of a header as text: UTF-8 (RFC 6532), or Windows-1252 where it is not.
pub(crate) fn text_of(bytes: &[u8]) -> Cow<'_, str> {
    charset::decode(None, bytes).0
}

/// A value unfolded (line breaks out, the white space after them kept) and trimmed.
pub fn unfold(value: &str) -> String {
    let unfolded: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    unfolded.trim().to_owned()
}

/// One header field.
#[derive(Debug, Clone, Copy)]
pub struct Header<'m> {
    name: &'m [u8],
    value: &'m [u8],
}

impl<'m> Header<'m> {
    pub(crate) fn new(raw: &'m [u8], span: Span) -> Self {
        Self { name: &raw[span.name.0..span.name.1], value: &raw[span.value.0..span.value.1] }
    }

    /// The name as written.
    pub fn name(&self) -> &'m str {
        std::str::from_utf8(self.name).unwrap_or_default()
    }

    /// Whether the field is called `name` (any case).
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }

    /// The value as written: from after the colon, with its line breaks and the last one.
    pub fn raw_value(&self) -> &'m [u8] {
        self.value
    }

    /// The value unfolded and trimmed, without decoding.
    pub fn unfolded(&self) -> String {
        unfold(&text_of(self.value))
    }

    /// The value as unstructured text (RFC 5322, 3.2.5): unfolded, encoded words decoded, trimmed.
    pub fn text(&self) -> String {
        words::decode(&self.unfolded()).trim().to_owned()
    }

    /// The value as an address list.
    pub fn addresses(&self) -> address::AddressList {
        address::parse(&text_of(self.value))
    }

    /// The value as a date.
    pub fn date(&self) -> Option<date::DateTime> {
        date::parse(&text_of(self.value))
    }

    /// The value as message ids (RFC 5322, 3.6.4), without angle brackets.
    pub fn message_ids(&self) -> Vec<String> {
        message_ids(&text_of(self.value))
    }

    /// The value as URLs in angle brackets (RFC 2369).
    pub fn urls(&self) -> Vec<String> {
        let text = self.unfolded();
        let mut out = Vec::new();
        let mut rest = text.as_str();
        while let Some(open) = rest.find('<') {
            let Some(close) = rest[open..].find('>') else { break };
            let url: String = rest[open + 1..open + close].chars().filter(|c| !c.is_whitespace()).collect();
            if !url.is_empty() {
                out.push(url);
            }
            rest = &rest[open + close + 1..];
        }
        out
    }

    /// The value as a comma-separated list (`Keywords`, `Content-Language`): each item decoded and trimmed.
    pub fn list(&self) -> Vec<String> {
        let text = self.text();
        let mut items = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        let mut depth = 0;
        for c in text.chars() {
            match c {
                '"' if depth == 0 => quoted = !quoted,
                '(' if !quoted => depth += 1,
                ')' if !quoted && depth > 0 => depth -= 1,
                ',' if !quoted && depth == 0 => items.push(std::mem::take(&mut current)),
                c if depth == 0 => current.push(c),
                _ => {}
            }
        }
        items.push(current);
        items.into_iter().map(|item| item.trim().to_owned()).filter(|item| !item.is_empty()).collect()
    }
}

/// Message ids: those in angle brackets; without any, a value of one word is the id.
pub fn message_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    let mut depth = 0;
    let mut cleaned = String::with_capacity(text.len());
    for c in rest.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            c if depth == 0 => cleaned.push(c),
            _ => {}
        }
    }
    rest = &cleaned;
    while let Some(open) = rest.find('<') {
        let close = rest[open..].find('>').map_or(rest.len(), |close| open + close);
        let id: String = rest[open + 1..close].chars().filter(|c| !c.is_whitespace()).collect();
        if !id.is_empty() {
            out.push(id);
        }
        rest = rest.get(close + 1..).unwrap_or_default();
    }
    if out.is_empty() {
        let trimmed = cleaned.trim();
        if !trimmed.is_empty() && !trimmed.contains(char::is_whitespace) && !trimmed.contains(['<', '>']) {
            out.push(trimmed.to_owned());
        }
    }
    out
}

/// The fields of one header section.
#[derive(Debug, Clone, Copy)]
pub struct Headers<'m> {
    raw: &'m [u8],
    spans: &'m [Span],
}

impl<'m> Headers<'m> {
    pub(crate) fn new(raw: &'m [u8], spans: &'m [Span]) -> Self {
        Self { raw, spans }
    }

    pub fn iter(&self) -> impl Iterator<Item = Header<'m>> + 'm {
        let raw = self.raw;
        self.spans.iter().map(move |span| Header::new(raw, *span))
    }

    /// The first field called `name`.
    pub fn get(&self, name: &str) -> Option<Header<'m>> {
        self.iter().find(|header| header.is(name))
    }

    /// The last field called `name`.
    pub fn last(&self, name: &str) -> Option<Header<'m>> {
        self.iter().filter(|header| header.is(name)).last()
    }

    /// Every field called `name`, in order.
    pub fn all(&self, name: &str) -> impl Iterator<Item = Header<'m>> + 'm {
        let name = name.to_owned();
        self.iter().filter(move |header| header.is(&name))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(raw: &[u8]) -> (Vec<Span>, usize) {
        read(raw, 0, raw.len())
    }

    #[test]
    fn fields_and_their_ranges() {
        let raw = b"Subject: Hello\r\n  world\r\nX-Empty:\r\nTo : a@x\r\n\r\nBody";
        let (spans, body) = headers(raw);
        assert_eq!(body, raw.len() - 4);
        let fields: Vec<Header<'_>> = spans.iter().map(|s| Header::new(raw, *s)).collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), "Subject");
        assert_eq!(fields[0].raw_value(), b" Hello\r\n  world\r\n");
        assert_eq!(fields[0].text(), "Hello  world");
        assert_eq!(fields[1].raw_value(), b"\r\n");
        assert_eq!(fields[2].name(), "To");
        // Bare line feeds, junk lines and no body.
        let raw = b" leading continuation\nFrom alice Sat Oct 24\nSubject: x\nnot a field\n More\n";
        let (spans, body) = headers(raw);
        assert_eq!(spans.len(), 1);
        assert_eq!(body, raw.len());
        assert_eq!(Header::new(raw, spans[0]).raw_value(), b" x\n");
    }

    #[test]
    fn values_in_their_forms() {
        let raw = "Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\n and more\r\nReferences: <a@x>\r\n <b@y> (old)\r\n\
                   In-Reply-To: lone@id\r\nList-Post: <mailto:list@x.example>, <https://x.example/post>\r\n\
                   Keywords: one, \"two, three\", four\r\nX-Latin: Gr\u{fc}\u{df}e\r\n\r\n";
        let mut raw = raw.as_bytes().to_vec();
        // Latin-1 bytes in a header.
        let at = raw.windows(4).position(|w| w == "Gr\u{fc}".as_bytes()).unwrap();
        raw.splice(at..at + 7, b"Gr\xfc\xdfe".iter().copied());
        let (spans, _) = headers(&raw);
        let all = Headers::new(&raw, &spans);
        assert_eq!(all.get("subject").unwrap().text(), "Grüße and more");
        assert_eq!(all.get("references").unwrap().message_ids(), ["a@x", "b@y"]);
        assert_eq!(all.get("in-reply-to").unwrap().message_ids(), ["lone@id"]);
        assert_eq!(all.get("list-post").unwrap().urls(), ["mailto:list@x.example", "https://x.example/post"]);
        assert_eq!(all.get("keywords").unwrap().list(), ["one", "two, three", "four"]);
        assert_eq!(all.get("x-latin").unwrap().text(), "Grüße");
        assert!(all.contains("KEYWORDS") && !all.contains("Cc"));
        assert_eq!(message_ids("Your message of Monday"), Vec::<String>::new());
    }
}
