// SPDX-License-Identifier: MIT
//! `Content-Type` (RFC 2045, 5.1) and `Content-Disposition` (RFC 2183): a type – with a subtype for content types –
//! and parameters, their values unquoted, joined from continuations and decoded from their charset (RFC 2231, 3–4),
//! encoded words in them decoded as mail programs write them there.

use crate::{charset, words};

/// A content type or a disposition: `type/subtype; name=value …`, names and values as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentType {
    kind: String,
    subtype: Option<String>,
    parameters: Vec<(String, String)>,
}

impl ContentType {
    pub fn new(kind: impl Into<String>, subtype: Option<String>, parameters: Vec<(String, String)>) -> Self {
        Self { kind: kind.into(), subtype, parameters }
    }

    /// The type (`text`), or the disposition (`attachment`).
    pub fn ctype(&self) -> &str {
        &self.kind
    }

    pub fn subtype(&self) -> Option<&str> {
        self.subtype.as_deref()
    }

    /// Whether this is `kind/subtype`, ignoring case.
    pub fn is(&self, kind: &str, subtype: &str) -> bool {
        self.kind.eq_ignore_ascii_case(kind) && self.subtype.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(subtype))
    }

    /// The value of the parameter `name` (any case).
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.parameters.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The parameters in the order they came.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.parameters.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// `type/subtype` in lower case.
    pub fn media_type(&self) -> String {
        match &self.subtype {
            Some(subtype) => format!("{}/{}", self.kind, subtype).to_ascii_lowercase(),
            None => self.kind.to_ascii_lowercase(),
        }
    }
}

/// Skips white space and comments (nested, with quoted pairs).
fn skip_cfws(text: &[u8], mut i: usize) -> usize {
    loop {
        while i < text.len() && text[i].is_ascii_whitespace() {
            i += 1;
        }
        if text.get(i) != Some(&b'(') {
            return i.min(text.len());
        }
        let mut depth = 0;
        while i < text.len() {
            match text[i] {
                b'\\' => i += 1,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
}

/// A token up to one of `stops`, white space or a comment.
fn token<'a>(text: &'a str, i: &mut usize, stops: &[u8]) -> &'a str {
    let bytes = text.as_bytes();
    let start = *i;
    while *i < bytes.len() && !bytes[*i].is_ascii_whitespace() && bytes[*i] != b'(' && !stops.contains(&bytes[*i]) {
        *i += 1;
    }
    &text[start..*i]
}

/// A quoted string from the quote at `i`: its content without quoted pairs.
fn quoted(text: &str, i: &mut usize) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    *i += 1;
    while *i < bytes.len() {
        match bytes[*i] {
            b'"' => {
                *i += 1;
                break;
            }
            b'\\' if *i + 1 < bytes.len() => {
                out.push(bytes[*i + 1]);
                *i += 2;
                continue;
            }
            b'\r' | b'\n' => {}
            b => out.push(b),
        }
        *i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads a content type (`with_subtype`) or a disposition from a header value (unfolded or not); `None` without a
/// type.
pub fn parse(value: &str, with_subtype: bool) -> Option<ContentType> {
    let bytes = value.as_bytes();
    let mut i = skip_cfws(bytes, 0);
    let kind = token(value, &mut i, if with_subtype { b"/;" } else { b";" }).trim_matches('"');
    if kind.is_empty() {
        return None;
    }
    i = skip_cfws(bytes, i);
    let mut subtype = None;
    if with_subtype && bytes.get(i) == Some(&b'/') {
        i = skip_cfws(bytes, i + 1);
        let sub = token(value, &mut i, b";").trim_matches('"');
        if !sub.is_empty() {
            subtype = Some(sub.to_owned());
        }
    }
    // name, value, whether it was quoted
    let mut raw: Vec<(String, String)> = Vec::new();
    loop {
        i = skip_cfws(bytes, i);
        if i >= bytes.len() {
            break;
        }
        if bytes[i] != b';' {
            // Junk before the next parameter.
            while i < bytes.len() && bytes[i] != b';' {
                if bytes[i] == b'"' {
                    quoted(value, &mut i);
                } else {
                    i += 1;
                }
            }
            continue;
        }
        i = skip_cfws(bytes, i + 1);
        let name = token(value, &mut i, b"=;");
        i = skip_cfws(bytes, i);
        if bytes.get(i) != Some(&b'=') {
            continue;
        }
        i = skip_cfws(bytes, i + 1);
        let parameter_value = if bytes.get(i) == Some(&b'"') {
            quoted(value, &mut i)
        } else {
            let start = i;
            // A token; real mail has spaces in unquoted values (`name=my file.pdf`).
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            value[start..i].trim().to_owned()
        };
        if !name.is_empty() {
            raw.push((name.to_owned(), parameter_value));
        }
    }
    Some(ContentType { kind: kind.to_owned(), subtype, parameters: join(raw) })
}

/// RFC 2231's continuations (`name*0`, `name*1*` …) and charsets (`name*=utf-8''…`) joined into plain parameters,
/// in the place of each name's first piece; a plain parameter gives way to an extended one of the same name.
fn join(raw: Vec<(String, String)>) -> Vec<(String, String)> {
    struct Joined {
        name: String,
        plain: Option<String>,
        // (section, extended, value)
        pieces: Vec<(u32, bool, String)>,
    }
    let mut joined: Vec<Joined> = Vec::new();
    for (name, value) in raw {
        let (base, section, extended) = match name.split_once('*') {
            None => (name.as_str(), None, false),
            Some((base, rest)) => {
                let (number, extended) = match rest.strip_suffix('*') {
                    Some(number) => (number, true),
                    None if rest.is_empty() => ("", true),
                    None => (rest, false),
                };
                match number {
                    "" => (base, Some(0), extended),
                    number => match number.parse::<u32>() {
                        Ok(n) => (base, Some(n), extended),
                        Err(_) => (name.as_str(), None, false),
                    },
                }
            }
        };
        let entry = match joined.iter_mut().position(|j| j.name.eq_ignore_ascii_case(base)) {
            Some(at) => &mut joined[at],
            None => {
                joined.push(Joined { name: base.to_owned(), plain: None, pieces: Vec::new() });
                joined.last_mut().expect("just pushed")
            }
        };
        match section {
            None => {
                if entry.plain.is_none() {
                    entry.plain = Some(value);
                }
            }
            Some(n) => entry.pieces.push((n, extended, value)),
        }
    }
    joined
        .into_iter()
        .map(|entry| {
            if entry.pieces.is_empty() {
                let value = entry.plain.unwrap_or_default();
                let value = if value.contains("=?") { words::decode(&value) } else { value };
                return (entry.name, value);
            }
            let mut pieces = entry.pieces;
            pieces.sort_by_key(|(n, _, _)| *n);
            let mut charset_label: Option<String> = None;
            let mut bytes = Vec::new();
            for (index, (_, extended, value)) in pieces.into_iter().enumerate() {
                if !extended {
                    bytes.extend_from_slice(value.as_bytes());
                    continue;
                }
                let value = if index == 0 {
                    // charset'language'value
                    let mut parts = value.splitn(3, '\'');
                    match (parts.next(), parts.next(), parts.next()) {
                        (Some(label), Some(_), Some(rest)) => {
                            charset_label = Some(label.to_owned()).filter(|l| !l.is_empty());
                            rest.to_owned()
                        }
                        _ => value,
                    }
                } else {
                    value
                };
                bytes.extend(percent_decode(value.as_bytes()));
            }
            (entry.name, charset::decode(charset_label.as_deref(), &bytes).0.into_owned())
        })
        .collect()
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%'
            && let (Some(h), Some(l)) = (
                input.get(i + 1).and_then(|&b| (b as char).to_digit(16)),
                input.get(i + 2).and_then(|&b| (b as char).to_digit(16)),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content_type(value: &str) -> ContentType {
        parse(value, true).unwrap()
    }

    #[test]
    fn content_types() {
        let t = content_type("text/plain; charset=\"utf-8\"; format=flowed");
        assert_eq!((t.ctype(), t.subtype()), ("text", Some("plain")));
        assert_eq!(t.attribute("CHARSET"), Some("utf-8"));
        assert_eq!(t.attributes().collect::<Vec<_>>(), [("charset", "utf-8"), ("format", "flowed")]);
        let t = content_type(" Multipart/Mixed ;\r\n\tboundary=\"----=_Part_1\\\"x\" (a comment)");
        assert_eq!(t.media_type(), "multipart/mixed");
        assert_eq!(t.attribute("boundary"), Some("----=_Part_1\"x"));
        let t = content_type("text/plain (Plain text) ; charset = us-ascii ;");
        assert_eq!(t.attribute("charset"), Some("us-ascii"));
        let t = content_type("text");
        assert_eq!((t.ctype(), t.subtype()), ("text", None));
        assert!(parse("", true).is_none() && parse(" ; x=y", true).is_none());
        let t = content_type("application/pdf; name=my file.pdf; x");
        assert_eq!(t.attribute("name"), Some("my file.pdf"));
        assert!(t.is("APPLICATION", "pdf"));
    }

    #[test]
    fn parameters_of_rfc_2231() {
        // RFC 2231, 3 and 4.
        let t = content_type(
            "message/external-body; access-type=URL;\r\n URL*0=\"ftp://\";\r\n URL*1=\"cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar\"",
        );
        assert_eq!(t.attribute("url"), Some("ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar"));
        let t = content_type("application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A");
        assert_eq!(t.attribute("title"), Some("This is ***fun***"));
        let t = content_type(
            "application/x-stuff; title*0*=us-ascii'en'This%20is%20even%20more%20; title*1*=%2A%2A%2Afun%2A%2A%2A%20; title*2=\"isn't it!\"",
        );
        assert_eq!(t.attribute("title"), Some("This is even more ***fun*** isn't it!"));
        let d = parse("attachment; filename*=UTF-8''Plan%20f%C3%BCr%20M%C3%A4rz.txt; filename=\"Plan.txt\"", false)
            .unwrap();
        assert_eq!(d.ctype(), "attachment");
        assert_eq!(d.attribute("filename"), Some("Plan für März.txt"));
        let d = parse("attachment; filename*1=\"b.txt\"; filename*0=\"a\"", false).unwrap();
        assert_eq!(d.attribute("filename"), Some("ab.txt"), "out of order");
        let d = parse("attachment; filename*=iso-8859-1''Gr%FC%DFe.txt", false).unwrap();
        assert_eq!(d.attribute("filename"), Some("Grüße.txt"));
    }

    #[test]
    fn parameters_as_mail_programs_write_them() {
        let d = parse("attachment; filename=\"=?utf-8?B?R3LDvMOfZS5wZGY=?=\"", false).unwrap();
        assert_eq!(d.attribute("filename"), Some("Grüße.pdf"));
        let d = parse("inline; filename=\"Grüße.pdf\"", false).unwrap();
        assert_eq!(d.attribute("filename"), Some("Grüße.pdf"));
        let t = content_type("text/plain;charset=windows-1252;;; ;name=x");
        assert_eq!(t.attribute("charset"), Some("windows-1252"));
        assert_eq!(t.attribute("name"), Some("x"));
    }
}
