// SPDX-License-Identifier: AGPL-3.0-or-later
//! A message as the checks see it: the raw header fields in their order and the body, never decoded – signatures are
//! over the bytes as they came. Lines end in CRLF; a bare LF is taken as a line end as well. And the canonical forms of
//! headers and bodies (RFC 6376, 3.4), which DKIM and ARC hash.

/// A header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    /// The name as written, without the whitespace before the colon.
    pub name: &'a [u8],
    /// The whole field: name, colon, value with its folding, and its line end.
    pub raw: &'a [u8],
    /// Where the value starts in `raw` (after the colon).
    pub value_start: usize,
}

impl<'a> Header<'a> {
    /// The value: after the colon, without the final line end.
    pub fn value(&self) -> &'a [u8] {
        let value = &self.raw[self.value_start..];
        let value = value.strip_suffix(b"\n").unwrap_or(value);
        value.strip_suffix(b"\r").unwrap_or(value)
    }

    /// The value unfolded, with the whitespace around it removed, as text (lossy).
    pub fn text(&self) -> String {
        let value = String::from_utf8_lossy(self.value());
        value.split(['\r', '\n']).map(|line| line.trim_end_matches([' ', '\t'])).collect::<Vec<_>>().join("").trim().to_owned()
    }

    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }
}

/// A message's header fields and body.
#[derive(Debug, Clone)]
pub struct Message<'a> {
    pub headers: Vec<Header<'a>>,
    pub body: &'a [u8],
    /// Lines in the header section that are no header field (no colon): nothing signs them.
    pub malformed: usize,
}

impl<'a> Message<'a> {
    /// Splits `raw`; a message without the empty line has no body.
    pub fn parse(raw: &'a [u8]) -> Self {
        let mut headers: Vec<Header<'a>> = Vec::new();
        let mut malformed = 0;
        let mut position = 0;
        let mut body = &raw[raw.len()..];
        // The field being gathered: its start and the end of its name.
        let mut current: Option<(usize, usize, usize)> = None;
        let finish = |current: &mut Option<(usize, usize, usize)>, end: usize, headers: &mut Vec<Header<'a>>| {
            if let Some((start, name_end, colon)) = current.take() {
                headers.push(Header { name: &raw[start..name_end], raw: &raw[start..end], value_start: colon + 1 - start });
            }
        };
        while position < raw.len() {
            let line_end = raw[position..].iter().position(|byte| *byte == b'\n').map_or(raw.len(), |at| position + at + 1);
            let line = &raw[position..line_end];
            if line == b"\r\n" || line == b"\n" {
                finish(&mut current, position, &mut headers);
                body = &raw[line_end..];
                return Self { headers, body, malformed };
            }
            if matches!(line.first(), Some(b' ' | b'\t')) && current.is_some() {
                // A continuation of the field.
            } else {
                finish(&mut current, position, &mut headers);
                match line.iter().position(|byte| *byte == b':') {
                    Some(colon) => {
                        let name = line[..colon].trim_ascii_end();
                        let valid = !name.is_empty() && name.iter().all(|byte| (33..=126).contains(byte));
                        if valid {
                            current = Some((position, position + name.len(), position + colon));
                        } else {
                            malformed += 1;
                        }
                    }
                    None => malformed += 1,
                }
            }
            position = line_end;
        }
        finish(&mut current, raw.len(), &mut headers);
        Self { headers, body, malformed }
    }

    /// The fields called `name`, in order.
    pub fn all<'b>(&'b self, name: &'b str) -> impl Iterator<Item = &'b Header<'a>> + 'b {
        self.headers.iter().filter(move |header| header.is(name))
    }

    /// The first field called `name`.
    pub fn first(&self, name: &str) -> Option<&Header<'a>> {
        self.headers.iter().find(|header| header.is(name))
    }

    /// The domains of the addresses in `From` (RFC 5322, 3.6.2), in lower case – DMARC's identifier (RFC 7489, 3.1).
    pub fn from_domains(&self) -> Vec<String> {
        self.all("From").flat_map(|header| addresses(&header.text())).filter_map(|address| {
            address.rsplit_once('@').map(|(_, domain)| domain.trim_end_matches('.').to_ascii_lowercase())
        }).collect()
    }

    /// The first address of the first `From`, in lower case, or empty.
    pub fn first_from_address(&self) -> String {
        self.first("From").and_then(|header| addresses(&header.text()).into_iter().next()).unwrap_or_default().to_lowercase()
    }
}

/// The addresses in an address list (RFC 5322, 3.4): those in angle brackets, else the words with an `@`; comments and
/// quoted display names are skipped.
pub fn addresses(list: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut plain = String::new();
    let mut bracket: Option<String> = None;
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = 0usize;
    let flush = |plain: &mut String, found: &mut Vec<String>| {
        let word = plain.trim();
        if word.contains('@') && !word.contains(' ') {
            found.push(word.to_owned());
        }
        plain.clear();
    };
    for c in list.chars() {
        if escaped {
            escaped = false;
            if let Some(address) = bracket.as_mut() {
                address.push(c);
            }
            continue;
        }
        match c {
            '\\' if quoted || comment > 0 => escaped = true,
            '"' if comment == 0 => {
                quoted = !quoted;
                if let Some(address) = bracket.as_mut() {
                    address.push(c);
                }
            }
            _ if quoted => {
                if let Some(address) = bracket.as_mut() {
                    address.push(c);
                }
            }
            '(' => comment += 1,
            ')' if comment > 0 => comment -= 1,
            _ if comment > 0 => {}
            '<' => {
                plain.clear();
                bracket = Some(String::new());
            }
            '>' => {
                if let Some(address) = bracket.take() {
                    let address = address.trim();
                    if !address.is_empty() {
                        found.push(address.to_owned());
                    }
                }
            }
            ',' | ';' | ':' if bracket.is_none() => {
                if c == ':' {
                    plain.clear(); // A group's name (RFC 5322, 3.4).
                } else {
                    flush(&mut plain, &mut found);
                }
            }
            _ => match bracket.as_mut() {
                Some(address) => address.push(c),
                None => plain.push(c),
            },
        }
    }
    flush(&mut plain, &mut found);
    found
}

/// Canonicalization (RFC 6376, 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Canonicalization {
    #[default]
    Simple,
    Relaxed,
}

impl Canonicalization {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "simple" => Some(Self::Simple),
            "relaxed" => Some(Self::Relaxed),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Relaxed => "relaxed",
        }
    }

    /// A header field in canonical form, with its CRLF (RFC 6376, 3.4.1 and 3.4.2).
    pub fn header(self, raw: &[u8], out: &mut Vec<u8>) {
        match self {
            Self::Simple => {
                out.extend_from_slice(raw);
                if !raw.ends_with(b"\r\n") {
                    if raw.ends_with(b"\n") {
                        out.pop();
                    }
                    out.extend_from_slice(b"\r\n");
                }
            }
            Self::Relaxed => {
                let colon = raw.iter().position(|byte| *byte == b':').unwrap_or(raw.len());
                for byte in raw[..colon].trim_ascii() {
                    out.push(byte.to_ascii_lowercase());
                }
                out.push(b':');
                let value = raw.get(colon + 1..).unwrap_or_default();
                let mut space = false;
                let mut started = false;
                for &byte in value {
                    match byte {
                        b'\r' | b'\n' => {}
                        b' ' | b'\t' => space = true,
                        _ => {
                            if space && started {
                                out.push(b' ');
                            }
                            space = false;
                            started = true;
                            out.push(byte);
                        }
                    }
                }
                out.extend_from_slice(b"\r\n");
            }
        }
    }

    /// The body in canonical form (RFC 6376, 3.4.3 and 3.4.4).
    pub fn body(self, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 2);
        // Empty lines are held back until something follows them: those at the end are dropped.
        let mut empty_lines = 0usize;
        let mut lines = body.split_inclusive(|byte| *byte == b'\n').peekable();
        while let Some(line) = lines.next() {
            let content = line.strip_suffix(b"\n").unwrap_or(line);
            let content = content.strip_suffix(b"\r").unwrap_or(content);
            let canonical: Vec<u8> = match self {
                Self::Simple => content.to_vec(),
                Self::Relaxed => {
                    let mut reduced = Vec::with_capacity(content.len());
                    let mut space = false;
                    for &byte in content {
                        if byte == b' ' || byte == b'\t' {
                            space = true;
                        } else {
                            if space {
                                reduced.push(b' ');
                            }
                            space = false;
                            reduced.push(byte);
                        }
                    }
                    reduced
                }
            };
            if canonical.is_empty() {
                // A last line without line end and without content is no line at all.
                if line.ends_with(b"\n") || lines.peek().is_some() {
                    empty_lines += 1;
                }
                continue;
            }
            for _ in 0..empty_lines {
                out.extend_from_slice(b"\r\n");
            }
            empty_lines = 0;
            out.extend_from_slice(&canonical);
            out.extend_from_slice(b"\r\n");
        }
        if out.is_empty() && self == Self::Simple {
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6376, 3.4.5, examples 1 to 3.
    const EXAMPLE: &[u8] = b"A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";

    #[test]
    fn rfc_6376_canonicalization_examples() {
        let message = Message::parse(EXAMPLE);
        assert_eq!(message.headers.len(), 2);
        let mut relaxed = Vec::new();
        let mut simple = Vec::new();
        for header in &message.headers {
            Canonicalization::Relaxed.header(header.raw, &mut relaxed);
            Canonicalization::Simple.header(header.raw, &mut simple);
        }
        assert_eq!(relaxed, b"a:X\r\nb:Y Z\r\n");
        assert_eq!(simple, b"A: X\r\nB : Y\t\r\n\tZ  \r\n");
        assert_eq!(Canonicalization::Relaxed.body(message.body), b" C\r\nD E\r\n");
        assert_eq!(Canonicalization::Simple.body(message.body), b" C \r\nD \t E\r\n");
    }

    #[test]
    fn empty_bodies_and_missing_line_ends() {
        assert_eq!(Canonicalization::Simple.body(b""), b"\r\n");
        assert_eq!(Canonicalization::Relaxed.body(b""), b"");
        assert_eq!(Canonicalization::Simple.body(b"\r\n\r\n"), b"\r\n");
        assert_eq!(Canonicalization::Relaxed.body(b"\r\n \r\n"), b"");
        assert_eq!(Canonicalization::Simple.body(b"a"), b"a\r\n");
        assert_eq!(Canonicalization::Relaxed.body(b"a \r\n\r\nb  "), b"a\r\n\r\nb\r\n");
    }

    #[test]
    fn headers_and_addresses() {
        let raw = b"From: \"Doe, Jane\" <Jane@Example.COM>, bob@b.example (Bob)\r\nSubject: x\r\n y\r\nbroken\r\n\r\nbody";
        let message = Message::parse(raw);
        assert_eq!(message.headers.len(), 2);
        assert_eq!(message.malformed, 1);
        assert_eq!(message.body, b"body");
        assert_eq!(message.first("subject").unwrap().text(), "x y");
        assert_eq!(message.from_domains(), ["example.com", "b.example"]);
        assert_eq!(message.first_from_address(), "jane@example.com");
        assert_eq!(addresses("Group: a@x.example, b@y.example;"), ["a@x.example", "b@y.example"]);
        assert_eq!(addresses("\"a@quoted\" <real@x.example>"), ["real@x.example"]);
        let headers_only = Message::parse(b"Subject: x\r\n");
        assert_eq!((headers_only.headers.len(), headers_only.body), (1, &b""[..]));
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x0bad_cafe_dead_beefu64;
        let alphabet = b"From:<>@\" ()\\,;\r\n\tab\xc3";
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state % 64) as usize;
            let input: Vec<u8> =
                (0..length).map(|i| alphabet[((state >> (i % 50)) as usize ^ i) % alphabet.len()]).collect();
            let message = Message::parse(&input);
            let _ = message.from_domains();
            let mut out = Vec::new();
            for header in &message.headers {
                Canonicalization::Relaxed.header(header.raw, &mut out);
                let _ = header.text();
            }
            let _ = Canonicalization::Relaxed.body(message.body);
            let _ = Canonicalization::Simple.body(message.body);
        }
    }
}
