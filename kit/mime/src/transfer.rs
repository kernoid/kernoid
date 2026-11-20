// SPDX-License-Identifier: MIT
//! Content transfer encodings (RFC 2045, 6): base64 and quoted-printable both ways, read leniently – characters
//! outside the alphabet are skipped, padding may be missing, broken `=` sequences stay as written.

/// A `Content-Transfer-Encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    SevenBit,
    EightBit,
    Binary,
    Base64,
    QuotedPrintable,
    /// One kernoid cannot undo (`x-uuencode`, a typo …): the content is kept as it is.
    Unknown,
}

impl Encoding {
    /// The encoding a header value names; `7bit` without one.
    pub fn parse(value: Option<&str>) -> Self {
        let Some(value) = value else { return Self::SevenBit };
        let value = value.trim().trim_matches('"').trim();
        let value = value.split([';', ' ', '\t', '(']).next().unwrap_or_default();
        match value.to_ascii_lowercase().as_str() {
            "" | "7bit" | "7-bit" => Self::SevenBit,
            "8bit" | "8-bit" => Self::EightBit,
            "binary" => Self::Binary,
            "base64" => Self::Base64,
            "quoted-printable" => Self::QuotedPrintable,
            _ => Self::Unknown,
        }
    }

    /// Whether the content is the data as it is.
    pub fn is_identity(self) -> bool {
        matches!(self, Self::SevenBit | Self::EightBit | Self::Binary)
    }

    /// `content` without this encoding.
    pub fn decode(self, content: &[u8]) -> std::borrow::Cow<'_, [u8]> {
        match self {
            Self::Base64 => std::borrow::Cow::Owned(base64_decode(content)),
            Self::QuotedPrintable => std::borrow::Cow::Owned(qp_decode(content)),
            _ => std::borrow::Cow::Borrowed(content),
        }
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sextet(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

/// Base64 (RFC 2045, 6.8; the URL alphabet too): what is not in the alphabet is skipped, `=` ends the data.
pub fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let (mut bits, mut count) = (0u32, 0u32);
    for &b in input {
        if b == b'=' {
            // Padding; another quantum may follow in concatenated data.
            bits = 0;
            count = 0;
            continue;
        }
        let Some(value) = sextet(b) else { continue };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    out
}

/// Base64 in one line.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Base64 in lines of 76 characters, each ending in CRLF.
pub fn base64_lines(input: &[u8]) -> String {
    let encoded = base64_encode(input);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 38 + 2);
    for line in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Quoted-printable (RFC 2045, 6.7): `=XX` in either case, soft line breaks (`=` at the end of a line, white space
/// after it allowed); a `=` that starts neither stays as it is.
pub fn qp_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != b'=' {
            out.push(b);
            i += 1;
            continue;
        }
        if let (Some(high), Some(low)) =
            (input.get(i + 1).and_then(|&b| hex(b)), input.get(i + 2).and_then(|&b| hex(b)))
        {
            out.push(high << 4 | low);
            i += 3;
            continue;
        }
        // A soft line break: `=`, optional white space, the line's end (or the end of the input).
        let mut j = i + 1;
        while matches!(input.get(j), Some(b' ' | b'\t')) {
            j += 1;
        }
        match input.get(j) {
            Some(b'\r') if input.get(j + 1) == Some(&b'\n') => i = j + 2,
            Some(b'\n') => i = j + 1,
            None => i = j,
            _ => {
                out.push(b'=');
                i += 1;
            }
        }
    }
    out
}

/// The `Q` encoding of encoded words (RFC 2047, 4.2): quoted-printable with `_` for a space.
pub fn q_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'_' => out.push(b' '),
            b'=' => {
                if let (Some(high), Some(low)) =
                    (input.get(i + 1).and_then(|&b| hex(b)), input.get(i + 2).and_then(|&b| hex(b)))
                {
                    out.push(high << 4 | low);
                    i += 3;
                    continue;
                }
                out.push(b'=');
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// Text as quoted-printable with lines of at most 76 characters; line breaks (CRLF or LF) become CRLF.
pub fn qp_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() + input.len() / 8);
    let mut lines = input.split(|&b| b == b'\n').peekable();
    while let Some(line) = lines.next() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let last_line = lines.peek().is_none();
        let mut length = 0;
        for (i, &b) in line.iter().enumerate() {
            let at_end = i + 1 == line.len();
            let plain = (b'!'..=b'~').contains(&b) && b != b'=' || (matches!(b, b' ' | b'\t') && !at_end);
            let piece = if plain { (b as char).to_string() } else { format!("={b:02X}") };
            if length + piece.len() > 75 {
                out.push_str("=\r\n");
                length = 0;
            }
            out.push_str(&piece);
            length += piece.len();
        }
        if !last_line {
            out.push_str("\r\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_both_ways() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(base64_encode(data).as_bytes()), data);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode(b"Zm9v\r\nYmFy"), b"foobar");
        assert_eq!(base64_decode(b"Zm8"), b"fo", "without padding");
        assert_eq!(base64_decode(b"Zm8=\r\nYg=="), b"fob", "concatenated");
        assert_eq!(base64_decode(b"Z m 9 v !"), b"foo");
        let long = vec![7u8; 200];
        let lines = base64_lines(&long);
        assert!(lines.lines().all(|line| line.len() <= 76));
        assert_eq!(base64_decode(lines.as_bytes()), long);
    }

    #[test]
    fn quoted_printable_both_ways() {
        assert_eq!(qp_decode(b"Gr=C3=BC=c3=9fe"), "Grüße".as_bytes());
        assert_eq!(qp_decode(b"soft=\r\nbreak= \r\nend=\nx"), b"softbreakendx");
        assert_eq!(qp_decode(b"a=ZZb=3"), b"a=ZZb=3");
        assert_eq!(qp_decode(b"end="), b"end");
        assert_eq!(q_decode(b"Gr=C3=BC=C3=9Fe_dich"), "Grüße dich".as_bytes());
        let text = "Grüße aus Köln, a = b \r\nnext line\r\n".repeat(5);
        let encoded = qp_encode(text.as_bytes());
        assert!(encoded.lines().all(|line| line.len() <= 76), "{encoded}");
        assert!(encoded.contains("b=20\r\n"), "trailing space is encoded: {encoded}");
        assert_eq!(qp_decode(encoded.as_bytes()), text.as_bytes());
        assert_eq!(qp_decode(qp_encode(b"x".repeat(300).as_slice()).as_bytes()), b"x".repeat(300));
    }

    #[test]
    fn encodings_by_name() {
        assert_eq!(Encoding::parse(Some(" Base64 ")), Encoding::Base64);
        assert_eq!(Encoding::parse(Some("QUOTED-PRINTABLE")), Encoding::QuotedPrintable);
        assert_eq!(Encoding::parse(Some("8bit")), Encoding::EightBit);
        assert_eq!(Encoding::parse(None), Encoding::SevenBit);
        assert_eq!(Encoding::parse(Some("x-uuencode")), Encoding::Unknown);
    }
}
