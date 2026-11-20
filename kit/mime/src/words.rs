// SPDX-License-Identifier: MIT
//! Encoded words (RFC 2047, with the language of RFC 2231, 5): `=?charset?B|Q?text?=` in header fields. Reading
//! drops the white space between adjacent encoded words and joins the bytes of adjacent words of the same charset
//! before decoding them – mail programs split characters and base64 quanta across words. Words are also read where
//! RFC 2047 does not allow them (inside quoted strings and parameter values, glued to other text), as mail programs
//! write them there.

use crate::{charset, transfer};

enum Piece<'a> {
    Text(&'a str),
    Word { charset: &'a str, bytes: Vec<u8> },
}

/// One encoded word at the start of `text`: its charset, its decoded bytes and its length.
fn word(text: &str) -> Option<(&str, Vec<u8>, usize)> {
    let rest = text.strip_prefix("=?")?;
    let question = rest.find('?')?;
    let charset = &rest[..question];
    if charset.is_empty() || charset.contains(|c: char| c.is_whitespace() || c == '=' || !c.is_ascii()) {
        return None;
    }
    let rest = &rest[question + 1..];
    let mut chars = rest.chars();
    let encoding = chars.next()?;
    if !encoding.is_ascii() || chars.next()? != '?' {
        return None;
    }
    let payload_start = 2;
    let end = rest[payload_start..].find("?=")? + payload_start;
    let payload = &rest[payload_start..end];
    if payload.contains(|c: char| c.is_whitespace()) {
        return None;
    }
    let bytes = match encoding {
        'B' | 'b' => transfer::base64_decode(payload.as_bytes()),
        'Q' | 'q' => transfer::q_decode(payload.as_bytes()),
        _ => return None,
    };
    Some((charset, bytes, 2 + question + 1 + end + 2))
}

/// `text` with its encoded words decoded.
pub fn decode(text: &str) -> String {
    if !text.contains("=?") {
        return text.to_owned();
    }
    let mut pieces: Vec<Piece<'_>> = Vec::new();
    let mut literal = 0;
    let mut i = 0;
    while let Some(found) = text[i..].find("=?") {
        let at = i + found;
        match word(&text[at..]) {
            Some((charset, bytes, length)) => {
                if at > literal {
                    pieces.push(Piece::Text(&text[literal..at]));
                }
                pieces.push(Piece::Word { charset, bytes });
                i = at + length;
                literal = i;
            }
            None => i = at + 2,
        }
    }
    if literal < text.len() {
        pieces.push(Piece::Text(&text[literal..]));
    }
    // White space between two words goes; adjacent words of one charset become one.
    let mut out = String::with_capacity(text.len());
    let mut pending: Option<(&str, Vec<u8>)> = None;
    let flush = |out: &mut String, pending: &mut Option<(&str, Vec<u8>)>| {
        if let Some((charset, bytes)) = pending.take() {
            out.push_str(&charset::decode(Some(charset), &bytes).0);
        }
    };
    let mut index = 0;
    while index < pieces.len() {
        let next_is_word = matches!(pieces.get(index + 1), Some(Piece::Word { .. }));
        match &mut pieces[index] {
            Piece::Word { charset, bytes } => match &mut pending {
                Some((current, gathered)) if current.eq_ignore_ascii_case(charset) => {
                    gathered.append(bytes);
                }
                _ => {
                    flush(&mut out, &mut pending);
                    pending = Some((charset, std::mem::take(bytes)));
                }
            },
            Piece::Text(text) => {
                let between_words = text.chars().all(char::is_whitespace) && pending.is_some() && next_is_word;
                if !between_words {
                    flush(&mut out, &mut pending);
                    out.push_str(text);
                }
            }
        }
        index += 1;
    }
    flush(&mut out, &mut pending);
    out
}

/// Whether `text` can stand in a header field as it is: printable ASCII and white space, and nothing that would
/// read as an encoded word.
pub fn is_plain(text: &str) -> bool {
    text.bytes().all(|b| (0x20..0x7f).contains(&b) || b == b'\t') && !text.contains("=?")
}

/// `text` as encoded words of UTF-8, each at most 75 characters, separated by spaces – `Q` for mostly ASCII text,
/// `B` otherwise; text that needs none as it is (line breaks become spaces).
pub fn encode(text: &str) -> String {
    let text = text.replace(['\r', '\n'], " ");
    if is_plain(&text) {
        return text;
    }
    let other = text.bytes().filter(|b| !b.is_ascii_alphanumeric() && *b != b' ').count();
    let q = other * 3 < text.len();
    let mut words = Vec::new();
    let mut chunk = String::new();
    let mut length = 0;
    let cost = |c: char| -> usize {
        if q {
            if c.is_ascii_alphanumeric() || c == ' ' || "!*+-/".contains(c) { 1 } else { 3 * c.len_utf8() }
        } else {
            c.len_utf8()
        }
    };
    // `=?utf-8?Q?` and `?=`: 12 of 75 characters; base64 of 45 bytes is 60 characters.
    let limit = if q { 63 } else { 45 };
    for c in text.chars() {
        if length + cost(c) > limit && !chunk.is_empty() {
            words.push(encode_word(&chunk, q));
            chunk.clear();
            length = 0;
        }
        chunk.push(c);
        length += cost(c);
    }
    if !chunk.is_empty() {
        words.push(encode_word(&chunk, q));
    }
    words.join(" ")
}

fn encode_word(text: &str, q: bool) -> String {
    if !q {
        return format!("=?utf-8?B?{}?=", transfer::base64_encode(text.as_bytes()));
    }
    let mut out = String::from("=?utf-8?Q?");
    for b in text.bytes() {
        match b {
            b' ' => out.push('_'),
            b if b.is_ascii_alphanumeric() || b"!*+-/".contains(&b) => out.push(b as char),
            b => out.push_str(&format!("={b:02X}")),
        }
    }
    out.push_str("?=");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_of_rfc_2047() {
        // RFC 2047, 8.
        assert_eq!(decode("=?ISO-8859-1?Q?a?="), "a");
        assert_eq!(decode("=?ISO-8859-1?Q?a?= b"), "a b");
        assert_eq!(decode("=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?="), "ab");
        assert_eq!(decode("=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?="), "ab");
        assert_eq!(decode("=?ISO-8859-1?Q?a?=\r\n    =?ISO-8859-1?Q?b?="), "ab");
        assert_eq!(decode("=?ISO-8859-1?Q?a_b?="), "a b");
        assert_eq!(decode("=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?="), "a b");
        assert_eq!(decode("=?US-ASCII?Q?Keith_Moore?="), "Keith Moore");
        assert_eq!(decode("=?ISO-8859-1?Q?Andr=E9?= Pirard"), "André Pirard");
        assert_eq!(
            decode(
                "=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?="
            ),
            "If you can read this you understand the example."
        );
        // RFC 2231, 5: a language.
        assert_eq!(decode("=?US-ASCII*EN?Q?Keith_Moore?="), "Keith Moore");
    }

    #[test]
    fn words_as_mail_programs_write_them() {
        // A character split across two words, and words without space between them.
        assert_eq!(decode("=?utf-8?B?R3LD?= =?utf-8?B?vMOfZQ==?="), "Grüße");
        assert_eq!(decode("=?utf-8?q?Gr=C3?==?utf-8?q?=BC=C3=9Fe?="), "Grüße");
        assert_eq!(decode("Gr=?UTF-8?Q?=C3=BC=C3=9Fe?="), "Grüße");
        assert_eq!(decode("Re: =?utf-8?q?Gr=C3=BC=C3=9Fe?= aus Köln"), "Re: Grüße aus Köln");
        assert_eq!(decode("=?gb2312?B?xOO6ww==?="), "你好");
        assert_eq!(decode("=?iso-2022-jp?B?GyRCJCIbKEI=?="), "あ");
        // Not words.
        assert_eq!(decode("a =? b ?= c"), "a =? b ?= c");
        assert_eq!(decode("=?utf-8?x?abc?="), "=?utf-8?x?abc?=");
        assert_eq!(decode("=?utf-8?q?unterminated"), "=?utf-8?q?unterminated");
        assert_eq!(decode("=?"), "=?");
    }

    #[test]
    fn writing_words() {
        assert_eq!(encode("Hello"), "Hello");
        for text in [
            "Grüße aus Köln",
            "日本語のテキストはとても長くなることがありますので分割されなければなりません、本当に長いです",
            "a=?b?=c",
            &"Dateien hinzugefügt zum Ordner „Einreichungen“ ".repeat(4),
        ] {
            let encoded = encode(text);
            assert!(encoded.is_ascii(), "{encoded}");
            assert!(encoded.split(' ').all(|word| word.len() <= 75), "{encoded}");
            assert_eq!(decode(&encoded), text.replace("\r\n", " "));
        }
    }
}
