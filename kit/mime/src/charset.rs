// SPDX-License-Identifier: MIT
//! Charsets (RFC 2046, 4.1.2; RFC 2278): text in the charset a label names, as UTF-8. Labels are those of the WHATWG
//! Encoding Standard (through encoding_rs) – `iso-8859-1` is read as Windows-1252, a superset –, and UTF-7 (RFC 2152).
//! Real mail lies about its charset: text labelled US-ASCII, or not labelled at all, or with a label nobody knows, is
//! read as UTF-8 when it is valid UTF-8 and as Windows-1252 otherwise.

use std::borrow::Cow;

/// `bytes` as text in the charset `label` names, and whether that went wrong somewhere (bytes the charset does not
/// have, replaced by U+FFFD).
pub fn decode<'a>(label: Option<&str>, bytes: &'a [u8]) -> (Cow<'a, str>, bool) {
    let label = label.map(normalize).unwrap_or_default();
    match label.as_str() {
        "" | "us-ascii" | "ascii" | "us_ascii" | "ansi_x3.4-1968" | "iso646-us" | "x-unknown" | "unknown"
        | "unknown-8bit" | "x-user-defined" | "default" | "8bit" | "7bit" | "binary" => (guess(bytes), false),
        "utf-8" | "utf8" => utf8(bytes),
        "utf-7" | "utf7" | "unicode-1-1-utf-7" | "csunicode11utf7" => utf7(bytes),
        label => match encoding_rs::Encoding::for_label_no_replacement(label.as_bytes()) {
            Some(encoding) if encoding == encoding_rs::UTF_8 => utf8(bytes),
            Some(encoding) => {
                let (text, errors) = encoding.decode_without_bom_handling(bytes);
                (text, errors)
            }
            None => (guess(bytes), false),
        },
    }
}

/// Whether kernoid can read text in the charset `label` names.
pub fn is_known(label: &str) -> bool {
    let label = normalize(label);
    matches!(label.as_str(), "us-ascii" | "ascii" | "utf-8" | "utf8" | "utf-7" | "utf7")
        || encoding_rs::Encoding::for_label_no_replacement(label.as_bytes()).is_some()
}

/// A label in lower case, without quotes, the language of RFC 2231 (`utf-8*de`) and with a few spellings mail
/// programs use that the Encoding Standard does not list.
fn normalize(label: &str) -> String {
    let label = label.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    let label = label.split('*').next().unwrap_or_default().to_ascii_lowercase();
    if let Some(number) = label.strip_prefix("cp-").or_else(|| label.strip_prefix("win-")) {
        return format!("windows-{number}");
    }
    if let Some(number) = label.strip_prefix("cp").filter(|n| n.starts_with("125") && n.len() == 4) {
        return format!("windows-{number}");
    }
    match label.as_str() {
        "latin-1" | "iso8859_1" | "iso_8859_1" => "iso-8859-1".into(),
        "ks_c_5601" | "ks_c_5601-1989" | "ksc5601" | "ks_c_5601_1987" => "euc-kr".into(),
        "x-sjis" | "sjis" | "shift-jis" | "x-shift-jis" | "ms932" | "cp932" | "windows-31j" => "shift_jis".into(),
        "gb2312-80" | "x-gb2312" | "euc-cn" | "x-euc-cn" | "cp936" | "ms936" => "gbk".into(),
        "big5hkscs" | "cp950" => "big5".into(),
        _ => label,
    }
}

/// Valid UTF-8 as it is, else Windows-1252.
fn guess(bytes: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Cow::Borrowed(text),
        Err(_) => encoding_rs::WINDOWS_1252.decode_without_bom_handling(bytes).0,
    }
}

/// UTF-8, without a byte order mark; malformed sequences become U+FFFD.
fn utf8(bytes: &[u8]) -> (Cow<'_, str>, bool) {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => (Cow::Borrowed(text), false),
        Err(_) => (String::from_utf8_lossy(bytes), true),
    }
}

/// UTF-7 (RFC 2152): runs of modified base64 between `+` and `-` (or the first character outside base64) carry
/// UTF-16; `+-` is a plus sign.
fn utf7(bytes: &[u8]) -> (Cow<'_, str>, bool) {
    if !bytes.contains(&b'+') && bytes.is_ascii() {
        return (Cow::Borrowed(std::str::from_utf8(bytes).unwrap_or_default()), false);
    }
    let value = |b: u8| -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = String::with_capacity(bytes.len());
    let mut errors = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'+' {
            if b.is_ascii() {
                out.push(b as char);
            } else {
                out.push('\u{fffd}');
                errors = true;
            }
            i += 1;
            continue;
        }
        i += 1;
        if bytes.get(i) == Some(&b'-') {
            out.push('+');
            i += 1;
            continue;
        }
        let (mut bits, mut count, mut units) = (0u32, 0u32, Vec::new());
        while let Some(v) = bytes.get(i).copied().and_then(value) {
            bits = (bits << 6) | v;
            count += 6;
            if count >= 16 {
                count -= 16;
                units.push(((bits >> count) & 0xffff) as u16);
            }
            bits &= (1 << count) - 1;
            i += 1;
        }
        if bytes.get(i) == Some(&b'-') {
            i += 1;
        }
        let text = String::from_utf16_lossy(&units);
        errors |= text.contains('\u{fffd}');
        out.push_str(&text);
    }
    (Cow::Owned(out), errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(label: &str, bytes: &[u8]) -> String {
        decode(Some(label), bytes).0.into_owned()
    }

    #[test]
    fn charsets_of_mail() {
        assert_eq!(text("ISO-8859-1", b"Gr\xfc\xdfe"), "Grüße");
        assert_eq!(text("\"iso-8859-15\"", b"\xa4"), "€");
        assert_eq!(text("windows-1252", b"\x80"), "€");
        assert_eq!(text("cp1252", b"\x80"), "€");
        assert_eq!(text("koi8-r", b"\xf0\xd2\xc9\xd7\xc5\xd4"), "Привет");
        assert_eq!(text("windows-1251", b"\xcf\xf0\xe8\xe2\xe5\xf2"), "Привет");
        assert_eq!(text("iso-8859-2", b"\xb1"), "ą");
        assert_eq!(text("iso-8859-7", b"\xe1"), "α");
        assert_eq!(text("shift_jis", b"\x82\xa0"), "あ");
        assert_eq!(text("euc-jp", b"\xa4\xa2"), "あ");
        assert_eq!(text("iso-2022-jp", b"\x1b$B$\"\x1b(B"), "あ");
        assert_eq!(text("gb2312", b"\xc4\xe3\xba\xc3"), "你好");
        assert_eq!(text("gb18030", b"\xc4\xe3\xba\xc3"), "你好");
        assert_eq!(text("big5", b"\xa7\x41"), "你");
        assert_eq!(text("ks_c_5601-1987", b"\xbe\xc8"), "안");
        assert_eq!(text("euc-kr", b"\xbe\xc8"), "안");
        assert_eq!(text("utf-16le", b"A\x00"), "A");
        assert_eq!(text("utf-8*de", "ü".as_bytes()), "ü");
    }

    #[test]
    fn labels_that_lie() {
        assert_eq!(text("us-ascii", "Grüße".as_bytes()), "Grüße");
        assert_eq!(text("us-ascii", b"Gr\xfc\xdfe"), "Grüße");
        assert_eq!(text("x-something", "Grüße".as_bytes()), "Grüße");
        assert_eq!(decode(None, b"Gr\xfc\xdfe").0, "Grüße");
        let (text, errors) = decode(Some("utf-8"), b"Gr\xfc\xdfe");
        assert!(errors && text.contains('\u{fffd}'));
        assert!(!decode(Some("utf-8"), "Grüße".as_bytes()).1);
        assert!(is_known("ISO-8859-1") && is_known("utf-7") && !is_known("x-nothing"));
    }

    #[test]
    fn utf_7() {
        assert_eq!(text("utf-7", b"Hi Mom -+Jjo--!"), "Hi Mom -☺-!");
        assert_eq!(text("utf-7", b"A+ImIDkQ."), "A≢Α.");
        assert_eq!(text("utf-7", b"1 +- 1"), "1 + 1");
        assert_eq!(text("utf-7", b"+ZeVnLIqe-"), "日本語");
        assert_eq!(text("utf-7", b"plain"), "plain");
    }
}
