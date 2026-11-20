// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mailbox names in modified UTF-7 (RFC 3501, 5.1.3), for clients that have not enabled UTF-8 (RFC 6855, RFC 9051):
//! printable ASCII stands for itself, `&` is `&-`, and everything else is UTF-16 in base64 with `,` for `/`, between
//! `&` and `-`.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

fn sextet(byte: u8) -> Option<u32> {
    ALPHABET.iter().position(|&c| c == byte).map(|position| position as u32)
}

/// A name in modified UTF-7.
pub(crate) fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();
    fn flush(out: &mut String, pending: &mut Vec<u16>) {
        if pending.is_empty() {
            return;
        }
        out.push('&');
        let bytes: Vec<u8> = pending.iter().flat_map(|unit| unit.to_be_bytes()).collect();
        for chunk in bytes.chunks(3) {
            let value = chunk.iter().enumerate().fold(0u32, |value, (i, &b)| value | u32::from(b) << (16 - 8 * i));
            let sextets = chunk.len() + 1;
            for i in 0..sextets {
                out.push(ALPHABET[(value >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out.push('-');
        pending.clear();
    }
    for c in name.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut out, &mut pending);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut units = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut units));
        }
    }
    flush(&mut out, &mut pending);
    out
}

/// A name from modified UTF-7; `None` if it is not valid modified UTF-7 (then it is taken as it is).
pub(crate) fn decode(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(0x20..=0x7e).contains(&byte) {
            return None;
        }
        if byte != b'&' {
            out.push(byte as char);
            index += 1;
            continue;
        }
        let end = index + 1 + bytes[index + 1..].iter().position(|&b| b == b'-')?;
        let encoded = &bytes[index + 1..end];
        index = end + 1;
        if encoded.is_empty() {
            out.push('&');
            continue;
        }
        let mut units = Vec::new();
        let (mut buffer, mut bits) = (0u32, 0u32);
        for &b in encoded {
            buffer = (buffer << 6 | sextet(b)?) & 0xff_ffff;
            bits += 6;
            if bits >= 16 {
                bits -= 16;
                units.push((buffer >> bits) as u16);
            }
        }
        // Leftover bits must be zero padding, shorter than a sextet's worth.
        if bits >= 6 || buffer & ((1 << bits) - 1) != 0 {
            return None;
        }
        let text = char::decode_utf16(units).collect::<Result<String, _>>().ok()?;
        // Printable ASCII must not be encoded.
        if text.chars().any(|c| (' '..='~').contains(&c)) {
            return None;
        }
        out.push_str(&text);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_go_both_ways() {
        for (plain, encoded) in [
            ("INBOX", "INBOX"),
            ("Österreich", "&ANY-sterreich"),
            ("Ünï", "&ANw-n&AO8-"),
            ("Ünïcödé", "&ANw-n&AO8-c&APY-d&AOk-"),
            ("A & B", "A &- B"),
            ("日本語", "&ZeVnLIqe-"),
            ("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
            ("😀", "&2D3eAA-"),
        ] {
            assert_eq!(encode(plain), encoded);
            assert_eq!(decode(encoded).as_deref(), Some(plain));
        }
        assert_eq!(decode("&AMQ-sterreich").as_deref(), Some("Ästerreich"));
        for bad in ["&AMQ", "&A-", "&AGE-", "&*-", "Ü", "&2D0-"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
