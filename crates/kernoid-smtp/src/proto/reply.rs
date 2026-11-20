// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replies as the client reads them (RFC 5321, 4.2): lines of a three-digit code, `-` while more lines follow and a
//! space (or nothing) on the last; every line the same code. An enhanced status code (RFC 2034, RFC 3463) at the start
//! of the text is taken apart. The reply to `EHLO` names the server and its extensions (RFC 5321, 4.1.1.1).

use std::fmt;

/// The most a reply may take, its lines together – an `EHLO` reply has many.
pub const MAX_REPLY: usize = 16 * 1024;

/// A reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// The enhanced status code, `[0, 0, 0]` when the server gave none.
    pub esc: [u8; 3],
    /// The text of its lines, joined with LF, without the codes.
    pub message: String,
}

impl fmt::Display for Reply {
    /// As the server writes it, every line with its CRLF.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<&str> = self.message.split('\n').collect();
        let last = lines.len() - 1;
        for (index, line) in lines.into_iter().enumerate() {
            let separator = if index == last { ' ' } else { '-' };
            match self.esc {
                [0, 0, 0] => write!(f, "{}{separator}{line}\r\n", self.code)?,
                [class, subject, detail] => {
                    write!(f, "{}{separator}{class}.{subject}.{detail} {line}\r\n", self.code)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    #[error("not an SMTP reply")]
    Invalid,
    #[error("the reply is too long")]
    TooLong,
}

/// The enhanced status code at the start of `text` with the text after it, if it has one whose class fits `code`.
fn enhanced(code: u16, text: &str) -> Option<([u8; 3], &str)> {
    let (word, rest) = match text.split_once(' ') {
        Some((word, rest)) => (word, rest),
        None => (text, ""),
    };
    let mut parts = word.split('.');
    let mut part = |max: usize| -> Option<u8> {
        let part = parts.next().filter(|part| !part.is_empty() && part.len() <= max)?;
        part.bytes().all(|byte| byte.is_ascii_digit()).then(|| part.parse().ok())?
    };
    let esc = [part(1)?, part(3)?, part(3)?];
    if parts.next().is_some() || !matches!(esc[0], 2 | 4 | 5) || u16::from(esc[0]) != code / 100 {
        return None;
    }
    Some((esc, rest))
}

/// Reads the first complete reply in `input`: the reply and how many bytes it took, or `None` if it is not complete
/// yet. A line that cannot be part of a reply is an error at once.
pub fn parse(input: &[u8]) -> Result<Option<(Reply, usize)>, ReplyError> {
    let mut used = 0;
    let mut code = None;
    let mut lines: Vec<&str> = Vec::new();
    loop {
        let rest = &input[used..];
        let Some(end) = rest.iter().position(|byte| *byte == b'\n') else {
            // An incomplete line is checked as far as it goes.
            if rest.len() >= 3 && !rest[..3].iter().all(u8::is_ascii_digit) {
                return Err(ReplyError::Invalid);
            }
            if input.len() > MAX_REPLY {
                return Err(ReplyError::TooLong);
            }
            return Ok(None);
        };
        let line = &rest[..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        used += end + 1;
        if used > MAX_REPLY {
            return Err(ReplyError::TooLong);
        }
        let line = std::str::from_utf8(line).map_err(|_| ReplyError::Invalid)?;
        let digits = line.get(..3).filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()));
        let Some(this) = digits.and_then(|digits| digits.parse::<u16>().ok()) else {
            return Err(ReplyError::Invalid);
        };
        if !(200..600).contains(&this) || code.is_some_and(|code| code != this) {
            return Err(ReplyError::Invalid);
        }
        code = Some(this);
        let (last, text) = match line.as_bytes().get(3) {
            None => (true, ""),
            Some(b' ') => (true, &line[4..]),
            Some(b'-') => (false, &line[4..]),
            Some(_) => return Err(ReplyError::Invalid),
        };
        lines.push(text);
        if last {
            break;
        }
    }
    let code = code.ok_or(ReplyError::Invalid)?;
    let esc = lines.first().and_then(|first| enhanced(code, first)).map(|(esc, _)| esc).unwrap_or_default();
    let message: Vec<&str> = lines
        .into_iter()
        .map(|line| match enhanced(code, line) {
            Some((found, text)) if found == esc && esc != [0, 0, 0] => text,
            _ => line,
        })
        .collect();
    Ok(Some((Reply { code, esc, message: message.join("\n") }, used)))
}

/// Extensions in an `EHLO` reply, as bits.
pub const EXT_8BIT_MIME: u32 = 1 << 0;
pub const EXT_PIPELINING: u32 = 1 << 1;
pub const EXT_SIZE: u32 = 1 << 2;
pub const EXT_START_TLS: u32 = 1 << 3;
pub const EXT_SMTP_UTF8: u32 = 1 << 4;
pub const EXT_CHUNKING: u32 = 1 << 5;
pub const EXT_ENHANCED_STATUS_CODES: u32 = 1 << 6;
pub const EXT_AUTH: u32 = 1 << 7;
pub const EXT_DSN: u32 = 1 << 8;
pub const EXT_REQUIRE_TLS: u32 = 1 << 9;
pub const EXT_BINARY_MIME: u32 = 1 << 10;

/// The reply to `EHLO`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ehlo {
    /// The name the server gave.
    pub hostname: String,
    /// The extensions offered (`EXT_*`).
    pub capabilities: u32,
    /// `SIZE`'s limit; 0 when none was given.
    pub size: usize,
    /// The SASL mechanisms of `AUTH` (`AUTH_*` of `request`).
    pub auth_mechanisms: u64,
}

impl Ehlo {
    /// No extensions – a server that answered `HELO`.
    pub fn new(hostname: String) -> Self {
        Self { hostname, ..Self::default() }
    }

    pub fn has_capability(&self, capability: u32) -> bool {
        self.capabilities & capability != 0
    }

    /// The extensions of a `250` reply to `EHLO`.
    pub fn from_reply(reply: &Reply) -> Self {
        let mut lines = reply.message.split('\n');
        let hostname = lines.next().unwrap_or_default().split(' ').next().unwrap_or_default().to_owned();
        let mut ehlo = Self::new(hostname);
        for line in lines {
            let mut words = line.split_ascii_whitespace();
            let Some(keyword) = words.next() else { continue };
            let capability = match keyword.to_ascii_uppercase().as_str() {
                "8BITMIME" => EXT_8BIT_MIME,
                "PIPELINING" => EXT_PIPELINING,
                "SIZE" => {
                    ehlo.size = words.next().and_then(|size| size.parse().ok()).unwrap_or(0);
                    EXT_SIZE
                }
                "STARTTLS" => EXT_START_TLS,
                "SMTPUTF8" => EXT_SMTP_UTF8,
                "CHUNKING" => EXT_CHUNKING,
                "ENHANCEDSTATUSCODES" => EXT_ENHANCED_STATUS_CODES,
                "AUTH" => {
                    ehlo.auth_mechanisms |= words.map(super::request::mechanism).fold(0, |all, one| all | one);
                    EXT_AUTH
                }
                "DSN" => EXT_DSN,
                "REQUIRETLS" => EXT_REQUIRE_TLS,
                "BINARYMIME" => EXT_BINARY_MIME,
                _ => 0,
            };
            ehlo.capabilities |= capability;
        }
        ehlo
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::request::AUTH_PLAIN;

    #[test]
    fn replies_of_one_and_more_lines() {
        let (reply, used) = parse(b"250 2.1.0 OK\r\nrest").unwrap().unwrap();
        assert_eq!((reply.code, reply.esc, reply.message.as_str(), used), (250, [2, 1, 0], "OK", 14));
        let (reply, _) = parse(b"550-5.1.1 No such\r\n550 5.1.1 user\r\n").unwrap().unwrap();
        assert_eq!((reply.code, reply.esc, reply.message.as_str()), (550, [5, 1, 1], "No such\nuser"));
        assert_eq!(reply.to_string(), "550-5.1.1 No such\r\n550 5.1.1 user\r\n");
        let (reply, _) = parse(b"220 mx ESMTP\n").unwrap().unwrap();
        assert_eq!((reply.esc, reply.message.as_str()), ([0, 0, 0], "mx ESMTP"));
        let (reply, _) = parse(b"354\r\n").unwrap().unwrap();
        assert_eq!(reply.code, 354);
        // A class that does not fit the code is text.
        let (reply, _) = parse(b"250 5.0.0 odd\r\n").unwrap().unwrap();
        assert_eq!((reply.esc, reply.message.as_str()), ([0, 0, 0], "5.0.0 odd"));
        assert_eq!(parse(b"250-first\r\n250 sec").unwrap(), None);
        assert_eq!(parse(b"25").unwrap(), None);
    }

    #[test]
    fn what_is_no_reply_is_refused() {
        for broken in [
            &b"HTTP/1.1 400 Bad Request\r\n"[..],
            b"HTTP",
            b"250-a\r\n251 b\r\n",
            b"250xok\r\n",
            b"999 what\r\n",
            b"\xff\xfe\xfd\r\n",
        ] {
            assert!(parse(broken).is_err(), "{}", String::from_utf8_lossy(broken));
        }
        let long = format!("250-{}\r\n", "x".repeat(MAX_REPLY));
        assert_eq!(parse(long.as_bytes()), Err(ReplyError::TooLong));
    }

    #[test]
    fn ehlo_lists_the_extensions() {
        let text = b"250-mx.other.example Hello\r\n250-SIZE 1000\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n\
                     250-STARTTLS\r\n250-X-UNKNOWN\r\n250 SMTPUTF8\r\n";
        let (reply, _) = parse(text).unwrap().unwrap();
        let ehlo = Ehlo::from_reply(&reply);
        assert_eq!(ehlo.hostname, "mx.other.example");
        assert_eq!(ehlo.size, 1000);
        for capability in [EXT_SIZE, EXT_PIPELINING, EXT_AUTH, EXT_START_TLS, EXT_SMTP_UTF8] {
            assert!(ehlo.has_capability(capability));
        }
        assert!(!ehlo.has_capability(EXT_CHUNKING));
        assert!(ehlo.auth_mechanisms & AUTH_PLAIN != 0);
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b"0123456789 -.\r\n\xc3\xa4ab";
        for _ in 0..20_000 {
            let length = (next() % 60) as usize;
            let input: Vec<u8> = (0..length).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
            if let Ok(Some((reply, _))) = parse(&input) {
                let _ = Ehlo::from_reply(&reply);
                let _ = reply.to_string();
            }
        }
    }
}
