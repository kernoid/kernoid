// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writing responses (RFC 9051, 7): status responses with their codes, strings – quoted when they can be, literals
//! when not –, mailbox names in UTF-8 or modified UTF-7, flag lists and `FETCH` responses.

use std::fmt;

use super::{sequence, utf7};

/// The response codes kernoid sends (RFC 9051, 7.1, and the extensions').
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Code {
    Capability(String),
    PermanentFlags(&'static str),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
    Closed,
    HighestModSeq(u64),
    /// CONDSTORE (RFC 7162): the messages a conditional `STORE` left alone.
    Modified(Vec<u32>),
    /// UIDPLUS (RFC 4315).
    AppendUid {
        uid_validity: u32,
        uids: Vec<u32>,
    },
    CopyUid {
        uid_validity: u32,
        source: Vec<u32>,
        target: Vec<u32>,
    },
    /// RFC 5530.
    NonExistent,
    NoPerm,
    Cannot,
    AlreadyExists,
    HasChildren,
    ExpungeIssued,
    OverQuota,
    TooBig,
    Unavailable,
    AuthenticationFailed,
    PrivacyRequired,
    /// BINARY (RFC 3516).
    UnknownCte,
    BadCharset,
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Code::Capability(list) => write!(f, "CAPABILITY {list}"),
            Code::PermanentFlags(flags) => write!(f, "PERMANENTFLAGS ({flags})"),
            Code::ReadOnly => f.write_str("READ-ONLY"),
            Code::ReadWrite => f.write_str("READ-WRITE"),
            Code::TryCreate => f.write_str("TRYCREATE"),
            Code::UidNext(uid) => write!(f, "UIDNEXT {uid}"),
            Code::UidValidity(validity) => write!(f, "UIDVALIDITY {validity}"),
            Code::Unseen(number) => write!(f, "UNSEEN {number}"),
            Code::Closed => f.write_str("CLOSED"),
            Code::HighestModSeq(modseq) => write!(f, "HIGHESTMODSEQ {modseq}"),
            Code::Modified(numbers) => write!(f, "MODIFIED {}", sequence::compact(numbers)),
            Code::AppendUid { uid_validity, uids } => {
                write!(f, "APPENDUID {uid_validity} {}", sequence::ordered(uids))
            }
            Code::CopyUid { uid_validity, source, target } => {
                write!(f, "COPYUID {uid_validity} {} {}", sequence::ordered(source), sequence::ordered(target))
            }
            Code::NonExistent => f.write_str("NONEXISTENT"),
            Code::NoPerm => f.write_str("NOPERM"),
            Code::Cannot => f.write_str("CANNOT"),
            Code::AlreadyExists => f.write_str("ALREADYEXISTS"),
            Code::HasChildren => f.write_str("HASCHILDREN"),
            Code::ExpungeIssued => f.write_str("EXPUNGEISSUED"),
            Code::OverQuota => f.write_str("OVERQUOTA"),
            Code::TooBig => f.write_str("TOOBIG"),
            Code::Unavailable => f.write_str("UNAVAILABLE"),
            Code::AuthenticationFailed => f.write_str("AUTHENTICATIONFAILED"),
            Code::PrivacyRequired => f.write_str("PRIVACYREQUIRED"),
            Code::UnknownCte => f.write_str("UNKNOWN-CTE"),
            Code::BadCharset => f.write_str("BADCHARSET (UTF-8 US-ASCII)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Ok,
    No,
    Bad,
    Bye,
}

/// A status response: `OK`, `NO`, `BAD` or `BYE`, with a code and a text. An `OK` without a text is a command's
/// completion; the session writes `<COMMAND> completed` for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    pub kind: Kind,
    pub code: Option<Code>,
    pub text: String,
}

impl Status {
    fn new(kind: Kind, text: impl Into<String>) -> Self {
        Self { kind, code: None, text: text.into() }
    }

    /// The command completed.
    pub fn done() -> Self {
        Self::new(Kind::Ok, "")
    }

    pub fn ok(text: impl Into<String>) -> Self {
        Self::new(Kind::Ok, text)
    }

    pub fn no(text: impl Into<String>) -> Self {
        Self::new(Kind::No, text)
    }

    pub fn bad(text: impl Into<String>) -> Self {
        Self::new(Kind::Bad, text)
    }

    pub fn bye(text: impl Into<String>) -> Self {
        Self::new(Kind::Bye, text)
    }

    /// The store could not be reached: try again later.
    pub fn unavailable() -> Self {
        Self::no("Temporary failure, try again later").with_code(Code::Unavailable)
    }

    pub fn with_code(mut self, code: Code) -> Self {
        self.code = Some(code);
        self
    }

    pub fn is_ok(&self) -> bool {
        self.kind == Kind::Ok
    }

    /// The response line, tagged or untagged (`*`).
    pub fn line(&self, tag: Option<&str>) -> Vec<u8> {
        let kind = match self.kind {
            Kind::Ok => "OK",
            Kind::No => "NO",
            Kind::Bad => "BAD",
            Kind::Bye => "BYE",
        };
        let mut line = format!("{} {kind} ", tag.unwrap_or("*"));
        if let Some(code) = &self.code {
            line.push_str(&format!("[{code}] "));
        }
        // A text never carries a line break.
        line.extend(self.text.chars().map(|c| if c.is_control() { ' ' } else { c }));
        line.push_str("\r\n");
        line.into_bytes()
    }
}

/// Whether bytes can go into a quoted string: no line breaks or NUL, at most a line's worth, and 8-bit only in UTF-8.
fn quotable(bytes: &[u8], utf8: bool) -> bool {
    bytes.len() <= 1024
        && bytes.iter().all(|&b| b != 0 && b != b'\r' && b != b'\n' && (b < 0x80 || utf8))
        && (!utf8 || std::str::from_utf8(bytes).is_ok())
}

/// A string: quoted if it can be, else a literal.
pub(crate) fn string(out: &mut Vec<u8>, bytes: &[u8], utf8: bool) {
    if quotable(bytes, utf8) {
        out.push(b'"');
        for &byte in bytes {
            if byte == b'"' || byte == b'\\' {
                out.push(b'\\');
            }
            out.push(byte);
        }
        out.push(b'"');
    } else {
        literal(out, bytes);
    }
}

/// A string, or `NIL`.
pub(crate) fn nstring(out: &mut Vec<u8>, bytes: Option<&[u8]>, utf8: bool) {
    match bytes {
        Some(bytes) => string(out, bytes, utf8),
        None => out.extend_from_slice(b"NIL"),
    }
}

pub(crate) fn literal(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", bytes.len()).as_bytes());
    out.extend_from_slice(bytes);
}

/// A binary literal (RFC 3516): `~{n}`.
pub(crate) fn literal8(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'~');
    literal(out, bytes);
}

/// A mailbox name: UTF-8 when the client enabled it, else modified UTF-7.
pub(crate) fn mailbox(out: &mut Vec<u8>, name: &str, utf8: bool) {
    if utf8 {
        string(out, name.as_bytes(), true);
    } else {
        string(out, utf7::encode(name).as_bytes(), false);
    }
}

/// `(\Seen $Work)`.
pub(crate) fn flag_list(out: &mut Vec<u8>, flags: &[String]) {
    out.push(b'(');
    for (index, flag) in flags.iter().enumerate() {
        if index > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(flag.as_bytes());
    }
    out.push(b')');
}

/// `* n FETCH (…)`, its items written one after another.
pub(crate) struct FetchResponse {
    out: Vec<u8>,
    first: bool,
}

impl FetchResponse {
    pub fn new(number: u32) -> Self {
        Self { out: format!("* {number} FETCH (").into_bytes(), first: true }
    }

    /// The buffer for the next item, after the space that separates it from the one before.
    pub fn item(&mut self) -> &mut Vec<u8> {
        if !self.first {
            self.out.push(b' ');
        }
        self.first = false;
        &mut self.out
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.out.extend_from_slice(b")\r\n");
        self.out
    }
}

/// `"17-Jul-1996 02:44:25 +0000"`: an internal date, in UTC.
pub(crate) fn internal_date(out: &mut Vec<u8>, timestamp: jiff::Timestamp) {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let at = jiff::tz::Offset::UTC.to_datetime(timestamp);
    let month = MONTHS[(at.month() - 1).clamp(0, 11) as usize];
    out.extend_from_slice(
        format!(
            "\"{:>2}-{month}-{:04} {:02}:{:02}:{:02} +0000\"",
            at.day(),
            at.year(),
            at.hour(),
            at.minute(),
            at.second()
        )
        .as_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(write: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut out = Vec::new();
        write(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn strings_quoted_or_literal() {
        assert_eq!(written(|out| string(out, b"Quote \"me\" \\", false)), "\"Quote \\\"me\\\" \\\\\"");
        assert_eq!(written(|out| string(out, b"two\r\nlines", false)), "{10}\r\ntwo\r\nlines");
        assert_eq!(written(|out| string(out, "Grüße".as_bytes(), false)), "{7}\r\nGrüße");
        assert_eq!(written(|out| string(out, "Grüße".as_bytes(), true)), "\"Grüße\"");
        assert_eq!(written(|out| nstring(out, None, true)), "NIL");
        assert_eq!(written(|out| literal8(out, b"\0x")), "~{2}\r\n\0x");
        assert_eq!(written(|out| mailbox(out, "Österreich", false)), "\"&ANY-sterreich\"");
        assert_eq!(written(|out| mailbox(out, "Österreich", true)), "\"Österreich\"");
        assert_eq!(written(|out| flag_list(out, &["\\Seen".into(), "$Work".into()])), "(\\Seen $Work)");
        assert_eq!(
            written(|out| internal_date(out, "2026-11-05T09:03:07Z".parse().unwrap())),
            "\" 5-Nov-2026 09:03:07 +0000\""
        );
    }

    #[test]
    fn status_lines() {
        let line = Status::no("No such\r\nmailbox").with_code(Code::NonExistent).line(Some("a1"));
        assert_eq!(line, b"a1 NO [NONEXISTENT] No such  mailbox\r\n");
        let code = Code::CopyUid { uid_validity: 7, source: vec![3, 4, 9], target: vec![10, 11, 12] };
        assert_eq!(Status::ok("Moved").with_code(code).line(None), b"* OK [COPYUID 7 3:4,9 10:12] Moved\r\n");
        assert_eq!(
            Status::done().with_code(Code::Modified(vec![9, 2, 3])).line(Some("t")),
            b"t OK [MODIFIED 2:3,9] \r\n"
        );
        let mut fetch = FetchResponse::new(3);
        fetch.item().extend_from_slice(b"UID 7");
        fetch.item().extend_from_slice(b"FLAGS ()");
        assert_eq!(fetch.finish(), b"* 3 FETCH (UID 7 FLAGS ())\r\n");
    }
}
