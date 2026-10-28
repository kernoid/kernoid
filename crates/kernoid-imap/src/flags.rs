// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP flags are JMAP keywords (RFC 8621, 4.1.1): `\Seen` is `$seen`, and so on; `\Deleted` is `$deleted` (which
//! only IMAP's `EXPUNGE` acts on); `$Important` and `\Important` are `$important`, shown as `$Important`.
//! `\Recent` is never set (RFC 9051 dropped it).

use kernoid_mail::{Keyword, Rights};

use crate::proto::protocol::Flag;

/// The keyword of a flag; `None` for `\Recent` and other system flags kernoid does not keep.
pub(crate) fn keyword(flag: &Flag) -> Option<Keyword> {
    let mut name = Vec::new();
    flag.serialize(&mut name);
    let name = String::from_utf8(name).ok()?.to_ascii_lowercase();
    let name = match name.as_str() {
        "\\seen" | "\\draft" | "\\flagged" | "\\answered" | "\\deleted" | "\\important" => format!("${}", &name[1..]),
        system if system.starts_with('\\') => return None,
        _ => name,
    };
    Keyword::parse(&name).ok()
}

/// The flag of a stored keyword.
pub(crate) fn flag(keyword: &str) -> Flag {
    match Flag::parse_jmap(keyword.to_owned()) {
        Flag::Important => Flag::Keyword("$Important".into()),
        flag => flag,
    }
}

/// The right a keyword needs (RFC 4314, 4): `s` for `\Seen`, `t` for `\Deleted`, `w` for the others.
pub(crate) fn right(keyword: &str) -> Rights {
    match keyword {
        Keyword::SEEN => Rights::SEEN,
        "$deleted" => Rights::DELETE,
        _ => Rights::WRITE,
    }
}

pub(crate) fn flags(keywords: &[String]) -> Vec<Flag> {
    keywords.iter().map(|keyword| flag(keyword)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_flags_are_dollar_keywords() {
        assert_eq!(keyword(&Flag::Seen).unwrap().as_str(), "$seen");
        assert_eq!(keyword(&Flag::Deleted).unwrap().as_str(), "$deleted");
        assert_eq!(keyword(&Flag::Forwarded).unwrap().as_str(), "$forwarded");
        assert_eq!(keyword(&Flag::Keyword("Work".into())).unwrap().as_str(), "work");
        assert_eq!(keyword(&Flag::Recent), None);
        assert_eq!(keyword(&Flag::Important).unwrap().as_str(), "$important");
        let mut out = Vec::new();
        for flag in flags(&["$seen".into(), "$deleted".into(), "work".into()]) {
            flag.serialize(&mut out);
            out.push(b' ');
        }
        assert_eq!(out, b"\\Seen \\Deleted work ");
    }
}
