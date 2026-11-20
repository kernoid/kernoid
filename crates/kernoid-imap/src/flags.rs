// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP flags are JMAP keywords (RFC 8621, 4.1.1): `\Seen` is `$seen`, and so on; `\Deleted` is `$deleted` (which
//! only IMAP's `EXPUNGE` acts on); `$Important` and `\Important` are `$important`, shown as `$Important`.
//! `\Recent` is never set (RFC 9051 dropped it).

use kernoid_mail::{Keyword, Rights};

/// The system flags kernoid keeps, by their keyword.
const SYSTEM: [(&str, &str); 5] = [
    ("$seen", "\\Seen"),
    ("$answered", "\\Answered"),
    ("$flagged", "\\Flagged"),
    ("$deleted", "\\Deleted"),
    ("$draft", "\\Draft"),
];

/// Keywords of the IANA registry, shown as registered.
const REGISTERED: [&str; 6] = ["$Forwarded", "$MDNSent", "$Junk", "$NotJunk", "$Phishing", "$Important"];

/// The keyword of a flag; `None` for `\Recent` and other system flags kernoid does not keep.
pub(crate) fn keyword(flag: &str) -> Option<Keyword> {
    let name = flag.to_ascii_lowercase();
    let name = match name.strip_prefix('\\') {
        Some(system @ ("seen" | "draft" | "flagged" | "answered" | "deleted" | "important")) => format!("${system}"),
        Some(_) => return None,
        None => name,
    };
    Keyword::parse(&name).ok()
}

/// The flag of a stored keyword.
pub(crate) fn flag(keyword: &str) -> String {
    if let Some((_, system)) = SYSTEM.iter().find(|(stored, _)| *stored == keyword) {
        return (*system).to_owned();
    }
    match REGISTERED.iter().find(|registered| registered.eq_ignore_ascii_case(keyword)) {
        Some(registered) => (*registered).to_owned(),
        None => keyword.to_owned(),
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

pub(crate) fn flags(keywords: &[String]) -> Vec<String> {
    keywords.iter().map(|keyword| flag(keyword)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_flags_are_dollar_keywords() {
        assert_eq!(keyword("\\Seen").unwrap().as_str(), "$seen");
        assert_eq!(keyword("\\DELETED").unwrap().as_str(), "$deleted");
        assert_eq!(keyword("$Forwarded").unwrap().as_str(), "$forwarded");
        assert_eq!(keyword("Work").unwrap().as_str(), "work");
        assert_eq!(keyword("\\Recent"), None);
        assert_eq!(keyword("\\Important").unwrap().as_str(), "$important");
        assert_eq!(
            flags(&["$seen".into(), "$deleted".into(), "work".into(), "$junk".into(), "$important".into()]),
            ["\\Seen", "\\Deleted", "work", "$Junk", "$Important"]
        );
    }
}
