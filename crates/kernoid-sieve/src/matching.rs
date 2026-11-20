// SPDX-License-Identifier: AGPL-3.0-or-later
//! Comparators (RFC 4790: `i;octet`, `i;ascii-casemap`, `i;ascii-numeric`) and match types (RFC 5228, 2.7: `:is`,
//! `:contains`, `:matches`; RFC 5231: `:count`, `:value`).

use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Comparator {
    Octet,
    AsciiCaseMap,
    AsciiNumeric,
}

impl Comparator {
    pub(crate) fn from_name(name: &str) -> Option<Comparator> {
        match name.to_ascii_lowercase().as_str() {
            "i;octet" => Some(Comparator::Octet),
            "i;ascii-casemap" => Some(Comparator::AsciiCaseMap),
            "i;ascii-numeric" => Some(Comparator::AsciiNumeric),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Relation {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

impl Relation {
    pub(crate) fn from_name(name: &str) -> Option<Relation> {
        match name.to_ascii_lowercase().as_str() {
            "gt" => Some(Relation::Gt),
            "ge" => Some(Relation::Ge),
            "lt" => Some(Relation::Lt),
            "le" => Some(Relation::Le),
            "eq" => Some(Relation::Eq),
            "ne" => Some(Relation::Ne),
            _ => None,
        }
    }

    fn holds(self, ordering: Ordering) -> bool {
        match self {
            Relation::Gt => ordering == Ordering::Greater,
            Relation::Ge => ordering != Ordering::Less,
            Relation::Lt => ordering == Ordering::Less,
            Relation::Le => ordering != Ordering::Greater,
            Relation::Eq => ordering == Ordering::Equal,
            Relation::Ne => ordering != Ordering::Equal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchType {
    Is,
    Contains,
    Matches,
    Count(Relation),
    Value(Relation),
}

/// How a test compares: the match type with its comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Matcher {
    pub kind: MatchType,
    pub comparator: Comparator,
}

impl Default for Matcher {
    fn default() -> Self {
        Matcher { kind: MatchType::Is, comparator: Comparator::AsciiCaseMap }
    }
}

/// The digits `i;ascii-numeric` sees at the start of a string, without leading zeros; `None` (no digit) is
/// positive infinity.
fn numeric(text: &str) -> Option<&str> {
    let end = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    if end == 0 {
        return None;
    }
    let digits = text[..end].trim_start_matches('0');
    Some(if digits.is_empty() { "0" } else { digits })
}

fn order(comparator: Comparator, value: &str, key: &str) -> Ordering {
    match comparator {
        Comparator::Octet => value.as_bytes().cmp(key.as_bytes()),
        Comparator::AsciiCaseMap => {
            value.bytes().map(|b| b.to_ascii_lowercase()).cmp(key.bytes().map(|b| b.to_ascii_lowercase()))
        }
        Comparator::AsciiNumeric => match (numeric(value), numeric(key)) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        },
    }
}

impl Matcher {
    /// Whether `value` matches `key`; a successful `:matches` fills `captures` with the whole value and what each
    /// wildcard took (RFC 5229, 3.2). Not for `:count`, which counts values.
    pub(crate) fn matches(&self, value: &str, key: &str, captures: &mut Option<Vec<String>>) -> bool {
        match self.kind {
            MatchType::Is => order(self.comparator, value, key) == Ordering::Equal,
            MatchType::Value(relation) => relation.holds(order(self.comparator, value, key)),
            MatchType::Count(_) => false,
            MatchType::Contains => match self.comparator {
                Comparator::Octet => value.contains(key),
                _ => value.to_ascii_lowercase().contains(&key.to_ascii_lowercase()),
            },
            MatchType::Matches => {
                let fold = self.comparator != Comparator::Octet;
                glob(value, key, fold, captures)
            }
        }
    }

    /// For `:count`: whether the number of values stands in the relation to `key`.
    pub(crate) fn count(&self, count: usize, key: &str) -> bool {
        match self.kind {
            MatchType::Count(relation) => relation.holds(order(self.comparator, &count.to_string(), key)),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Glob {
    Char(char),
    One,
    Any,
}

fn pattern(key: &str) -> Vec<Glob> {
    let mut out = Vec::with_capacity(key.len());
    let mut chars = key.chars();
    while let Some(c) = chars.next() {
        out.push(match c {
            '*' => Glob::Any,
            '?' => Glob::One,
            '\\' => Glob::Char(chars.next().unwrap_or('\\')),
            c => Glob::Char(c),
        });
    }
    out
}

/// `:matches`: `*` takes any run of characters, `?` one, `\` makes the next one plain. A wildcard takes as little
/// as it can, the first one first; the work is at most the product of the lengths.
fn glob(value: &str, key: &str, fold: bool, captures: &mut Option<Vec<String>>) -> bool {
    let pattern = pattern(key);
    let text: Vec<char> = value.chars().collect();
    let same = |a: char, b: char| if fold { a.eq_ignore_ascii_case(&b) } else { a == b };
    // What each wildcard took, as ranges of `text`.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    // The last `*`: its place in the pattern, where it started, how far it reaches, and the spans before it.
    let mut star: Option<(usize, usize, usize, usize)> = None;
    let (mut p, mut t) = (0, 0);
    while t < text.len() {
        match pattern.get(p) {
            Some(Glob::Any) => {
                spans.push((t, t));
                star = Some((p, t, t, spans.len()));
                p += 1;
                continue;
            }
            Some(Glob::One) => {
                spans.push((t, t + 1));
                p += 1;
                t += 1;
                continue;
            }
            Some(Glob::Char(c)) if same(*c, text[t]) => {
                p += 1;
                t += 1;
                continue;
            }
            _ => {}
        }
        let Some((star_p, start, reach, kept)) = star else {
            return false;
        };
        let reach = reach + 1;
        star = Some((star_p, start, reach, kept));
        spans.truncate(kept);
        if let Some(span) = spans.last_mut() {
            *span = (start, reach);
        }
        p = star_p + 1;
        t = reach;
    }
    while pattern.get(p) == Some(&Glob::Any) {
        spans.push((t, t));
        p += 1;
    }
    if p != pattern.len() {
        return false;
    }
    if let Some(captures) = captures {
        captures.clear();
        captures.push(value.to_owned());
        captures.extend(spans.iter().take(9).map(|&(from, to)| text[from..to].iter().collect::<String>()));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(kind: MatchType, comparator: Comparator) -> Matcher {
        Matcher { kind, comparator }
    }

    fn is(comparator: Comparator, value: &str, key: &str) -> bool {
        matcher(MatchType::Is, comparator).matches(value, key, &mut None)
    }

    fn glob_captures(value: &str, key: &str) -> Option<Vec<String>> {
        let mut captures = Some(Vec::new());
        glob(value, key, true, &mut captures).then(|| captures.unwrap())
    }

    #[test]
    fn comparators() {
        assert!(is(Comparator::Octet, "Frobnitzm", "Frobnitzm"));
        assert!(!is(Comparator::Octet, "Frobnitzm", "frobnitzm"));
        assert!(is(Comparator::AsciiCaseMap, "Frobnitzm", "fROBNITZM"));
        assert!(!is(Comparator::AsciiCaseMap, "Ä", "ä"));
        assert!(is(Comparator::AsciiNumeric, "0042", "42"));
        assert!(is(Comparator::AsciiNumeric, "42abc", "42"));
        assert!(is(Comparator::AsciiNumeric, "abc", "def"));
        assert!(!is(Comparator::AsciiNumeric, "abc", "0"));
        let value = |relation, comparator, a: &str, b: &str| {
            matcher(MatchType::Value(relation), comparator).matches(a, b, &mut None)
        };
        assert!(value(Relation::Gt, Comparator::AsciiNumeric, "10", "9"));
        assert!(value(Relation::Gt, Comparator::AsciiNumeric, "x", "99999999999999999999999"));
        assert!(value(Relation::Lt, Comparator::Octet, "10", "9"));
        assert!(value(Relation::Ge, Comparator::AsciiCaseMap, "B", "a"));
        assert!(value(Relation::Le, Comparator::AsciiCaseMap, "A", "a"));
        assert!(value(Relation::Ne, Comparator::Octet, "A", "a"));
        assert!(value(Relation::Eq, Comparator::AsciiNumeric, "007", "7"));
        let count = matcher(MatchType::Count(Relation::Ge), Comparator::AsciiNumeric);
        assert!(count.count(3, "2") && count.count(2, "2") && !count.count(1, "2"));
    }

    #[test]
    fn contains() {
        let contains = |comparator, value, key| matcher(MatchType::Contains, comparator).matches(value, key, &mut None);
        assert!(contains(Comparator::AsciiCaseMap, "Hello World", "WORLD"));
        assert!(!contains(Comparator::Octet, "Hello World", "WORLD"));
        assert!(contains(Comparator::Octet, "anything", ""));
    }

    #[test]
    fn matches_with_wildcards_and_escapes() {
        assert!(glob("Frobnitzm", "fRoB*", true, &mut None));
        assert!(!glob("Frobnitzm", "fRoB*", false, &mut None));
        assert!(glob("", "*", true, &mut None));
        assert!(!glob("", "?", true, &mut None));
        assert!(glob("abc", "a?c", true, &mut None));
        assert!(glob("a*c", "a\\*c", true, &mut None));
        assert!(!glob("abc", "a\\*c", true, &mut None));
        assert!(glob("mississippi", "*ss*ss*", true, &mut None));
        assert!(glob("mississippi", "m*i*i*i*", true, &mut None));
        assert!(!glob("mississippi", "m*x*", true, &mut None));
        assert!(glob("abcabc", "*abc", true, &mut None));
        assert!(glob("äöü", "?ö?", true, &mut None));
        // A long run of stars stays fast.
        let long = "a".repeat(5000);
        assert!(!glob(&long, &"*a".repeat(200).replace("*a*a", "*a*b"), true, &mut None));
    }

    #[test]
    fn match_variables_rfc_5229_examples() {
        assert_eq!(
            glob_captures("[acme-users] [fwd] version 1.0 is out", "[*] *").unwrap(),
            ["[acme-users] [fwd] version 1.0 is out", "acme-users", "[fwd] version 1.0 is out"]
        );
        assert_eq!(
            glob_captures("<coyote@ACME.Example.COM>", "<*@*.*>").unwrap()[1..],
            ["coyote", "ACME", "Example.COM"]
        );
        assert_eq!(glob_captures("abc", "?*?").unwrap()[1..], ["a", "b", "c"]);
        assert_eq!(glob_captures("ab", "a*b*").unwrap()[1..], ["", ""]);
        assert_eq!(glob_captures("xyz", "x*z").unwrap()[1..], ["y"]);
        assert!(glob_captures("xyz", "x*a").is_none());
        assert_eq!(glob_captures(&"x".repeat(12), &"?".repeat(12)).unwrap().len(), 10);
    }
}
