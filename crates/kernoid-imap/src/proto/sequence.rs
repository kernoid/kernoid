// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sequence sets (RFC 9051, 9: `sequence-set`): numbers and ranges of message sequence numbers or UIDs, `*` for the
//! largest one in use and `$` for the result of the last `SEARCH … SAVE` (RFC 5182) – and the compact form of a list
//! of numbers that responses use.

use std::fmt::Write;

/// One end of a range: a number, or `*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    Number(u32),
    Last,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item {
    /// `n`, `*`, or `n:m` in either order.
    Range(Bound, Bound),
    /// `$`.
    Saved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SequenceSet(pub Vec<Item>);

impl Bound {
    fn value(self, last: u32) -> u32 {
        match self {
            Bound::Number(number) => number,
            Bound::Last => last,
        }
    }
}

impl SequenceSet {
    /// Whether `value` is in the set; `last` is what `*` stands for, `saved` whether the message is in the saved
    /// result.
    pub fn contains(&self, value: u32, last: u32, saved: bool) -> bool {
        self.0.iter().any(|item| match item {
            Item::Saved => saved,
            Item::Range(from, to) => {
                let (from, to) = (from.value(last), to.value(last));
                (from.min(to)..=from.max(to)).contains(&value)
            }
        })
    }

    /// Parses `1,3:5,7:*,$`; `None` for anything else.
    pub fn parse(text: &[u8]) -> Option<Self> {
        fn bound(text: &[u8]) -> Option<Bound> {
            if text == b"*" {
                return Some(Bound::Last);
            }
            if text.is_empty() || text.len() > 10 || !text.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let number: u32 = std::str::from_utf8(text).ok()?.parse().ok()?;
            (number > 0).then_some(Bound::Number(number))
        }
        if text.is_empty() {
            return None;
        }
        let mut items = Vec::new();
        for part in text.split(|&byte| byte == b',') {
            if part == b"$" {
                items.push(Item::Saved);
                continue;
            }
            let item = match part.iter().position(|&byte| byte == b':') {
                Some(colon) => Item::Range(bound(&part[..colon])?, bound(&part[colon + 1..])?),
                None => {
                    let single = bound(part)?;
                    Item::Range(single, single)
                }
            };
            items.push(item);
        }
        Some(Self(items))
    }
}

/// Numbers in the order given, consecutive runs as ranges: `1:3,7,5` – for `COPYUID`, whose two lists pair up.
pub(crate) fn ordered(numbers: &[u32]) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index < numbers.len() {
        let start = numbers[index];
        let mut end = start;
        while index + 1 < numbers.len() && end.checked_add(1) == Some(numbers[index + 1]) {
            index += 1;
            end = numbers[index];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            let _ = write!(out, "{start}");
        } else {
            let _ = write!(out, "{start}:{end}");
        }
        index += 1;
    }
    out
}

/// Numbers sorted and without duplicates, as ranges.
pub(crate) fn compact(numbers: &[u32]) -> String {
    let mut sorted = numbers.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    ordered(&sorted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_parse_and_match() {
        let set = SequenceSet::parse(b"1,3:5,9:*").unwrap();
        assert!(set.contains(1, 12, false) && !set.contains(2, 12, false) && set.contains(4, 12, false));
        assert!(set.contains(12, 12, false) && !set.contains(13, 12, false));
        // `n:*` with `*` below `n` is the range from `*` to `n`.
        assert!(SequenceSet::parse(b"100:*").unwrap().contains(50, 50, false));
        assert!(SequenceSet::parse(b"5:2").unwrap().contains(3, 9, false));
        assert!(SequenceSet::parse(b"$").unwrap().contains(7, 9, true));
        assert!(!SequenceSet::parse(b"$,1").unwrap().contains(7, 9, false));
        for bad in [&b""[..], b"0", b"1,", b",1", b"1:", b"a", b"1::2", b"99999999999", b"4294967296", b"*:x"] {
            assert_eq!(SequenceSet::parse(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        assert!(SequenceSet::parse(b"4294967295").is_some());
    }

    #[test]
    fn numbers_compact() {
        assert_eq!(compact(&[6, 1, 2, 4, 2, 3]), "1:4,6");
        assert_eq!(ordered(&[3, 4, 1, 9, 10]), "3:4,1,9:10");
        assert_eq!(ordered(&[u32::MAX, 1]), "4294967295,1");
        assert_eq!(compact(&[]), "");
    }
}
