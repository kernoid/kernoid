// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tag lists (RFC 6376, 3.2): `name=value` pairs separated by `;`, with folding whitespace around names and values.
//! DKIM signatures and keys, ARC's headers and DMARC records (RFC 7489, 6.4) are written in them.

use std::ops::Range;

/// A tag: its name, its value without the whitespace around it, and where the value stands in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub value: String,
    /// The bytes after `=` up to the `;` that ends the tag (or the end): the value with the whitespace around it, as
    /// DKIM removes it for `b=` (RFC 6376, 3.7).
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    #[error("a tag without '='")]
    NoEquals,
    #[error("an invalid tag name")]
    InvalidName,
    #[error("an invalid tag value of {0}")]
    InvalidValue(String),
    #[error("the tag {0} appears twice")]
    Duplicate(String),
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Parses a tag list.
pub fn parse(input: &[u8]) -> Result<Vec<Tag>, TagError> {
    let mut tags: Vec<Tag> = Vec::new();
    let mut start = 0;
    while start <= input.len() {
        let end = input[start..].iter().position(|byte| *byte == b';').map_or(input.len(), |at| start + at);
        let segment = &input[start..end];
        if segment.iter().all(|byte| is_whitespace(*byte)) {
            // An empty tag: only a trailing `;` makes one, and it is allowed (RFC 6376, 3.2) – others are tolerated.
            start = end + 1;
            continue;
        }
        let equals = segment.iter().position(|byte| *byte == b'=').ok_or(TagError::NoEquals)?;
        let name = std::str::from_utf8(segment[..equals].trim_ascii()).map_err(|_| TagError::InvalidName)?;
        let valid_name = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_name {
            return Err(TagError::InvalidName);
        }
        let raw_value = &segment[equals + 1..];
        let value = std::str::from_utf8(raw_value.trim_ascii())
            .ok()
            .filter(|value| value.chars().all(|c| !c.is_control() || matches!(c, ' ' | '\t' | '\r' | '\n')))
            .ok_or_else(|| TagError::InvalidValue(name.to_owned()))?;
        if tags.iter().any(|tag| tag.name == name) {
            return Err(TagError::Duplicate(name.to_owned()));
        }
        let value_start = start + equals + 1;
        tags.push(Tag { name: name.to_owned(), value: value.to_owned(), span: value_start..end });
        start = end + 1;
    }
    Ok(tags)
}

/// The value of a tag.
pub fn get<'a>(tags: &'a [Tag], name: &str) -> Option<&'a str> {
    tags.iter().find(|tag| tag.name == name).map(|tag| tag.value.as_str())
}

/// A value with all whitespace removed – base64 in `b=`, `bh=` and `p=`.
pub fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Folding whitespace inside a value made single spaces: `h=from : to` and the like.
pub fn words(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_with_folding_and_a_trailing_semicolon() {
        let input = b" v=1; a=rsa-sha256;\r\n\tb=AbC\r\n dEf ;bh=x=;";
        let tags = parse(input).unwrap();
        assert_eq!(tags.len(), 4);
        assert_eq!(get(&tags, "b"), Some("AbC\r\n dEf"));
        assert_eq!(compact(get(&tags, "b").unwrap()), "AbCdEf");
        assert_eq!(get(&tags, "bh"), Some("x="));
        let b = &tags[2];
        assert_eq!(&input[b.span.clone()], b"AbC\r\n dEf ");
        assert_eq!(get(&tags, "x"), None);
    }

    #[test]
    fn broken_lists_are_refused() {
        assert_eq!(parse(b"v=1; a"), Err(TagError::NoEquals));
        assert_eq!(parse(b"1v=1"), Err(TagError::InvalidName));
        assert_eq!(parse(b"v=1; v=2"), Err(TagError::Duplicate("v".into())));
        assert!(parse(b"v=\x01").is_err());
        assert_eq!(parse(b"").unwrap(), Vec::new());
        assert_eq!(parse(b";;").unwrap(), Vec::new());
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x1234_5678_9abc_def1u64;
        let alphabet = b"ab=; \t\r\nv1_\xc3\xa4\x00";
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state % 40) as usize;
            let input: Vec<u8> = (0..length).map(|i| alphabet[((state >> (i % 60)) as usize + i) % alphabet.len()]).collect();
            let _ = parse(&input);
        }
    }
}
