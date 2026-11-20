// SPDX-License-Identifier: AGPL-3.0-or-later
//! What happens to strings: encoded characters (RFC 5228, 2.4.2.4) when the script is compiled, and references to
//! variables (RFC 5229, 3) – kept as a template, filled in when the script runs – with the modifiers of `set`.

/// A string of the script; a template only where `variables` is required and the string refers to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Constant(String),
    Template(Vec<Part>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part {
    Text(String),
    /// A variable by its name in lower case.
    Variable(String),
    /// A match variable: `${0}` to `${9}`; higher numbers are never set.
    Match(usize),
}

impl Value {
    pub(crate) fn constant(&self) -> Option<&str> {
        match self {
            Value::Constant(text) => Some(text),
            Value::Template(_) => None,
        }
    }
}

/// Whether `name` is a variable's name: an identifier (RFC 5229, 3).
pub(crate) fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Finds `${…}` in `text`: the byte range of the whole reference and of what is between the braces.
fn references(text: &str) -> impl Iterator<Item = (usize, usize, usize)> + '_ {
    let mut from = 0;
    std::iter::from_fn(move || {
        let start = from + text[from..].find("${")?;
        let inner = start + 2;
        let close = inner + text[inner..].find('}')?;
        from = start + 1;
        Some((start, inner, close))
    })
}

/// Decodes `${hex:…}` and `${unicode:…}`; a sequence that is not well-formed stays as it is, a code point that is no
/// character or bytes that are no UTF-8 are errors.
pub(crate) fn decode_encoded(text: &str) -> Result<String, String> {
    if !text.contains("${") {
        return Ok(text.to_owned());
    }
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut copied = 0;
    for (start, inner, close) in references(text) {
        if start < copied {
            continue;
        }
        let content = &text[inner..close];
        let decoded = match content.split_once(':') {
            Some((kind, rest)) if kind.eq_ignore_ascii_case("hex") => hex(rest),
            Some((kind, rest)) if kind.eq_ignore_ascii_case("unicode") => unicode(rest)?,
            _ => None,
        };
        if let Some(bytes) = decoded {
            out.extend_from_slice(&text.as_bytes()[copied..start]);
            out.extend_from_slice(&bytes);
            copied = close + 1;
        }
    }
    out.extend_from_slice(&text.as_bytes()[copied..]);
    String::from_utf8(out).map_err(|_| "encoded characters that are not UTF-8".to_owned())
}

fn blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn hex(text: &str) -> Option<Vec<u8>> {
    let words: Vec<&str> = text.split(blank).filter(|word| !word.is_empty()).collect();
    if words.is_empty() {
        return None;
    }
    let mut bytes = Vec::new();
    for word in words {
        if word.len() % 2 != 0 || !word.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        for pair in word.as_bytes().chunks(2) {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
        }
    }
    Some(bytes)
}

fn unicode(text: &str) -> Result<Option<Vec<u8>>, String> {
    let words: Vec<&str> = text.split(blank).filter(|word| !word.is_empty()).collect();
    if words.is_empty() || !words.iter().all(|word| word.len() <= 6 && word.chars().all(|c| c.is_ascii_hexdigit())) {
        return Ok(None);
    }
    let mut out = String::new();
    for word in words {
        let point = u32::from_str_radix(word, 16).map_err(|_| "a malformed code point".to_owned())?;
        let c = char::from_u32(point).ok_or_else(|| format!("U+{point:X} is not a character"))?;
        out.push(c);
    }
    Ok(Some(out.into_bytes()))
}

/// The template of `text`: `${name}` and `${N}`; anything else after `${` is text.
pub(crate) fn template(text: String) -> Value {
    if !text.contains("${") {
        return Value::Constant(text);
    }
    let mut parts = Vec::new();
    let mut copied = 0;
    for (start, inner, close) in references(&text) {
        if start < copied {
            continue;
        }
        let content = &text[inner..close];
        let part = if !content.is_empty() && content.chars().all(|c| c.is_ascii_digit()) {
            let digits = content.trim_start_matches('0');
            Part::Match(if digits.is_empty() { 0 } else { digits.parse().unwrap_or(usize::MAX) })
        } else if is_identifier(content) {
            Part::Variable(content.to_ascii_lowercase())
        } else {
            continue;
        };
        if start > copied {
            parts.push(Part::Text(text[copied..start].to_owned()));
        }
        parts.push(part);
        copied = close + 1;
    }
    if parts.is_empty() {
        return Value::Constant(text);
    }
    if copied < text.len() {
        parts.push(Part::Text(text[copied..].to_owned()));
    }
    Value::Template(parts)
}

/// A modifier of `set` (RFC 5229, 4.1; `:encodeurl` from RFC 5435, 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modifier {
    Lower,
    Upper,
    LowerFirst,
    UpperFirst,
    QuoteWildcard,
    EncodeUrl,
    Length,
}

impl Modifier {
    pub(crate) fn from_tag(tag: &str) -> Option<Modifier> {
        Some(match tag {
            "lower" => Modifier::Lower,
            "upper" => Modifier::Upper,
            "lowerfirst" => Modifier::LowerFirst,
            "upperfirst" => Modifier::UpperFirst,
            "quotewildcard" => Modifier::QuoteWildcard,
            "encodeurl" => Modifier::EncodeUrl,
            "length" => Modifier::Length,
            _ => return None,
        })
    }

    /// Higher goes first; two of the same precedence are an error.
    pub(crate) fn precedence(self) -> u8 {
        match self {
            Modifier::Lower | Modifier::Upper => 40,
            Modifier::LowerFirst | Modifier::UpperFirst => 30,
            Modifier::QuoteWildcard => 20,
            Modifier::EncodeUrl => 15,
            Modifier::Length => 10,
        }
    }

    pub(crate) fn apply(self, value: String) -> String {
        match self {
            Modifier::Lower => value.to_lowercase(),
            Modifier::Upper => value.to_uppercase(),
            Modifier::LowerFirst | Modifier::UpperFirst => {
                let mut chars = value.chars();
                match chars.next() {
                    Some(first) if self == Modifier::LowerFirst => first.to_lowercase().chain(chars).collect(),
                    Some(first) => first.to_uppercase().chain(chars).collect(),
                    None => value,
                }
            }
            Modifier::QuoteWildcard => {
                let mut out = String::with_capacity(value.len());
                for c in value.chars() {
                    if matches!(c, '*' | '?' | '\\') {
                        out.push('\\');
                    }
                    out.push(c);
                }
                out
            }
            Modifier::EncodeUrl => {
                let mut out = String::with_capacity(value.len());
                for byte in value.bytes() {
                    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                        out.push(char::from(byte));
                    } else {
                        out.push_str(&format!("%{byte:02X}"));
                    }
                }
                out
            }
            Modifier::Length => value.chars().count().to_string(),
        }
    }
}

/// `text` cut to at most `max` bytes, at a character's boundary.
pub(crate) fn truncate(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_characters_rfc_5228_examples() {
        assert_eq!(decode_encoded("${hex:40}").unwrap(), "@");
        assert_eq!(decode_encoded("${hex: 40 }").unwrap(), "@");
        assert_eq!(decode_encoded("${HEX: 40}").unwrap(), "@");
        assert_eq!(decode_encoded("${hex:40").unwrap(), "${hex:40");
        assert_eq!(decode_encoded("${hex:400}").unwrap(), "${hex:400}");
        assert_eq!(decode_encoded("${hex:4${hex:30}}").unwrap(), "${hex:40}");
        assert_eq!(decode_encoded("${unicode:40}").unwrap(), "@");
        assert_eq!(decode_encoded("${ unicode:40}").unwrap(), "${ unicode:40}");
        assert_eq!(decode_encoded("${UNICODE:40}").unwrap(), "@");
        assert_eq!(decode_encoded("${UnICoDE:0000040}").unwrap(), "${UnICoDE:0000040}");
        assert_eq!(decode_encoded("${Unicode:40}").unwrap(), "@");
        assert_eq!(decode_encoded("${Unicode:Cool}").unwrap(), "${Unicode:Cool}");
        assert_eq!(decode_encoded("${unicode:}").unwrap(), "${unicode:}");
        assert_eq!(decode_encoded("${hex:e2 98 ba} ${unicode: 263a 20 263A}").unwrap(), "☺ ☺ ☺");
        assert_eq!(decode_encoded("${hex:c3}${hex:a4}").unwrap(), "ä");
        assert!(decode_encoded("${unicode:D800}").is_err());
        assert!(decode_encoded("${unicode:110000}").is_err());
        assert!(decode_encoded("${hex:ff}").is_err());
    }

    #[test]
    fn templates_find_variables_and_match_variables() {
        assert_eq!(template("plain".into()), Value::Constant("plain".into()));
        assert_eq!(
            template("a${Name}b${1}${x.y}${}${0002}".into()),
            Value::Template(vec![
                Part::Text("a".into()),
                Part::Variable("name".into()),
                Part::Text("b".into()),
                Part::Match(1),
                Part::Text("${x.y}${}".into()),
                Part::Match(2),
            ])
        );
        assert_eq!(
            template("${${a}}".into()),
            Value::Template(vec![Part::Text("${".into()), Part::Variable("a".into()), Part::Text("}".into()),])
        );
        assert_eq!(template("${00}".into()), Value::Template(vec![Part::Match(0)]));
        assert_eq!(template("${99999999999999999999999}".into()), Value::Template(vec![Part::Match(usize::MAX)]));
    }

    #[test]
    fn modifiers_rfc_5229_examples() {
        assert_eq!(Modifier::Upper.apply("juMBlEd lETteRS".into()), "JUMBLED LETTERS");
        assert_eq!(Modifier::Lower.apply("juMBlEd lETteRS".into()), "jumbled letters");
        assert_eq!(Modifier::UpperFirst.apply("juMBlEd lETteRS".into()), "JuMBlEd lETteRS");
        assert_eq!(Modifier::LowerFirst.apply("JuMBlEd lETteRS".into()), "juMBlEd lETteRS");
        assert_eq!(Modifier::Length.apply("juMBlEd lETteRS".into()), "15");
        assert_eq!(Modifier::Length.apply("äö".into()), "2");
        assert_eq!(Modifier::QuoteWildcard.apply("Rock*".into()), "Rock\\*");
        assert_eq!(Modifier::EncodeUrl.apply("a b/ä".into()), "a%20b%2F%C3%A4");
        assert_eq!(truncate("aä".into(), 2), "a");
    }
}
