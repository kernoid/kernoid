// SPDX-License-Identifier: MIT
//! Content lines – the syntax iCalendar (RFC 5545, 3.1) and vCard (RFC 6350, 3.3) share: `group.NAME;PARAM=a,b:value`,
//! folded at 75 octets, parameter values quoted and caret-encoded (RFC 6868). Values are kept as they are written
//! (escaped), so that what is not understood goes back out unchanged; [`Property`] reads them as text, lists, fields,
//! addresses and times.
//!
//! Reading is lenient, as files from the wild need: lines may end in LF alone, folds may use tabs, vCard 2.1 and 3.0
//! parameters may come without a name (`TEL;WORK;VOICE:`), and quoted-printable values (with their soft line breaks and
//! `CHARSET`) are decoded into plain values.

use std::fmt::{self, Write as _};

use crate::time::Time;

/// A parameter: its name in upper case and its values, unquoted and decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub values: Vec<String>,
}

impl Param {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Param { name: name.into().to_ascii_uppercase(), values: vec![value.into()] }
    }
}

/// A property: an optional group (vCard), its name in upper case, its parameters and its value as written – escaped,
/// unfolded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub group: Option<String>,
    pub name: String,
    pub params: Vec<Param>,
    pub value: String,
}

impl Property {
    /// A property with a value as written (already escaped where its type needs it).
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Property { group: None, name: name.into().to_ascii_uppercase(), params: Vec::new(), value: value.into() }
    }

    /// A property with a text value, escaped (RFC 5545, 3.3.11).
    pub fn text(name: impl Into<String>, text: &str) -> Self {
        Property::new(name, escape(text))
    }

    /// A property of a time, with `VALUE=DATE` or `TZID` as the time needs.
    pub fn time(name: impl Into<String>, time: &Time) -> Self {
        let mut property = Property::new(name, time.format());
        match time {
            Time::Date(_) => property.set_param("VALUE", "DATE"),
            Time::Zoned(_, tzid) => property.set_param("TZID", tzid.clone()),
            _ => {}
        }
        property
    }

    /// The same, with a parameter set.
    pub fn with_param(mut self, name: &str, value: impl Into<String>) -> Self {
        self.set_param(name, value);
        self
    }

    /// Whether the property is called `name` (any case).
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// The first value of a parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|param| param.name.eq_ignore_ascii_case(name))
            .and_then(|param| param.values.first())
            .map(String::as_str)
    }

    /// Every value of a parameter, of all its occurrences (`TYPE=work,voice;TYPE=pref`).
    pub fn param_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.params
            .iter()
            .filter(move |param| param.name.eq_ignore_ascii_case(name))
            .flat_map(|param| param.values.iter().map(String::as_str))
    }

    /// Whether a parameter has a value (any case).
    pub fn has_param_value(&self, name: &str, value: &str) -> bool {
        self.param_values(name).any(|known| known.eq_ignore_ascii_case(value))
    }

    /// Sets a parameter to one value, replacing what it had.
    pub fn set_param(&mut self, name: &str, value: impl Into<String>) {
        self.remove_param(name);
        self.params.push(Param::new(name, value));
    }

    /// Sets a parameter to several values.
    pub fn set_param_values(&mut self, name: &str, values: Vec<String>) {
        self.remove_param(name);
        if !values.is_empty() {
            self.params.push(Param { name: name.to_ascii_uppercase(), values });
        }
    }

    pub fn remove_param(&mut self, name: &str) {
        self.params.retain(|param| !param.name.eq_ignore_ascii_case(name));
    }

    /// The value as text: unescaped.
    pub fn as_text(&self) -> String {
        unescape(&self.value)
    }

    /// The value as a list of texts (`CATEGORIES:a,b`), each unescaped; empty items left out.
    pub fn texts(&self) -> Vec<String> {
        split_unescaped(&self.value, ',').into_iter().map(unescape).filter(|item| !item.is_empty()).collect()
    }

    /// The value as structured fields (`N`, `ADR`, `REQUEST-STATUS`): split at `;`, each field unescaped as a whole
    /// (a field's own list keeps its commas – see [`Property::field_lists`]).
    pub fn fields(&self) -> Vec<String> {
        split_unescaped(&self.value, ';').into_iter().map(unescape).collect()
    }

    /// The value as structured fields, each a list (RFC 6350, 5.4).
    pub fn field_lists(&self) -> Vec<Vec<String>> {
        split_unescaped(&self.value, ';')
            .into_iter()
            .map(|field| {
                split_unescaped(field, ',').into_iter().map(unescape).filter(|item| !item.is_empty()).collect()
            })
            .collect()
    }

    /// A calendar user's address (`ORGANIZER`, `ATTENDEE`): the value without `mailto:`, trimmed; `None` if empty.
    pub fn address(&self) -> Option<String> {
        let value = self.value.trim();
        let bare = strip_mailto(value).trim();
        (!bare.is_empty()).then(|| bare.to_owned())
    }

    /// The value as one time (`DTSTART`, `DUE`, `RECURRENCE-ID`): a date, a floating, UTC or zoned date-time.
    pub fn time_value(&self) -> Option<Time> {
        Time::parse(self.value.trim(), self.param("TZID"), self.is_date_valued())
    }

    /// The value as a list of times (`EXDATE`, `RDATE`); a period gives its start.
    pub fn time_values(&self) -> Vec<Time> {
        let date = self.is_date_valued();
        self.value
            .split(',')
            .filter_map(|item| {
                let item = item.trim();
                let start = item.split_once('/').map_or(item, |(start, _)| start);
                Time::parse(start, self.param("TZID"), date)
            })
            .collect()
    }

    /// The value as an integer.
    pub fn integer(&self) -> Option<i64> {
        self.value.trim().parse().ok()
    }

    fn is_date_valued(&self) -> bool {
        self.param("VALUE").is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
    }
}

/// `mailto:` taken off an address, in any case.
pub fn strip_mailto(value: &str) -> &str {
    match value.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("mailto:") => &value[7..],
        _ => value,
    }
}

/// Text escaped for a value (RFC 5545, 3.3.11; RFC 6350, 3.4): backslash, semicolon, comma and line breaks.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    out.push_str("\\n");
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// A value's text with its escapes undone; an unknown escape keeps the character escaped.
pub fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// A raw value split at `separator` where it is not escaped.
pub fn split_unescaped(raw: &str, separator: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (index, c) in raw.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == separator {
            out.push(&raw[start..index]);
            start = index + c.len_utf8();
        }
    }
    out.push(&raw[start..]);
    out
}

/// One node of the tree of `BEGIN`/`END` blocks a text holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Block {
    pub name: String,
    pub properties: Vec<Property>,
    pub blocks: Vec<Block>,
}

/// Why a text could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// The top-level blocks of a text; lines outside of any block are left out, unclosed blocks close at the end.
pub(crate) fn parse_blocks(text: &str) -> Result<Vec<Block>, Error> {
    let mut stack: Vec<Block> = Vec::new();
    let mut top = Vec::new();
    for line in logical_lines(text) {
        let Some(property) = parse_line(&line) else { continue };
        if property.group.is_none() && property.is("BEGIN") {
            let name = property.value.trim().to_ascii_uppercase();
            if name.is_empty() {
                return Err(Error("BEGIN without a name".into()));
            }
            stack.push(Block { name, properties: Vec::new(), blocks: Vec::new() });
        } else if property.group.is_none() && property.is("END") {
            let name = property.value.trim().to_ascii_uppercase();
            // An END closes the innermost block of its name; blocks left open inside it close with it.
            let Some(position) = stack.iter().rposition(|block| block.name == name) else {
                return Err(Error(format!("END:{name} without BEGIN")));
            };
            while stack.len() > position {
                let block = stack.pop().expect("not empty");
                match stack.last_mut() {
                    Some(parent) => parent.blocks.push(block),
                    None => top.push(block),
                }
            }
        } else if let Some(block) = stack.last_mut() {
            block.properties.push(property);
        }
    }
    while let Some(block) = stack.pop() {
        match stack.last_mut() {
            Some(parent) => parent.blocks.push(block),
            None => top.push(block),
        }
    }
    Ok(top)
}

/// The logical lines of a text: folds undone, quoted-printable soft line breaks joined, empty lines left out.
fn logical_lines(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out: Vec<String> = Vec::new();
    let mut soft_break = false;
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if soft_break && let Some(current) = out.last_mut() {
            current.pop(); // the `=` of the soft line break
            current.push_str(raw.strip_prefix([' ', '\t']).unwrap_or(raw));
        } else if let Some(rest) = raw.strip_prefix([' ', '\t'])
            && let Some(current) = out.last_mut()
        {
            current.push_str(rest);
        } else if raw.trim().is_empty() {
            soft_break = false;
            continue;
        } else {
            out.push(raw.to_owned());
        }
        let current = out.last().expect("pushed");
        soft_break = current.ends_with('=') && is_quoted_printable(current);
    }
    out
}

fn is_quoted_printable(line: &str) -> bool {
    let head = line.split_once(':').map_or(line, |(head, _)| head);
    head.to_ascii_uppercase().contains("QUOTED-PRINTABLE")
}

/// One logical line as a property; `None` for a line that is not one.
fn parse_line(line: &str) -> Option<Property> {
    let bytes = line.as_bytes();
    let mut position = 0;
    // The name, with its group.
    while position < bytes.len() && !matches!(bytes[position], b';' | b':') {
        position += 1;
    }
    if position >= bytes.len() {
        return None;
    }
    let full_name = line[..position].trim();
    if full_name.is_empty() {
        return None;
    }
    let (group, name) = match full_name.rsplit_once('.') {
        Some((group, name)) => (Some(group.to_owned()), name),
        None => (None, full_name),
    };
    let mut params: Vec<Param> = Vec::new();
    while bytes[position] == b';' {
        position += 1;
        let start = position;
        while position < bytes.len() && !matches!(bytes[position], b'=' | b';' | b':') {
            position += 1;
        }
        if position >= bytes.len() {
            return None;
        }
        let param_name = line[start..position].trim().to_ascii_uppercase();
        if bytes[position] != b'=' {
            // vCard 2.1 and 3.0: a value without a name is a type (`TEL;WORK;VOICE:`), or an encoding.
            if !param_name.is_empty() {
                let (name, value) = match param_name.as_str() {
                    "QUOTED-PRINTABLE" | "BASE64" | "B" => ("ENCODING", param_name.clone()),
                    _ => ("TYPE", param_name.to_ascii_lowercase()),
                };
                push_param(&mut params, name, value);
            }
            continue;
        }
        position += 1;
        let mut values = Vec::new();
        loop {
            if position < bytes.len() && bytes[position] == b'"' {
                position += 1;
                let start = position;
                while position < bytes.len() && bytes[position] != b'"' {
                    position += 1;
                }
                values.push(decode_param(&line[start..position]));
                position = (position + 1).min(bytes.len());
                // Anything up to the next separator after a closing quote is not standard; skip it.
                while position < bytes.len() && !matches!(bytes[position], b',' | b';' | b':') {
                    position += 1;
                }
            } else {
                let start = position;
                while position < bytes.len() && !matches!(bytes[position], b',' | b';' | b':') {
                    position += 1;
                }
                values.push(decode_param(line[start..position].trim()));
            }
            if position >= bytes.len() {
                return None;
            }
            if bytes[position] == b',' {
                position += 1;
                continue;
            }
            break;
        }
        params.push(Param { name: param_name, values });
    }
    let mut property =
        Property { group, name: name.to_ascii_uppercase(), params, value: line[position + 1..].to_owned() };
    decode_value(&mut property);
    Some(property)
}

fn push_param(params: &mut Vec<Param>, name: &str, value: String) {
    match params.iter_mut().find(|param| param.name == name) {
        Some(param) => param.values.push(value),
        None => params.push(Param { name: name.into(), values: vec![value] }),
    }
}

/// RFC 6868: `^n` a line break, `^^` a caret, `^'` a double quote.
fn decode_param(raw: &str) -> String {
    if !raw.contains('^') {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '^' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    out.push('\n');
                }
                Some('^') => {
                    chars.next();
                    out.push('^');
                }
                Some('\'') => {
                    chars.next();
                    out.push('"');
                }
                _ => out.push('^'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Quoted-printable values (vCard 2.1 and 3.0) decoded, in their `CHARSET`, and kept as plain values.
fn decode_value(property: &mut Property) {
    if !property.has_param_value("ENCODING", "QUOTED-PRINTABLE") {
        return;
    }
    let bytes = decode_quoted_printable(&property.value);
    let charset = property.param("CHARSET").unwrap_or("UTF-8").to_ascii_uppercase();
    let text = match charset.as_str() {
        "ISO-8859-1" | "LATIN1" | "ISO-8859-15" | "WINDOWS-1252" | "CP1252" => {
            bytes.iter().map(|&b| windows_1252(b)).collect::<String>()
        }
        _ => String::from_utf8_lossy(&bytes).into_owned(),
    };
    // Line breaks become escapes; the structure (`;`, `,`) of the decoded value stays as it was written.
    property.value = text.replace("\r\n", "\\n").replace('\n', "\\n");
    property.remove_param("ENCODING");
    property.remove_param("CHARSET");
}

fn decode_quoted_printable(raw: &str) -> Vec<u8> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'='
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
        {
            out.push(high << 4 | low);
            index += 3;
            continue;
        }
        if bytes[index] == b'=' && index + 1 == bytes.len() {
            // A trailing `=` (a soft line break at the very end).
            index += 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A byte of Windows-1252 (a superset of ISO 8859-1 in what is printable) as a character.
fn windows_1252(byte: u8) -> char {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž', '\u{8f}', '\u{90}', '‘',
        '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}', 'ž', 'Ÿ',
    ];
    match byte {
        0x80..=0x9f => HIGH[(byte - 0x80) as usize],
        _ => byte as char,
    }
}

/// Writes a property as a content line, folded at 75 octets, ending in CRLF.
pub(crate) fn write_property(out: &mut String, property: &Property) {
    let mut line = String::new();
    if let Some(group) = &property.group {
        line.push_str(group);
        line.push('.');
    }
    line.push_str(&property.name);
    for param in &property.params {
        line.push(';');
        line.push_str(&param.name);
        line.push('=');
        for (index, value) in param.values.iter().enumerate() {
            if index > 0 {
                line.push(',');
            }
            write_param_value(&mut line, value);
        }
    }
    line.push(':');
    line.push_str(&property.value);
    fold(out, &line);
}

fn write_param_value(out: &mut String, value: &str) {
    let quote = value.contains([':', ';', ',']) || value.starts_with(' ') || value.ends_with(' ');
    if quote {
        out.push('"');
    }
    for c in value.chars() {
        match c {
            '^' => out.push_str("^^"),
            '"' => out.push_str("^'"),
            '\n' => out.push_str("^n"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    if quote {
        out.push('"');
    }
}

/// A line folded at 75 octets (RFC 5545, 3.1), never inside a character.
fn fold(out: &mut String, line: &str) {
    let mut width = 0;
    for c in line.chars() {
        let len = c.len_utf8();
        if width + len > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(c);
        width += len;
    }
    out.push_str("\r\n");
}

/// Writes a block and what it holds.
pub(crate) fn write_block(out: &mut String, name: &str, properties: &[Property], inner: impl FnOnce(&mut String)) {
    let _ = write!(out, "BEGIN:{name}\r\n");
    for property in properties {
        write_property(out, property);
    }
    inner(out);
    let _ = write!(out, "END:{name}\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_unfold_and_params_decode() {
        let text = "BEGIN:VCARD\r\nVERSION:4.0\nNOTE:a long\r\n  note\r\n\tcontinued\r\nitem1.EMAIL;TYPE=\"work,pref\";X-A=^'q^'^n:a@b.example\r\n\
                    TEL;WORK;VOICE:+49 30 1\r\nEND:VCARD\r\n";
        let blocks = parse_blocks(text).unwrap();
        assert_eq!(blocks.len(), 1);
        let card = &blocks[0];
        assert_eq!(card.name, "VCARD");
        assert_eq!(card.properties[1].as_text(), "a long notecontinued");
        let email = &card.properties[2];
        assert_eq!(email.group.as_deref(), Some("item1"));
        assert_eq!(email.param_values("TYPE").collect::<Vec<_>>(), ["work,pref"]);
        assert_eq!(email.param("X-A"), Some("\"q\"\n"));
        let tel = &card.properties[3];
        assert_eq!(tel.param_values("TYPE").collect::<Vec<_>>(), ["work", "voice"]);
        assert_eq!(tel.value, "+49 30 1");
    }

    #[test]
    fn quoted_printable_is_decoded() {
        let text = "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=ISO-8859-1;ENCODING=QUOTED-PRINTABLE:M=FCller;J=\r\n=F6rg;;;\r\n\
                    NOTE;ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:Zeile 1=0D=0AZeile=20=C3=A4\r\nEND:VCARD\r\n";
        let card = &parse_blocks(text).unwrap()[0];
        assert_eq!(card.properties[1].fields(), ["Müller", "Jörg", "", "", ""]);
        assert!(card.properties[1].params.is_empty());
        assert_eq!(card.properties[2].as_text(), "Zeile 1\nZeile ä");
    }

    #[test]
    fn text_escapes_round_trip() {
        let text = "a;b,c\\d\ne";
        assert_eq!(escape(text), "a\\;b\\,c\\\\d\\ne");
        assert_eq!(unescape(&escape(text)), text);
        let property = Property::new("CATEGORIES", "one,two\\,three,");
        assert_eq!(property.texts(), ["one", "two,three"]);
        let property = Property::new("ADR", ";;Main St\\; 1;Town;;12345;DE");
        assert_eq!(property.fields()[2], "Main St; 1");
    }

    #[test]
    fn long_lines_fold_between_characters() {
        let mut out = String::new();
        let property = Property::text("SUMMARY", &"ä".repeat(60)).with_param("X-NOTE", "a:b");
        write_property(&mut out, &property);
        for line in out.split("\r\n").filter(|line| !line.is_empty()) {
            assert!(line.len() <= 75, "{line}");
        }
        assert!(out.starts_with("SUMMARY;X-NOTE=\"a:b\":"));
        let back = parse_blocks(&format!("BEGIN:X\r\n{out}END:X\r\n")).unwrap();
        assert_eq!(back[0].properties[0], property);
    }

    #[test]
    fn broken_nesting_is_closed_or_refused() {
        let blocks = parse_blocks("BEGIN:A\r\nBEGIN:B\r\nX:1\r\nEND:A\r\n").unwrap();
        assert_eq!(blocks[0].blocks[0].properties[0].value, "1");
        assert!(parse_blocks("END:A\r\n").is_err());
        let blocks = parse_blocks("BEGIN:A\r\nX:1\r\n").unwrap();
        assert_eq!(blocks.len(), 1);
    }
}
