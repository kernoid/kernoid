// SPDX-License-Identifier: MIT
//! The canonical encoding: JSON as defined by the JSON Canonicalization Scheme (RFC 8785), restricted to what the
//! core uses – no floating-point numbers, integers up to 2^53 − 1.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

/// Why a value cannot be encoded canonically.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// A number that is not an integer between −(2^53 − 1) and 2^53 − 1.
    #[error("number {0} is not a safe integer")]
    Number(String),
    /// The value cannot be represented as JSON, or the input is not JSON – including an object with two members of
    /// the same name.
    #[error("not representable as JSON: {0}")]
    Json(String),
}

/// The largest integer every JSON implementation represents exactly (2^53 − 1).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The canonical bytes of a value: UTF-8, no whitespace, object members sorted by their names' UTF-16 code units,
/// strings escaped only where JSON requires it.
pub fn to_canonical_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value).map_err(|e| CanonicalError::Json(e.to_string()))?;
    let mut out = String::new();
    write_value(&value, &mut out)?;
    Ok(out.into_bytes())
}

/// The canonical bytes of JSON text as received: every member is kept, also those the reader does not understand.
/// Rejects text that is not JSON, objects with two members of the same name, and numbers that are not safe integers.
pub fn canonicalize(json: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    let Strict(value) = serde_json::from_slice(json).map_err(|e| CanonicalError::Json(e.to_string()))?;
    let mut out = String::new();
    write_value(&value, &mut out)?;
    Ok(out.into_bytes())
}

/// A JSON value read without letting a later member silently replace an earlier one of the same name.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        // Kept as a float, so the encoder rejects it.
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let Strict(value) = map.next_value()?;
            if members.contains_key(&name) {
                return Err(de::Error::custom(format!("duplicate member {name:?}")));
            }
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let safe = n.as_u64().is_some_and(|v| v <= MAX_SAFE_INTEGER)
                || n.as_i64().is_some_and(|v| v.unsigned_abs() <= MAX_SAFE_INTEGER);
            if !safe {
                return Err(CanonicalError::Number(n.to_string()));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<_> = members.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (name, item)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A string as RFC 8785 writes it: `"` and `\` escaped, control characters as the short escapes or `\u00xx` in
/// lower case, everything else – including non-ASCII and `/` – as is.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn canon(value: Value) -> String {
        String::from_utf8(to_canonical_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn sorts_members_and_drops_whitespace() {
        assert_eq!(
            canon(json!({"b": 1, "a": [true, null, {"d": "x", "c": 2}]})),
            r#"{"a":[true,null,{"c":2,"d":"x"}],"b":1}"#
        );
    }

    #[test]
    fn sorts_by_utf16_code_units() {
        // RFC 8785, 3.2.3: "\u{10000}" (surrogate pair D800 DC00) sorts before "\u{FB33}".
        assert_eq!(canon(json!({"\u{FB33}": 1, "\u{10000}": 2})), "{\"\u{10000}\":2,\"\u{FB33}\":1}");
    }

    #[test]
    fn escapes_only_what_json_requires() {
        assert_eq!(canon(json!("a\"b\\c/€\u{1}\n")), "\"a\\\"b\\\\c/€\\u0001\\n\"");
        assert_eq!(canon(json!("\u{1f}")), "\"\\u001f\"");
    }

    #[test]
    fn canonicalizes_received_text() {
        let text = br#"{ "b" : [1, "\u00e9"], "a" : {"unknown": null} }"#;
        assert_eq!(canonicalize(text).unwrap(), "{\"a\":{\"unknown\":null},\"b\":[1,\"\u{e9}\"]}".as_bytes());
        let duplicate = canonicalize(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(duplicate.to_string().contains("duplicate member \"a\""), "{duplicate}");
        for bad in [&b"{"[..], b"1.5", b"9007199254740992", b"{\"a\":1e3}"] {
            assert!(canonicalize(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn allows_only_safe_integers() {
        assert_eq!(canon(json!(9_007_199_254_740_991u64)), "9007199254740991");
        assert_eq!(canon(json!(-42)), "-42");
        assert!(to_canonical_vec(&json!(9_007_199_254_740_992u64)).is_err());
        assert!(to_canonical_vec(&json!(1.5)).is_err());
    }
}
