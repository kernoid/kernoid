// SPDX-License-Identifier: AGPL-3.0-or-later
//! The CBOR WebAuthn needs (RFC 8949): what authenticators send – the attestation object, the COSE key and the
//! extensions in the authenticator data – is decoded here, nothing else. Only definite lengths (CTAP2's canonical
//! form allows no other), at most 16 levels deep and nothing longer than what is left of the input; tags and floats
//! are refused, as WebAuthn's structures have none. Encoding is for kernoid's own tests (the software authenticator).

/// A decoded item.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// An integer, unsigned (major type 0) or negative (1).
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pairs in the order they came; keys are unique.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

/// Why CBOR did not decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

const DEPTH: usize = 16;

impl Value {
    /// The value of `key` in a map.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs.iter().find(|(own, _)| own == key).map(|(_, value)| value),
            _ => None,
        }
    }

    /// The value of the text key `key` in a map.
    pub fn text_key(&self, key: &str) -> Option<&Value> {
        self.get(&Value::Text(key.to_owned()))
    }

    /// The value of the integer key `key` in a map (COSE's labels).
    pub fn int_key(&self, key: i128) -> Option<&Value> {
        self.get(&Value::Int(key))
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }
}

/// Decodes exactly one item filling `input`.
pub fn decode(input: &[u8]) -> Result<Value, Invalid> {
    let (value, used) = decode_prefix(input)?;
    if used != input.len() {
        return Err(Invalid("bytes after the item"));
    }
    Ok(value)
}

/// Decodes the item at the start of `input`; returns it and how many bytes it took.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), Invalid> {
    let mut reader = Reader { input, at: 0 };
    let value = reader.item(0)?;
    Ok((value, reader.at))
}

struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], Invalid> {
        let end = self.at.checked_add(count).filter(|end| *end <= self.input.len()).ok_or(Invalid("truncated"))?;
        let bytes = &self.input[self.at..end];
        self.at = end;
        Ok(bytes)
    }

    /// The argument of a head (RFC 8949, 3): the value, or a length.
    fn argument(&mut self, info: u8) -> Result<u64, Invalid> {
        let size = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Err(Invalid("indefinite length")),
            _ => return Err(Invalid("reserved additional information")),
        };
        let bytes = self.take(size)?;
        Ok(bytes.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    /// A length, which cannot exceed what is left of the input (each element takes at least a byte).
    fn length(&mut self, info: u8) -> Result<usize, Invalid> {
        let length = self.argument(info)?;
        usize::try_from(length)
            .ok()
            .filter(|length| *length <= self.input.len() - self.at)
            .ok_or(Invalid("longer than the input"))
    }

    fn item(&mut self, depth: usize) -> Result<Value, Invalid> {
        if depth > DEPTH {
            return Err(Invalid("nested too deep"));
        }
        let head = *self.take(1)?.first().expect("one byte");
        let (major, info) = (head >> 5, head & 0x1f);
        Ok(match major {
            0 => Value::Int(i128::from(self.argument(info)?)),
            1 => Value::Int(-1 - i128::from(self.argument(info)?)),
            2 => {
                let length = self.length(info)?;
                Value::Bytes(self.take(length)?.to_vec())
            }
            3 => {
                let length = self.length(info)?;
                let text = std::str::from_utf8(self.take(length)?).map_err(|_| Invalid("text is not UTF-8"))?;
                Value::Text(text.to_owned())
            }
            4 => {
                let length = self.length(info)?;
                let mut items = Vec::with_capacity(length);
                for _ in 0..length {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let length = self.length(info)?;
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(length);
                for _ in 0..length {
                    let key = self.item(depth + 1)?;
                    if pairs.iter().any(|(own, _)| *own == key) {
                        return Err(Invalid("a key twice in a map"));
                    }
                    let value = self.item(depth + 1)?;
                    pairs.push((key, value));
                }
                Value::Map(pairs)
            }
            6 => return Err(Invalid("tags are not used here")),
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(Invalid("floats and other simple values are not used here")),
            },
        })
    }
}

/// Encodes `value` – in the canonical form for what kernoid's tests build (map keys as given).
#[cfg(any(test, feature = "soft-passkey"))]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

#[cfg(any(test, feature = "soft-passkey"))]
fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => out.extend([major | 24, argument as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend((argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend((argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(argument.to_be_bytes());
        }
    }
}

#[cfg(any(test, feature = "soft-passkey"))]
fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(value) if *value >= 0 => head(0, *value as u64, out),
        Value::Int(value) => head(1, (-1 - *value) as u64, out),
        Value::Bytes(bytes) => {
            head(2, bytes.len() as u64, out);
            out.extend(bytes);
        }
        Value::Text(text) => {
            head(3, text.len() as u64, out);
            out.extend(text.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            items.iter().for_each(|item| write(item, out));
        }
        Value::Map(pairs) => {
            head(5, pairs.len() as u64, out);
            for (key, value) in pairs {
                write(key, out);
                write(value, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    /// Examples of RFC 8949, appendix A.
    #[test]
    fn decodes_the_rfcs_examples() {
        let cases = [
            ("00", Value::Int(0)),
            ("17", Value::Int(23)),
            ("1818", Value::Int(24)),
            ("1903e8", Value::Int(1000)),
            ("1a000f4240", Value::Int(1_000_000)),
            ("1bffffffffffffffff", Value::Int(18_446_744_073_709_551_615)),
            ("20", Value::Int(-1)),
            ("3863", Value::Int(-100)),
            ("3bffffffffffffffff", Value::Int(-18_446_744_073_709_551_616)),
            ("f4", Value::Bool(false)),
            ("f6", Value::Null),
            ("4401020304", Value::Bytes(vec![1, 2, 3, 4])),
            ("62c3bc", Value::Text("ü".into())),
            ("83010203", Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)])),
            ("a201020304", Value::Map(vec![(Value::Int(1), Value::Int(2)), (Value::Int(3), Value::Int(4))])),
        ];
        for (encoded, value) in cases {
            assert_eq!(decode(&hex(encoded)).unwrap(), value, "{encoded}");
            assert_eq!(encode(&value), hex(encoded), "{encoded}");
        }
    }

    #[test]
    fn refuses_what_webauthn_does_not_use() {
        for (encoded, why) in [
            ("5f42010243030405ff", "indefinite length"),
            ("c11a514b67b0", "tags are not used here"),
            ("f93c00", "floats and other simple values are not used here"),
            ("1c", "reserved additional information"),
            ("44010203", "longer than the input"),
            ("9bffffffffffffffff", "longer than the input"),
            ("a2010201", "a key twice in a map"),
            ("62c328", "text is not UTF-8"),
            ("0000", "bytes after the item"),
            ("19", "truncated"),
        ] {
            assert_eq!(decode(&hex(encoded)), Err(Invalid(why)), "{encoded}");
        }
        let deep = [vec![0x81; 17], vec![0x00]].concat();
        assert_eq!(decode(&deep), Err(Invalid("nested too deep")));
        let (value, used) = decode_prefix(&hex("0102")).unwrap();
        assert_eq!((value, used), (Value::Int(1), 1));
    }
}
