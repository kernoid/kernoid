// SPDX-License-Identifier: AGPL-3.0-or-later
//! A small, synchronous D-Bus client and the part of the Secret Service API the terminal app needs – kernoid's own,
//! written from the D-Bus Specification (wire format, authentication with `EXTERNAL`) and the Secret Service API draft
//! 0.2 (sessions, searching, unlocking with prompts, reading and creating items). It needs nothing but the standard
//! library, so that it can be tested alone against a real bus (`rustc --test src/dbus.rs`, see `tests` below).
//!
//! Secrets travel with the algorithm `plain`, which the API allows: the session bus is local to the user, and anyone
//! who can read it can ask the store for the secret as well.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// The largest message read (the specification allows 128 MiB; a secret is small).
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// A value on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Byte(u8),
    Bool(bool),
    U32(u32),
    Str(String),
    Path(String),
    Signature(String),
    /// An array with the signature of its elements (needed when it is empty).
    Array(String, Vec<Value>),
    Struct(Vec<Value>),
    /// A dictionary entry – only inside an array.
    Entry(Box<Value>, Box<Value>),
    Variant(Box<Value>),
}

impl Value {
    /// The signature of this value.
    pub fn signature(&self) -> String {
        match self {
            Value::Byte(_) => "y".into(),
            Value::Bool(_) => "b".into(),
            Value::U32(_) => "u".into(),
            Value::Str(_) => "s".into(),
            Value::Path(_) => "o".into(),
            Value::Signature(_) => "g".into(),
            Value::Array(element, _) => format!("a{element}"),
            Value::Struct(fields) => format!("({})", fields.iter().map(Value::signature).collect::<String>()),
            Value::Entry(key, value) => format!("{{{}{}}}", key.signature(), value.signature()),
            Value::Variant(_) => "v".into(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::Path(s) | Value::Signature(s) => Some(s),
            Value::Variant(inner) => inner.as_str(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(_, items) => Some(items),
            Value::Variant(inner) => inner.as_array(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// An array of strings as `a{ss}`.
    pub fn string_dict(entries: &BTreeMap<String, String>) -> Value {
        Value::Array(
            "{ss}".into(),
            entries
                .iter()
                .map(|(k, v)| Value::Entry(Box::new(Value::Str(k.clone())), Box::new(Value::Str(v.clone()))))
                .collect(),
        )
    }

    /// Bytes as `ay`.
    pub fn bytes(bytes: &[u8]) -> Value {
        Value::Array("y".into(), bytes.iter().map(|b| Value::Byte(*b)).collect())
    }

    /// The bytes of an `ay`.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.as_array()?.iter().map(|v| if let Value::Byte(b) = v { Some(*b) } else { None }).collect()
    }
}

// ---- Writing ----------------------------------------------------------------------------------------------------

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn pad(&mut self, alignment: usize) {
        while !self.out.len().is_multiple_of(alignment) {
            self.out.push(0);
        }
    }

    fn u32(&mut self, value: u32) {
        self.pad(4);
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, text: &str) {
        self.u32(text.len() as u32);
        self.out.extend_from_slice(text.as_bytes());
        self.out.push(0);
    }

    fn signature(&mut self, text: &str) {
        self.out.push(text.len() as u8);
        self.out.extend_from_slice(text.as_bytes());
        self.out.push(0);
    }

    fn value(&mut self, value: &Value) {
        match value {
            Value::Byte(b) => self.out.push(*b),
            Value::Bool(b) => self.u32(u32::from(*b)),
            Value::U32(n) => self.u32(*n),
            Value::Str(s) | Value::Path(s) => self.string(s),
            Value::Signature(s) => self.signature(s),
            Value::Array(element, items) => {
                self.u32(0);
                let length_at = self.out.len() - 4;
                self.pad(alignment(element.as_bytes()[0]));
                let start = self.out.len();
                for item in items {
                    self.value(item);
                }
                let length = (self.out.len() - start) as u32;
                self.out[length_at..length_at + 4].copy_from_slice(&length.to_le_bytes());
            }
            Value::Struct(fields) => {
                self.pad(8);
                for field in fields {
                    self.value(field);
                }
            }
            Value::Entry(key, value) => {
                self.pad(8);
                self.value(key);
                self.value(value);
            }
            Value::Variant(inner) => {
                self.signature(&inner.signature());
                self.value(inner);
            }
        }
    }
}

/// The alignment of a type by the first character of its signature.
fn alignment(code: u8) -> usize {
    match code {
        b'y' | b'g' | b'v' => 1,
        b'n' | b'q' => 2,
        b'x' | b't' | b'd' | b'(' | b'{' => 8,
        _ => 4,
    }
}

/// A message to send.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    pub destination: &'a str,
    pub path: &'a str,
    pub interface: &'a str,
    pub member: &'a str,
    pub body: Vec<Value>,
}

/// The bytes of a method call with `serial`.
pub fn encode_call(call: &Call, serial: u32) -> Vec<u8> {
    let mut body = Writer { out: Vec::new() };
    for value in &call.body {
        body.value(value);
    }
    let signature: String = call.body.iter().map(Value::signature).collect();
    let field = |code: u8, value: Value| Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(value))]);
    let mut fields = vec![
        field(1, Value::Path(call.path.into())),
        field(2, Value::Str(call.interface.into())),
        field(3, Value::Str(call.member.into())),
        field(6, Value::Str(call.destination.into())),
    ];
    if !signature.is_empty() {
        fields.push(field(8, Value::Signature(signature)));
    }
    let mut message = Writer { out: vec![b'l', 1, 0, 1] };
    message.u32(body.out.len() as u32);
    message.u32(serial);
    message.value(&Value::Array("(yv)".into(), fields));
    message.pad(8);
    message.out.extend_from_slice(&body.out);
    message.out
}

// ---- Reading ----------------------------------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    little: bool,
    /// Nesting of containers, bounded as the specification bounds it.
    depth: usize,
}

impl Reader<'_> {
    fn pad(&mut self, alignment: usize) -> Result<(), String> {
        let to = self.at.div_ceil(alignment) * alignment;
        if to > self.data.len() {
            return Err("a message cut short".into());
        }
        self.at = to;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.data.len()).ok_or("a message cut short")?;
        let bytes = &self.data[self.at..end];
        self.at = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, String> {
        self.pad(4)?;
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| "a message cut short")?;
        Ok(if self.little { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) })
    }

    fn text(&mut self, len: usize) -> Result<String, String> {
        let bytes = self.take(len + 1)?;
        String::from_utf8(bytes[..len].to_vec()).map_err(|_| "a string that is not UTF-8".into())
    }

    /// One value of the complete type at the start of `signature`; returns it and the rest of the signature.
    fn value<'s>(&mut self, signature: &'s str) -> Result<(Value, &'s str), String> {
        let code = *signature.as_bytes().first().ok_or("an empty signature")?;
        let rest = &signature[1..];
        Ok(match code {
            b'y' => (Value::Byte(self.take(1)?[0]), rest),
            b'b' => (Value::Bool(self.u32()? != 0), rest),
            b'u' | b'i' => (Value::U32(self.u32()?), rest),
            b's' | b'o' => {
                let len = self.u32()? as usize;
                let text = self.text(len)?;
                (if code == b's' { Value::Str(text) } else { Value::Path(text) }, rest)
            }
            b'g' => {
                let len = usize::from(self.take(1)?[0]);
                (Value::Signature(self.text(len)?), rest)
            }
            b'v' => {
                let len = usize::from(self.take(1)?[0]);
                let inner = self.text(len)?;
                let value = self.nested(|reader| reader.value(&inner))?;
                if !value.1.is_empty() {
                    return Err("a variant of more than one type".into());
                }
                (Value::Variant(Box::new(value.0)), rest)
            }
            b'a' => {
                let element_len = complete_type(rest)?;
                let element = &rest[..element_len];
                let length = self.u32()? as usize;
                self.pad(alignment(element.as_bytes()[0]))?;
                let end =
                    self.at.checked_add(length).filter(|end| *end <= self.data.len()).ok_or("an array too long")?;
                let mut items = Vec::new();
                self.nested(|reader| {
                    while reader.at < end {
                        items.push(reader.value(element)?.0);
                    }
                    Ok(())
                })?;
                if self.at != end {
                    return Err("an array of the wrong length".into());
                }
                (Value::Array(element.to_owned(), items), &rest[element_len..])
            }
            b'(' | b'{' => {
                let len = complete_type(signature)?;
                let inner = &signature[1..len - 1];
                self.pad(8)?;
                let mut fields = Vec::new();
                self.nested(|reader| {
                    let mut inner = inner;
                    while !inner.is_empty() {
                        let (value, next) = reader.value(inner)?;
                        fields.push(value);
                        inner = next;
                    }
                    Ok(())
                })?;
                let value = if code == b'{' {
                    let mut fields = fields.into_iter();
                    match (fields.next(), fields.next(), fields.next()) {
                        (Some(key), Some(value), None) => Value::Entry(Box::new(key), Box::new(value)),
                        _ => return Err("a dictionary entry not of two".into()),
                    }
                } else {
                    Value::Struct(fields)
                };
                (value, &signature[len..])
            }
            other => return Err(format!("a type not read here: {}", other as char)),
        })
    }

    fn nested<T>(&mut self, read: impl FnOnce(&mut Self) -> Result<T, String>) -> Result<T, String> {
        self.depth += 1;
        if self.depth > 64 {
            return Err("values nested too deep".into());
        }
        let result = read(self);
        self.depth -= 1;
        result
    }
}

/// The length of the complete type at the start of `signature`.
fn complete_type(signature: &str) -> Result<usize, String> {
    let bytes = signature.as_bytes();
    match bytes.first() {
        None => Err("an empty signature".into()),
        Some(b'a') => Ok(1 + complete_type(&signature[1..])?),
        Some(open @ (b'(' | b'{')) => {
            let close = if *open == b'(' { b')' } else { b'}' };
            let mut at = 1;
            while bytes.get(at) != Some(&close) {
                if at >= bytes.len() || at > 255 {
                    return Err("a signature not closed".into());
                }
                at += complete_type(&signature[at..])?;
            }
            Ok(at + 1)
        }
        Some(_) => Ok(1),
    }
}

/// A message received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: u8,
    pub serial: u32,
    pub reply_serial: Option<u32>,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error: Option<String>,
    pub body: Vec<Value>,
}

const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;
const SIGNAL: u8 = 4;

/// The length of the message whose first 16 bytes are `start`.
pub fn message_length(start: &[u8; 16]) -> Result<usize, String> {
    let little = match start[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err("not a D-Bus message".into()),
    };
    let read = |at: usize| {
        let bytes: [u8; 4] = start[at..at + 4].try_into().unwrap_or_default();
        (if little { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) }) as usize
    };
    let (body, fields) = (read(4), read(12));
    let header = (16 + fields).div_ceil(8) * 8;
    let total = header.checked_add(body).filter(|total| *total <= MAX_MESSAGE).ok_or("a message too large")?;
    Ok(total)
}

/// Reads a whole message.
pub fn decode(data: &[u8]) -> Result<Message, String> {
    let little = data.first() == Some(&b'l');
    let mut reader = Reader { data, at: 12, little, depth: 0 };
    let kind = *data.get(1).ok_or("a message cut short")?;
    let serial = {
        let mut at = Reader { data, at: 8, little, depth: 0 };
        at.u32()?
    };
    let (fields, _) = reader.value("a(yv)")?;
    let mut message = Message {
        kind,
        serial,
        reply_serial: None,
        path: None,
        interface: None,
        member: None,
        error: None,
        body: Vec::new(),
    };
    let mut signature = String::new();
    for field in fields.as_array().unwrap_or_default() {
        let Value::Struct(parts) = field else { continue };
        let (Some(Value::Byte(code)), Some(Value::Variant(value))) = (parts.first(), parts.get(1)) else { continue };
        match (code, value.as_ref()) {
            (1, Value::Path(p)) => message.path = Some(p.clone()),
            (2, Value::Str(s)) => message.interface = Some(s.clone()),
            (3, Value::Str(s)) => message.member = Some(s.clone()),
            (4, Value::Str(s)) => message.error = Some(s.clone()),
            (5, Value::U32(n)) => message.reply_serial = Some(*n),
            (8, Value::Signature(s)) => signature = s.clone(),
            _ => {}
        }
    }
    reader.pad(8)?;
    let mut rest = signature.as_str();
    while !rest.is_empty() {
        let (value, next) = reader.value(rest)?;
        message.body.push(value);
        rest = next;
    }
    Ok(message)
}

// ---- The connection ---------------------------------------------------------------------------------------------

/// A connection to the session bus.
#[derive(Debug)]
pub struct Bus {
    stream: BufReader<UnixStream>,
    serial: u32,
    /// Signals that came while waiting for a reply.
    signals: Vec<Message>,
}

impl Bus {
    /// Connects to the session bus of `DBUS_SESSION_BUS_ADDRESS` and says hello.
    pub fn session() -> Result<Bus, String> {
        let address =
            std::env::var("DBUS_SESSION_BUS_ADDRESS").map_err(|_| "no session bus (DBUS_SESSION_BUS_ADDRESS)")?;
        let stream = connect(&address)?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
        let mut bus = Bus { stream: BufReader::new(stream), serial: 0, signals: Vec::new() };
        bus.authenticate()?;
        bus.call(&Call {
            destination: "org.freedesktop.DBus",
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member: "Hello",
            body: vec![],
        })?;
        Ok(bus)
    }

    fn authenticate(&mut self) -> Result<(), String> {
        let uid = user_id()?;
        let hex: String = uid.to_string().bytes().map(|b| format!("{b:02x}")).collect();
        let stream = self.stream.get_mut();
        stream.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes()).map_err(|e| e.to_string())?;
        let mut line = String::new();
        // A line of the authentication is short; a longer one is not a bus.
        (&mut self.stream).take(512).read_line(&mut line).map_err(|e| e.to_string())?;
        if !line.starts_with("OK ") {
            return Err(format!("the session bus refused the login: {}", line.trim()));
        }
        self.stream.get_mut().write_all(b"BEGIN\r\n").map_err(|e| e.to_string())
    }

    /// Calls a method and returns its reply's values; an error reply is an error.
    pub fn call(&mut self, call: &Call) -> Result<Vec<Value>, String> {
        self.serial += 1;
        let serial = self.serial;
        self.stream.get_mut().write_all(&encode_call(call, serial)).map_err(|e| e.to_string())?;
        loop {
            let message = self.receive()?;
            match message.kind {
                METHOD_RETURN if message.reply_serial == Some(serial) => return Ok(message.body),
                ERROR if message.reply_serial == Some(serial) => {
                    let detail = message.body.first().and_then(Value::as_str).unwrap_or_default().to_owned();
                    return Err(format!("{}: {detail}", message.error.unwrap_or_default()));
                }
                // Kept for `signal`, a few at most: others (NameAcquired) are of no use here.
                SIGNAL if self.signals.len() < 64 => self.signals.push(message),
                _ => {}
            }
        }
    }

    /// Waits for a signal of `member` on `path`.
    pub fn signal(&mut self, path: &str, member: &str, timeout: Duration) -> Result<Message, String> {
        let wanted = |m: &Message| m.path.as_deref() == Some(path) && m.member.as_deref() == Some(member);
        if let Some(at) = self.signals.iter().position(wanted) {
            return Ok(self.signals.remove(at));
        }
        self.stream.get_mut().set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let result = loop {
            let message = match self.receive() {
                Ok(message) => message,
                Err(error) => break Err(error),
            };
            if message.kind == SIGNAL && wanted(&message) {
                break Ok(message);
            }
        };
        self.stream.get_mut().set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| e.to_string())?;
        result
    }

    fn receive(&mut self) -> Result<Message, String> {
        let mut start = [0u8; 16];
        self.stream.read_exact(&mut start).map_err(|e| format!("the session bus: {e}"))?;
        let length = message_length(&start)?;
        let mut data = start.to_vec();
        data.resize(length, 0);
        self.stream.read_exact(&mut data[16..]).map_err(|e| format!("the session bus: {e}"))?;
        decode(&data)
    }
}

/// Connects to the first address of `addresses` this can reach: `unix:path=…`, or `unix:abstract=…` on Linux.
fn connect(addresses: &str) -> Result<UnixStream, String> {
    let mut last = format!("no address of the session bus to reach: {addresses}");
    for address in addresses.split(';') {
        let Some(keys) = address.strip_prefix("unix:") else { continue };
        for pair in keys.split(',') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = unescape(value);
            let stream = match key {
                "path" => {
                    use std::os::unix::ffi::OsStrExt;
                    UnixStream::connect(std::ffi::OsStr::from_bytes(&value))
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                "abstract" => {
                    #[cfg(target_os = "android")]
                    use std::os::android::net::SocketAddrExt;
                    #[cfg(target_os = "linux")]
                    use std::os::linux::net::SocketAddrExt;
                    std::os::unix::net::SocketAddr::from_abstract_name(&value)
                        .and_then(|addr| UnixStream::connect_addr(&addr))
                }
                _ => continue,
            };
            match stream {
                Ok(stream) => return Ok(stream),
                Err(error) => last = format!("the session bus: {error}"),
            }
        }
    }
    Err(last)
}

/// A value of an address with its `%xx` escapes undone.
fn unescape(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = if bytes[at] == b'%' {
            value.get(at + 1..at + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok())
        } else {
            None
        };
        if let Some(byte) = escaped {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

/// The user this process runs as: the owner of `/proc/self`, or of a file it makes.
fn user_id() -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        return Ok(meta.uid());
    }
    let path = std::env::temp_dir().join(format!("kernoid-uid-{}", std::process::id()));
    let file = std::fs::File::create(&path).map_err(|e| format!("finding the user: {e}"))?;
    let uid = file.metadata().map(|m| m.uid()).map_err(|e| format!("finding the user: {e}"));
    let _ = std::fs::remove_file(&path);
    uid
}

// ---- The Secret Service -----------------------------------------------------------------------------------------

const SECRETS: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";

/// How long a prompt to unlock may take the user.
const PROMPT_TIME: Duration = Duration::from_secs(300);

/// A session with the Secret Service.
#[derive(Debug)]
pub struct Secrets {
    bus: Bus,
    session: String,
}

impl Secrets {
    pub fn open() -> Result<Secrets, String> {
        let mut bus = Bus::session()?;
        let reply = bus.call(&Call {
            destination: SECRETS,
            path: SERVICE_PATH,
            interface: SERVICE,
            member: "OpenSession",
            body: vec![Value::Str("plain".into()), Value::Variant(Box::new(Value::Str(String::new())))],
        })?;
        let session = reply.get(1).and_then(Value::as_str).ok_or("no session from the Secret Service")?.to_owned();
        Ok(Secrets { bus, session })
    }

    /// The secret of the item with `attributes`, if there is one.
    pub fn get(&mut self, attributes: &BTreeMap<String, String>) -> Result<Option<Vec<u8>>, String> {
        let reply = self.service("SearchItems", vec![Value::string_dict(attributes)])?;
        let paths = |value: Option<&Value>| -> Vec<String> {
            value
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        let (unlocked, locked) = (paths(reply.first()), paths(reply.get(1)));
        let item = match (unlocked.into_iter().next(), locked.into_iter().next()) {
            (Some(item), _) => item,
            (None, Some(item)) => {
                self.unlock(&item)?;
                item
            }
            (None, None) => return Ok(None),
        };
        let reply = self.bus.call(&Call {
            destination: SECRETS,
            path: &item,
            interface: "org.freedesktop.Secret.Item",
            member: "GetSecret",
            body: vec![Value::Path(self.session.clone())],
        })?;
        let Some(Value::Struct(secret)) = reply.first() else { return Err("no secret in the answer".into()) };
        secret.get(2).and_then(Value::to_bytes).map(Some).ok_or_else(|| "no secret in the answer".into())
    }

    /// Keeps `secret` in an item with `label` and `attributes` in the default collection, replacing one with the same
    /// attributes.
    pub fn set(&mut self, label: &str, attributes: &BTreeMap<String, String>, secret: &[u8]) -> Result<(), String> {
        let reply = self.service("ReadAlias", vec![Value::Str("default".into())])?;
        let collection = reply.first().and_then(Value::as_str).unwrap_or("/").to_owned();
        if collection == "/" {
            return Err("the Secret Service has no default collection".into());
        }
        self.unlock(&collection)?;
        let property = |name: &str, value: Value| {
            Value::Entry(Box::new(Value::Str(name.into())), Box::new(Value::Variant(Box::new(value))))
        };
        let properties = Value::Array(
            "{sv}".into(),
            vec![
                property("org.freedesktop.Secret.Item.Label", Value::Str(label.into())),
                property("org.freedesktop.Secret.Item.Attributes", Value::string_dict(attributes)),
            ],
        );
        let secret = Value::Struct(vec![
            Value::Path(self.session.clone()),
            Value::bytes(&[]),
            Value::bytes(secret),
            Value::Str("text/plain".into()),
        ]);
        let reply = self.bus.call(&Call {
            destination: SECRETS,
            path: &collection,
            interface: "org.freedesktop.Secret.Collection",
            member: "CreateItem",
            body: vec![properties, secret, Value::Bool(true)],
        })?;
        match reply.get(1).and_then(Value::as_str) {
            Some(prompt) if prompt != "/" => self.prompt(prompt),
            _ => Ok(()),
        }
    }

    fn service(&mut self, member: &str, body: Vec<Value>) -> Result<Vec<Value>, String> {
        self.bus.call(&Call { destination: SECRETS, path: SERVICE_PATH, interface: SERVICE, member, body })
    }

    /// Unlocks an item or a collection – through a prompt of the desktop when the service asks for one.
    fn unlock(&mut self, path: &str) -> Result<(), String> {
        let reply = self.service("Unlock", vec![Value::Array("o".into(), vec![Value::Path(path.into())])])?;
        match reply.get(1).and_then(Value::as_str) {
            Some(prompt) if prompt != "/" => self.prompt(prompt),
            _ => Ok(()),
        }
    }

    fn prompt(&mut self, prompt: &str) -> Result<(), String> {
        let rule =
            format!("type='signal',interface='org.freedesktop.Secret.Prompt',member='Completed',path='{prompt}'");
        self.bus.call(&Call {
            destination: "org.freedesktop.DBus",
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member: "AddMatch",
            body: vec![Value::Str(rule)],
        })?;
        self.bus.call(&Call {
            destination: SECRETS,
            path: prompt,
            interface: "org.freedesktop.Secret.Prompt",
            member: "Prompt",
            body: vec![Value::Str(String::new())],
        })?;
        let completed = self.bus.signal(prompt, "Completed", PROMPT_TIME)?;
        if completed.body.first().and_then(Value::as_bool) == Some(true) {
            return Err("the key store stayed locked".into());
        }
        Ok(())
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        let session = self.session.clone();
        let _ = self.bus.call(&Call {
            destination: SECRETS,
            path: &session,
            interface: "org.freedesktop.Secret.Session",
            member: "Close",
            body: vec![],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Call<'static> {
        Call {
            destination: "org.freedesktop.DBus",
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member: "Hello",
            body: vec![],
        }
    }

    #[test]
    fn a_call_on_the_wire() {
        let bytes = encode_call(&hello(), 1);
        // Little-endian, a method call, no flags, version 1, no body, serial 1.
        assert_eq!(&bytes[..12], &[b'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0]);
        // The header fields: the path first, as (yv) with the variant's signature `o`.
        assert_eq!(&bytes[16..24], &[1, 1, b'o', 0, 21, 0, 0, 0]);
        assert_eq!(&bytes[24..46], b"/org/freedesktop/DBus\0");
        assert_eq!(bytes.len() % 8, 0);
        let fields_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        assert_eq!(bytes.len(), (16 + fields_len).div_ceil(8) * 8);
    }

    #[test]
    fn messages_read_back() {
        let attributes =
            BTreeMap::from([("service".to_owned(), "kernoid".to_owned()), ("username".into(), "a@x".into())]);
        let body = vec![
            Value::Str("plain".into()),
            Value::Variant(Box::new(Value::Str(String::new()))),
            Value::string_dict(&attributes),
            Value::Struct(vec![
                Value::Path("/s/1".into()),
                Value::bytes(&[]),
                Value::bytes(b"key"),
                Value::Str("t".into()),
            ]),
            Value::Bool(true),
            Value::Array("o".into(), vec![]),
            Value::Array(
                "{sv}".into(),
                vec![Value::Entry(Box::new(Value::Str("a".into())), Box::new(Value::Variant(Box::new(Value::U32(7)))))],
            ),
        ];
        let call = Call { body: body.clone(), ..hello() };
        let bytes = encode_call(&call, 9);
        assert_eq!(message_length(&bytes[..16].try_into().unwrap()).unwrap(), bytes.len());
        let message = decode(&bytes).unwrap();
        assert_eq!((message.kind, message.serial), (1, 9));
        assert_eq!(message.member.as_deref(), Some("Hello"));
        assert_eq!(message.path.as_deref(), Some("/org/freedesktop/DBus"));
        assert_eq!(message.body, body);
        assert_eq!(message.body[3].signature(), "(oayays)");
    }

    #[test]
    fn a_big_endian_reply() {
        // A method return in big-endian: reply serial 5, signature `s`, body "ok".
        let mut message = vec![b'B', 2, 0, 1, 0, 0, 0, 7, 0, 0, 0, 3];
        let fields: Vec<u8> = vec![
            5, 1, b'u', 0, 0, 0, 0, 5, // (yv): REPLY_SERIAL = 5
            8, 1, b'g', 0, 1, b's', 0, // (yv): SIGNATURE = "s"
        ];
        message.extend_from_slice(&(fields.len() as u32).to_be_bytes());
        message.extend_from_slice(&fields);
        while message.len() % 8 != 0 {
            message.push(0);
        }
        message.extend_from_slice(&[0, 0, 0, 2, b'o', b'k', 0]);
        assert_eq!(message_length(&message[..16].try_into().unwrap()).unwrap(), message.len());
        let message = decode(&message).unwrap();
        assert_eq!((message.kind, message.serial, message.reply_serial), (2, 3, Some(5)));
        assert_eq!(message.body, vec![Value::Str("ok".into())]);
    }

    #[test]
    fn broken_messages_are_errors() {
        let bytes = encode_call(&Call { body: vec![Value::Str("x".into())], ..hello() }, 1);
        for cut in [13, 20, bytes.len() - 1] {
            assert!(decode(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut huge = [0u8; 16];
        huge[0] = b'l';
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(message_length(&huge).is_err());
        huge[0] = b'x';
        assert!(message_length(&huge).is_err());
        // Variants nested beyond the limit.
        let mut deep = Value::U32(1);
        for _ in 0..100 {
            deep = Value::Variant(Box::new(deep));
        }
        assert!(decode(&encode_call(&Call { body: vec![deep], ..hello() }, 1)).is_err());
        assert!(complete_type("(ss").is_err() && complete_type("a").is_err());
    }

    #[test]
    fn addresses() {
        assert_eq!(unescape("/run/user/1000/bus%2cx"), b"/run/user/1000/bus,x");
        assert!(connect("tcp:host=x,port=1").is_err());
    }

    /// Against a real Secret Service on the session bus – run where there is one with
    /// `KERNOID_TEST_SECRET_SERVICE=1`, e.g. in a container:
    /// `dbus-run-session -- sh -c 'echo pw | gnome-keyring-daemon --unlock --components=secrets; ./dbus-test'`.
    #[test]
    fn against_a_secret_service() {
        if std::env::var_os("KERNOID_TEST_SECRET_SERVICE").is_none() {
            return;
        }
        let attributes =
            BTreeMap::from([("service".to_owned(), "kernoid test".to_owned()), ("username".into(), "a@x".into())]);
        let mut secrets = Secrets::open().unwrap();
        secrets.set("kernoid test", &attributes, b"first").unwrap();
        assert_eq!(secrets.get(&attributes).unwrap().as_deref(), Some(b"first".as_slice()));
        secrets.set("kernoid test", &attributes, b"second").unwrap();
        drop(secrets);
        let mut secrets = Secrets::open().unwrap();
        assert_eq!(secrets.get(&attributes).unwrap().as_deref(), Some(b"second".as_slice()));
        let other = BTreeMap::from([("service".to_owned(), "kernoid none".to_owned())]);
        assert_eq!(secrets.get(&other).unwrap(), None);
    }
}
