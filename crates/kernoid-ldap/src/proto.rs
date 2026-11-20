// SPDX-License-Identifier: AGPL-3.0-or-later
//! LDAPv3 messages (RFC 4511, 4) in BER (X.690, with RFC 4511, 5.1's restrictions: definite lengths only, one-byte
//! tags) – what a read-only directory reads and answers: bind (simple; SASL is read to be refused), unbind, search with
//! its filters, scopes and attributes, the entries and result of a search, extended operations (StartTLS, Who am I?),
//! abandon, and the requests that would change the directory, read only as far as needed to refuse them. Controls are
//! read; the simple paged results control (RFC 2696) is understood. kernoid's own, written from the RFCs; both
//! directions, so that tests can play the client.

use std::io;

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// The longest message read: a directory's requests are short.
pub const MAX_MESSAGE: usize = 1 << 20;

/// How deep filters may nest.
const FILTER_DEPTH: usize = 32;

/// Simple paged results (RFC 2696).
pub const OID_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";

/// A message: its id, the operation and the controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: i32,
    pub op: Op,
    pub controls: Vec<Control>,
}

impl Message {
    pub fn new(id: i32, op: Op) -> Self {
        Message { id, op, controls: Vec::new() }
    }
}

/// An operation (RFC 4511, 4.2 to 4.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest,
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(LdapResult),
    /// The requests that would change the directory: only their content as it came, to be refused.
    ModifyRequest(Vec<u8>),
    ModifyResponse(LdapResult),
    AddRequest(Vec<u8>),
    AddResponse(LdapResult),
    /// The DN to delete.
    DelRequest(String),
    DelResponse(LdapResult),
    ModifyDnRequest(Vec<u8>),
    ModifyDnResponse(LdapResult),
    CompareRequest(Vec<u8>),
    CompareResponse(LdapResult),
    /// The id of the message to abandon.
    AbandonRequest(i32),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    pub version: i32,
    pub dn: String,
    pub auth: BindAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAuth {
    /// A password; empty for an anonymous or unauthenticated bind.
    Simple(String),
    Sasl {
        mechanism: String,
        credentials: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindResponse {
    pub result: LdapResult,
    pub sasl_credentials: Option<Vec<u8>>,
}

/// The scope of a search (RFC 4511, 4.5.1.2; `Children` is subordinateSubtree of draft-sermersheim-ldap-subordinate-scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    OneLevel,
    Subtree,
    Children,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    Never,
    InSearching,
    FindingBase,
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub base: String,
    pub scope: Scope,
    pub deref: DerefAliases,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

/// A search filter (RFC 4511, 4.5.1.7); assertion values as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Equality(String, String),
    Substring(String, Substrings),
    GreaterOrEqual(String, String),
    LessOrEqual(String, String),
    Present(String),
    Approx(String, String),
    Extensible(ExtensibleMatch),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Substrings {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensibleMatch {
    pub rule: Option<String>,
    pub attribute: Option<String>,
    pub value: String,
    pub dn_attributes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialAttribute {
    pub name: String,
    pub values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultEntry {
    pub dn: String,
    pub attributes: Vec<PartialAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRequest {
    pub name: String,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub name: Option<String>,
    pub value: Option<Vec<u8>>,
}

/// The result of an operation (RFC 4511, 4.1.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    pub code: ResultCode,
    pub matched_dn: String,
    pub message: String,
    pub referral: Vec<String>,
}

impl LdapResult {
    pub fn new(code: ResultCode, message: &str) -> Self {
        LdapResult { code, matched_dn: String::new(), message: message.to_owned(), referral: Vec::new() }
    }
}

/// Result codes (RFC 4511, appendix A) – those kernoid answers with, and any other as its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    OperationsError,
    ProtocolError,
    SizeLimitExceeded,
    AuthMethodNotSupported,
    ConfidentialityRequired,
    NoSuchObject,
    InvalidCredentials,
    InsufficientAccessRights,
    Busy,
    UnwillingToPerform,
    Other,
    Code(u32),
}

impl ResultCode {
    fn number(self) -> u32 {
        match self {
            ResultCode::Success => 0,
            ResultCode::OperationsError => 1,
            ResultCode::ProtocolError => 2,
            ResultCode::SizeLimitExceeded => 4,
            ResultCode::AuthMethodNotSupported => 7,
            ResultCode::ConfidentialityRequired => 13,
            ResultCode::NoSuchObject => 32,
            ResultCode::InvalidCredentials => 49,
            ResultCode::InsufficientAccessRights => 50,
            ResultCode::Busy => 51,
            ResultCode::UnwillingToPerform => 53,
            ResultCode::Other => 80,
            ResultCode::Code(number) => number,
        }
    }

    fn from_number(number: u32) -> Self {
        [
            ResultCode::Success,
            ResultCode::OperationsError,
            ResultCode::ProtocolError,
            ResultCode::SizeLimitExceeded,
            ResultCode::AuthMethodNotSupported,
            ResultCode::ConfidentialityRequired,
            ResultCode::NoSuchObject,
            ResultCode::InvalidCredentials,
            ResultCode::InsufficientAccessRights,
            ResultCode::Busy,
            ResultCode::UnwillingToPerform,
            ResultCode::Other,
        ]
        .into_iter()
        .find(|code| code.number() == number)
        .unwrap_or(ResultCode::Code(number))
    }
}

/// A control (RFC 4511, 4.1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Simple paged results (RFC 2696): the page size asked for, or the size estimate answered, and the cookie.
    PagedResults {
        size: i32,
        cookie: Vec<u8>,
    },
    Other {
        oid: String,
        critical: bool,
        value: Option<Vec<u8>>,
    },
}

/// A message that is not LDAP as RFC 4511 has it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an LDAP message: {0}")]
pub struct Invalid(pub &'static str);

impl From<Invalid> for io::Error {
    fn from(error: Invalid) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

type Result<T> = std::result::Result<T, Invalid>;

// Tags: universal, application (0x40, constructed 0x60) and context-specific (0x80, constructed 0xa0) – RFC 4511, 4.
const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const ENUMERATED: u8 = 0x0a;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;

const fn application(number: u8, constructed: bool) -> u8 {
    0x40 | number | if constructed { 0x20 } else { 0 }
}

const fn context(number: u8, constructed: bool) -> u8 {
    0x80 | number | if constructed { 0x20 } else { 0 }
}

/// A reader of BER elements.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next element: its tag and content.
    fn element(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, header, length) = header(self.data)?.ok_or(Invalid("truncated"))?;
        let end = header.checked_add(length).filter(|end| *end <= self.data.len()).ok_or(Invalid("truncated"))?;
        let content = &self.data[header..end];
        self.data = &self.data[end..];
        Ok((tag, content))
    }

    /// The next element, which must have `tag`.
    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (found, content) = self.element()?;
        if found != tag {
            return Err(Invalid("an unexpected element"));
        }
        Ok(content)
    }

    /// The next element if it has `tag`.
    fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>> {
        if self.peek() == Some(tag) { self.expect(tag).map(Some) } else { Ok(None) }
    }

    fn end(&self) -> Result<()> {
        if self.data.is_empty() { Ok(()) } else { Err(Invalid("more than the element holds")) }
    }

    fn integer(&mut self, tag: u8) -> Result<i64> {
        integer(self.expect(tag)?)
    }

    fn int32(&mut self, tag: u8) -> Result<i32> {
        i32::try_from(self.integer(tag)?).map_err(|_| Invalid("an integer out of range"))
    }

    fn string(&mut self, tag: u8) -> Result<String> {
        text(self.expect(tag)?)
    }

    fn boolean(&mut self) -> Result<bool> {
        match self.expect(BOOLEAN)? {
            [value] => Ok(*value != 0),
            _ => Err(Invalid("a boolean of another length")),
        }
    }
}

/// The tag, the length of the header and the length of the content of the element at the start of `data`; none if
/// `data` does not hold the header yet.
fn header(data: &[u8]) -> Result<Option<(u8, usize, usize)>> {
    let Some(&tag) = data.first() else { return Ok(None) };
    if tag & 0x1f == 0x1f {
        return Err(Invalid("a tag of more than one byte"));
    }
    let Some(&first) = data.get(1) else { return Ok(None) };
    if first < 0x80 {
        return Ok(Some((tag, 2, usize::from(first))));
    }
    let bytes = usize::from(first & 0x7f);
    if bytes == 0 {
        return Err(Invalid("an indefinite length"));
    }
    if bytes > 4 {
        return Err(Invalid("a length longer than a message may be"));
    }
    let Some(length) = data.get(2..2 + bytes) else { return Ok(None) };
    let length = length.iter().fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
    Ok(Some((tag, 2 + bytes, length)))
}

fn integer(content: &[u8]) -> Result<i64> {
    if content.is_empty() || content.len() > 8 {
        return Err(Invalid("an integer of another length"));
    }
    let negative = content[0] & 0x80 != 0;
    let start = if negative { -1i64 } else { 0 };
    Ok(content.iter().fold(start, |value, byte| (value << 8) | i64::from(*byte)))
}

fn text(content: &[u8]) -> Result<String> {
    String::from_utf8(content.to_vec()).map_err(|_| Invalid("text that is not UTF-8"))
}

fn result(reader: &mut Reader<'_>) -> Result<LdapResult> {
    let code = reader.integer(ENUMERATED)?;
    let code = u32::try_from(code).map_err(|_| Invalid("a result code out of range"))?;
    let matched_dn = reader.string(OCTET_STRING)?;
    let message = reader.string(OCTET_STRING)?;
    let mut referral = Vec::new();
    if let Some(content) = reader.optional(context(3, true))? {
        let mut uris = Reader::new(content);
        while !uris.is_empty() {
            referral.push(uris.string(OCTET_STRING)?);
        }
    }
    Ok(LdapResult { code: ResultCode::from_number(code), matched_dn, message, referral })
}

fn filter(tag: u8, content: &[u8], depth: usize) -> Result<Filter> {
    if depth > FILTER_DEPTH {
        return Err(Invalid("a filter nested too deep"));
    }
    let assertion = |content| -> Result<(String, String)> {
        let mut reader = Reader::new(content);
        let name = reader.string(OCTET_STRING)?;
        let value = String::from_utf8_lossy(reader.expect(OCTET_STRING)?).into_owned();
        reader.end()?;
        Ok((name, value))
    };
    let set = |content| -> Result<Vec<Filter>> {
        let mut reader = Reader::new(content);
        let mut filters = Vec::new();
        while !reader.is_empty() {
            let (tag, content) = reader.element()?;
            filters.push(filter(tag, content, depth + 1)?);
        }
        Ok(filters)
    };
    Ok(match tag {
        0xa0 => Filter::And(set(content)?),
        0xa1 => Filter::Or(set(content)?),
        0xa2 => {
            let mut reader = Reader::new(content);
            let (tag, inner) = reader.element()?;
            reader.end()?;
            Filter::Not(Box::new(filter(tag, inner, depth + 1)?))
        }
        0xa3 => {
            let (name, value) = assertion(content)?;
            Filter::Equality(name, value)
        }
        0xa4 => {
            let mut reader = Reader::new(content);
            let name = reader.string(OCTET_STRING)?;
            let mut parts = Reader::new(reader.expect(SEQUENCE)?);
            reader.end()?;
            let mut substrings = Substrings::default();
            let mut first = true;
            while !parts.is_empty() {
                let (tag, value) = parts.element()?;
                let value = String::from_utf8_lossy(value).into_owned();
                if substrings.final_.is_some() {
                    return Err(Invalid("a substring after the final one"));
                }
                match tag {
                    0x80 if first => substrings.initial = Some(value),
                    0x81 => substrings.any.push(value),
                    0x82 => substrings.final_ = Some(value),
                    _ => return Err(Invalid("a substring of another kind")),
                }
                first = false;
            }
            if first {
                return Err(Invalid("a substring filter without substrings"));
            }
            Filter::Substring(name, substrings)
        }
        0xa5 => {
            let (name, value) = assertion(content)?;
            Filter::GreaterOrEqual(name, value)
        }
        0xa6 => {
            let (name, value) = assertion(content)?;
            Filter::LessOrEqual(name, value)
        }
        0x87 => Filter::Present(text(content)?),
        0xa8 => {
            let (name, value) = assertion(content)?;
            Filter::Approx(name, value)
        }
        0xa9 => {
            let mut reader = Reader::new(content);
            let rule = reader.optional(0x81)?.map(text).transpose()?;
            let attribute = reader.optional(0x82)?.map(text).transpose()?;
            let value = String::from_utf8_lossy(reader.expect(0x83)?).into_owned();
            let dn_attributes = match reader.optional(0x84)? {
                Some([flag]) => *flag != 0,
                Some(_) => return Err(Invalid("a boolean of another length")),
                None => false,
            };
            reader.end()?;
            Filter::Extensible(ExtensibleMatch { rule, attribute, value, dn_attributes })
        }
        _ => return Err(Invalid("a filter of no known kind")),
    })
}

fn search_request(content: &[u8]) -> Result<SearchRequest> {
    let mut reader = Reader::new(content);
    let base = reader.string(OCTET_STRING)?;
    let scope = match reader.integer(ENUMERATED)? {
        0 => Scope::Base,
        1 => Scope::OneLevel,
        2 => Scope::Subtree,
        3 => Scope::Children,
        _ => return Err(Invalid("a scope of no known kind")),
    };
    let deref = match reader.integer(ENUMERATED)? {
        0 => DerefAliases::Never,
        1 => DerefAliases::InSearching,
        2 => DerefAliases::FindingBase,
        3 => DerefAliases::Always,
        _ => return Err(Invalid("a deref of no known kind")),
    };
    let size_limit = reader.int32(INTEGER)?;
    let time_limit = reader.int32(INTEGER)?;
    if size_limit < 0 || time_limit < 0 {
        return Err(Invalid("a negative limit"));
    }
    let types_only = reader.boolean()?;
    let (tag, inner) = reader.element()?;
    let filter = filter(tag, inner, 0)?;
    let mut list = Reader::new(reader.expect(SEQUENCE)?);
    reader.end()?;
    let mut attributes = Vec::new();
    while !list.is_empty() {
        attributes.push(list.string(OCTET_STRING)?);
    }
    Ok(SearchRequest { base, scope, deref, size_limit, time_limit, types_only, filter, attributes })
}

fn controls(content: &[u8]) -> Result<Vec<Control>> {
    let mut reader = Reader::new(content);
    let mut controls = Vec::new();
    while !reader.is_empty() {
        let mut control = Reader::new(reader.expect(SEQUENCE)?);
        let oid = control.string(OCTET_STRING)?;
        let critical = if control.peek() == Some(BOOLEAN) { control.boolean()? } else { false };
        let value = control.optional(OCTET_STRING)?.map(<[u8]>::to_vec);
        control.end()?;
        controls.push(match (oid.as_str(), &value) {
            (OID_PAGED_RESULTS, Some(value)) => {
                let mut outer = Reader::new(value);
                let mut paged = Reader::new(outer.expect(SEQUENCE)?);
                outer.end()?;
                let size = paged.int32(INTEGER)?;
                let cookie = paged.expect(OCTET_STRING)?.to_vec();
                paged.end()?;
                Control::PagedResults { size, cookie }
            }
            _ => Control::Other { oid, critical, value },
        });
    }
    Ok(controls)
}

/// Reads the content of an LDAPMessage (the SEQUENCE's).
pub fn decode_message(content: &[u8]) -> Result<Message> {
    let mut reader = Reader::new(content);
    let id = reader.int32(INTEGER)?;
    if id < 0 {
        return Err(Invalid("a negative message id"));
    }
    let (tag, op) = reader.element()?;
    let mut inner = Reader::new(op);
    let op = match tag {
        0x60 => {
            let version = inner.int32(INTEGER)?;
            let dn = inner.string(OCTET_STRING)?;
            let auth = match inner.element()? {
                (0x80, password) => BindAuth::Simple(text(password)?),
                (0xa3, sasl) => {
                    let mut sasl = Reader::new(sasl);
                    let mechanism = sasl.string(OCTET_STRING)?;
                    let credentials = sasl.optional(OCTET_STRING)?.map(<[u8]>::to_vec);
                    sasl.end()?;
                    BindAuth::Sasl { mechanism, credentials }
                }
                _ => return Err(Invalid("an authentication of no known kind")),
            };
            inner.end()?;
            Op::BindRequest(BindRequest { version, dn, auth })
        }
        0x61 => {
            let result = result(&mut inner)?;
            let sasl_credentials = inner.optional(0x87)?.map(<[u8]>::to_vec);
            inner.end()?;
            Op::BindResponse(BindResponse { result, sasl_credentials })
        }
        0x42 => {
            inner.end()?;
            Op::UnbindRequest
        }
        0x63 => Op::SearchRequest(search_request(op)?),
        0x64 => {
            let dn = inner.string(OCTET_STRING)?;
            let mut list = Reader::new(inner.expect(SEQUENCE)?);
            inner.end()?;
            let mut attributes = Vec::new();
            while !list.is_empty() {
                let mut attribute = Reader::new(list.expect(SEQUENCE)?);
                let name = attribute.string(OCTET_STRING)?;
                let mut set = Reader::new(attribute.expect(SET)?);
                attribute.end()?;
                let mut values = Vec::new();
                while !set.is_empty() {
                    values.push(set.expect(OCTET_STRING)?.to_vec());
                }
                attributes.push(PartialAttribute { name, values });
            }
            Op::SearchResultEntry(SearchResultEntry { dn, attributes })
        }
        0x65 | 0x67 | 0x69 | 0x6b | 0x6d | 0x6f => {
            let result = result(&mut inner)?;
            inner.end()?;
            match tag {
                0x65 => Op::SearchResultDone(result),
                0x67 => Op::ModifyResponse(result),
                0x69 => Op::AddResponse(result),
                0x6b => Op::DelResponse(result),
                0x6d => Op::ModifyDnResponse(result),
                _ => Op::CompareResponse(result),
            }
        }
        0x66 => Op::ModifyRequest(op.to_vec()),
        0x68 => Op::AddRequest(op.to_vec()),
        0x4a => Op::DelRequest(text(op)?),
        0x6c => Op::ModifyDnRequest(op.to_vec()),
        0x6e => Op::CompareRequest(op.to_vec()),
        0x50 => Op::AbandonRequest(i32::try_from(integer(op)?).map_err(|_| Invalid("an id out of range"))?),
        0x77 => {
            let name = inner.string(0x80)?;
            let value = inner.optional(0x81)?.map(<[u8]>::to_vec);
            inner.end()?;
            Op::ExtendedRequest(ExtendedRequest { name, value })
        }
        0x78 => {
            let result = result(&mut inner)?;
            let name = inner.optional(0x8a)?.map(text).transpose()?;
            let value = inner.optional(0x8b)?.map(<[u8]>::to_vec);
            inner.end()?;
            Op::ExtendedResponse(ExtendedResponse { result, name, value })
        }
        _ => return Err(Invalid("an operation of no known kind")),
    };
    let controls = match reader.optional(context(0, true))? {
        Some(content) => controls(content)?,
        None => Vec::new(),
    };
    reader.end()?;
    Ok(Message { id, op, controls })
}

/// Writes an element: its tag, its length and `content`.
fn element(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend(&bytes[skip..]);
    }
    out.extend(content);
}

/// A constructed element whose content `fill` writes.
fn constructed(tag: u8, out: &mut Vec<u8>, fill: impl FnOnce(&mut Vec<u8>)) {
    let mut content = Vec::new();
    fill(&mut content);
    element(tag, &content, out);
}

fn write_integer(tag: u8, value: i64, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    // The shortest two's complement: drop leading bytes that only repeat the sign.
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    element(tag, &bytes[start..], out);
}

fn write_boolean(tag: u8, value: bool, out: &mut Vec<u8>) {
    element(tag, &[if value { 0xff } else { 0 }], out);
}

fn write_result(result: &LdapResult, out: &mut Vec<u8>) {
    write_integer(ENUMERATED, i64::from(result.code.number()), out);
    element(OCTET_STRING, result.matched_dn.as_bytes(), out);
    element(OCTET_STRING, result.message.as_bytes(), out);
    if !result.referral.is_empty() {
        constructed(context(3, true), out, |out| {
            result.referral.iter().for_each(|uri| element(OCTET_STRING, uri.as_bytes(), out));
        });
    }
}

fn write_filter(filter: &Filter, out: &mut Vec<u8>) {
    let assertion = |tag, name: &str, value: &str, out: &mut Vec<u8>| {
        constructed(tag, out, |out| {
            element(OCTET_STRING, name.as_bytes(), out);
            element(OCTET_STRING, value.as_bytes(), out);
        })
    };
    match filter {
        Filter::And(filters) => constructed(0xa0, out, |out| filters.iter().for_each(|f| write_filter(f, out))),
        Filter::Or(filters) => constructed(0xa1, out, |out| filters.iter().for_each(|f| write_filter(f, out))),
        Filter::Not(inner) => constructed(0xa2, out, |out| write_filter(inner, out)),
        Filter::Equality(name, value) => assertion(0xa3, name, value, out),
        Filter::Substring(name, substrings) => constructed(0xa4, out, |out| {
            element(OCTET_STRING, name.as_bytes(), out);
            constructed(SEQUENCE, out, |out| {
                if let Some(initial) = &substrings.initial {
                    element(0x80, initial.as_bytes(), out);
                }
                substrings.any.iter().for_each(|any| element(0x81, any.as_bytes(), out));
                if let Some(last) = &substrings.final_ {
                    element(0x82, last.as_bytes(), out);
                }
            });
        }),
        Filter::GreaterOrEqual(name, value) => assertion(0xa5, name, value, out),
        Filter::LessOrEqual(name, value) => assertion(0xa6, name, value, out),
        Filter::Present(name) => element(0x87, name.as_bytes(), out),
        Filter::Approx(name, value) => assertion(0xa8, name, value, out),
        Filter::Extensible(matching) => constructed(0xa9, out, |out| {
            if let Some(rule) = &matching.rule {
                element(0x81, rule.as_bytes(), out);
            }
            if let Some(attribute) = &matching.attribute {
                element(0x82, attribute.as_bytes(), out);
            }
            element(0x83, matching.value.as_bytes(), out);
            if matching.dn_attributes {
                write_boolean(0x84, true, out);
            }
        }),
    }
}

/// Writes a message.
pub fn encode_message(message: &Message, out: &mut Vec<u8>) {
    constructed(SEQUENCE, out, |out| {
        write_integer(INTEGER, i64::from(message.id), out);
        match &message.op {
            Op::BindRequest(request) => constructed(application(0, true), out, |out| {
                write_integer(INTEGER, i64::from(request.version), out);
                element(OCTET_STRING, request.dn.as_bytes(), out);
                match &request.auth {
                    BindAuth::Simple(password) => element(context(0, false), password.as_bytes(), out),
                    BindAuth::Sasl { mechanism, credentials } => constructed(context(3, true), out, |out| {
                        element(OCTET_STRING, mechanism.as_bytes(), out);
                        if let Some(credentials) = credentials {
                            element(OCTET_STRING, credentials, out);
                        }
                    }),
                }
            }),
            Op::BindResponse(response) => constructed(application(1, true), out, |out| {
                write_result(&response.result, out);
                if let Some(credentials) = &response.sasl_credentials {
                    element(context(7, false), credentials, out);
                }
            }),
            Op::UnbindRequest => element(application(2, false), &[], out),
            Op::SearchRequest(request) => constructed(application(3, true), out, |out| {
                element(OCTET_STRING, request.base.as_bytes(), out);
                let scope = match request.scope {
                    Scope::Base => 0,
                    Scope::OneLevel => 1,
                    Scope::Subtree => 2,
                    Scope::Children => 3,
                };
                write_integer(ENUMERATED, scope, out);
                let deref = match request.deref {
                    DerefAliases::Never => 0,
                    DerefAliases::InSearching => 1,
                    DerefAliases::FindingBase => 2,
                    DerefAliases::Always => 3,
                };
                write_integer(ENUMERATED, deref, out);
                write_integer(INTEGER, i64::from(request.size_limit), out);
                write_integer(INTEGER, i64::from(request.time_limit), out);
                write_boolean(BOOLEAN, request.types_only, out);
                write_filter(&request.filter, out);
                constructed(SEQUENCE, out, |out| {
                    request.attributes.iter().for_each(|name| element(OCTET_STRING, name.as_bytes(), out));
                });
            }),
            Op::SearchResultEntry(entry) => constructed(application(4, true), out, |out| {
                element(OCTET_STRING, entry.dn.as_bytes(), out);
                constructed(SEQUENCE, out, |out| {
                    for attribute in &entry.attributes {
                        constructed(SEQUENCE, out, |out| {
                            element(OCTET_STRING, attribute.name.as_bytes(), out);
                            constructed(SET, out, |out| {
                                attribute.values.iter().for_each(|value| element(OCTET_STRING, value, out));
                            });
                        });
                    }
                });
            }),
            Op::SearchResultDone(result) => constructed(application(5, true), out, |out| write_result(result, out)),
            Op::ModifyRequest(content) => element(application(6, true), content, out),
            Op::ModifyResponse(result) => constructed(application(7, true), out, |out| write_result(result, out)),
            Op::AddRequest(content) => element(application(8, true), content, out),
            Op::AddResponse(result) => constructed(application(9, true), out, |out| write_result(result, out)),
            Op::DelRequest(dn) => element(application(10, false), dn.as_bytes(), out),
            Op::DelResponse(result) => constructed(application(11, true), out, |out| write_result(result, out)),
            Op::ModifyDnRequest(content) => element(application(12, true), content, out),
            Op::ModifyDnResponse(result) => constructed(application(13, true), out, |out| write_result(result, out)),
            Op::CompareRequest(content) => element(application(14, true), content, out),
            Op::CompareResponse(result) => constructed(application(15, true), out, |out| write_result(result, out)),
            Op::AbandonRequest(id) => write_integer(application(16, false), i64::from(*id), out),
            Op::ExtendedRequest(request) => constructed(application(23, true), out, |out| {
                element(context(0, false), request.name.as_bytes(), out);
                if let Some(value) = &request.value {
                    element(context(1, false), value, out);
                }
            }),
            Op::ExtendedResponse(response) => constructed(application(24, true), out, |out| {
                write_result(&response.result, out);
                if let Some(name) = &response.name {
                    element(context(10, false), name.as_bytes(), out);
                }
                if let Some(value) = &response.value {
                    element(context(11, false), value, out);
                }
            }),
        }
        if !message.controls.is_empty() {
            constructed(context(0, true), out, |out| {
                for control in &message.controls {
                    constructed(SEQUENCE, out, |out| match control {
                        Control::PagedResults { size, cookie } => {
                            element(OCTET_STRING, OID_PAGED_RESULTS.as_bytes(), out);
                            let mut value = Vec::new();
                            constructed(SEQUENCE, &mut value, |value| {
                                write_integer(INTEGER, i64::from(*size), value);
                                element(OCTET_STRING, cookie, value);
                            });
                            element(OCTET_STRING, &value, out);
                        }
                        Control::Other { oid, critical, value } => {
                            element(OCTET_STRING, oid.as_bytes(), out);
                            if *critical {
                                write_boolean(BOOLEAN, true, out);
                            }
                            if let Some(value) = value {
                                element(OCTET_STRING, value, out);
                            }
                        }
                    });
                }
            });
        }
    });
}

/// LDAP messages over a stream, for `tokio_util`'s `Framed`: every message is a SEQUENCE.
#[derive(Debug, Default)]
pub struct Codec;

impl Decoder for Codec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, buffer: &mut BytesMut) -> io::Result<Option<Message>> {
        let Some((tag, header, length)) = header(buffer)? else { return Ok(None) };
        if tag != SEQUENCE {
            return Err(Invalid("a message that is not a SEQUENCE").into());
        }
        if length > MAX_MESSAGE {
            return Err(Invalid("a message longer than kernoid reads").into());
        }
        if buffer.len() < header + length {
            buffer.reserve(header + length - buffer.len());
            return Ok(None);
        }
        let message = decode_message(&buffer[header..header + length])?;
        buffer.advance(header + length);
        Ok(Some(message))
    }
}

impl Encoder<Message> for Codec {
    type Error = io::Error;

    fn encode(&mut self, message: Message, buffer: &mut BytesMut) -> io::Result<()> {
        let mut out = Vec::new();
        encode_message(&message, &mut out);
        buffer.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    fn round_trip(message: Message) {
        let mut out = Vec::new();
        encode_message(&message, &mut out);
        let mut buffer = BytesMut::from(&out[..]);
        assert_eq!(Codec.decode(&mut buffer).unwrap(), Some(message));
        assert!(buffer.is_empty());
    }

    /// A bind as ldapsearch sends it (`-x -D cn=admin -w secret`), read byte by byte.
    #[test]
    fn reads_a_simple_bind() {
        let bytes = hex("30 1c 02 01 01 60 15 02 01 03 04 08 63 6e 3d 61 64 6d 69 6e 80 06 73 65 63 72 65 74 a0 00");
        let mut codec = Codec;
        let mut buffer = BytesMut::new();
        for byte in &bytes[..bytes.len() - 1] {
            buffer.extend_from_slice(&[*byte]);
            assert_eq!(codec.decode(&mut buffer).unwrap(), None);
        }
        buffer.extend_from_slice(&bytes[bytes.len() - 1..]);
        let message = codec.decode(&mut buffer).unwrap().unwrap();
        assert_eq!(
            message,
            Message::new(
                1,
                Op::BindRequest(BindRequest {
                    version: 3,
                    dn: "cn=admin".into(),
                    auth: BindAuth::Simple("secret".into())
                })
            )
        );
    }

    /// A search with a filter of every kind, the paged results control, and the answers.
    #[test]
    fn every_message_round_trips() {
        let filter = Filter::And(vec![
            Filter::Or(vec![
                Filter::Equality("objectClass".into(), "person".into()),
                Filter::Approx("cn".into(), "alice".into()),
            ]),
            Filter::Not(Box::new(Filter::Present("telephoneNumber".into()))),
            Filter::Substring(
                "mail".into(),
                Substrings {
                    initial: Some("a".into()),
                    any: vec!["b".into(), "c".into()],
                    final_: Some(".example".into()),
                },
            ),
            Filter::GreaterOrEqual("uidNumber".into(), "1000".into()),
            Filter::LessOrEqual("uidNumber".into(), "2000".into()),
            Filter::Extensible(ExtensibleMatch {
                rule: Some("caseExactMatch".into()),
                attribute: Some("cn".into()),
                value: "Alice".into(),
                dn_attributes: true,
            }),
        ]);
        let mut search = Message::new(
            2_147_483_647,
            Op::SearchRequest(SearchRequest {
                base: "o=firma".into(),
                scope: Scope::Subtree,
                deref: DerefAliases::Always,
                size_limit: 500,
                time_limit: 0,
                types_only: false,
                filter,
                attributes: vec!["mail".into(), "+".into()],
            }),
        );
        search.controls = vec![
            Control::PagedResults { size: 100, cookie: vec![1, 2] },
            Control::Other { oid: "1.2.3".into(), critical: true, value: Some(vec![0]) },
        ];
        round_trip(search);
        let ok = LdapResult::new(ResultCode::Success, "");
        let mut refused = LdapResult::new(ResultCode::NoSuchObject, "no such entry");
        refused.matched_dn = "o=firma".into();
        refused.referral = vec!["ldap://elsewhere/".into()];
        for op in [
            Op::BindRequest(BindRequest {
                version: 3,
                dn: String::new(),
                auth: BindAuth::Sasl { mechanism: "EXTERNAL".into(), credentials: None },
            }),
            Op::BindResponse(BindResponse { result: ok.clone(), sasl_credentials: Some(vec![9]) }),
            Op::UnbindRequest,
            Op::SearchResultEntry(SearchResultEntry {
                dn: "uid=ä,o=firma".into(),
                attributes: vec![
                    PartialAttribute { name: "mail".into(), values: vec![b"a@firma.example".to_vec(), vec![0; 300]] },
                    PartialAttribute { name: "cn".into(), values: Vec::new() },
                ],
            }),
            Op::SearchResultDone(refused),
            Op::ModifyRequest(hex("04 00 30 00")),
            Op::ModifyResponse(LdapResult::new(ResultCode::UnwillingToPerform, "read only")),
            Op::AddResponse(LdapResult::new(ResultCode::Code(68), "")),
            Op::DelRequest("uid=a,o=firma".into()),
            Op::DelResponse(ok.clone()),
            Op::CompareResponse(ok.clone()),
            Op::AbandonRequest(300),
            Op::ExtendedRequest(ExtendedRequest { name: "1.3.6.1.4.1.1466.20037".into(), value: None }),
            Op::ExtendedResponse(ExtendedResponse { result: ok, name: None, value: Some(b"dn:o=x".to_vec()) }),
        ] {
            round_trip(Message::new(7, op));
        }
    }

    #[test]
    fn integers_are_the_shortest_twos_complement() {
        for (value, encoded) in [
            (0, "020100"),
            (127, "02017f"),
            (128, "02020080"),
            (256, "02020100"),
            (-1, "0201ff"),
            (-128, "020180"),
            (-129, "0202ff7f"),
        ] {
            let mut out = Vec::new();
            write_integer(INTEGER, value, &mut out);
            assert_eq!(out, hex(encoded), "{value}");
            assert_eq!(integer(&out[2..]).unwrap(), value);
        }
    }

    #[test]
    fn what_is_not_ldap_is_refused() {
        let decode = |text: &str| Codec.decode(&mut BytesMut::from(&hex(text)[..]));
        let refused = |text: &str, why: &str| {
            let error = decode(text).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{text}");
            assert!(error.to_string().ends_with(why), "{text}: {error}");
        };
        refused("31 00", "a message that is not a SEQUENCE");
        refused("30 80 00 00", "an indefinite length");
        refused("30 84 7f ff ff ff", "a message longer than kernoid reads");
        refused("30 03 02 01 ff", "a negative message id");
        refused("30 05 02 01 01 7f 00", "a tag of more than one byte");
        refused("30 05 02 01 01 79 00", "an operation of no known kind");
        refused("30 06 02 01 01 42 01 00", "more than the element holds");
        refused("30 07 02 01 01 60 02 02 05", "truncated");
        // A filter nested deeper than 32.
        let mut filter = hex("87 01 61");
        for _ in 0..40 {
            filter = [vec![0xa2, filter.len() as u8], filter].concat();
            if filter.len() > 120 {
                break;
            }
        }
        let mut deep = Vec::new();
        let search = [hex("04 00 0a 01 00 0a 01 00 02 01 00 02 01 00 01 01 00"), filter, hex("30 00")].concat();
        element(SEQUENCE, &[hex("02 01 01"), [vec![0x63, search.len() as u8], search].concat()].concat(), &mut deep);
        assert!(Codec.decode(&mut BytesMut::from(&deep[..])).unwrap_err().to_string().contains("nested too deep"));
        assert_eq!(decode("30 05 02").unwrap(), None, "waits for the rest");
    }
}
