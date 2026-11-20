// SPDX-License-Identifier: AGPL-3.0-or-later
//! DKIM (RFC 6376): signatures verified with the keys DNS publishes, and messages signed with kernoid's keys. The
//! algorithms are `rsa-sha256` (RSA keys of 1024 bits and more) and `ed25519-sha256` (RFC 8463); `rsa-sha1` is no
//! longer acceptable (RFC 8301, 3.1) and gives the result `policy`. ARC's message signatures (RFC 8617, 4.1.2) are
//! the same signature under another name; `arc` uses what is here.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    digest,
    rand::SystemRandom,
    rsa::KeyPair as RsaKeyPair,
    signature::{self, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey},
};
use base64::Engine;

use super::{
    message::{Canonicalization, Header, Message},
    tags::{self, Tag},
};
use crate::{Dns, dns::DnsError};

/// At most this many signatures of a message are verified; the rest are left out.
const MAX_SIGNATURES: usize = 10;

/// DKIM's results (RFC 8601, 2.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimResult {
    Pass,
    Neutral(String),
    Fail(String),
    /// Signed, but in a way kernoid does not accept (`rsa-sha1`).
    Policy(String),
    TempError(String),
    PermError(String),
    None,
}

impl DkimResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Neutral(_) => "neutral",
            Self::Fail(_) => "fail",
            Self::Policy(_) => "policy",
            Self::TempError(_) => "temperror",
            Self::PermError(_) => "permerror",
            Self::None => "none",
        }
    }

    /// Why, for all but `pass` and `none`.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Neutral(reason)
            | Self::Fail(reason)
            | Self::Policy(reason)
            | Self::TempError(reason)
            | Self::PermError(reason) => Some(reason),
            Self::Pass | Self::None => None,
        }
    }
}

/// The signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

impl Algorithm {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "rsa-sha1" => Some(Self::RsaSha1),
            "rsa-sha256" => Some(Self::RsaSha256),
            "ed25519-sha256" => Some(Self::Ed25519Sha256),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RsaSha1 => "rsa-sha1",
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }

    fn hash(self) -> &'static str {
        match self {
            Self::RsaSha1 => "sha1",
            Self::RsaSha256 | Self::Ed25519Sha256 => "sha256",
        }
    }

    fn key_type(self) -> KeyType {
        match self {
            Self::RsaSha1 | Self::RsaSha256 => KeyType::Rsa,
            Self::Ed25519Sha256 => KeyType::Ed25519,
        }
    }
}

/// A signature: of DKIM (`DKIM-Signature`), or ARC's of a message (`ARC-Message-Signature`, with `i=` the instance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: Algorithm,
    pub domain: String,
    pub selector: String,
    /// `h=`, in lower case.
    pub headers: Vec<String>,
    /// `i=` of DKIM (the agent or user identifier, `@d` by default).
    pub identity: String,
    /// `i=` of ARC: the instance.
    pub instance: u32,
    pub body_length: Option<usize>,
    pub header_canonicalization: Canonicalization,
    pub body_canonicalization: Canonicalization,
    pub body_hash: Vec<u8>,
    pub signature: Vec<u8>,
    /// `b=` as written, without whitespace.
    pub b: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

/// Which kind of signature header is parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dkim,
    ArcMessage,
}

fn base64(value: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(tags::compact(value)).ok()
}

fn number(value: &str) -> Option<u64> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 12 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())?
}

/// A domain name as DKIM takes it: labels of letters, digits, `-` and `_`, in lower case, without the final dot.
pub(crate) fn domain_name(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63 && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    valid.then_some(value)
}

impl Signature {
    /// Parses the value of a signature header; the error says why it is a `permerror`.
    pub(crate) fn parse(value: &[u8], kind: Kind) -> Result<(Self, Vec<Tag>), String> {
        let tags = tags::parse(value).map_err(|error| format!("signature syntax: {error}"))?;
        let get = |name: &str| tags::get(&tags, name);
        let required = |name: &str| get(name).ok_or_else(|| format!("the signature has no {name}="));
        let instance = match kind {
            Kind::Dkim => {
                if required("v")? != "1" {
                    return Err("the signature's version is not 1".into());
                }
                0
            }
            Kind::ArcMessage => number(required("i")?)
                .and_then(|instance| u32::try_from(instance).ok())
                .filter(|instance| (1..=50).contains(instance))
                .ok_or("the instance is not 1 to 50")?,
        };
        let algorithm = Algorithm::parse(required("a")?).ok_or("an unknown signing algorithm")?;
        let b = tags::compact(required("b")?);
        let signature = base64(&b).filter(|signature| !signature.is_empty()).ok_or("b= is not base64")?;
        let body_hash = base64(required("bh")?).filter(|hash| !hash.is_empty()).ok_or("bh= is not base64")?;
        let domain = domain_name(required("d")?).ok_or("d= is not a domain")?;
        let selector = domain_name(required("s")?).ok_or("s= is not a selector")?;
        let headers: Vec<String> = required("h")?
            .split(':')
            .map(|name| name.trim().to_ascii_lowercase())
            .collect();
        if headers.iter().any(String::is_empty) {
            return Err("h= names an empty header".into());
        }
        if !headers.iter().any(|name| name == "from") {
            return Err("the From header is not signed".into());
        }
        if kind == Kind::ArcMessage && headers.iter().any(|name| name == "arc-seal") {
            return Err("the message signature signs ARC-Seal".into());
        }
        let (header_canonicalization, body_canonicalization) = match get("c") {
            None => (Canonicalization::Simple, Canonicalization::Simple),
            Some(value) => {
                let (header, body) = value.split_once('/').unwrap_or((value, "simple"));
                (
                    Canonicalization::parse(header.trim()).ok_or("an unknown canonicalization")?,
                    Canonicalization::parse(body.trim()).ok_or("an unknown canonicalization")?,
                )
            }
        };
        let identity = match (kind, get("i")) {
            (Kind::Dkim, Some(identity)) => {
                let identity = identity.trim().to_ascii_lowercase();
                let (_, identity_domain) = identity.rsplit_once('@').ok_or("i= is not an identity")?;
                let identity_domain = identity_domain.trim_end_matches('.');
                if identity_domain != domain && !identity_domain.ends_with(&format!(".{domain}")) {
                    return Err("i= is not in the domain of d=".into());
                }
                identity
            }
            _ => format!("@{domain}"),
        };
        if let Some(query) = get("q")
            && !query.split(':').any(|method| method.trim().eq_ignore_ascii_case("dns/txt"))
        {
            return Err("an unknown query method".into());
        }
        let body_length = match get("l") {
            Some(length) => Some(number(length).ok_or("l= is not a number")? as usize),
            None => None,
        };
        let timestamp = get("t").map(|value| number(value).ok_or("t= is not a number")).transpose()?;
        let expiration = get("x").map(|value| number(value).ok_or("x= is not a number")).transpose()?;
        if let (Some(timestamp), Some(expiration)) = (timestamp, expiration)
            && expiration < timestamp
        {
            return Err("the signature expires before it was made".into());
        }
        let parsed = Self {
            algorithm,
            domain,
            selector,
            headers,
            identity,
            instance,
            body_length,
            header_canonicalization,
            body_canonicalization,
            body_hash,
            signature,
            b,
            timestamp,
            expiration,
        };
        Ok((parsed, tags))
    }
}

/// The types of keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ed25519,
}

/// A key record (RFC 6376, 3.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainKey {
    pub key_type: KeyType,
    /// The public key; empty when it was revoked.
    pub public: Vec<u8>,
    /// `h=`: the hashes the key may be used with; `None` for any.
    pub hashes: Option<Vec<String>>,
    /// `t=y`: the domain is testing DKIM.
    pub testing: bool,
    /// `t=s`: `i=` must be in `d=` itself, not a subdomain.
    pub strict: bool,
}

impl DomainKey {
    pub fn parse(record: &str) -> Result<Self, String> {
        let tags = tags::parse(record.as_bytes()).map_err(|error| format!("key syntax: {error}"))?;
        if let Some(version) = tags.iter().position(|tag| tag.name == "v")
            && (version != 0 || tags[version].value != "DKIM1")
        {
            return Err("the key's version is not DKIM1".into());
        }
        let get = |name: &str| tags::get(&tags, name);
        let key_type = match get("k").map(str::to_ascii_lowercase).as_deref() {
            None | Some("rsa") => KeyType::Rsa,
            Some("ed25519") => KeyType::Ed25519,
            Some(_) => return Err("an unknown key type".into()),
        };
        let public = get("p").ok_or("the key record has no p=")?;
        let public = if tags::compact(public).is_empty() { Vec::new() } else { base64(public).ok_or("p= is not base64")? };
        let hashes = get("h").map(|value| value.split(':').map(|hash| hash.trim().to_ascii_lowercase()).collect());
        if let Some(services) = get("s")
            && !services.split(':').any(|service| matches!(service.trim(), "*" | "email"))
        {
            return Err("the key is not for email".into());
        }
        let flags: Vec<String> =
            get("t").map(|value| value.split(':').map(|flag| flag.trim().to_ascii_lowercase()).collect()).unwrap_or_default();
        Ok(Self {
            key_type,
            public,
            hashes,
            testing: flags.iter().any(|flag| flag == "y"),
            strict: flags.iter().any(|flag| flag == "s"),
        })
    }

    /// Whether `signature` verifies `data` with this key and `algorithm`.
    pub fn verifies(&self, algorithm: Algorithm, data: &[u8], signature: &[u8]) -> bool {
        match (algorithm, self.key_type) {
            (Algorithm::RsaSha256, KeyType::Rsa) => {
                // RFC 8301, 3.2: keys of fewer than 1024 bits are not acceptable – aws-lc-rs refuses them here.
                UnparsedPublicKey::new(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, &self.public)
                    .verify(data, signature)
                    .is_ok()
            }
            (Algorithm::Ed25519Sha256, KeyType::Ed25519) => {
                // RFC 8463, 3: Ed25519 signs the SHA-256 hash of the data.
                let hash = digest::digest(&digest::SHA256, data);
                UnparsedPublicKey::new(&signature::ED25519, &self.public).verify(hash.as_ref(), signature).is_ok()
            }
            _ => false,
        }
    }
}

/// What the check of one signature found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimOutput {
    pub result: DkimResult,
    /// The signature, when it could be parsed.
    pub signature: Option<Signature>,
    /// The key said `t=y`.
    pub testing: bool,
}

impl DkimOutput {
    pub fn result(&self) -> &DkimResult {
        &self.result
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

/// The hash of the body as `signature` takes it (canonicalized, cut to `l=`), or `None` if the body is shorter than
/// `l=`.
pub(crate) fn body_hash(body: &[u8], canonicalization: Canonicalization, length: Option<usize>) -> Option<Vec<u8>> {
    let canonical = canonicalization.body(body);
    let hashed = match length {
        Some(length) if length > canonical.len() => return None,
        Some(length) => &canonical[..length],
        None => &canonical[..],
    };
    Some(digest::digest(&digest::SHA256, hashed).as_ref().to_vec())
}

/// The header fields `names` selects, canonicalized: each name takes the last instance not taken yet; names with no
/// instance left add nothing (RFC 6376, 5.4.2).
pub(crate) fn signed_headers(message: &Message<'_>, names: &[String], canonicalization: Canonicalization) -> Vec<u8> {
    let mut taken: HashMap<&str, usize> = HashMap::new();
    let mut out = Vec::new();
    for name in names {
        let instances: Vec<&Header<'_>> = message.all(name).collect();
        let used = taken.entry(name.as_str()).or_default();
        if *used < instances.len() {
            let header = instances[instances.len() - 1 - *used];
            canonicalization.header(header.raw, &mut out);
        }
        *used += 1;
    }
    out
}

/// The signature header itself as it is hashed: canonicalized, with the value of `b=` taken out and without its
/// final line end (RFC 6376, 3.7).
pub(crate) fn without_b(header: &Header<'_>, tags: &[Tag], canonicalization: Canonicalization) -> Vec<u8> {
    let mut raw = header.raw.to_vec();
    if let Some(b) = tags.iter().find(|tag| tag.name == "b") {
        let start = header.value_start + b.span.start;
        let end = header.value_start + b.span.end;
        // The span reaches the line end when b= is last: the line end stays.
        let end = end.min(header.value_start + header.value().len());
        raw.drain(start..end);
    }
    let mut out = Vec::new();
    canonicalization.header(&raw, &mut out);
    out.truncate(out.len() - 2);
    out
}

/// Seconds since 1970.
pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0)
}

/// Looks up the key of `selector` at `domain`.
pub(crate) async fn key(dns: &Dns, selector: &str, domain: &str) -> Result<DomainKey, DkimResult> {
    let records = match dns.txt(&format!("{selector}._domainkey.{domain}")).await {
        Ok(records) => records,
        Err(DnsError::Temporary(error)) => return Err(DkimResult::TempError(format!("key unavailable: {error}"))),
        Err(_) => return Err(DkimResult::PermError("no key for the signature".into())),
    };
    let mut last = None;
    for record in records {
        match DomainKey::parse(&record) {
            Ok(key) => return Ok(key),
            Err(error) => last = Some(error),
        }
    }
    Err(DkimResult::PermError(last.unwrap_or_else(|| "no key for the signature".into())))
}

/// Checks a signature whose header is `header` and whose parsed form is `signature` against `message`.
pub(crate) async fn check(
    dns: &Dns,
    message: &Message<'_>,
    header: &Header<'_>,
    signature: &Signature,
    tags: &[Tag],
) -> (DkimResult, bool) {
    if signature.algorithm == Algorithm::RsaSha1 {
        return (DkimResult::Policy("rsa-sha1 is no longer accepted (RFC 8301)".into()), false);
    }
    if signature.expiration.is_some_and(|expiration| expiration < now()) {
        return (DkimResult::Fail("the signature has expired".into()), false);
    }
    let key = match key(dns, &signature.selector, &signature.domain).await {
        Ok(key) => key,
        Err(result) => return (result, false),
    };
    if key.hashes.as_ref().is_some_and(|hashes| !hashes.iter().any(|hash| hash == signature.algorithm.hash())) {
        return (DkimResult::PermError("the key does not allow the signature's hash".into()), key.testing);
    }
    if key.public.is_empty() {
        return (DkimResult::Fail("the key was revoked".into()), key.testing);
    }
    if key.key_type != signature.algorithm.key_type() {
        return (DkimResult::PermError("the key does not fit the signing algorithm".into()), key.testing);
    }
    if key.strict && signature.identity.rsplit_once('@').is_some_and(|(_, domain)| domain != signature.domain) {
        return (DkimResult::PermError("the key allows no subdomain in i=".into()), key.testing);
    }
    match body_hash(message.body, signature.body_canonicalization, signature.body_length) {
        Some(hash) if hash == signature.body_hash => {}
        _ => return (DkimResult::Fail("the body hash did not verify".into()), key.testing),
    }
    let mut data = signed_headers(message, &signature.headers, signature.header_canonicalization);
    data.extend_from_slice(&without_b(header, tags, signature.header_canonicalization));
    if key.verifies(signature.algorithm, &data, &signature.signature) {
        (DkimResult::Pass, key.testing)
    } else {
        (DkimResult::Fail("the signature did not verify".into()), key.testing)
    }
}

/// Verifies the DKIM signatures of `message`; empty if it has none.
pub async fn verify(dns: &Dns, message: &Message<'_>) -> Vec<DkimOutput> {
    let mut outputs = Vec::new();
    for header in message.all("DKIM-Signature").take(MAX_SIGNATURES) {
        let output = match Signature::parse(header.value(), Kind::Dkim) {
            Ok((signature, tags)) => {
                let (result, testing) = check(dns, message, header, &signature, &tags).await;
                DkimOutput { result, signature: Some(signature), testing }
            }
            Err(error) => DkimOutput { result: DkimResult::PermError(error), signature: None, testing: false },
        };
        outputs.push(output);
    }
    outputs
}

/// A private key that signs.
pub enum SigningKey {
    Rsa(RsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rsa(_) => "SigningKey::Rsa",
            Self::Ed25519(_) => "SigningKey::Ed25519",
        })
    }
}

impl SigningKey {
    /// An RSA key from PKCS#8 (or PKCS#1) DER.
    pub fn rsa(der: &[u8]) -> Result<Self, String> {
        RsaKeyPair::from_pkcs8(der)
            .or_else(|_| RsaKeyPair::from_der(der))
            .map(Self::Rsa)
            .map_err(|error| format!("an RSA key: {error}"))
    }

    /// An Ed25519 key from PKCS#8 DER.
    pub fn ed25519(der: &[u8]) -> Result<Self, String> {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).map(Self::Ed25519).map_err(|error| format!("an Ed25519 key: {error}"))
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::RsaSha256,
            Self::Ed25519(_) => Algorithm::Ed25519Sha256,
        }
    }

    /// The public key as a key record's `p=` has it.
    pub fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Rsa(key) => key.public_key().as_ref().to_vec(),
            Self::Ed25519(key) => key.public_key().as_ref().to_vec(),
        }
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Rsa(key) => {
                let mut signature = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut signature)
                    .map_err(|error| format!("signing: {error}"))?;
                Ok(signature)
            }
            Self::Ed25519(key) => {
                let hash = digest::digest(&digest::SHA256, data);
                Ok(key.sign(hash.as_ref()).as_ref().to_vec())
            }
        }
    }
}

/// A header with its tags folded to lines of about 76 characters, the value of `b=` last and folded alone.
pub(crate) fn fold(name: &str, tags: &[(&str, String)], b: &str) -> String {
    let mut header = format!("{name}:");
    let mut line = header.len();
    for (tag, value) in tags {
        let item = format!(" {tag}={value};");
        if line + item.len() > 76 && line > name.len() + 1 {
            header.push_str("\r\n\t");
            line = 1;
            header.push_str(item.trim_start());
            line += item.len() - 1;
        } else {
            header.push_str(&item);
            line += item.len();
        }
    }
    header.push_str("\r\n\tb=");
    line = 3;
    let mut rest = b;
    while !rest.is_empty() {
        let room = 76usize.saturating_sub(line).max(1);
        let (piece, after) = rest.split_at(room.min(rest.len()));
        header.push_str(piece);
        rest = after;
        if !rest.is_empty() {
            header.push_str("\r\n\t");
            line = 1;
        }
    }
    header.push_str("\r\n");
    header
}

/// Builds a signature header named `name`: `tags` (without `b=`) are written, the header with an empty `b=` is
/// canonicalized relaxed and appended to `signed`, and the key signs it.
pub(crate) fn finish(name: &str, tags: &[(&str, String)], key: &SigningKey, mut signed: Vec<u8>) -> Result<String, String> {
    let unsigned = fold(name, tags, "");
    let header = Header { name: name.as_bytes(), raw: unsigned.as_bytes(), value_start: name.len() + 1 };
    let parsed = tags::parse(header.value()).map_err(|error| error.to_string())?;
    signed.extend_from_slice(&without_b(&header, &parsed, Canonicalization::Relaxed));
    let signature = key.sign(&signed)?;
    Ok(fold(name, tags, &base64::engine::general_purpose::STANDARD.encode(signature)))
}

/// Signs `raw` for `domain` with `key` under `selector`: the headers named in `headers` that the message has (each
/// instance), relaxed/relaxed. The `DKIM-Signature` header, with its line end.
pub fn sign(raw: &[u8], key: &SigningKey, domain: &str, selector: &str, headers: &[&str]) -> Result<String, String> {
    let message = Message::parse(raw);
    let names: Vec<String> = headers
        .iter()
        .flat_map(|name| std::iter::repeat_n(name.to_ascii_lowercase(), message.all(name).count()))
        .collect();
    if !names.iter().any(|name| name == "from") {
        return Err("the message has no From header".into());
    }
    let body_hash = body_hash(message.body, Canonicalization::Relaxed, None).unwrap_or_default();
    let display: Vec<String> = headers
        .iter()
        .flat_map(|name| std::iter::repeat_n((*name).to_owned(), message.all(name).count()))
        .collect();
    let tags = [
        ("v", "1".to_owned()),
        ("a", key.algorithm().as_str().to_owned()),
        ("s", selector.to_owned()),
        ("d", domain.to_owned()),
        ("c", "relaxed/relaxed".to_owned()),
        ("h", display.join(":")),
        ("t", now().to_string()),
        ("bh", base64::engine::general_purpose::STANDARD.encode(body_hash)),
    ];
    let signed = signed_headers(&message, &names, Canonicalization::Relaxed);
    finish("DKIM-Signature", &tags, key, signed)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use super::*;
    use crate::dns::FOREVER;

    /// RFC 8463, appendix A.
    pub(crate) const RFC8463_MESSAGE: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n \
d=football.example.com; i=@football.example.com;\r\n \
q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n \
subject : date : message-id : from : subject : date;\r\n \
bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n \
b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n \
Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n\
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n \
d=football.example.com; i=@football.example.com;\r\n \
q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n \
date : message-id : from : subject : date;\r\n \
bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n \
b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n \
DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n \
dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\n\
From: Joe SixPack <joe@football.example.com>\r\n\
To: Suzie Q <suzie@shopping.example.net>\r\n\
Subject: Is dinner ready?\r\n\
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n\
Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n\
\r\n\
Hi.\r\n\
\r\n\
We lost the game.  Are you hungry yet?\r\n\
\r\n\
Joe.\r\n";

    pub(crate) const RFC8463_ED25519: &str = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    pub(crate) const RFC8463_RSA: &str = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";

    pub(crate) fn txt(dns: &Dns, name: &str, records: &[&str]) {
        let records = records.iter().map(|record| (*record).to_owned()).collect();
        dns.txt.insert(crate::dns::absolute(name).into(), Ok(records), Instant::now() + FOREVER);
    }

    fn rfc8463_dns() -> Dns {
        let dns = Dns::offline();
        txt(&dns, "brisbane._domainkey.football.example.com", &[RFC8463_ED25519]);
        txt(&dns, "test._domainkey.football.example.com", &[RFC8463_RSA]);
        dns
    }

    #[tokio::test]
    async fn rfc_8463_example_verifies() {
        let dns = rfc8463_dns();
        let message = Message::parse(RFC8463_MESSAGE.as_bytes());
        let outputs = verify(&dns, &message).await;
        assert_eq!(outputs.len(), 2);
        for output in &outputs {
            assert_eq!(output.result, DkimResult::Pass, "{output:?}");
        }
        assert_eq!(outputs[0].signature.as_ref().unwrap().algorithm, Algorithm::Ed25519Sha256);
        assert_eq!(outputs[1].signature.as_ref().unwrap().selector, "test");

        // A changed body, a changed signed header, an added From: no longer.
        for (from, to) in [("We lost", "We won"), ("Is dinner ready?", "Is lunch ready?")] {
            let changed = RFC8463_MESSAGE.replace(from, to);
            let outputs = verify(&dns, &Message::parse(changed.as_bytes())).await;
            assert!(outputs.iter().all(|output| matches!(output.result, DkimResult::Fail(_))), "{outputs:?}");
        }
        let added = RFC8463_MESSAGE.replace("To: Suzie", "From: mallory@evil.example\r\nTo: Suzie");
        let outputs = verify(&dns, &Message::parse(added.as_bytes())).await;
        assert!(outputs.iter().all(|output| matches!(output.result, DkimResult::Fail(_))), "{outputs:?}");
        // Unsigned headers may change; relaxed canonicalization takes refolding.
        let refolded = RFC8463_MESSAGE.replace("Subject: Is dinner ready?", "Subject:   Is dinner\r\n\tready?  ")
            .replace("Joe.\r\n", "Joe.\r\n\r\n\r\n");
        let outputs = verify(&dns, &Message::parse(format!("X-Added: yes\r\n{refolded}").as_bytes())).await;
        assert!(outputs.iter().all(|output| output.result == DkimResult::Pass), "{outputs:?}");
    }

    #[tokio::test]
    async fn keys_that_are_missing_revoked_or_unfit() {
        let message = Message::parse(RFC8463_MESSAGE.as_bytes());
        // Offline and nothing cached: the key is unavailable for now.
        let outputs = verify(&Dns::offline(), &message).await;
        assert!(outputs.iter().all(|output| matches!(output.result, DkimResult::TempError(_))));
        let dns = Dns::offline();
        dns.txt.insert("brisbane._domainkey.football.example.com.".into(), Err(crate::dns::Negative::NxDomain), Instant::now() + FOREVER);
        txt(&dns, "test._domainkey.football.example.com", &["v=DKIM1; k=rsa; p="]);
        let outputs = verify(&dns, &message).await;
        assert!(matches!(outputs[0].result, DkimResult::PermError(_)), "{:?}", outputs[0]);
        assert_eq!(outputs[1].result, DkimResult::Fail("the key was revoked".into()));
        let dns = Dns::offline();
        txt(&dns, "brisbane._domainkey.football.example.com", &[RFC8463_RSA]);
        txt(&dns, "test._domainkey.football.example.com", &["v=DKIM1; k=rsa; h=sha1; p=AAAA"]);
        let outputs = verify(&dns, &message).await;
        assert!(outputs.iter().all(|output| matches!(output.result, DkimResult::PermError(_))), "{outputs:?}");
    }

    #[tokio::test]
    async fn rsa_sha1_and_broken_signatures() {
        let dns = rfc8463_dns();
        let sha1 = RFC8463_MESSAGE.replacen("a=rsa-sha256", "a=rsa-sha1", 1);
        let outputs = verify(&dns, &Message::parse(sha1.as_bytes())).await;
        assert!(matches!(outputs[1].result, DkimResult::Policy(_)), "{outputs:?}");
        for broken in [
            "v=2; a=rsa-sha256; b=AA==; bh=AA==; d=x.example; h=from; s=s",
            "v=1; a=rsa-sha256; b=AA==; bh=AA==; d=x.example; h=to; s=s",
            "v=1; a=rsa-md5; b=AA==; bh=AA==; d=x.example; h=from; s=s",
            "v=1; a=rsa-sha256; b=AA==; bh=AA==; d=x.example; h=from; s=s; i=a@y.example",
            "v=1; a=rsa-sha256; b=AA==; bh=AA==; d=x.example; h=from",
            "v=1; a=rsa-sha256; b=!!; bh=AA==; d=x.example; h=from; s=s",
            "v=1; a=rsa-sha256; b=AA==; bh=AA==; d=x.example; h=from; s=s; t=20; x=10",
        ] {
            let raw = format!("DKIM-Signature: {broken}\r\nFrom: a@x.example\r\n\r\nx\r\n");
            let outputs = verify(&dns, &Message::parse(raw.as_bytes())).await;
            assert!(matches!(outputs[0].result, DkimResult::PermError(_)), "{broken}: {outputs:?}");
        }
        // An expired signature fails.
        let raw = "DKIM-Signature: v=1; a=rsa-sha256; b=AA==; bh=AA==; d=x.example; h=from; s=s; x=10\r\nFrom: a@x.example\r\n\r\n";
        let outputs = verify(&dns, &Message::parse(raw.as_bytes())).await;
        assert_eq!(outputs[0].result, DkimResult::Fail("the signature has expired".into()));
    }

    pub(crate) fn ed25519_key() -> SigningKey {
        let document = Ed25519KeyPair::generate().unwrap().to_pkcs8().unwrap();
        SigningKey::ed25519(document.as_ref()).unwrap()
    }

    pub(crate) fn rsa_key() -> SigningKey {
        use aws_lc_rs::encoding::AsDer;
        let key = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = key.as_der().unwrap();
        SigningKey::rsa(der.as_ref()).unwrap()
    }

    pub(crate) fn publish(dns: &Dns, selector: &str, domain: &str, key: &SigningKey) {
        let kind = if key.algorithm() == Algorithm::RsaSha256 { "rsa" } else { "ed25519" };
        let public = match key {
            SigningKey::Rsa(pair) => {
                use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
                let der: PublicKeyX509Der<'static> = pair.public_key().as_der().unwrap();
                der.as_ref().to_vec()
            }
            SigningKey::Ed25519(_) => key.public_key(),
        };
        let record = format!("v=DKIM1; k={kind}; p={}", base64::engine::general_purpose::STANDARD.encode(public));
        txt(dns, &format!("{selector}._domainkey.{domain}"), &[&record]);
    }

    #[tokio::test]
    async fn what_kernoid_signs_verifies() {
        let raw = "From: Alice <alice@firma.example>\r\nTo: bob@b.example\r\nSubject: Hi\r\n\r\nHello.\r\n.dot\r\n";
        let dns = Dns::offline();
        for (selector, key) in [("kernoid1", rsa_key()), ("kernoid-ed1", ed25519_key())] {
            publish(&dns, selector, "firma.example", &key);
            let header = sign(raw.as_bytes(), &key, "firma.example", selector, &["From", "To", "Subject", "Date"]).unwrap();
            assert!(header.starts_with(&format!("DKIM-Signature: v=1; a={};", key.algorithm().as_str())), "{header}");
            assert!(header.lines().all(|line| line.len() <= 78), "{header}");
            let signed = format!("{header}{raw}");
            let outputs = verify(&dns, &Message::parse(signed.as_bytes())).await;
            assert_eq!(outputs[0].result, DkimResult::Pass, "{header}");
            let signature = outputs[0].signature.as_ref().unwrap();
            assert_eq!(signature.headers, ["from", "to", "subject"]);
            let tampered = signed.replace("Hello.", "Hello!");
            let outputs = verify(&dns, &Message::parse(tampered.as_bytes())).await;
            assert!(matches!(outputs[0].result, DkimResult::Fail(_)));
        }
        assert!(sign(b"Subject: x\r\n\r\n", &ed25519_key(), "firma.example", "s", &["From"]).is_err());
    }

    #[tokio::test]
    async fn body_length_limits_what_is_hashed() {
        let dns = Dns::offline();
        let key = ed25519_key();
        publish(&dns, "s", "firma.example", &key);
        // A signature with l= made by hand: the body hash of its first 7 octets.
        let raw = "From: a@firma.example\r\n\r\nHello.\r\n";
        let message = Message::parse(raw.as_bytes());
        let hash = body_hash(message.body, Canonicalization::Relaxed, Some(8)).unwrap();
        let tags = [
            ("v", "1".to_owned()),
            ("a", "ed25519-sha256".to_owned()),
            ("d", "firma.example".to_owned()),
            ("s", "s".to_owned()),
            ("c", "relaxed/relaxed".to_owned()),
            ("h", "from".to_owned()),
            ("l", "8".to_owned()),
            ("bh", base64::engine::general_purpose::STANDARD.encode(hash)),
        ];
        let header = finish("DKIM-Signature", &tags, &key, signed_headers(&message, &["from".into()], Canonicalization::Relaxed)).unwrap();
        let appended = format!("{header}{raw}Appended later.\r\n");
        let outputs = verify(&dns, &Message::parse(appended.as_bytes())).await;
        assert_eq!(outputs[0].result, DkimResult::Pass);
        let cut = format!("{header}From: a@firma.example\r\n\r\nHi\r\n");
        let outputs = verify(&dns, &Message::parse(cut.as_bytes())).await;
        assert!(matches!(outputs[0].result, DkimResult::Fail(_)));
    }

    #[test]
    fn key_records() {
        let key = DomainKey::parse(RFC8463_ED25519).unwrap();
        assert_eq!((key.key_type, key.public.len()), (KeyType::Ed25519, 32));
        let key = DomainKey::parse("k=rsa; t=y:s; p=AAAA").unwrap();
        assert!(key.testing && key.strict);
        assert!(DomainKey::parse("p=AAAA; v=DKIM1").is_err(), "v= must come first");
        assert!(DomainKey::parse("v=DKIM2; p=AAAA").is_err());
        assert!(DomainKey::parse("k=dsa; p=AAAA").is_err());
        assert!(DomainKey::parse("k=rsa").is_err());
        assert!(DomainKey::parse("s=web; p=AAAA").is_err());
    }
}
