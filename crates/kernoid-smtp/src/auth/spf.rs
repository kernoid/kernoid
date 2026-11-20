// SPDX-License-Identifier: AGPL-3.0-or-later
//! SPF (RFC 7208): whether the client's address may send for a domain – the domain of `MAIL FROM`, or the `HELO` name
//! (RFC 7208, 2.3, 2.4). `check_host()` of section 4 with all mechanisms and both modifiers, macros (section 7), and
//! the limits of section 4.6.4: ten terms that look up DNS, two lookups that find nothing, ten names of `mx` and `ptr`.
//! The `p` macro expands to `unknown`, as RFC 7208, 7.3 allows (it should not be published).

use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
};

use crate::{Dns, dns::DnsError};

/// Terms that may look up DNS (RFC 7208, 4.6.4).
const MAX_LOOKUPS: usize = 10;
/// Lookups that may find nothing (RFC 7208, 4.6.4).
const MAX_VOID_LOOKUPS: usize = 2;
/// Names `mx` and `ptr` look at (RFC 7208, 4.6.4).
const MAX_NAMES: usize = 10;

/// SPF's results (RFC 7208, 2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl SpfResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfOutput {
    pub result: SpfResult,
    /// The domain that was checked.
    pub domain: String,
    /// The explanation of a `fail` (`exp=`, RFC 7208, 6.2).
    pub explanation: Option<String>,
}

impl SpfOutput {
    pub fn new(domain: String) -> Self {
        Self { result: SpfResult::None, domain, explanation: None }
    }

    pub fn result(&self) -> SpfResult {
        self.result
    }
}

/// Which identity is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    MailFrom,
    Helo,
}

impl Identity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MailFrom => "mailfrom",
            Self::Helo => "helo",
        }
    }
}

/// What a check is asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfParameters {
    pub ip: IpAddr,
    pub helo: String,
    /// The receiving host (`%{r}`).
    pub hostname: String,
    /// `local@domain` (the local part `postmaster` for the `HELO` identity, RFC 7208, 2.3).
    pub sender: String,
    pub identity: Identity,
}

impl SpfParameters {
    /// The `MAIL FROM` identity; an empty address (a bounce) is checked as `postmaster@<helo>` (RFC 7208, 2.4).
    pub fn mail_from(ip: IpAddr, helo: &str, hostname: &str, address: &str) -> Self {
        let sender = if address.is_empty() {
            format!("postmaster@{helo}")
        } else if address.contains('@') {
            address.to_owned()
        } else {
            format!("postmaster@{address}")
        };
        Self { ip, helo: helo.to_owned(), hostname: hostname.to_owned(), sender, identity: Identity::MailFrom }
    }

    /// The `HELO` identity (RFC 7208, 2.3).
    pub fn helo(ip: IpAddr, helo: &str, hostname: &str) -> Self {
        Self {
            ip,
            helo: helo.to_owned(),
            hostname: hostname.to_owned(),
            sender: format!("postmaster@{helo}"),
            identity: Identity::Helo,
        }
    }

    /// The domain the check starts at.
    pub fn domain(&self) -> String {
        self.sender.rsplit_once('@').map(|(_, domain)| domain).unwrap_or_default().trim_end_matches('.').to_ascii_lowercase()
    }

    fn local(&self) -> &str {
        match self.sender.rsplit_once('@') {
            Some(("", _)) | None => "postmaster",
            Some((local, _)) => local,
        }
    }
}

/// Checks `parameters`.
pub async fn verify(dns: &Dns, parameters: &SpfParameters) -> SpfOutput {
    let domain = parameters.domain();
    let mut context = Context { dns, parameters, lookups: 0, voids: 0 };
    let (result, explanation) = match check_host(&mut context, domain.clone()).await {
        Ok(found) => found,
        Err(result) => (result, None),
    };
    SpfOutput { result, domain, explanation }
}

struct Context<'a> {
    dns: &'a Dns,
    parameters: &'a SpfParameters,
    lookups: usize,
    voids: usize,
}

impl Context<'_> {
    /// Counts a term that looks up DNS.
    fn count_lookup(&mut self) -> Result<(), SpfResult> {
        self.lookups += 1;
        if self.lookups > MAX_LOOKUPS { Err(SpfResult::PermError) } else { Ok(()) }
    }

    /// Counts a lookup that found nothing; a temporary failure is `temperror`.
    fn void<T>(&mut self, result: Result<Vec<T>, DnsError>) -> Result<Vec<T>, SpfResult> {
        match result {
            Ok(records) => Ok(records),
            Err(DnsError::Temporary(_)) => Err(SpfResult::TempError),
            Err(_) => {
                self.voids += 1;
                if self.voids > MAX_VOID_LOOKUPS { Err(SpfResult::PermError) } else { Ok(Vec::new()) }
            }
        }
    }
}

/// Whether `domain` can be checked: labels of at most 63 octets, at least two of them (RFC 7208, 4.3).
fn valid_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    labels.len() >= 2
        && domain.len() <= 253
        && labels.iter().all(|label| !label.is_empty() && label.len() <= 63 && !label.contains(char::is_whitespace))
}

/// The SPF record of `domain`: `None` if it has none; `permerror` for more than one.
async fn record(context: &mut Context<'_>, domain: &str) -> Result<Option<String>, SpfResult> {
    let records = match context.dns.txt(domain).await {
        Ok(records) => records,
        Err(DnsError::Temporary(_)) => return Err(SpfResult::TempError),
        Err(_) => return Ok(None),
    };
    let mut spf = records.into_iter().filter(|record| {
        let lower = record.to_ascii_lowercase();
        lower == "v=spf1" || lower.starts_with("v=spf1 ")
    });
    match (spf.next(), spf.next()) {
        (None, _) => Ok(None),
        (Some(record), None) => Ok(Some(record)),
        (Some(_), Some(_)) => Err(SpfResult::PermError),
    }
}

type Found = Result<(SpfResult, Option<String>), SpfResult>;

/// `check_host()` (RFC 7208, 4): the result, with the explanation of a `fail`.
fn check_host<'a, 'b: 'a>(
    context: &'a mut Context<'b>,
    domain: String,
) -> Pin<Box<dyn Future<Output = Found> + Send + 'a>> {
    Box::pin(async move {
        if !valid_domain(&domain) {
            return Ok((SpfResult::None, None));
        }
        let Some(text) = record(context, &domain).await? else { return Ok((SpfResult::None, None)) };
        let record = Record::parse(&text).map_err(|_| SpfResult::PermError)?;
        for directive in &record.directives {
            if matches(context, &domain, &directive.mechanism).await? {
                let explanation = match (directive.qualifier, &record.exp) {
                    (SpfResult::Fail, Some(exp)) => explain(context, &domain, exp).await,
                    _ => None,
                };
                return Ok((directive.qualifier, explanation));
            }
        }
        if let Some(redirect) = &record.redirect {
            context.count_lookup()?;
            let target = expand(context, &domain, redirect, false).map_err(|_| SpfResult::PermError)?;
            let target = truncate(&target);
            return match check_host(context, target).await? {
                // A redirect to a domain without a record is an error (RFC 7208, 6.1).
                (SpfResult::None, _) => Err(SpfResult::PermError),
                found => Ok(found),
            };
        }
        Ok((SpfResult::Neutral, None))
    })
}

/// The explanation of a `fail` (RFC 7208, 6.2); anything that goes wrong leaves it out.
async fn explain(context: &mut Context<'_>, domain: &str, exp: &str) -> Option<String> {
    let target = truncate(&expand(context, domain, exp, false).ok()?);
    let records = context.dns.txt(&target).await.ok()?;
    let [text] = records.as_slice() else { return None };
    let explanation = expand(context, domain, text, true).ok()?;
    explanation.is_ascii().then_some(explanation)
}

/// A mechanism (RFC 7208, 5).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mechanism {
    All,
    Include(String),
    A { domain: Option<String>, v4: u8, v6: u8 },
    Mx { domain: Option<String>, v4: u8, v6: u8 },
    Ptr(Option<String>),
    Ip(IpAddr, u8),
    Exists(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Directive {
    qualifier: SpfResult,
    mechanism: Mechanism,
}

/// A record's terms.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Record {
    directives: Vec<Directive>,
    redirect: Option<String>,
    exp: Option<String>,
}

impl Record {
    /// Parses a record (RFC 7208, 4.6, 12); any syntax error is `permerror`.
    fn parse(text: &str) -> Result<Self, ()> {
        let mut terms = text.split(' ').filter(|term| !term.is_empty());
        let version = terms.next().ok_or(())?;
        if !version.eq_ignore_ascii_case("v=spf1") {
            return Err(());
        }
        let mut record = Self::default();
        for term in terms {
            // A modifier: a name, `=`, a macro string – the name never a mechanism's with a qualifier.
            let name_end = term.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))).unwrap_or(term.len());
            if term[name_end..].starts_with('=') && term.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                let (name, value) = (term[..name_end].to_ascii_lowercase(), &term[name_end + 1..]);
                validate_macro(value, false)?;
                match name.as_str() {
                    "redirect" if record.redirect.is_none() => record.redirect = Some(value.to_owned()),
                    "exp" if record.exp.is_none() => record.exp = Some(value.to_owned()),
                    "redirect" | "exp" => return Err(()),
                    _ => {} // Unknown modifiers are ignored (RFC 7208, 6).
                }
                continue;
            }
            let (qualifier, rest) = match term.chars().next() {
                Some('+') => (SpfResult::Pass, &term[1..]),
                Some('-') => (SpfResult::Fail, &term[1..]),
                Some('~') => (SpfResult::SoftFail, &term[1..]),
                Some('?') => (SpfResult::Neutral, &term[1..]),
                _ => (SpfResult::Pass, term),
            };
            let name_end = rest.find([':', '/']).unwrap_or(rest.len());
            let (name, argument) = (rest[..name_end].to_ascii_lowercase(), &rest[name_end..]);
            let mechanism = match name.as_str() {
                "all" if argument.is_empty() => Mechanism::All,
                "include" => Mechanism::Include(domain_spec(argument)?.ok_or(())?),
                "exists" => Mechanism::Exists(domain_spec(argument)?.ok_or(())?),
                "a" | "mx" => {
                    let (spec, v4, v6) = dual_cidr(argument)?;
                    let domain = domain_spec(spec)?;
                    if name == "a" { Mechanism::A { domain, v4, v6 } } else { Mechanism::Mx { domain, v4, v6 } }
                }
                "ptr" => Mechanism::Ptr(domain_spec(argument)?),
                "ip4" | "ip6" => {
                    let argument = argument.strip_prefix(':').ok_or(())?;
                    let (address, length) = match argument.split_once('/') {
                        Some((address, length)) => (address, Some(length)),
                        None => (argument, None),
                    };
                    let ip: IpAddr = address.parse().map_err(|_| ())?;
                    let max = if name == "ip4" { 32 } else { 128 };
                    if (name == "ip4") != ip.is_ipv4() {
                        return Err(());
                    }
                    let length = match length {
                        Some(length) => cidr_length(length, max)?,
                        None => max,
                    };
                    Mechanism::Ip(ip, length)
                }
                _ => return Err(()),
            };
            record.directives.push(Directive { qualifier, mechanism });
        }
        Ok(record)
    }
}

fn cidr_length(value: &str, max: u8) -> Result<u8, ()> {
    if value.is_empty() || value.len() > 3 || !value.bytes().all(|byte| byte.is_ascii_digit()) || (value.len() > 1 && value.starts_with('0')) {
        return Err(());
    }
    value.parse::<u8>().ok().filter(|length| *length <= max).ok_or(())
}

/// The optional `/ip4-cidr-length` and `//ip6-cidr-length` at the end of `a` and `mx` (RFC 7208, 5.6).
fn dual_cidr(argument: &str) -> Result<(&str, u8, u8), ()> {
    let mut rest = argument;
    let mut v6 = 128;
    if let Some(at) = rest.rfind("//") {
        v6 = cidr_length(&rest[at + 2..], 128)?;
        rest = &rest[..at];
    }
    let mut v4 = 32;
    if let Some(at) = rest.rfind('/')
        && rest[at + 1..].bytes().all(|byte| byte.is_ascii_digit())
    {
        v4 = cidr_length(&rest[at + 1..], 32)?;
        rest = &rest[..at];
    }
    Ok((rest, v4, v6))
}

/// `:domain-spec`, if given.
fn domain_spec(argument: &str) -> Result<Option<String>, ()> {
    if argument.is_empty() {
        return Ok(None);
    }
    let spec = argument.strip_prefix(':').filter(|spec| !spec.is_empty()).ok_or(())?;
    validate_macro(spec, false)?;
    Ok(Some(spec.to_owned()))
}

/// Checks a macro string's syntax (RFC 7208, 7.1).
fn validate_macro(value: &str, explanation: bool) -> Result<(), ()> {
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            if !explanation && (c.is_control() || c == ' ') {
                return Err(());
            }
            continue;
        }
        match chars.next() {
            Some('%' | '_' | '-') => {}
            Some('{') => {
                let letter = chars.next().ok_or(())?.to_ascii_lowercase();
                let allowed = "slodiphv".contains(letter) || (explanation && "crt".contains(letter));
                if !allowed {
                    return Err(());
                }
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    if !(c.is_ascii_digit() || matches!(c, 'r' | 'R' | '.' | '-' | '+' | ',' | '/' | '_' | '=')) {
                        return Err(());
                    }
                }
                if !closed {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
    }
    Ok(())
}

/// The dotted form of an address for `%{i}`: the four numbers, or IPv6's 32 nibbles (RFC 7208, 7.3).
fn dotted(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip
            .octets()
            .iter()
            .flat_map(|octet| [octet >> 4, octet & 0x0f])
            .map(|nibble| format!("{nibble:x}"))
            .collect::<Vec<_>>()
            .join("."),
    }
}

/// Expands the macros of `value` (RFC 7208, 7); `explanation` allows `c`, `r` and `t` and spaces.
fn expand(context: &Context<'_>, domain: &str, value: &str, explanation: bool) -> Result<String, ()> {
    validate_macro(value, explanation)?;
    let parameters = context.parameters;
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('_') => out.push(' '),
            Some('-') => out.push_str("%20"),
            Some('{') => {
                let letter = chars.next().ok_or(())?;
                let mut spec = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    spec.push(c);
                }
                let value = match letter.to_ascii_lowercase() {
                    's' => parameters.sender.clone(),
                    'l' => parameters.local().to_owned(),
                    'o' => parameters.domain(),
                    'd' => domain.to_owned(),
                    'i' => dotted(parameters.ip),
                    'p' => "unknown".to_owned(),
                    'v' => if parameters.ip.is_ipv4() { "in-addr" } else { "ip6" }.to_owned(),
                    'h' => parameters.helo.clone(),
                    'c' => parameters.ip.to_string(),
                    'r' => parameters.hostname.clone(),
                    't' => super::dkim::now().to_string(),
                    _ => return Err(()),
                };
                let digits: String = spec.chars().take_while(char::is_ascii_digit).collect();
                let rest = &spec[digits.len()..];
                let (reverse, delimiters) = match rest.strip_prefix(['r', 'R']) {
                    Some(delimiters) => (true, delimiters),
                    None => (false, rest),
                };
                let delimiters: Vec<char> = if delimiters.is_empty() { vec!['.'] } else { delimiters.chars().collect() };
                let mut parts: Vec<&str> = value.split(delimiters.as_slice()).collect();
                if reverse {
                    parts.reverse();
                }
                if !digits.is_empty() {
                    let keep: usize = digits.parse().map_err(|_| ())?;
                    if keep == 0 {
                        return Err(());
                    }
                    let skip = parts.len().saturating_sub(keep);
                    parts.drain(..skip);
                }
                let joined = parts.join(".");
                if letter.is_ascii_uppercase() {
                    out.push_str(&url_escape(&joined));
                } else {
                    out.push_str(&joined);
                }
            }
            _ => return Err(()),
        }
    }
    Ok(out)
}

/// Escapes what is not unreserved (RFC 3986, 2.3).
fn url_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A name of more than 253 characters loses labels on the left until it fits (RFC 7208, 7.3).
fn truncate(name: &str) -> String {
    let mut name = name.trim_end_matches('.');
    while name.len() > 253 {
        match name.split_once('.') {
            Some((_, rest)) => name = rest,
            None => break,
        }
    }
    name.to_ascii_lowercase()
}

/// Whether `ip` is in `network`/`length`.
fn in_network(ip: IpAddr, network: IpAddr, length: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = if length == 0 { 0 } else { u32::MAX << (32 - u32::from(length)) };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = if length == 0 { 0 } else { u128::MAX << (128 - u32::from(length)) };
            u128::from(ip) & mask == u128::from(network) & mask
        }
        // An IPv4-mapped client address is checked as IPv4 (RFC 7208, 5).
        (IpAddr::V6(ip), IpAddr::V4(_)) => ip.to_ipv4_mapped().is_some_and(|ip| in_network(IpAddr::V4(ip), network, length)),
        _ => false,
    }
}

/// The client's address as it is checked: IPv4 when it is IPv4-mapped.
fn client(parameters: &SpfParameters) -> IpAddr {
    match parameters.ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(parameters.ip, IpAddr::V4),
        ip => ip,
    }
}

/// Whether one of the addresses of `name` is the client's, within the lengths.
async fn address_matches(context: &mut Context<'_>, name: &str, v4: u8, v6: u8) -> Result<bool, SpfResult> {
    let ip = client(context.parameters);
    match ip {
        IpAddr::V4(_) => {
            let lookup = context.dns.ipv4(name).await;
            let addresses = context.void(lookup)?;
            Ok(addresses.into_iter().any(|address| in_network(ip, IpAddr::V4(address), v4)))
        }
        IpAddr::V6(_) => {
            let lookup = context.dns.ipv6(name).await;
            let addresses = context.void(lookup)?;
            Ok(addresses.into_iter().any(|address| in_network(ip, IpAddr::V6(address), v6)))
        }
    }
}

/// The target of a mechanism: its domain-spec expanded, or the current domain.
fn target(context: &Context<'_>, domain: &str, spec: &Option<String>) -> Result<String, SpfResult> {
    match spec {
        Some(spec) => expand(context, domain, spec, false).map(|name| truncate(&name)).map_err(|_| SpfResult::PermError),
        None => Ok(domain.to_owned()),
    }
}

/// The validated names of the client (RFC 7208, 5.5): PTR names whose addresses include it.
async fn validated_names(context: &mut Context<'_>) -> Result<Vec<String>, SpfResult> {
    let ip = client(context.parameters);
    let lookup = context.dns.ptr(ip).await;
    let names = context.void(lookup)?;
    let mut validated = Vec::new();
    for name in names.into_iter().take(MAX_NAMES) {
        let name = name.trim_end_matches('.').to_owned();
        let matches = match ip {
            IpAddr::V4(ip) => context.dns.ipv4(&name).await.is_ok_and(|found| found.contains(&ip)),
            IpAddr::V6(ip) => context.dns.ipv6(&name).await.is_ok_and(|found| found.contains(&ip)),
        };
        if matches {
            validated.push(name.to_ascii_lowercase());
        }
    }
    Ok(validated)
}

async fn matches(context: &mut Context<'_>, domain: &str, mechanism: &Mechanism) -> Result<bool, SpfResult> {
    match mechanism {
        Mechanism::All => Ok(true),
        Mechanism::Ip(network, length) => Ok(in_network(context.parameters.ip, *network, *length)),
        Mechanism::Include(spec) => {
            context.count_lookup()?;
            let target = target(context, domain, &Some(spec.clone()))?;
            match check_host(context, target).await {
                Ok((SpfResult::Pass, _)) => Ok(true),
                Ok((SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral, _)) => Ok(false),
                Ok((SpfResult::TempError, _)) | Err(SpfResult::TempError) => Err(SpfResult::TempError),
                Ok(_) | Err(_) => Err(SpfResult::PermError),
            }
        }
        Mechanism::A { domain: spec, v4, v6 } => {
            context.count_lookup()?;
            let name = target(context, domain, spec)?;
            address_matches(context, &name, *v4, *v6).await
        }
        Mechanism::Mx { domain: spec, v4, v6 } => {
            context.count_lookup()?;
            let name = target(context, domain, spec)?;
            let lookup = context.dns.mx(&name).await;
            let exchanges = context.void(lookup)?;
            if exchanges.len() > MAX_NAMES {
                return Err(SpfResult::PermError);
            }
            for exchange in exchanges {
                let host = exchange.exchange.trim_end_matches('.');
                if host.is_empty() {
                    continue;
                }
                if address_matches(context, host, *v4, *v6).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Mechanism::Ptr(spec) => {
            context.count_lookup()?;
            let target = target(context, domain, spec)?;
            let names = validated_names(context).await?;
            Ok(names.iter().any(|name| *name == target || name.ends_with(&format!(".{target}"))))
        }
        Mechanism::Exists(spec) => {
            context.count_lookup()?;
            let name = target(context, domain, &Some(spec.clone()))?;
            let lookup = context.dns.ipv4(&name).await;
            Ok(!context.void(lookup)?.is_empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Instant};

    use super::*;
    use crate::{auth::dkim::tests::txt, dns::FOREVER};

    fn parameters(ip: &str, sender: &str) -> SpfParameters {
        SpfParameters::mail_from(ip.parse().unwrap(), "mx.example.org", "mx.kernoid.example", sender)
    }

    fn context<'a>(dns: &'a Dns, parameters: &'a SpfParameters) -> Context<'a> {
        Context { dns, parameters, lookups: 0, voids: 0 }
    }

    /// RFC 7208, 7.4.
    #[test]
    fn rfc_7208_macro_examples() {
        let dns = Dns::offline();
        let v4 = parameters("192.0.2.3", "strong-bad@email.example.com");
        let context = context(&dns, &v4);
        let domain = "email.example.com";
        for (macro_string, expansion) in [
            ("%{s}", "strong-bad@email.example.com"),
            ("%{o}", "email.example.com"),
            ("%{d}", "email.example.com"),
            ("%{d4}", "email.example.com"),
            ("%{d3}", "email.example.com"),
            ("%{d2}", "example.com"),
            ("%{d1}", "com"),
            ("%{dr}", "com.example.email"),
            ("%{d2r}", "example.email"),
            ("%{l}", "strong-bad"),
            ("%{l-}", "strong.bad"),
            ("%{lr}", "strong-bad"),
            ("%{lr-}", "bad.strong"),
            ("%{l1r-}", "strong"),
            ("%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"),
            ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
            ("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"),
            ("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com"),
            ("%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"),
            ("%%%_%-", "% %20"),
            ("%{S}", "strong-bad%40email.example.com"),
        ] {
            assert_eq!(expand(&context, domain, macro_string, false).unwrap(), expansion, "{macro_string}");
        }
        let v6 = parameters("2001:db8::cb01", "strong-bad@email.example.com");
        let context = super::tests::context(&dns, &v6);
        assert_eq!(
            expand(&context, domain, "%{ir}.%{v}._spf.%{d2}", false).unwrap(),
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
        );
        for invalid in ["%(ir).sbl.example.org", "%{x}", "%{d0}", "%{c}", "%{d", "%"] {
            assert!(expand(&context, domain, invalid, false).is_err(), "{invalid}");
        }
        assert_eq!(expand(&context, domain, "%{c} via %{r}", true).unwrap(), "2001:db8::cb01 via mx.kernoid.example");
    }

    fn a(dns: &Dns, name: &str, addresses: &[[u8; 4]]) {
        let addresses = addresses.iter().map(|octets| Ipv4Addr::from(*octets)).collect();
        dns.ipv4.insert(crate::dns::absolute(name).into(), Ok(addresses), Instant::now() + FOREVER);
    }

    async fn check(dns: &Dns, ip: &str, sender: &str) -> SpfOutput {
        verify(dns, &parameters(ip, sender)).await
    }

    #[tokio::test]
    async fn mechanisms_and_qualifiers() {
        let dns = Dns::offline();
        txt(&dns, "example.com", &["v=spf1 ip4:192.0.2.0/24 a mx:mail.example.com/30 include:_spf.example.net ~all", "other"]);
        a(&dns, "example.com", &[[198, 51, 100, 7]]);
        dns.mx.insert(
            "mail.example.com.".into(),
            Ok(vec![crate::dns::Mx { preference: 10, exchange: "mx1.example.com.".into() }]),
            Instant::now() + FOREVER,
        );
        a(&dns, "mx1.example.com", &[[203, 0, 113, 9]]);
        for name in ["example.com.", "mx1.example.com."] {
            dns.ipv6.insert(name.into(), Err(crate::dns::Negative::NoRecords), Instant::now() + FOREVER);
        }
        txt(&dns, "_spf.example.net", &["v=spf1 ip6:2001:db8::/32 -all"]);
        for (ip, result) in [
            ("192.0.2.200", SpfResult::Pass),
            ("198.51.100.7", SpfResult::Pass),
            ("203.0.113.10", SpfResult::Pass),
            ("203.0.113.13", SpfResult::SoftFail),
            ("2001:db8::1", SpfResult::Pass),
            ("::ffff:192.0.2.1", SpfResult::Pass),
        ] {
            assert_eq!(check(&dns, ip, "alice@example.com").await.result, result, "{ip}");
        }
        // No record, an invalid one, two of them; a domain that is not one.
        txt(&dns, "two.example", &["v=spf1 -all", "v=spf1 +all"]);
        txt(&dns, "broken.example", &["v=spf1 ip4:300.0.0.1 -all"]);
        txt(&dns, "unknown.example", &["v=spf1 frob -all"]);
        txt(&dns, "mod.example", &["v=spf1 foo=bar -all"]);
        dns.txt.insert("none.example.".into(), Err(crate::dns::Negative::NxDomain), Instant::now() + FOREVER);
        for (sender, result) in [
            ("a@two.example", SpfResult::PermError),
            ("a@broken.example", SpfResult::PermError),
            ("a@unknown.example", SpfResult::PermError),
            ("a@mod.example", SpfResult::Fail),
            ("a@none.example", SpfResult::None),
            ("a@localhost", SpfResult::None),
            ("a@offline.example", SpfResult::TempError),
        ] {
            assert_eq!(check(&dns, "192.0.2.1", sender).await.result, result, "{sender}");
        }
    }

    #[tokio::test]
    async fn redirect_exists_and_explanations() {
        let dns = Dns::offline();
        txt(&dns, "example.org", &["v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} redirect=_spf.example.org exp=explain._spf.%{d}"]);
        a(&dns, "1.2.0.192.alice._spf.example.org", &[[127, 0, 0, 2]]);
        txt(&dns, "_spf.example.org", &["v=spf1 -all"]);
        txt(&dns, "explain._spf.example.org", &["%{i} is not one of %{d}'s designated mail servers."]);
        assert_eq!(check(&dns, "192.0.2.1", "alice@example.org").await.result, SpfResult::Pass);
        let unlisted = "9.2.0.192.bob._spf.example.org.";
        dns.ipv4.insert(unlisted.into(), Err(crate::dns::Negative::NxDomain), Instant::now() + FOREVER);
        let output = check(&dns, "192.0.2.9", "bob@example.org").await;
        assert_eq!(output.result, SpfResult::Fail);
        // The explanation belongs to the record whose directive matched – the redirect's has none.
        assert_eq!(output.explanation, None);
        txt(&dns, "exp.example", &["v=spf1 -all exp=explain._spf.example.org"]);
        let output = check(&dns, "192.0.2.9", "bob@exp.example").await;
        assert_eq!(output.explanation.as_deref(), Some("192.0.2.9 is not one of exp.example's designated mail servers."));
        // A redirect to a domain without a record.
        txt(&dns, "lost.example", &["v=spf1 redirect=nowhere.example"]);
        dns.txt.insert("nowhere.example.".into(), Err(crate::dns::Negative::NoRecords), Instant::now() + FOREVER);
        assert_eq!(check(&dns, "192.0.2.9", "a@lost.example").await.result, SpfResult::PermError);
        // Two redirects are an error.
        assert_eq!(Record::parse("v=spf1 redirect=a.example redirect=b.example"), Err(()));
    }

    #[tokio::test]
    async fn the_limits_of_lookups() {
        let dns = Dns::offline();
        // Eleven includes in a chain: the eleventh is one too many.
        for n in 0..12 {
            txt(&dns, &format!("l{n}.example"), &[&format!("v=spf1 include:l{}.example -all", n + 1)]);
        }
        assert_eq!(check(&dns, "192.0.2.1", "a@l0.example").await.result, SpfResult::PermError);
        txt(&dns, "ten.example", &["v=spf1 a:x1.ten.example a:x2.ten.example a:x3.ten.example ~all"]);
        for n in 1..=3 {
            dns.ipv4.insert(format!("x{n}.ten.example.").into(), Err(crate::dns::Negative::NxDomain), Instant::now() + FOREVER);
        }
        // Three lookups that find nothing: one more than allowed.
        assert_eq!(check(&dns, "192.0.2.1", "a@ten.example").await.result, SpfResult::PermError);
        txt(&dns, "two.example", &["v=spf1 a:x1.ten.example a:x2.ten.example ~all"]);
        assert_eq!(check(&dns, "192.0.2.1", "a@two.example").await.result, SpfResult::SoftFail);
    }

    #[tokio::test]
    async fn helo_and_bounces() {
        let dns = Dns::offline();
        txt(&dns, "mx.example.org", &["v=spf1 ip4:192.0.2.5 -all"]);
        let helo = SpfParameters::helo("192.0.2.5".parse().unwrap(), "mx.example.org", "mx.kernoid.example");
        assert_eq!(verify(&dns, &helo).await.result, SpfResult::Pass);
        let bounce = parameters("192.0.2.6", "");
        assert_eq!(bounce.sender, "postmaster@mx.example.org");
        let output = verify(&dns, &bounce).await;
        assert_eq!((output.result, output.domain.as_str()), (SpfResult::Fail, "mx.example.org"));
    }

    #[test]
    fn records_never_panic() {
        let mut state = 0x5eed_5eed_5eed_5eedu64;
        let alphabet = ["v=spf1", " ", "a", "mx", ":", "/", "//", "%{", "}", "ip4", "ip6", "1", "-", "~", "=", "redirect", "include", ".", "ä"];
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let record: String = (0..(state % 20)).map(|i| alphabet[((state >> (i * 3)) as usize) % alphabet.len()]).collect();
            let _ = Record::parse(&record);
            let _ = validate_macro(&record, true);
        }
    }
}
