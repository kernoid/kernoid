// SPDX-License-Identifier: AGPL-3.0-or-later
//! DNS for the checks (RFC 0002, 9.3) and for sending (10.2): hickory's resolver – and a second one that validates
//! DNSSEC, for DANE – with caches of what was found, so that one domain's SPF, DKIM and DMARC records are looked up
//! once while they are valid. Tests fill the caches instead of asking DNS; a resolver made with [`Dns::offline`] has
//! no name servers, so every lookup the caches cannot answer fails as a temporary error.
//!
//! Names are looked up as absolute names in lower case (`firma.example.`); the caches are keyed the same way.

use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use hickory_resolver::{
    TokioResolver,
    net::NetError,
    proto::rr::{Name, RData, RecordType},
};

/// A cached answer: records, or a negative answer (RFC 2308).
pub type Answer<T> = Result<Vec<T>, Negative>;

/// A negative answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negative {
    /// The name exists, without records of the type asked for (`NODATA`).
    NoRecords,
    /// The name does not exist (`NXDOMAIN`).
    NxDomain,
}

/// Why a lookup gave no records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("no records")]
    NoRecords,
    #[error("the domain does not exist")]
    NxDomain,
    /// No answer now – the name servers failed or did not answer; asking later may help.
    #[error("{0}")]
    Temporary(String),
}

impl DnsError {
    /// DNS answered that there is nothing: `NXDOMAIN` or no records of the type.
    pub fn is_negative(&self) -> bool {
        matches!(self, Self::NoRecords | Self::NxDomain)
    }
}

impl From<Negative> for DnsError {
    fn from(negative: Negative) -> Self {
        match negative {
            Negative::NoRecords => Self::NoRecords,
            Negative::NxDomain => Self::NxDomain,
        }
    }
}

/// Entries per cache; when full, expired entries go, and if that is not enough, all of them.
const CAPACITY: usize = 10_000;

/// A cache of DNS answers with their expiry.
#[derive(Debug)]
pub struct Cache<K, V>(Mutex<HashMap<K, (V, Instant)>>);

impl<K, V> Default for Cache<K, V> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Hash + Eq, V: Clone> Cache<K, V> {
    /// The value of `key`, while it is valid.
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.0.lock().expect("the DNS cache lock");
        entries.get(key).filter(|(_, until)| *until > Instant::now()).map(|(value, _)| value.clone())
    }

    /// Keeps `value` for `key` until `valid_until`.
    pub fn insert(&self, key: K, value: V, valid_until: Instant) {
        let mut entries = self.0.lock().expect("the DNS cache lock");
        if entries.len() >= CAPACITY {
            let now = Instant::now();
            entries.retain(|_, (_, until)| *until > now);
            if entries.len() >= CAPACITY {
                entries.clear();
            }
        }
        entries.insert(key, (value, valid_until));
    }

    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().expect("the DNS cache lock").remove(key).map(|(value, _)| value)
    }
}

/// An MX record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mx {
    pub preference: u16,
    /// The host, absolute; `.` for a null MX (RFC 7505).
    pub exchange: String,
}

/// The resolvers and their caches.
pub struct Dns {
    /// `None` for [`Dns::offline`].
    resolver: Option<TokioResolver>,
    /// A resolver that validates DNSSEC, for DANE (RFC 0002, 10.4); without it, DANE does not apply.
    pub dnssec: Option<TokioResolver>,
    /// TXT records, each record's strings joined.
    pub txt: Cache<Box<str>, Answer<String>>,
    pub mx: Cache<Box<str>, Answer<Mx>>,
    /// The names of an address, absolute.
    pub ptr: Cache<IpAddr, Answer<String>>,
    pub ipv4: Cache<Box<str>, Answer<Ipv4Addr>>,
    pub ipv6: Cache<Box<str>, Answer<Ipv6Addr>>,
}

impl std::fmt::Debug for Dns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns").finish_non_exhaustive()
    }
}

/// How long answers put into the caches by hand (tests) stay.
pub const FOREVER: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// `name` as the caches key it: lower case, absolute.
pub fn absolute(name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{name}.")
}

impl Dns {
    /// The system's resolvers (`/etc/resolv.conf`), one of them validating DNSSEC.
    pub fn from_system() -> Result<Self, String> {
        let resolver =
            TokioResolver::builder_tokio().and_then(|builder| builder.build()).map_err(|error| error.to_string())?;
        let mut builder = TokioResolver::builder_tokio().map_err(|error| error.to_string())?;
        builder.options_mut().validate = true;
        let dnssec = builder.build().map_err(|error| error.to_string())?;
        let mut dns = Self::with(Some(resolver));
        dns.dnssec = Some(dnssec);
        Ok(dns)
    }

    /// A resolver without name servers: every lookup the caches cannot answer fails at once. For tests.
    pub fn offline() -> Self {
        Self::with(None)
    }

    fn with(resolver: Option<TokioResolver>) -> Self {
        Self {
            resolver,
            dnssec: None,
            txt: Cache::default(),
            mx: Cache::default(),
            ptr: Cache::default(),
            ipv4: Cache::default(),
            ipv6: Cache::default(),
        }
    }

    /// The resolver itself, past the caches – for checks that must see what DNS shows now.
    pub fn resolver(&self) -> Option<&TokioResolver> {
        self.resolver.as_ref()
    }

    async fn lookup<T: Clone>(
        &self,
        cache: &Cache<Box<str>, Answer<T>>,
        name: &str,
        record_type: RecordType,
        take: impl Fn(&RData) -> Option<T>,
    ) -> Result<Vec<T>, DnsError> {
        let name = absolute(name);
        if let Some(answer) = cache.get(name.as_str()) {
            return answer.map_err(DnsError::from);
        }
        let resolver = self.resolver.as_ref().ok_or_else(|| DnsError::Temporary("no name servers".into()))?;
        let lookup = resolver.lookup(name.as_str(), record_type).await.map_err(error)?;
        let records: Vec<T> = lookup
            .answers()
            .iter()
            .filter(|record| record.record_type() == record_type)
            .filter_map(|record| take(&record.data))
            .collect();
        if records.is_empty() {
            return Err(DnsError::NoRecords);
        }
        cache.insert(name.into(), Ok(records.clone()), lookup.valid_until());
        Ok(records)
    }

    /// The TXT records of `name`, each one's strings joined (RFC 7208, 3.3).
    pub async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.lookup(&self.txt, name, RecordType::TXT, |data| match data {
            RData::TXT(txt) => Some(txt.txt_data.iter().map(|part| String::from_utf8_lossy(part)).collect()),
            _ => None,
        })
        .await
    }

    pub async fn mx(&self, name: &str) -> Result<Vec<Mx>, DnsError> {
        self.lookup(&self.mx, name, RecordType::MX, |data| match data {
            RData::MX(mx) => Some(Mx { preference: mx.preference, exchange: mx.exchange.to_ascii().to_lowercase() }),
            _ => None,
        })
        .await
    }

    pub async fn ipv4(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.lookup(&self.ipv4, name, RecordType::A, |data| match data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
        .await
    }

    pub async fn ipv6(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.lookup(&self.ipv6, name, RecordType::AAAA, |data| match data {
            RData::AAAA(address) => Some(address.0),
            _ => None,
        })
        .await
    }

    /// The addresses of `name` (A, then AAAA), at most `max`.
    pub async fn ips(&self, name: &str, max: usize) -> Result<Vec<IpAddr>, DnsError> {
        let v4 = self.ipv4(name).await;
        let v6 = self.ipv6(name).await;
        let mut ips: Vec<IpAddr> = Vec::new();
        if let Ok(addresses) = &v4 {
            ips.extend(addresses.iter().copied().map(IpAddr::V4));
        }
        if let Ok(addresses) = &v6 {
            ips.extend(addresses.iter().copied().map(IpAddr::V6));
        }
        ips.truncate(max);
        if !ips.is_empty() {
            return Ok(ips);
        }
        match (v4, v6) {
            (Err(DnsError::Temporary(error)), _) | (_, Err(DnsError::Temporary(error))) => {
                Err(DnsError::Temporary(error))
            }
            (Err(DnsError::NxDomain), _) | (_, Err(DnsError::NxDomain)) => Err(DnsError::NxDomain),
            _ => Err(DnsError::NoRecords),
        }
    }

    /// The names of `ip` (PTR, RFC 1035, 3.5), absolute and in lower case.
    pub async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        if let Some(answer) = self.ptr.get(&ip) {
            return answer.map_err(DnsError::from);
        }
        let resolver = self.resolver.as_ref().ok_or_else(|| DnsError::Temporary("no name servers".into()))?;
        let lookup = resolver.lookup(Name::from(ip), RecordType::PTR).await.map_err(error)?;
        let names: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::PTR(name) => Some(name.0.to_ascii().to_lowercase()),
                _ => None,
            })
            .collect();
        if names.is_empty() {
            return Err(DnsError::NoRecords);
        }
        self.ptr.insert(ip, Ok(names.clone()), lookup.valid_until());
        Ok(names)
    }
}

fn error(error: NetError) -> DnsError {
    if error.is_nx_domain() {
        DnsError::NxDomain
    } else if error.is_no_records_found() {
        DnsError::NoRecords
    } else {
        DnsError::Temporary(error.to_string())
    }
}
