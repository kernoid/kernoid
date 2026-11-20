// SPDX-License-Identifier: AGPL-3.0-or-later
//! DNS for the checks (RFC 0002, 9.3): mail-auth's resolver with caches of what it found, so that one domain's SPF,
//! DKIM and DMARC records are looked up once while they are valid. Tests fill the caches instead of asking DNS.

use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use mail_auth::{
    DnsCache, MessageAuthenticator, Mx, Negative, Parameters, RecordSet, ResolverCache, TxtRecord,
    hickory_resolver::config::{ResolverConfig, ResolverOpts},
};

/// A cached answer: records, or the negative answer (RFC 2308) mail-auth keeps as well.
pub type Answer<T> = Result<RecordSet<T>, Negative>;

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

impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for Cache<K, V> {
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.0.lock().expect("the DNS cache lock");
        entries.get(name).filter(|(_, until)| *until > Instant::now()).map(|(value, _)| value.clone())
    }

    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().expect("the DNS cache lock").remove(name).map(|(value, _)| value)
    }

    fn insert(&self, key: K, value: V, valid_until: Instant) {
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
}

/// The resolver and its caches.
pub struct Dns {
    pub authenticator: MessageAuthenticator,
    /// A resolver that validates DNSSEC, for DANE (RFC 0002, 10.4); without it, DANE does not apply.
    pub dnssec: Option<MessageAuthenticator>,
    pub txt: Cache<Box<str>, TxtRecord>,
    pub mx: Cache<Box<str>, Answer<Mx>>,
    pub ptr: Cache<IpAddr, Answer<Box<str>>>,
    pub ipv4: Cache<Box<str>, Answer<Ipv4Addr>>,
    pub ipv6: Cache<Box<str>, Answer<Ipv6Addr>>,
}

impl DnsCache for Dns {
    type Txt = Cache<Box<str>, TxtRecord>;
    type Mx = Cache<Box<str>, Answer<Mx>>;
    type Ipv4 = Cache<Box<str>, Answer<Ipv4Addr>>;
    type Ipv6 = Cache<Box<str>, Answer<Ipv6Addr>>;
    type Ptr = Cache<IpAddr, Answer<Box<str>>>;

    fn txt(&self) -> Option<&Self::Txt> {
        Some(&self.txt)
    }

    fn mx(&self) -> Option<&Self::Mx> {
        Some(&self.mx)
    }

    fn ipv4(&self) -> Option<&Self::Ipv4> {
        Some(&self.ipv4)
    }

    fn ipv6(&self) -> Option<&Self::Ipv6> {
        Some(&self.ipv6)
    }

    fn ptr(&self) -> Option<&Self::Ptr> {
        Some(&self.ptr)
    }
}

impl std::fmt::Debug for Dns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns").finish_non_exhaustive()
    }
}

/// How long answers put into the caches by hand (tests) stay.
pub const FOREVER: Duration = Duration::from_secs(365 * 24 * 60 * 60);


impl Dns {
    /// The system's resolvers (`/etc/resolv.conf`).
    pub fn from_system() -> Result<Self, String> {
        let mut dns = MessageAuthenticator::new_system_conf().map(Self::with).map_err(|error| error.to_string())?;
        let (config, mut options) =
            mail_auth::hickory_resolver::system_conf::read_system_conf().map_err(|error| error.to_string())?;
        options.validate = true;
        dns.dnssec = Some(MessageAuthenticator::new(config, options).map_err(|error| error.to_string())?);
        Ok(dns)
    }

    /// A resolver without name servers: every lookup the caches cannot answer fails at once. For tests.
    pub fn offline() -> Self {
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_millis(10);
        options.attempts = 0;
        Self::with(
            MessageAuthenticator::new(ResolverConfig::from_parts(None, Vec::new(), Vec::new()), options)
                .expect("a resolver without name servers"),
        )
    }

    fn with(authenticator: MessageAuthenticator) -> Self {
        Self {
            authenticator,
            dnssec: None,
            txt: Cache::default(),
            mx: Cache::default(),
            ptr: Cache::default(),
            ipv4: Cache::default(),
            ipv6: Cache::default(),
        }
    }

    /// The parameters for a check, with the caches.
    pub(crate) fn parameters<P>(&self, input: P) -> Parameters<'_, P, Self> {
        Parameters::new(input).with_cache(self)
    }
}
