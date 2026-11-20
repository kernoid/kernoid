// SPDX-License-Identifier: AGPL-3.0-or-later
//! iprev (RFC 8601, 3): the client's address has a name (PTR) whose addresses include it again.

use std::net::IpAddr;

use crate::{Dns, dns::DnsError};

/// Names of the address that are looked up again (as SPF limits `ptr`, RFC 7208, 4.6.4).
const MAX_NAMES: usize = 10;

/// iprev's results (RFC 8601, 2.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IprevResult {
    Pass,
    Fail(String),
    TempError(String),
    PermError(String),
    None,
}

impl IprevResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail(_) => "fail",
            Self::TempError(_) => "temperror",
            Self::PermError(_) => "permerror",
            Self::None => "none",
        }
    }
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IprevOutput {
    pub result: IprevResult,
    /// The names that lead back to the address (for `pass`), absolute.
    pub ptr: Option<Vec<String>>,
}

/// Checks `ip`.
pub async fn verify(dns: &Dns, ip: IpAddr) -> IprevOutput {
    let names = match dns.ptr(ip).await {
        Ok(names) => names,
        Err(DnsError::Temporary(error)) => return IprevOutput { result: IprevResult::TempError(error), ptr: None },
        Err(error) => return IprevOutput { result: IprevResult::Fail(format!("no name: {error}")), ptr: None },
    };
    let mut confirmed = Vec::new();
    let mut temporary = None;
    for name in names.iter().take(MAX_NAMES) {
        let found = match ip {
            IpAddr::V4(ip) => dns.ipv4(name).await.map(|addresses| addresses.contains(&ip)),
            IpAddr::V6(ip) => dns.ipv6(name).await.map(|addresses| addresses.contains(&ip)),
        };
        match found {
            Ok(true) => confirmed.push(name.clone()),
            Ok(false) => {}
            Err(DnsError::Temporary(error)) => temporary = Some(error),
            Err(_) => {}
        }
    }
    if !confirmed.is_empty() {
        IprevOutput { result: IprevResult::Pass, ptr: Some(confirmed) }
    } else if let Some(error) = temporary {
        IprevOutput { result: IprevResult::TempError(error), ptr: Some(names) }
    } else {
        IprevOutput { result: IprevResult::Fail("no name leads back to the address".into()), ptr: Some(names) }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Instant};

    use super::*;
    use crate::dns::{FOREVER, Negative};

    #[tokio::test]
    async fn names_that_lead_back() {
        let dns = Dns::offline();
        let ip: IpAddr = "192.0.2.25".parse().unwrap();
        assert!(matches!(verify(&dns, ip).await.result, IprevResult::TempError(_)));
        dns.ptr.insert(ip, Ok(vec!["mail.example.".into(), "other.example.".into()]), Instant::now() + FOREVER);
        dns.ipv4.insert("other.example.".into(), Ok(vec![Ipv4Addr::new(192, 0, 2, 99)]), Instant::now() + FOREVER);
        dns.ipv4.insert("mail.example.".into(), Ok(vec![Ipv4Addr::new(192, 0, 2, 25)]), Instant::now() + FOREVER);
        let output = verify(&dns, ip).await;
        assert_eq!(output, IprevOutput { result: IprevResult::Pass, ptr: Some(vec!["mail.example.".into()]) });
        dns.ipv4.insert("mail.example.".into(), Err(Negative::NxDomain), Instant::now() + FOREVER);
        assert!(matches!(verify(&dns, ip).await.result, IprevResult::Fail(_)));
        let unnamed: IpAddr = "192.0.2.26".parse().unwrap();
        dns.ptr.insert(unnamed, Err(Negative::NxDomain), Instant::now() + FOREVER);
        assert!(matches!(verify(&dns, unnamed).await.result, IprevResult::Fail(_)));
    }
}
