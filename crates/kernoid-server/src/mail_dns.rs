// SPDX-License-Identifier: AGPL-3.0-or-later
//! The DNS records of the tenants' mail domains and their DKIM keys, behind a trait: the administration of identity
//! (domains) shows them where kernoid handles mail, and is built without the mail crates where it does not
//! (RFC 0009, 3).

use std::{future::Future, pin::Pin};

/// One DNS record a mail domain needs, and whether it is published.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// `MX`, `SPF`, `DKIM` or `DMARC`.
    pub kind: String,
    pub name: String,
    /// `MX` or `TXT`.
    pub record_type: String,
    pub expected: String,
    pub found: Vec<String>,
    /// `ok`, `missing` or `different`.
    pub status: String,
}

/// Why a DKIM key could not be changed.
#[derive(Debug, thiserror::Error)]
pub enum DkimFailure {
    #[error("the algorithm is rsa or ed25519")]
    UnknownAlgorithm,
    #[error("the key could not be made: {0}")]
    Failed(String),
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Checks the records of mail domains and changes their DKIM keys – kernoid-smtp's checker.
pub trait MailDns: Send + Sync + std::fmt::Debug {
    fn check<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<DnsRecord>>;
    /// Starts a change of the domain's DKIM key with `algorithm` (`rsa`, `ed25519`); the new key's selector.
    fn rotate_dkim<'a>(&'a self, domain: &'a str, algorithm: &'a str) -> BoxFuture<'a, Result<String, DkimFailure>>;
}

#[cfg(feature = "data")]
impl MailDns for kernoid_smtp::dns_check::Checker {
    fn check<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Vec<DnsRecord>> {
        Box::pin(async move {
            kernoid_smtp::dns_check::Checker::check(self, domain)
                .await
                .into_iter()
                .map(|check| DnsRecord {
                    kind: check.kind.into(),
                    name: check.name,
                    record_type: check.record_type.into(),
                    expected: check.expected,
                    found: check.found,
                    status: check.status.as_str().into(),
                })
                .collect()
        })
    }

    fn rotate_dkim<'a>(&'a self, domain: &'a str, algorithm: &'a str) -> BoxFuture<'a, Result<String, DkimFailure>> {
        Box::pin(async move {
            let algorithm = kernoid_smtp::dkim::Algorithm::parse(algorithm).ok_or(DkimFailure::UnknownAlgorithm)?;
            kernoid_smtp::dns_check::Checker::rotate_dkim(self, domain, algorithm)
                .await
                .map_err(|error| DkimFailure::Failed(error.to_string()))
        })
    }
}
