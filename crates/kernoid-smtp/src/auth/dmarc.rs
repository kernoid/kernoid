// SPDX-License-Identifier: AGPL-3.0-or-later
//! DMARC (RFC 7489): whether the domain in `From` is the one SPF or DKIM authenticated, and what its owner asks for when
//! it is not. Policy records and organizational domains are found by the DNS tree walk of DMARCbis
//! (draft-ietf-dmarc-dmarcbis, 4.10) instead of a public suffix list: at most eight queries, `psd=n` and `psd=y` end a
//! walk. Of the newer tags, `np` (domains that do not exist) and `t` (testing: one step milder) are honoured; `pct`
//! below 100 counts as testing, as DMARCbis maps it.

use super::{
    dkim::{DkimOutput, DkimResult},
    spf::{SpfOutput, SpfResult},
    tags,
};
use crate::{Dns, dns::DnsError};

/// Queries of one tree walk (DMARCbis, 4.10).
const MAX_QUERIES: usize = 8;

/// DMARC's results (RFC 8601, 2.7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcResult {
    Pass,
    Fail,
    None,
    TempError,
    PermError,
}

impl DmarcResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

/// What a domain owner asks for mail that fails (`p=`, `sp=`, `np=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    #[default]
    None,
    Quarantine,
    Reject,
}

impl Policy {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "quarantine" => Some(Self::Quarantine),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }

    /// One step milder, for a domain that is testing.
    fn milder(self) -> Self {
        match self {
            Self::Reject => Self::Quarantine,
            Self::Quarantine | Self::None => Self::None,
        }
    }
}

/// `psd=` (DMARCbis, 4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Psd {
    Yes,
    No,
    #[default]
    Unknown,
}

/// A policy record (RFC 7489, 6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub policy: Policy,
    pub subdomain_policy: Option<Policy>,
    pub nonexistent_policy: Option<Policy>,
    /// Strict alignment for DKIM (`adkim=s`) and SPF (`aspf=s`).
    pub strict_dkim: bool,
    pub strict_spf: bool,
    pub testing: bool,
    pub psd: Psd,
}

impl Record {
    /// Parses a record; `None` if it is no DMARC record or cannot be used (RFC 7489, 6.6.3, DMARCbis 4.10.1).
    pub fn parse(text: &str) -> Option<Self> {
        let tags = tags::parse(text.as_bytes()).ok()?;
        let first = tags.first()?;
        if first.name != "v" || first.value != "DMARC1" {
            return None;
        }
        let get = |name: &str| tags::get(&tags, name);
        let policy = get("p").map(Policy::parse);
        let subdomain = get("sp").map(Policy::parse);
        let nonexistent = get("np").map(Policy::parse);
        let valid = matches!(policy, Some(Some(_))) && !matches!(subdomain, Some(None)) && !matches!(nonexistent, Some(None));
        let (policy, subdomain_policy, nonexistent_policy) = if valid {
            (policy.flatten().unwrap_or_default(), subdomain.flatten(), nonexistent.flatten())
        } else {
            // Without a valid policy, a record that asks for reports is read as p=none; others are not used.
            let reports = get("rua").is_some_and(|rua| rua.split(',').any(|uri| uri.trim().contains(':')));
            if !reports {
                return None;
            }
            (Policy::None, None, None)
        };
        let strict = |name: &str| get(name).is_some_and(|value| value.trim().eq_ignore_ascii_case("s"));
        let percent = get("pct").and_then(|value| value.trim().parse::<u8>().ok()).unwrap_or(100);
        let testing = get("t").is_some_and(|value| value.trim().eq_ignore_ascii_case("y")) || percent < 100;
        let psd = match get("psd").map(|value| value.trim().to_ascii_lowercase()).as_deref() {
            Some("y") => Psd::Yes,
            Some("n") => Psd::No,
            _ => Psd::Unknown,
        };
        Some(Self {
            policy,
            subdomain_policy,
            nonexistent_policy,
            strict_dkim: strict("adkim"),
            strict_spf: strict("aspf"),
            testing,
            psd,
        })
    }
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcOutput {
    pub result: DmarcResult,
    /// The domain of `From`.
    pub domain: String,
    /// The policy that applies when the result is `fail`: the record's, for this domain, made milder when it is
    /// testing.
    pub policy: Policy,
    pub spf_aligned: bool,
    pub dkim_aligned: bool,
}

impl DmarcOutput {
    pub fn result(&self) -> DmarcResult {
        self.result
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    fn of(result: DmarcResult, domain: &str) -> Self {
        Self { result, domain: domain.to_owned(), policy: Policy::None, spf_aligned: false, dkim_aligned: false }
    }
}

/// The record at `_dmarc.<domain>`: `Ok(None)` when there is none or more than one.
async fn lookup(dns: &Dns, domain: &str) -> Result<Option<Record>, DnsError> {
    let records = match dns.txt(&format!("_dmarc.{domain}")).await {
        Ok(records) => records,
        Err(DnsError::Temporary(error)) => return Err(DnsError::Temporary(error)),
        Err(_) => return Ok(None),
    };
    let mut found = records.iter().filter_map(|record| Record::parse(record));
    match (found.next(), found.next()) {
        (Some(record), None) => Ok(Some(record)),
        _ => Ok(None),
    }
}

/// The targets of a tree walk after `domain` (DMARCbis, 4.10, steps 3–7): shortened to seven labels if it has eight or
/// more, then one label less each time, down to the top-level domain.
fn walk(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    let mut start = if labels.len() >= 8 { labels.len() - 7 } else { 1 };
    let mut targets = Vec::new();
    while start < labels.len() && targets.len() < MAX_QUERIES - 1 {
        targets.push(labels[start..].join("."));
        start += 1;
    }
    targets
}

/// The record that applies to `domain` and where it was found (DMARCbis, 4.10.1).
async fn discover(dns: &Dns, domain: &str) -> Result<Option<(Record, String)>, DnsError> {
    if let Some(record) = lookup(dns, domain).await? {
        return Ok(Some((record, domain.to_owned())));
    }
    for target in walk(domain) {
        // An error further up is no answer; the walk goes on.
        if let Ok(Some(record)) = lookup(dns, &target).await {
            return Ok(Some((record, target)));
        }
    }
    Ok(None)
}

/// The organizational domain of `domain` (DMARCbis, 4.10.2).
async fn organizational(dns: &Dns, domain: &str) -> String {
    let mut found: Vec<(String, Record)> = Vec::new();
    let targets = std::iter::once(domain.to_owned()).chain(walk(domain));
    for target in targets {
        let Ok(Some(record)) = lookup(dns, &target).await else { continue };
        let psd = record.psd;
        found.push((target, record));
        if psd != Psd::Unknown {
            break;
        }
    }
    for (index, (target, record)) in found.iter().enumerate() {
        match record.psd {
            Psd::No => return target.clone(),
            Psd::Yes if target != domain => {
                // The domain one label below this one, on the way to `domain`.
                let labels = target.split('.').count() + 1;
                let all: Vec<&str> = domain.split('.').collect();
                return all[all.len() - labels..].join(".");
            }
            _ if index + 1 == found.len() => return target.clone(),
            _ => {}
        }
    }
    domain.to_owned()
}

/// Whether `a` and `b` are aligned: the same, or (relaxed) of the same organizational domain.
async fn aligned(dns: &Dns, a: &str, b: &str, strict: bool) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    if strict {
        return false;
    }
    // Domains that share no parent below the top level cannot share an organizational domain: no queries for them.
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    let shared = a.rsplit('.').zip(b.rsplit('.')).take_while(|(x, y)| x == y).count();
    if shared < 2 {
        return false;
    }
    let (a_org, b_org) = (organizational(dns, &a).await, organizational(dns, &b).await);
    a_org == b_org
}

/// Whether `domain` exists at all (for `np=`): it has an address or an MX, or DNS could not say.
async fn exists(dns: &Dns, domain: &str) -> bool {
    let not_there = |result: Result<Vec<()>, DnsError>| matches!(result, Err(DnsError::NxDomain));
    let a = dns.ipv4(domain).await.map(|found| found.into_iter().map(drop).collect());
    let aaaa = dns.ipv6(domain).await.map(|found| found.into_iter().map(drop).collect());
    let mx = dns.mx(domain).await.map(|found| found.into_iter().map(drop).collect());
    !(not_there(a) && not_there(aaaa) && not_there(mx))
}

/// Checks a message whose `From` has the domain `from_domain`, with what SPF found for `mail_from_domain` and what
/// DKIM found. A message without exactly one `From` domain is a `permerror`.
pub async fn verify(dns: &Dns, from_domains: &[String], mail_from_domain: &str, spf: &SpfOutput, dkim: &[DkimOutput]) -> DmarcOutput {
    let mut domains: Vec<&String> = from_domains.iter().collect();
    domains.dedup();
    let [domain] = domains.as_slice() else {
        return DmarcOutput::of(DmarcResult::PermError, from_domains.first().map_or("", String::as_str));
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || !domain.contains('.') {
        return DmarcOutput::of(DmarcResult::None, &domain);
    }
    let (record, found_at) = match discover(dns, &domain).await {
        Ok(Some(found)) => found,
        Ok(None) => return DmarcOutput::of(DmarcResult::None, &domain),
        Err(_) => return DmarcOutput::of(DmarcResult::TempError, &domain),
    };
    let spf_aligned = spf.result == SpfResult::Pass && aligned(dns, mail_from_domain, &domain, record.strict_spf).await;
    let mut dkim_aligned = false;
    for output in dkim {
        if let (DkimResult::Pass, Some(signature)) = (&output.result, &output.signature)
            && aligned(dns, &signature.domain, &domain, record.strict_dkim).await
        {
            dkim_aligned = true;
            break;
        }
    }
    let mut policy = if found_at == domain {
        record.policy
    } else if record.nonexistent_policy.is_some() && !exists(dns, &domain).await {
        record.nonexistent_policy.unwrap_or(record.policy)
    } else {
        record.subdomain_policy.unwrap_or(record.policy)
    };
    if record.testing {
        policy = policy.milder();
    }
    let result = if spf_aligned || dkim_aligned { DmarcResult::Pass } else { DmarcResult::Fail };
    DmarcOutput { result, domain, policy, spf_aligned, dkim_aligned }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::{
        auth::dkim::{Algorithm, Signature, tests::txt},
        auth::message::Canonicalization,
        dns::{FOREVER, Negative},
    };

    fn spf(result: SpfResult, domain: &str) -> SpfOutput {
        SpfOutput { result, domain: domain.into(), explanation: None }
    }

    fn dkim(result: DkimResult, domain: &str) -> DkimOutput {
        let signature = Signature {
            algorithm: Algorithm::Ed25519Sha256,
            domain: domain.into(),
            selector: "s".into(),
            headers: vec!["from".into()],
            identity: format!("@{domain}"),
            instance: 0,
            body_length: None,
            header_canonicalization: Canonicalization::Relaxed,
            body_canonicalization: Canonicalization::Relaxed,
            body_hash: vec![1],
            signature: vec![1],
            b: "AQ==".into(),
            timestamp: None,
            expiration: None,
        };
        DkimOutput { result, signature: Some(signature), testing: false }
    }

    fn none(dns: &Dns, name: &str) {
        dns.txt.insert(crate::dns::absolute(name).into(), Err(Negative::NoRecords), Instant::now() + FOREVER);
    }

    /// A resolver where every `_dmarc` name not set has no records, as the DNS would answer.
    fn dns(records: &[(&str, &str)]) -> Dns {
        let dns = Dns::offline();
        for name in [
            "_dmarc.example.com", "_dmarc.com", "_dmarc.mail.example.com", "_dmarc.a.mail.example.com",
            "_dmarc.example.net", "_dmarc.net", "_dmarc.bank.example", "_dmarc.example", "_dmarc.mega.bank.example",
            "_dmarc.giant.bank.example", "_dmarc.b.giant.bank.example",
        ] {
            none(&dns, name);
        }
        for (name, record) in records {
            txt(&dns, name, &[record]);
        }
        dns
    }

    async fn check(dns: &Dns, from: &str, mail_from: &str, spf_result: SpfResult, dkim: &[DkimOutput]) -> DmarcOutput {
        verify(dns, &[from.to_owned()], mail_from, &spf(spf_result, mail_from), dkim).await
    }

    #[tokio::test]
    async fn alignment_relaxed_and_strict() {
        let dns = dns(&[("_dmarc.example.com", "v=DMARC1; p=reject")]);
        // SPF of a subdomain, DKIM of a subdomain: relaxed alignment through the organizational domain.
        let output = check(&dns, "example.com", "mail.example.com", SpfResult::Pass, &[]).await;
        assert_eq!((output.result, output.spf_aligned), (DmarcResult::Pass, true));
        let output = check(&dns, "a.mail.example.com", "x.example.net", SpfResult::Pass, &[dkim(DkimResult::Pass, "example.com")]).await;
        assert_eq!((output.result, output.dkim_aligned, output.spf_aligned), (DmarcResult::Pass, true, false));
        // The record came from the organizational domain: p= for its subdomains, sp= absent.
        assert_eq!(output.policy, Policy::Reject);
        // Not aligned, or not passing: fail.
        let output = check(&dns, "example.com", "example.net", SpfResult::Pass, &[dkim(DkimResult::Fail("x".into()), "example.com")]).await;
        assert_eq!((output.result, output.policy), (DmarcResult::Fail, Policy::Reject));
        let output = check(&dns, "example.com", "example.com", SpfResult::SoftFail, &[]).await;
        assert_eq!(output.result, DmarcResult::Fail);

        let dns = super::tests::dns(&[("_dmarc.example.com", "v=DMARC1; p=quarantine; sp=none; adkim=s; aspf=s")]);
        let output = check(&dns, "example.com", "mail.example.com", SpfResult::Pass, &[dkim(DkimResult::Pass, "mail.example.com")]).await;
        assert_eq!((output.result, output.policy), (DmarcResult::Fail, Policy::Quarantine));
        let output = check(&dns, "example.com", "example.com", SpfResult::Pass, &[]).await;
        assert_eq!(output.result, DmarcResult::Pass);
        // sp= for a subdomain that has no record of its own.
        let output = check(&dns, "mail.example.com", "other.example.net", SpfResult::Pass, &[]).await;
        assert_eq!((output.result, output.policy), (DmarcResult::Fail, Policy::None));
    }

    #[tokio::test]
    async fn the_tree_walk_and_psd() {
        // DMARCbis, appendix: a PSD with psd=y; the organizational domain is the one below it.
        let dns = dns(&[
            ("_dmarc.example", "v=DMARC1; p=reject; psd=y"),
            ("_dmarc.giant.bank.example", "v=DMARC1; p=quarantine"),
        ]);
        assert_eq!(organizational(&dns, "b.giant.bank.example").await, "bank.example");
        assert_eq!(organizational(&dns, "bank.example").await, "bank.example");
        // psd=n ends the walk at its domain.
        let dns = super::tests::dns(&[
            ("_dmarc.mail.example.com", "v=DMARC1; p=none; psd=n"),
            ("_dmarc.example.com", "v=DMARC1; p=reject"),
        ]);
        assert_eq!(organizational(&dns, "a.mail.example.com").await, "mail.example.com");
        assert!(!aligned(&dns, "a.mail.example.com", "example.com", false).await);
        assert!(aligned(&dns, "a.mail.example.com", "mail.example.com", false).await);
        // Without records the domain is its own.
        let dns = super::tests::dns(&[]);
        assert_eq!(organizational(&dns, "a.mail.example.com").await, "a.mail.example.com");
        assert_eq!(check(&dns, "example.com", "example.com", SpfResult::Pass, &[]).await.result, DmarcResult::None);
        // At most eight queries, the long name shortened to seven labels at once.
        assert_eq!(
            walk("a.b.c.d.e.f.g.h.i.j.mail.example.com"),
            [
                "g.h.i.j.mail.example.com", "h.i.j.mail.example.com", "i.j.mail.example.com", "j.mail.example.com",
                "mail.example.com", "example.com", "com"
            ]
        );
        assert_eq!(walk("example.com"), ["com"]);
    }

    #[tokio::test]
    async fn testing_nonexistent_domains_and_errors() {
        let dns = dns(&[("_dmarc.example.com", "v=DMARC1; p=reject; t=y; np=reject; sp=none")]);
        let output = check(&dns, "example.com", "x.example.net", SpfResult::Pass, &[]).await;
        assert_eq!((output.result, output.policy), (DmarcResult::Fail, Policy::Quarantine));
        // A subdomain DNS knows nothing of: np=.
        let ghost = "ghost.example.com.";
        dns.ipv4.insert(ghost.into(), Err(Negative::NxDomain), Instant::now() + FOREVER);
        dns.ipv6.insert(ghost.into(), Err(Negative::NxDomain), Instant::now() + FOREVER);
        dns.mx.insert(ghost.into(), Err(Negative::NxDomain), Instant::now() + FOREVER);
        none(&dns, "_dmarc.ghost.example.com");
        let output = check(&dns, "ghost.example.com", "x.example.net", SpfResult::Pass, &[]).await;
        assert_eq!(output.policy, Policy::Quarantine, "np=reject made milder by t=y");
        // Two From domains, no answer, a broken record.
        let output = verify(&dns, &["a.example".into(), "b.example".into()], "a.example", &spf(SpfResult::Pass, "a.example"), &[]).await;
        assert_eq!(output.result, DmarcResult::PermError);
        let offline = Dns::offline();
        assert_eq!(check(&offline, "example.com", "example.com", SpfResult::Pass, &[]).await.result, DmarcResult::TempError);
        assert_eq!(Record::parse("v=DMARC1; p=bounce"), None);
        assert_eq!(Record::parse("p=reject; v=DMARC1"), None);
        assert_eq!(Record::parse("v=DMARC1; p=bounce; rua=mailto:r@example.com").unwrap().policy, Policy::None);
        assert!(Record::parse("v=DMARC1; p=reject; pct=50").unwrap().testing);
        assert_eq!(Record::parse("v=DMARC1; p=reject; psd=n").unwrap().psd, Psd::No);
    }
}
