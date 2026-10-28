// SPDX-License-Identifier: AGPL-3.0-or-later
//! The DNS check of a tenant's mail domain (RFC 0002, 10.5): which records to publish, and whether they are. It reads
//! DNS when asked and changes nothing.

use kernoid_store::PgPool;
use mail_auth::hickory_resolver::proto::rr::RData;

use crate::{Dns, dkim};

/// What kernoid suggests for DMARC.
pub const SUGGESTED_DMARC: &str = "v=DMARC1; p=quarantine";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Published as expected.
    Ok,
    /// Not published.
    Missing,
    /// Published, but not as expected.
    Different,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Different => "different",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordCheck {
    /// `MX`, `SPF`, `DKIM` or `DMARC`.
    pub kind: &'static str,
    /// Where it belongs.
    pub name: String,
    /// The record type: `MX` or `TXT`.
    pub record_type: &'static str,
    pub expected: String,
    pub found: Vec<String>,
    pub status: Status,
}

/// The TXT records at `name`, each joined from its strings.
async fn txt(dns: &Dns, name: &str) -> Vec<String> {
    match dns.authenticator.resolver().txt_lookup(format!("{name}.")).await {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => {
                    Some(txt.txt_data.iter().map(|part| String::from_utf8_lossy(part)).collect::<String>())
                }
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn words(record: &str) -> Vec<String> {
    record.split_whitespace().map(str::to_ascii_lowercase).collect()
}

/// The `p=` value of a DKIM record.
fn dkim_key(record: &str) -> Option<String> {
    record
        .split(';')
        .map(str::trim)
        .find_map(|tag| tag.strip_prefix("p="))
        .map(|key| key.chars().filter(|c| !c.is_whitespace()).collect())
}

/// What the administration API checks with.
pub struct Checker {
    pub dns: Dns,
    pub pool: PgPool,
    /// `smtp.hostname`.
    pub hostname: String,
    /// `smtp.spf`.
    pub spf: Option<String>,
}

impl std::fmt::Debug for Checker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checker").field("hostname", &self.hostname).finish_non_exhaustive()
    }
}

impl Checker {
    pub async fn check(&self, domain: &str) -> Vec<RecordCheck> {
        check(&self.dns, &self.pool, &self.hostname, self.spf.as_deref(), domain).await
    }
}

/// Checks the records of `domain` against what kernoid at `hostname` needs; `spf` replaces the suggested SPF record.
pub async fn check(dns: &Dns, pool: &PgPool, hostname: &str, spf: Option<&str>, domain: &str) -> Vec<RecordCheck> {
    let mut checks = Vec::new();

    let exchanges: Vec<String> = match dns.authenticator.resolver().mx_lookup(format!("{domain}.")).await {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::MX(mx) => Some(mx.exchange.to_ascii().trim_end_matches('.').to_lowercase()),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    let status = if exchanges.is_empty() {
        Status::Missing
    } else if exchanges.iter().any(|exchange| exchange == hostname) {
        Status::Ok
    } else {
        Status::Different
    };
    checks.push(RecordCheck {
        kind: "MX",
        name: domain.to_owned(),
        record_type: "MX",
        expected: format!("10 {hostname}."),
        found: exchanges,
        status,
    });

    let expected_spf = spf.unwrap_or("v=spf1 mx -all").to_owned();
    let spf_records: Vec<String> =
        txt(dns, domain).await.into_iter().filter(|record| record.to_ascii_lowercase().starts_with("v=spf1")).collect();
    let status = match spf_records.as_slice() {
        [] => Status::Missing,
        [record] if words(record) == words(&expected_spf) => Status::Ok,
        _ => Status::Different,
    };
    checks.push(RecordCheck {
        kind: "SPF",
        name: domain.to_owned(),
        record_type: "TXT",
        expected: expected_spf,
        found: spf_records,
        status,
    });

    if let Ok(Some((selector, expected))) = dkim::public_record(pool, domain).await {
        let name = format!("{selector}._domainkey.{domain}");
        let found = txt(dns, &name).await;
        let status = match found.as_slice() {
            [] => Status::Missing,
            records if records.iter().any(|record| dkim_key(record) == dkim_key(&expected)) => Status::Ok,
            _ => Status::Different,
        };
        checks.push(RecordCheck { kind: "DKIM", name, record_type: "TXT", expected, found, status });
    }

    let name = format!("_dmarc.{domain}");
    let found: Vec<String> = txt(dns, &name)
        .await
        .into_iter()
        .filter(|record| record.to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();
    // Any DMARC policy will do; what it says is the tenant's choice.
    let status = if found.is_empty() { Status::Missing } else { Status::Ok };
    checks.push(RecordCheck {
        kind: "DMARC",
        name,
        record_type: "TXT",
        expected: SUGGESTED_DMARC.to_owned(),
        found,
        status,
    });
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_compare_by_content() {
        assert_eq!(words("v=spf1  MX -all"), words("v=spf1 mx -all"));
        assert_eq!(dkim_key("v=DKIM1; k=rsa; p=AB CD").as_deref(), Some("ABCD"));
        assert_eq!(dkim_key("v=DKIM1; k=rsa"), None);
    }
}
