// SPDX-License-Identifier: AGPL-3.0-or-later
//! MTA-STS (RFC 8461, RFC 0002 10.4): a domain kernoid sends to may say, in a TXT record at `_mta-sts.<domain>` and a
//! policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`, which MX hosts take its mail and whether TLS
//! with a valid certificate is required. kernoid keeps policies in PostgreSQL (`mta_sts_policies`) for their
//! `max_age`, so that every worker knows them and a policy outlives a restart; the TXT record's `id` says when a new
//! policy must be fetched (RFC 8461, 5.1).

use jiff::Timestamp;
use jiff_sqlx::ToSqlx;
use kernoid_store::PgPool;
use mail_auth::mta_sts::MtaStsRecord;

use crate::Dns;

/// Largest policy read (RFC 8461, 3.3 suggests 64 KiB).
const MAX_POLICY: usize = 64 * 1024;

/// The longest `max_age` a policy may have (RFC 8461, 3.2): about a year.
const MAX_AGE_LIMIT: u64 = 31_557_600;

/// The shortest time a policy is kept, so that a domain with `max_age: 0` is not asked at every delivery.
const MIN_LIFETIME: u64 = 300;

/// What a policy asks of senders (RFC 8461, 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Deliver only to the named hosts, over TLS with a valid certificate.
    Enforce,
    /// Report failures, but deliver anyway.
    Testing,
    /// No policy any longer.
    None,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Testing => "testing",
            Self::None => "none",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::Enforce, Self::Testing, Self::None].into_iter().find(|mode| mode.as_str() == value)
    }
}

/// A domain's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    /// `mx` lines: a host name, or `*.` and a domain for any one label below it.
    pub mx: Vec<String>,
    pub max_age: u64,
}

/// A host name in lower case, without a final dot, with its labels in ASCII (A-labels); as it is if it is not one.
fn normalized_host(name: &str) -> String {
    let name = name.trim().trim_end_matches('.');
    idna::domain_to_ascii(name).unwrap_or_else(|_| name.to_ascii_lowercase())
}

impl Policy {
    /// Parses a policy file (RFC 8461, 3.2): `key: value` lines, ended by LF or CRLF. `version` must be `STSv1`,
    /// `mode` and `max_age` must be given, and `mx` at least once unless the mode is `none`; unknown keys are
    /// ignored, as the RFC asks.
    pub fn parse(text: &str, id: String) -> Result<Self, String> {
        let mut version = None;
        let mut mode = None;
        let mut max_age = None;
        let mut mx = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Err(format!("not a key and a value: {line}"));
            };
            let value = value.trim();
            match key.trim() {
                "version" if version.is_none() => version = Some(value.to_owned()),
                "mode" if mode.is_none() => {
                    mode = Some(Mode::parse(value).ok_or_else(|| format!("unknown mode {value}"))?);
                }
                "max_age" if max_age.is_none() => {
                    let seconds = value
                        .parse::<u64>()
                        .ok()
                        .filter(|seconds| *seconds <= MAX_AGE_LIMIT && value.len() <= 10)
                        .ok_or_else(|| format!("max_age {value} is not a number of seconds up to a year"))?;
                    max_age = Some(seconds);
                }
                "mx" => {
                    if value.is_empty() {
                        return Err("an mx line without a host".into());
                    }
                    let pattern = match value.strip_prefix("*.") {
                        Some(domain) => format!("*.{}", normalized_host(domain)),
                        None => normalized_host(value),
                    };
                    mx.push(pattern);
                }
                // A key given twice counts the first time (RFC 8461, 3.2); others are extensions.
                _ => {}
            }
        }
        if version.as_deref() != Some("STSv1") {
            return Err("the version is not STSv1".into());
        }
        let mode = mode.ok_or("the policy has no mode")?;
        let max_age = max_age.ok_or("the policy has no max_age")?;
        if mx.is_empty() && mode != Mode::None {
            return Err("the policy names no MX host".into());
        }
        Ok(Self { id, mode, mx, max_age })
    }

    /// Whether `host` may receive the domain's mail (RFC 8461, 4.1): a wildcard covers one label.
    pub fn allows(&self, host: &str) -> bool {
        let host = normalized_host(host);
        self.mx.iter().any(|pattern| match pattern.strip_prefix("*.") {
            Some(domain) => host
                .strip_suffix(domain)
                .and_then(|rest| rest.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            None => *pattern == host,
        })
    }

    /// Whether the policy is enforced: only then does it change how kernoid delivers.
    pub fn enforced(&self) -> bool {
        self.mode == Mode::Enforce
    }
}

/// How long a policy is kept: its `max_age`, but at least a few minutes and at most a year.
fn lifetime(max_age: u64) -> jiff::SignedDuration {
    let seconds = max_age.clamp(MIN_LIFETIME, MAX_AGE_LIMIT);
    jiff::SignedDuration::from_secs(i64::try_from(seconds).unwrap_or(i64::MAX))
}

/// The policy kept for `domain`, if it has not expired.
async fn cached(pool: &PgPool, domain: &str) -> Option<Policy> {
    let row = sqlx::query!(
        r#"SELECT policy_id, mode, mx, EXTRACT(EPOCH FROM expires_at - fetched_at)::bigint AS "max_age!"
           FROM mta_sts_policies WHERE domain = $1 AND expires_at > now()"#,
        domain,
    )
    .fetch_optional(pool)
    .await;
    match row {
        Ok(Some(row)) => {
            let max_age = u64::try_from(row.max_age).unwrap_or_default();
            Some(Policy { id: row.policy_id, mode: Mode::parse(&row.mode)?, mx: row.mx, max_age })
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, %domain, "reading a kept MTA-STS policy");
            None
        }
    }
}

/// Keeps `policy` for `domain` until its lifetime is over.
async fn keep(pool: &PgPool, domain: &str, policy: &Policy) {
    let expires_at = Timestamp::now() + lifetime(policy.max_age);
    let kept = sqlx::query!(
        "INSERT INTO mta_sts_policies (domain, policy_id, mode, mx, expires_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (domain) DO UPDATE
         SET policy_id = EXCLUDED.policy_id, mode = EXCLUDED.mode, mx = EXCLUDED.mx, fetched_at = now(),
             expires_at = EXCLUDED.expires_at",
        domain,
        policy.id,
        policy.mode.as_str(),
        &policy.mx,
        expires_at.to_sqlx(),
    )
    .execute(pool)
    .await;
    if let Err(error) = kept {
        tracing::warn!(%error, %domain, "keeping an MTA-STS policy");
    }
}

/// Fetches the policy file of `domain` over HTTPS, without following redirects (RFC 8461, 3.3).
async fn fetch(allow_private: bool, domain: &str, id: String) -> Result<Policy, String> {
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let client = kernoid_oidc::outbound::client_without_redirects(allow_private);
    let mut response = client.get(&url).send().await.map_err(|error| format!("{url}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("{url}: {}", response.status()));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("text/plain") {
        return Err(format!("{url}: not text/plain"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| format!("{url}: {error}"))? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_POLICY {
            return Err(format!("{url}: the policy is too large"));
        }
    }
    let text = String::from_utf8(body).map_err(|_| format!("{url}: not UTF-8"))?;
    Policy::parse(&text, id)
}

/// The domain's policy, if it has one: from the cache while its id is current, else fetched over HTTPS (public
/// addresses only, no redirects). A domain whose policy cannot be had now is treated as having none, unless a policy
/// is still cached (RFC 8461, 5.1).
pub async fn lookup(dns: &Dns, pool: &PgPool, allow_private: bool, domain: &str) -> Option<Policy> {
    let domain = normalized_host(domain);
    let record = dns.authenticator.txt_lookup::<MtaStsRecord>(format!("_mta-sts.{domain}."), Some(&dns.txt)).await;
    let kept = cached(pool, &domain).await;
    let Ok(record) = record else {
        // No record (or no answer now): a policy still kept goes on (RFC 8461, 5.1).
        return kept;
    };
    if let Some(policy) = kept.as_ref().filter(|policy| policy.id == record.id) {
        return Some(policy.clone());
    }
    match fetch(allow_private, &domain, record.id.clone()).await {
        Ok(policy) => {
            keep(pool, &domain, &policy).await;
            Some(policy)
        }
        Err(error) => {
            tracing::info!(%domain, %error, "fetching an MTA-STS policy failed");
            kept
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.Example.NET\r\n\
                          max_age: 86400\r\nextension: ignored\r\n";

    #[test]
    fn policies_are_parsed_as_the_rfc_writes_them() {
        let policy = Policy::parse(POLICY, "20261024".into()).unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.max_age, 86_400);
        assert_eq!(policy.mx, ["mail.example.com", "*.example.net"]);
        assert!(policy.enforced());
        // LF alone ends lines too; a key given twice counts the first time.
        let testing = Policy::parse("version: STSv1\nmode: testing\nmode: enforce\nmx: a.example\nmax_age: 5\n", "x".into())
            .unwrap();
        assert_eq!(testing.mode, Mode::Testing);
        assert!(!testing.enforced());
        assert!(Policy::parse("version: STSv1\nmode: none\nmax_age: 0\n", "x".into()).is_ok(), "none needs no mx");
    }

    #[test]
    fn broken_policies_are_refused() {
        for text in [
            "mode: enforce\nmx: a.example\nmax_age: 60\n",
            "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 60\n",
            "version: STSv1\nmode: always\nmx: a.example\nmax_age: 60\n",
            "version: STSv1\nmode: enforce\nmax_age: 60\n",
            "version: STSv1\nmode: enforce\nmx: a.example\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 99999999999\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -1\n",
            "version: STSv1\nmode enforce\n",
        ] {
            assert!(Policy::parse(text, "x".into()).is_err(), "{text}");
        }
    }

    #[test]
    fn policies_name_hosts_and_wildcards_of_one_label() {
        let policy = Policy::parse(POLICY, "x".into()).unwrap();
        assert!(policy.allows("mail.example.com"));
        assert!(policy.allows("MAIL.example.com."));
        assert!(!policy.allows("mx.example.com"));
        assert!(!policy.allows("example.com"));
        assert!(policy.allows("mx1.example.net"));
        assert!(!policy.allows("a.mx1.example.net"), "one label only");
        assert!(!policy.allows("example.net"));
        assert!(!policy.allows("badexample.net"));
    }

    #[test]
    fn international_names_compare_as_a_labels() {
        let policy = Policy::parse("version: STSv1\nmode: enforce\nmx: *.bücher.example\nmax_age: 60\n", "x".into())
            .unwrap();
        assert_eq!(policy.mx, ["*.xn--bcher-kva.example"]);
        assert!(policy.allows("mx.xn--bcher-kva.example"));
        assert!(policy.allows("mx.bücher.example"));
    }

    #[test]
    fn lifetimes_stay_sensible() {
        assert_eq!(lifetime(0), jiff::SignedDuration::from_secs(300));
        assert_eq!(lifetime(86_400), jiff::SignedDuration::from_hours(24));
        assert_eq!(lifetime(u64::MAX), jiff::SignedDuration::from_secs(31_557_600));
    }
}
