// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! MTA-STS (RFC 8461, RFC 0002 10.4): the policy of a domain kernoid sends to. Derived from Stalwart's
//! `crates/smtp/src/outbound/mta_sts` (v0.16.27: parsing the policy, matching MX hosts, looking it up). kernoid keeps
//! policies in PostgreSQL for their `max_age`, so that every worker knows them and a policy outlives a restart.

use chrono::Utc;
use kernoid_store::PgPool;
use mail_auth::mta_sts::MtaSts;

use crate::Dns;

/// Largest policy read.
const MAX_POLICY: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Testing,
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
        match value {
            "enforce" => Some(Self::Enforce),
            "testing" => Some(Self::Testing),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    /// `mx` lines: a host name, or `*.` and a domain for any one label below it.
    pub mx: Vec<String>,
    pub max_age: u64,
}

fn to_a_label(domain: &str) -> String {
    idna::domain_to_ascii(domain).map(|domain| domain.to_lowercase()).unwrap_or_else(|_| domain.to_lowercase())
}

impl Policy {
    /// Parses a policy file (RFC 8461, 3.2).
    pub fn parse(text: &str, id: String) -> Result<Self, String> {
        let mut mode = None;
        let mut max_age = 86_400;
        let mut mx = Vec::new();
        let mut version = false;
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else { continue };
            let value = value.trim();
            match key.trim() {
                "version" if value.eq_ignore_ascii_case("STSv1") => version = true,
                "version" => return Err(format!("unsupported version {value:?}")),
                "mode" => mode = Some(Mode::parse(value).ok_or_else(|| format!("unsupported mode {value:?}"))?),
                "max_age" => max_age = value.parse().unwrap_or(max_age),
                "mx" if !value.is_empty() => match value.strip_prefix("*.") {
                    Some(suffix) if !suffix.is_empty() => mx.push(format!("*.{}", to_a_label(suffix))),
                    Some(_) => {}
                    None => mx.push(to_a_label(value)),
                },
                _ => {}
            }
        }
        if !version {
            return Err("no version".into());
        }
        let mode = mode.ok_or("no mode")?;
        if mx.is_empty() && mode != Mode::None {
            return Err("no mx".into());
        }
        Ok(Self { id, mode, mx, max_age })
    }

    /// Whether `host` may receive the domain's mail (RFC 8461, 4.1): a wildcard covers one label.
    pub fn allows(&self, host: &str) -> bool {
        if self.mode == Mode::None {
            return true;
        }
        let host = host.trim_end_matches('.').to_lowercase();
        self.mx.iter().any(|pattern| match pattern.strip_prefix("*.") {
            Some(domain) => host.split_once('.').is_some_and(|(_, suffix)| suffix == domain),
            None => *pattern == host,
        })
    }

    pub fn enforced(&self) -> bool {
        self.mode == Mode::Enforce
    }
}

/// How long a policy is kept: its `max_age`, if that is sensible.
fn lifetime(max_age: u64) -> chrono::Duration {
    let seconds = if (3_600..31_557_600).contains(&max_age) { max_age } else { 86_400 };
    chrono::Duration::seconds(seconds as i64)
}

async fn cached(pool: &PgPool, domain: &str) -> Option<Policy> {
    let row = sqlx::query!(
        "SELECT policy_id, mode, mx, expires_at FROM mta_sts_policies WHERE domain = $1 AND expires_at > now()",
        domain,
    )
    .fetch_optional(pool)
    .await
    .ok()??;
    Some(Policy {
        id: row.policy_id,
        mode: Mode::parse(&row.mode)?,
        mx: row.mx,
        max_age: (row.expires_at - Utc::now()).num_seconds().max(0) as u64,
    })
}

/// The domain's policy, if it has one: from the cache while its id is current, else fetched over HTTPS (public
/// addresses only, no redirects). A domain whose policy cannot be had now is treated as having none, unless a policy
/// is still cached (RFC 8461, 5.1).
pub async fn lookup(dns: &Dns, pool: &PgPool, allow_private: bool, domain: &str) -> Option<Policy> {
    let record = match dns.authenticator.txt_lookup::<MtaSts>(format!("_mta-sts.{domain}."), Some(&dns.txt)).await {
        Ok(record) => record,
        Err(_) => return cached(pool, domain).await,
    };
    if let Some(policy) = cached(pool, domain).await
        && policy.id == record.id
    {
        return Some(policy);
    }
    match fetch(allow_private, domain, &record.id).await {
        Ok(policy) => {
            let expires = Utc::now() + lifetime(policy.max_age);
            let stored = sqlx::query!(
                "INSERT INTO mta_sts_policies (domain, policy_id, mode, mx, expires_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (domain) DO UPDATE SET policy_id = $2, mode = $3, mx = $4, fetched_at = now(), expires_at = $5",
                domain,
                policy.id,
                policy.mode.as_str(),
                &policy.mx,
                expires,
            )
            .execute(pool)
            .await;
            if let Err(error) = stored {
                tracing::warn!(%error, %domain, "keeping an MTA-STS policy");
            }
            Some(policy)
        }
        Err(error) => {
            tracing::info!(%domain, %error, "no MTA-STS policy could be fetched");
            cached(pool, domain).await
        }
    }
}

async fn fetch(allow_private: bool, domain: &str, id: &str) -> Result<Policy, String> {
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let response = kernoid_oidc::outbound::client_without_redirects(allow_private)
        .get(&url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("{url}: {}", response.status()));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_POLICY {
            return Err("the policy is too large".into());
        }
    }
    Policy::parse(&String::from_utf8_lossy(&body), id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_name_hosts_and_wildcards_of_one_label() {
        let policy = Policy::parse(
            "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n",
            "20261024".into(),
        )
        .unwrap();
        assert!(policy.enforced());
        assert!(policy.allows("mail.example.com"));
        assert!(policy.allows("MX1.Example.net."));
        assert!(!policy.allows("a.b.example.net"), "a wildcard covers one label");
        assert!(!policy.allows("other.example.com"));
        assert_eq!(policy.max_age, 604_800);
        assert!(Policy::parse("mode: enforce\nmx: a.example\n", "x".into()).is_err(), "no version");
        assert!(Policy::parse("version: STSv1\nmode: enforce\n", "x".into()).is_err(), "no mx");
        let testing = Policy::parse("version: STSv1\nmode: testing\nmx: a.example\n", "x".into()).unwrap();
        assert!(!testing.enforced());
    }
}
