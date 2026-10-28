// SPDX-License-Identifier: AGPL-3.0-or-later
//! Domain names as kernoid stores and compares them.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A fully qualified domain name: lower case, without a trailing dot, at least two labels of letters, digits and
/// hyphens (1–63 characters, no hyphen at either end), at most 253 characters. Internationalised names are given
/// in their ASCII form (`xn--…`), so that two spellings of one name cannot both be registered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a valid domain name")]
pub struct InvalidDomain(pub String);

impl DomainName {
    pub fn parse(input: &str) -> Result<Self, InvalidDomain> {
        let invalid = || InvalidDomain(input.to_owned());
        let name = input.trim().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<&str> = name.split('.').collect();
        let label_ok = |label: &&str| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        let top_level_ok = labels.last().is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()));
        if name.len() > 253 || labels.len() < 2 || !labels.iter().all(label_ok) || !top_level_ok {
            return Err(invalid());
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for DomainName {
    type Error = InvalidDomain;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DomainName> for String {
    fn from(name: DomainName) -> Self {
        name.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalised() {
        assert_eq!(DomainName::parse(" Mail.Example.ORG. ").unwrap().as_str(), "mail.example.org");
        assert_eq!(DomainName::parse("xn--mnchen-3ya.de").unwrap().as_str(), "xn--mnchen-3ya.de");
        assert_eq!(DomainName::parse("a-1.b2.example").unwrap().as_str(), "a-1.b2.example");
    }

    #[test]
    fn invalid() {
        let long_label = format!("{}.org", "a".repeat(64));
        let long_name = format!("{}org", "a.".repeat(127));
        for bad in [
            "",
            "localhost",
            "example",
            ".org",
            "a..org",
            "-a.org",
            "a-.org",
            "a_b.org",
            "münchen.de",
            "1.2.3.4",
            "example.org:443",
            "*.example.org",
            "a b.org",
            &long_label,
            &long_name,
        ] {
            assert!(DomainName::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn serde_validates() {
        assert!(serde_json::from_str::<DomainName>(r#""Example.org""#).is_ok());
        assert!(serde_json::from_str::<DomainName>(r#""not a domain""#).is_err());
    }
}
