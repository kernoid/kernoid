// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mail addresses as kernoid stores and compares them: they are login names as well.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::DomainName;

/// `local@domain`, lower case. The local part has 1 to 64 characters of letters, digits and `.`, `_`, `-` (no dot at
/// either end, no two in a row). `+` is not allowed: it is kept for subaddresses – `alice+news@example.org` is
/// delivered to `alice@example.org` – so that nobody can register an address that reads like someone else's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address {
    full: String,
    at: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a valid address")]
pub struct InvalidAddress(pub String);

impl Address {
    pub fn parse(input: &str) -> Result<Self, InvalidAddress> {
        let invalid = || InvalidAddress(input.to_owned());
        let (local, domain) = input.trim().rsplit_once('@').ok_or_else(invalid)?;
        let local = local.to_ascii_lowercase();
        let domain = DomainName::parse(domain).map_err(|_| invalid())?;
        let local_ok = (1..=64).contains(&local.len())
            && local.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
            && !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..");
        if !local_ok {
            return Err(invalid());
        }
        Ok(Self { at: local.len(), full: format!("{local}@{domain}") })
    }

    pub fn as_str(&self) -> &str {
        &self.full
    }

    pub fn local(&self) -> &str {
        &self.full[..self.at]
    }

    pub fn domain(&self) -> DomainName {
        DomainName::parse(&self.full[self.at + 1..]).expect("checked when parsed")
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.full)
    }
}

impl TryFrom<String> for Address {
    type Error = InvalidAddress;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Address> for String {
    fn from(address: Address) -> Self {
        address.full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalised() {
        let address = Address::parse(" Alice.Example@Firma.DE ").unwrap();
        assert_eq!(
            (address.as_str(), address.local(), address.domain().as_str()),
            ("alice.example@firma.de", "alice.example", "firma.de")
        );
        assert_eq!(Address::parse("a_b-c.d@sub.example.org").unwrap().as_str(), "a_b-c.d@sub.example.org");
    }

    #[test]
    fn invalid() {
        let long = format!("{}@example.org", "a".repeat(65));
        for bad in [
            "",
            "alice",
            "@example.org",
            "alice@",
            "alice@localhost",
            "alice+news@example.org",
            ".alice@example.org",
            "alice.@example.org",
            "al..ice@example.org",
            "al ice@example.org",
            "\"alice\"@example.org",
            "älice@example.org",
            "alice@exa_mple.org",
            &long,
        ] {
            assert!(Address::parse(bad).is_err(), "{bad:?}");
        }
    }
}
