// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Sender Rewriting Scheme for forwarded mail (RFC 0002, 10.6): a message a Sieve `redirect` sends on keeps the
//! original sender – rewritten into an address of the forwarding domain, so that SPF holds at the next server, and
//! a bounce finds its way back. `SRS0=<hash>=<day>=<domain>=<local>@<forwarding domain>`, as in the scheme of Shevek
//! (libsrs2), with two differences that matter only to kernoid, which alone reverses these addresses: the hash is
//! HMAC-SHA256 in base32 (kernoid keeps local parts in lower case, and base32 has no case), and it covers the day,
//! the domain and the local part in lower case. An address is good for 21 days.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// How many days an SRS address can be bounced to.
const MAX_AGE_DAYS: u64 = 21;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const HASH_LENGTH: usize = 6;

/// Days since the epoch, modulo 1024 – two base32 characters.
fn day_stamp(day: u64) -> String {
    let day = day % 1024;
    [BASE32[(day >> 5) as usize] as char, BASE32[(day & 31) as usize] as char].into_iter().collect()
}

fn parse_day(stamp: &str) -> Option<u64> {
    let mut value = 0u64;
    let bytes = stamp.as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    for byte in bytes {
        value = value * 32 + BASE32.iter().position(|c| c == byte)? as u64;
    }
    Some(value)
}

fn hash(secret: &[u8], stamp: &str, domain: &str, local: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes a key of any length");
    for part in [stamp, domain, local] {
        mac.update(part.to_lowercase().as_bytes());
        mac.update(b"\0");
    }
    let bytes = mac.finalize().into_bytes();
    // Base32 of the first bits: five per character.
    let mut bits = 0u64;
    for byte in &bytes[..8] {
        bits = (bits << 8) | u64::from(*byte);
    }
    (0..HASH_LENGTH).map(|i| BASE32[((bits >> (59 - 5 * i)) & 31) as usize] as char).collect()
}

/// The SRS address under which `sender` is forwarded from `forwarding_domain` on `day` (days since the epoch).
/// Sender addresses that are SRS addresses already get wrapped again: their bounces come back here first.
pub fn forward(secret: &[u8], sender: &str, forwarding_domain: &str, day: u64) -> Option<String> {
    let (local, domain) = sender.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    let stamp = day_stamp(day);
    let hash = hash(secret, &stamp, domain, local);
    Some(format!("SRS0={hash}={stamp}={domain}={local}@{forwarding_domain}"))
}

/// The original sender of an SRS address made by [`forward`] – if its hash holds and it is at most 21 days old on
/// `day`; `None` for anything else.
pub fn reverse(secret: &[u8], address: &str, day: u64) -> Option<String> {
    let (local, _) = address.rsplit_once('@')?;
    let rest = local.strip_prefix("SRS0=").or_else(|| local.strip_prefix("srs0="))?;
    let mut parts = rest.splitn(4, '=');
    let (given, stamp, domain, original) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if domain.is_empty() || original.is_empty() {
        return None;
    }
    let stamp = stamp.to_lowercase();
    let made = parse_day(&stamp)?;
    let age = (day % 1024 + 1024 - made) % 1024;
    if age > MAX_AGE_DAYS {
        return None;
    }
    let expected = hash(secret, &stamp, domain, original);
    // Compared over the whole length whatever differs: no hint at how much of a guess was right.
    let given = given.to_lowercase();
    let same =
        given.len() == expected.len() && given.bytes().zip(expected.bytes()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0;
    same.then(|| format!("{original}@{domain}"))
}

/// Today, as SRS counts it.
pub fn today() -> u64 {
    (chrono::Utc::now().timestamp() / 86_400).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::{forward, reverse};

    const SECRET: &[u8] = b"a secret of the installation";

    #[test]
    fn a_forwarded_sender_comes_back() {
        let day = 20_390;
        let address = forward(SECRET, "Bob.Smith@Example.org", "firma.example", day).unwrap();
        assert!(address.starts_with("SRS0=") && address.ends_with("=Example.org=Bob.Smith@firma.example"), "{address}");
        // kernoid keeps recipients in lower case.
        let lower = address.to_lowercase();
        assert_eq!(reverse(SECRET, &lower, day).as_deref(), Some("bob.smith@example.org"));
        assert_eq!(reverse(SECRET, &address, day + 21).as_deref(), Some("Bob.Smith@Example.org"));
    }

    #[test]
    fn forged_or_old_addresses_are_refused() {
        let day = 20_390;
        let address = forward(SECRET, "bob@example.org", "firma.example", day).unwrap();
        assert_eq!(reverse(SECRET, &address, day + 22), None, "too old");
        assert_eq!(reverse(b"another secret", &address, day), None);
        let changed = address.replace("=example.org=", "=evil.example=");
        assert_eq!(reverse(SECRET, &changed, day), None);
        assert_eq!(reverse(SECRET, "alice@firma.example", day), None);
        // Across the wrap of the day counter.
        let late = forward(SECRET, "bob@example.org", "firma.example", 1023).unwrap();
        assert_eq!(reverse(SECRET, &late, 1030).as_deref(), Some("bob@example.org"));
    }
}
