// SPDX-License-Identifier: AGPL-3.0-or-later
//! Password hashes: Argon2id with the parameters OWASP recommends as a minimum (19 MiB, 2 passes, 1 lane). Hashes are
//! PHC strings, so that each records its own parameters; a hash made with other parameters is replaced at the next
//! successful login.

use std::sync::LazyLock;

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

use crate::IdentityError;

const MEMORY_KIB: u32 = 19 * 1024;
const PASSES: u32 = 2;
const LANES: u32 = 1;
/// Shortest password, in characters (NIST SP 800-63B asks for at least 8; kernoid asks for more).
pub const MIN_CHARS: usize = 12;
/// Longest password, in bytes – long enough for passphrases, short enough not to be a way to occupy the server.
pub const MAX_BYTES: usize = 1024;

fn argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(MEMORY_KIB, PASSES, LANES, None).expect("valid"))
}

/// Checked against when an account has no password or does not exist, so that the time an answer takes does not
/// tell whether an address exists.
static DUMMY: LazyLock<String> = LazyLock::new(|| hash_unchecked("not a password of anyone").expect("hashing works"));

pub(crate) fn check_policy(password: &str) -> Result<(), IdentityError> {
    if password.chars().count() < MIN_CHARS || password.len() > MAX_BYTES {
        return Err(IdentityError::Refused(format!(
            "a password has at least {MIN_CHARS} characters and at most {MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn hash_unchecked(password: &str) -> Result<String, IdentityError> {
    argon2()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| IdentityError::Refused(format!("cannot hash the password: {error}")))
}

/// Hashes `password` after checking the policy. Takes tens of milliseconds: call it off the async threads.
pub(crate) fn hash(password: &str) -> Result<String, IdentityError> {
    check_policy(password)?;
    hash_unchecked(password)
}

/// Whether `password` matches `hash`; with no hash, checks against a dummy and says no.
pub(crate) fn verify(hash: Option<&str>, password: &str) -> bool {
    let stored = hash.unwrap_or(DUMMY.as_str());
    let matches = PasswordHash::new(stored)
        .map(|parsed| argon2().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false);
    matches && hash.is_some()
}

/// Whether `hash` was made with other parameters than the current ones.
pub(crate) fn needs_rehash(hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else { return true };
    let current = Params::new(MEMORY_KIB, PASSES, LANES, None).expect("valid");
    parsed.algorithm.as_str() != "argon2id"
        || Params::try_from(&parsed).map_or(true, |params| {
            (params.m_cost(), params.t_cost(), params.p_cost())
                != (current.m_cost(), current.t_cost(), current.p_cost())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_and_differ() {
        let first = hash("correct horse battery staple").unwrap();
        let second = hash("correct horse battery staple").unwrap();
        assert!(first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{first}");
        assert_ne!(first, second, "every hash has its own salt");
        assert!(verify(Some(&first), "correct horse battery staple"));
        assert!(!verify(Some(&first), "correct horse battery stapl"));
        assert!(!verify(None, "not a password of anyone"), "the dummy never lets anyone in");
        assert!(!needs_rehash(&first));
    }

    #[test]
    fn old_parameters_are_rehashed() {
        let weak = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(8 * 1024, 1, 1, None).unwrap())
            .hash_password(b"correct horse battery staple")
            .unwrap()
            .to_string();
        assert!(verify(Some(&weak), "correct horse battery staple"));
        assert!(needs_rehash(&weak));
        assert!(needs_rehash("not a phc string"));
    }

    #[test]
    fn policy() {
        assert!(hash("short").is_err());
        assert!(hash(&"x".repeat(MAX_BYTES + 1)).is_err());
        assert!(check_policy("zwölf Zeichen").is_ok(), "counted in characters, not bytes");
    }
}
