// SPDX-License-Identifier: MIT
//! An account's key (RFC 0006, 4): made by the client, of one of two kinds; its secret key leaves the client only as
//! a protected copy – the OpenPGP secret key protected with Argon2 and AEAD (RFC 9580, 3.7) under a passphrase: a
//! passkey's PRF output, a recovery code, a device's own secret.

use pgp::{
    composed::{
        ArmorOptions, Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
        SignedPublicSubKey, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{aead::AeadAlgorithm, ecc_curve::ECCCurve, sym::SymmetricKeyAlgorithm},
    ser::Serialize,
    types::{KeyDetails, KeyVersion, Password, PublicParams, S2kParams, StringToKey},
};
use rand::{Rng, rngs::OsRng};

use crate::{Error, Result};

/// The kind of an account's key (RFC 0006, 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// v6, ML-DSA-65+Ed25519 with an ML-KEM-768+X25519 subkey (RFC 9980): secure against recorded mail being
    /// decrypted by a quantum computer later.
    Pqc,
    /// v4, Ed25519 with an X25519 subkey (Curve25519 as GnuPG knows it): for correspondents whose programs know only v4.
    Compatible,
}

impl Kind {
    pub fn of(key: &SignedPublicKey) -> Option<Kind> {
        match key.version() {
            KeyVersion::V6 => Some(Kind::Pqc),
            KeyVersion::V4 => Some(Kind::Compatible),
            _ => None,
        }
    }
}

/// An account's secret key, unlocked.
#[derive(Debug, Clone)]
pub struct SecretKey(pub(crate) SignedSecretKey);

/// A public key – one's own or someone else's.
#[derive(Debug, Clone)]
pub struct PublicKey(pub(crate) SignedPublicKey);

impl SecretKey {
    /// Makes a key for the given addresses (the first becomes the primary user id).
    pub fn generate(kind: Kind, addresses: &[&str]) -> Result<SecretKey> {
        let (first, others) = addresses.split_first().ok_or_else(|| Error::Key("no address".to_owned()))?;
        let (version, primary, encryption) = match kind {
            Kind::Pqc => (KeyVersion::V6, KeyType::MlDsa65Ed25519, KeyType::MlKem768X25519),
            Kind::Compatible => (KeyVersion::V4, KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519Legacy)),
        };
        let subkey = SubkeyParamsBuilder::default()
            .version(version)
            .key_type(encryption)
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false)
            .build()
            .map_err(|e| Error::Key(e.to_string()))?;
        let mut params = SecretKeyParamsBuilder::default();
        params
            .version(version)
            .key_type(primary)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(format!("<{first}>"))
            .user_ids(others.iter().map(|a| format!("<{a}>")).collect())
            .feature_seipd_v2(kind == Kind::Pqc)
            .preferred_symmetric_algorithms(
                [SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128].into_iter().collect(),
            )
            .subkeys(vec![subkey]);
        if kind == Kind::Pqc {
            params
                .preferred_aead_algorithms([(SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb)].into_iter().collect());
        }
        let params = params.build().map_err(|e| Error::Key(e.to_string()))?;
        Ok(SecretKey(params.generate(OsRng)?))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(SignedPublicKey::from(self.0.clone()))
    }

    pub fn fingerprint(&self) -> String {
        hex(self.0.fingerprint().as_bytes())
    }

    /// A protected copy of the secret key, binary: every secret part protected with Argon2 (RFC 9106, choice 2) and
    /// AES-256-OCB under `passphrase`.
    pub fn protect(&self, passphrase: &str) -> Result<Vec<u8>> {
        let mut key = self.0.clone();
        let password = Password::from(passphrase);
        key.primary_key.set_password_with_s2k(&password, s2k())?;
        for subkey in &mut key.secret_subkeys {
            subkey.key.set_password_with_s2k(&password, s2k())?;
        }
        Ok(key.to_bytes()?)
    }

    /// Unlocks a protected copy. A wrong passphrase and a damaged copy are the same `Unlock`.
    pub fn unlock(protected: &[u8], passphrase: &str) -> Result<SecretKey> {
        let mut key = SignedSecretKey::from_bytes(protected).map_err(|e| Error::Key(e.to_string()))?;
        key.verify_bindings().map_err(|e| Error::Key(e.to_string()))?;
        let password = Password::from(passphrase);
        key.primary_key.remove_password(&password).map_err(|_| Error::Unlock)?;
        for subkey in &mut key.secret_subkeys {
            subkey.key.remove_password(&password).map_err(|_| Error::Unlock)?;
        }
        Ok(SecretKey(key))
    }

    /// The secret key unprotected, armored – only for the user to keep or move to another program.
    pub fn export(&self) -> Result<String> {
        Ok(self.0.to_armored_string(ArmorOptions::default())?)
    }

    pub fn import(armored_or_binary: &[u8]) -> Result<SecretKey> {
        let (key, _) = SignedSecretKey::from_reader_single(armored_or_binary).map_err(|e| Error::Key(e.to_string()))?;
        key.verify_bindings().map_err(|e| Error::Key(e.to_string()))?;
        if key.primary_key.secret_params().is_encrypted() {
            return Err(Error::Key("the key is protected; remove its passphrase first".to_owned()));
        }
        let algorithms = std::iter::once(key.primary_key.public_params())
            .chain(key.secret_subkeys.iter().map(|s| s.key.public_params()));
        if !algorithms.into_iter().all(supported) {
            return Err(Error::Key("only Curve25519 and post-quantum keys can be used here".to_owned()));
        }
        Ok(SecretKey(key))
    }
}

impl PublicKey {
    /// Reads a public key, armored or binary, and checks its self-signatures.
    pub fn parse(armored_or_binary: &[u8]) -> Result<PublicKey> {
        let (key, _) = SignedPublicKey::from_reader_single(armored_or_binary).map_err(|e| Error::Key(e.to_string()))?;
        key.verify_bindings().map_err(|e| Error::Key(e.to_string()))?;
        Ok(PublicKey(key))
    }

    pub fn fingerprint(&self) -> String {
        hex(self.0.fingerprint().as_bytes())
    }

    pub fn kind(&self) -> Option<Kind> {
        Kind::of(&self.0)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes()?)
    }

    pub fn armored(&self) -> Result<String> {
        Ok(self.0.to_armored_string(ArmorOptions::default())?)
    }

    /// The addresses of the key's user ids (the part in angle brackets, or the whole id).
    pub fn addresses(&self) -> Vec<String> {
        self.0
            .details
            .users
            .iter()
            .filter_map(|user| user.id.as_str())
            .map(|id| match (id.rfind('<'), id.rfind('>')) {
                (Some(start), Some(end)) if start < end => id[start + 1..end].to_owned(),
                _ => id.to_owned(),
            })
            .collect()
    }

    /// The subkeys that may encrypt: an algorithm that can, and a binding that says so.
    pub(crate) fn encryption_subkeys(&self) -> Vec<&SignedPublicSubKey> {
        self.0
            .public_subkeys
            .iter()
            .filter(|subkey| subkey.key.algorithm().can_encrypt())
            .filter(|subkey| {
                subkey.signatures.iter().any(|s| s.key_flags().encrypt_comms() || s.key_flags().encrypt_storage())
            })
            .collect()
    }
}

/// A recovery code (RFC 0006, 4.2): 32 characters of Crockford's Base32 – 160 bits – in groups of four.
pub fn recovery_code() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut rng = OsRng;
    (0..32)
        .map(|i| {
            let c = ALPHABET[rng.gen_range(0..ALPHABET.len())] as char;
            if i > 0 && i % 4 == 0 { format!("-{c}") } else { c.to_string() }
        })
        .collect()
}

/// A recovery code as the user may type it: upper case, without separators and spaces, with Crockford's look-alikes.
pub fn normalize_recovery_code(typed: &str) -> String {
    let code: String = typed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect();
    code.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// The algorithms of the two kinds (RFC 0006, 4.1). Secret keys of others – RSA, NIST curves, X448 – are not taken:
/// their arithmetic (crypto-bigint 0.5 for the curves) is not constant-time (RUSTSEC-2026-0387, `deny.toml`).
fn supported(params: &PublicParams) -> bool {
    match params {
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) | PublicParams::X25519(_) => true,
        PublicParams::MlDsa65Ed25519(_) | PublicParams::MlKem768X25519(_) => true,
        PublicParams::ECDH(ecdh) => ecdh.curve() == ECCCurve::Curve25519Legacy,
        _ => false,
    }
}

fn s2k() -> S2kParams {
    let mut rng = OsRng;
    let aead_mode = AeadAlgorithm::Ocb;
    let mut nonce = vec![0u8; aead_mode.nonce_size()];
    rng.fill(&mut nonce[..]);
    let mut salt = [0u8; 16];
    rng.fill(&mut salt[..]);
    S2kParams::Aead {
        sym_alg: SymmetricKeyAlgorithm::AES256,
        aead_mode,
        s2k: StringToKey::Argon2 { salt, t: 3, p: 4, m_enc: 16 },
        nonce: nonce.into(),
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
