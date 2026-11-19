// SPDX-License-Identifier: MIT
//! Encrypting data to keys and decrypting it (RFC 0006): OpenPGP messages, AEAD (SEIPDv2, AES-256-OCB) when every
//! recipient's key is v6, otherwise SEIPDv1 as v4 programs read it; signed with the sender's key if one is given.

use pgp::{
    composed::{ArmorOptions, Message, MessageBuilder},
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{KeyDetails, KeyVersion, Password},
};
use rand::rngs::OsRng;

use crate::{Error, PublicKey, Result, SecretKey, keys::hex};

/// Encrypts `data` to every encryption subkey of each recipient. Armored for mail, binary for storage.
pub fn encrypt(data: &[u8], recipients: &[&PublicKey], signer: Option<&SecretKey>, armor: bool) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(Error::NoEncryptionKey);
    }
    let subkeys: Vec<_> = recipients.iter().map(|r| r.encryption_subkeys()).collect();
    if subkeys.iter().any(Vec::is_empty) {
        return Err(Error::NoEncryptionKey);
    }
    let v6 = recipients.iter().all(|r| r.0.version() == KeyVersion::V6);
    let mut builder = MessageBuilder::from_bytes("", data.to_vec());
    if let Some(signer) = signer {
        builder.sign(&signer.0.primary_key, Password::empty(), HashAlgorithm::Sha512);
    }
    let out = if v6 {
        let mut builder =
            builder.seipd_v2(OsRng, SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb, Default::default());
        for subkey in subkeys.iter().flatten() {
            builder.encrypt_to_key(OsRng, subkey)?;
        }
        if armor {
            builder.to_armored_string(OsRng, ArmorOptions::default())?.into_bytes()
        } else {
            builder.to_vec(OsRng)?
        }
    } else {
        let mut builder = builder.seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
        for subkey in subkeys.iter().flatten() {
            builder.encrypt_to_key(OsRng, subkey)?;
        }
        if armor {
            builder.to_armored_string(OsRng, ArmorOptions::default())?.into_bytes()
        } else {
            builder.to_vec(OsRng)?
        }
    };
    Ok(out)
}

/// What a decryption gave.
#[derive(Debug, Clone)]
pub struct Decrypted {
    pub data: Vec<u8>,
    /// Whether the message was signed at all.
    pub signed: bool,
    /// The fingerprint of the key among `senders` whose signature is valid, if any.
    pub verified_by: Option<String>,
}

/// Decrypts an OpenPGP message (armored or binary) with any of `keys`, and checks its signature against `senders`.
pub fn decrypt(data: &[u8], keys: &[&SecretKey], senders: &[&PublicKey]) -> Result<Decrypted> {
    let message = if is_armored(data) {
        Message::from_armor(data).map_err(|_| Error::NotEncrypted)?.0
    } else {
        Message::from_bytes(data).map_err(|_| Error::NotEncrypted)?
    };
    if !message.is_encrypted() {
        return Err(Error::NotEncrypted);
    }
    let passwords: Vec<Password> = keys.iter().map(|_| Password::empty()).collect();
    let mut message = message
        .decrypt_with_keys(passwords.iter().collect(), keys.iter().map(|k| &k.0).collect())
        .map_err(|_| Error::Decrypt)?;
    if message.is_compressed() {
        message = message.decompress().map_err(|_| Error::Decrypt)?;
    }
    let data = message.as_data_vec().map_err(|_| Error::Decrypt)?;
    let signed = matches!(message, Message::Signed { .. });
    let verified_by = signed
        .then(|| {
            senders.iter().find_map(|sender| {
                let keys = std::iter::once(&sender.0 as &dyn pgp::types::VerifyingKey)
                    .chain(sender.0.public_subkeys.iter().map(|s| s as &dyn pgp::types::VerifyingKey));
                keys.into_iter().find(|k| message.verify(*k).is_ok()).map(|_| hex(sender.0.fingerprint().as_bytes()))
            })
        })
        .flatten();
    Ok(Decrypted { data, signed, verified_by })
}

pub(crate) fn is_armored(data: &[u8]) -> bool {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    data[start..].starts_with(b"-----BEGIN PGP")
}
