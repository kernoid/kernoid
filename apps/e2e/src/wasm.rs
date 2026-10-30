// SPDX-License-Identifier: MIT
//! The web app's view (`@kernoid/e2e`): a `Keyring` that holds unlocked secret keys and known public keys inside
//! WebAssembly – JavaScript names them by fingerprint and never sees a secret key, except by asking to export one.

use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use crate::{Error, Kind, PublicKey, SecretKey, keys, message, mime};

fn js(error: Error) -> JsError {
    JsError::new(&error.to_string())
}

#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct Keyring {
    secrets: HashMap<String, SecretKey>,
    publics: HashMap<String, PublicKey>,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct Decrypted {
    data: Vec<u8>,
    signed: bool,
    verified_by: Option<String>,
}

#[wasm_bindgen]
impl Decrypted {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signed(&self) -> bool {
        self.signed
    }

    #[wasm_bindgen(getter, js_name = verifiedBy)]
    pub fn verified_by(&self) -> Option<String> {
        self.verified_by.clone()
    }
}

impl From<message::Decrypted> for Decrypted {
    fn from(d: message::Decrypted) -> Self {
        Decrypted { data: d.data, signed: d.signed, verified_by: d.verified_by }
    }
}

#[wasm_bindgen]
impl Keyring {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Keyring {
        Keyring::default()
    }

    /// Makes a key (`pqc` or `compatible`) and keeps it; returns its fingerprint.
    pub fn generate(&mut self, kind: &str, addresses: Vec<String>) -> Result<String, JsError> {
        let kind = match kind {
            "pqc" => Kind::Pqc,
            "compatible" => Kind::Compatible,
            _ => return Err(JsError::new("the kind is pqc or compatible")),
        };
        let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
        let key = SecretKey::generate(kind, &addresses).map_err(js)?;
        Ok(self.keep(key))
    }

    /// Unlocks a protected copy and keeps the key; returns its fingerprint.
    pub fn unlock(&mut self, protected: &[u8], passphrase: &str) -> Result<String, JsError> {
        let key = SecretKey::unlock(protected, passphrase).map_err(js)?;
        Ok(self.keep(key))
    }

    /// Takes an unprotected secret key from another program; returns its fingerprint.
    #[wasm_bindgen(js_name = importSecret)]
    pub fn import_secret(&mut self, key: &[u8]) -> Result<String, JsError> {
        let key = SecretKey::import(key).map_err(js)?;
        Ok(self.keep(key))
    }

    /// Adds someone's public key; returns its fingerprint.
    #[wasm_bindgen(js_name = addPublic)]
    pub fn add_public(&mut self, key: &[u8]) -> Result<String, JsError> {
        let key = PublicKey::parse(key).map_err(js)?;
        let fingerprint = key.fingerprint();
        self.publics.insert(fingerprint.clone(), key);
        Ok(fingerprint)
    }

    /// Forgets a secret key (logging out).
    pub fn forget(&mut self, fingerprint: &str) {
        self.secrets.remove(fingerprint);
    }

    #[wasm_bindgen(js_name = hasSecret)]
    pub fn has_secret(&self, fingerprint: &str) -> bool {
        self.secrets.contains_key(fingerprint)
    }

    /// A protected copy of a kept secret key.
    pub fn protect(&self, fingerprint: &str, passphrase: &str) -> Result<Vec<u8>, JsError> {
        self.secret(fingerprint)?.protect(passphrase).map_err(js)
    }

    /// The secret key unprotected and armored – for the user to keep.
    #[wasm_bindgen(js_name = exportSecret)]
    pub fn export_secret(&self, fingerprint: &str) -> Result<String, JsError> {
        self.secret(fingerprint)?.export().map_err(js)
    }

    /// The public key, binary.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self, fingerprint: &str) -> Result<Vec<u8>, JsError> {
        self.public(fingerprint)?.to_bytes().map_err(js)
    }

    #[wasm_bindgen(js_name = publicArmored)]
    pub fn public_armored(&self, fingerprint: &str) -> Result<String, JsError> {
        self.public(fingerprint)?.armored().map_err(js)
    }

    /// `pqc` or `compatible`.
    pub fn kind(&self, fingerprint: &str) -> Result<String, JsError> {
        Ok(match self.public(fingerprint)?.kind() {
            Some(Kind::Pqc) => "pqc",
            Some(Kind::Compatible) => "compatible",
            None => "other",
        }
        .to_owned())
    }

    pub fn addresses(&self, fingerprint: &str) -> Result<Vec<String>, JsError> {
        Ok(self.public(fingerprint)?.addresses())
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        recipients: Vec<String>,
        signer: Option<String>,
        armor: bool,
    ) -> Result<Vec<u8>, JsError> {
        let recipients = self.publics_of(&recipients)?;
        let signer = signer.as_deref().map(|f| self.secret(f)).transpose()?;
        message::encrypt(data, &recipients, signer, armor).map_err(js)
    }

    /// Decrypts with any kept secret key; checks the signature against the public keys named.
    pub fn decrypt(&self, data: &[u8], senders: Vec<String>) -> Result<Decrypted, JsError> {
        let senders = self.known_publics(&senders);
        message::decrypt(data, &self.all_secrets(), &senders).map(Decrypted::from).map_err(js)
    }

    #[wasm_bindgen(js_name = encryptMessage)]
    pub fn encrypt_message(
        &self,
        raw: &[u8],
        recipients: Vec<String>,
        signer: Option<String>,
    ) -> Result<Vec<u8>, JsError> {
        let recipients = self.publics_of(&recipients)?;
        let signer = signer.as_deref().map(|f| self.secret(f)).transpose()?;
        mime::encrypt_message(raw, &recipients, signer).map_err(js)
    }

    #[wasm_bindgen(js_name = decryptMessage)]
    pub fn decrypt_message(&self, raw: &[u8], senders: Vec<String>) -> Result<Decrypted, JsError> {
        let senders = self.known_publics(&senders);
        mime::decrypt_message(raw, &self.all_secrets(), &senders).map(Decrypted::from).map_err(js)
    }

    /// The summary of an encrypted message as JSON (`subject`, `preview`, `hasAttachment`).
    #[wasm_bindgen(js_name = decryptSummary)]
    pub fn decrypt_summary(&self, data: &[u8]) -> Result<String, JsError> {
        let summary = mime::decrypt_summary(data, &self.all_secrets()).map_err(js)?;
        serde_json::to_string(&summary).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = encryptedSummary)]
    pub fn encrypted_summary(&self, raw: &[u8], recipients: Vec<String>) -> Result<Vec<u8>, JsError> {
        let recipients = self.publics_of(&recipients)?;
        mime::encrypted_summary(raw, &recipients).map_err(js)
    }
}

impl Keyring {
    fn keep(&mut self, key: SecretKey) -> String {
        let fingerprint = key.fingerprint();
        self.publics.insert(fingerprint.clone(), key.public());
        self.secrets.insert(fingerprint.clone(), key);
        fingerprint
    }

    fn secret(&self, fingerprint: &str) -> Result<&SecretKey, JsError> {
        self.secrets.get(fingerprint).ok_or_else(|| JsError::new("no such secret key"))
    }

    fn public(&self, fingerprint: &str) -> Result<&PublicKey, JsError> {
        self.publics.get(fingerprint).ok_or_else(|| JsError::new("no such public key"))
    }

    fn publics_of(&self, fingerprints: &[String]) -> Result<Vec<&PublicKey>, JsError> {
        fingerprints.iter().map(|f| self.public(f)).collect()
    }

    fn known_publics(&self, fingerprints: &[String]) -> Vec<&PublicKey> {
        fingerprints.iter().filter_map(|f| self.publics.get(f)).collect()
    }

    fn all_secrets(&self) -> Vec<&SecretKey> {
        self.secrets.values().collect()
    }
}

#[wasm_bindgen(js_name = isEncrypted)]
pub fn is_encrypted(raw: &[u8]) -> bool {
    mime::is_encrypted(raw)
}

/// The summary of a plain message as JSON – what an app encrypts when it stores a message itself.
#[wasm_bindgen]
pub fn summary(raw: &[u8]) -> Result<String, JsError> {
    let summary = mime::summary(raw).map_err(js)?;
    serde_json::to_string(&summary).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = recoveryCode)]
pub fn recovery_code() -> String {
    keys::recovery_code()
}

#[wasm_bindgen(js_name = normalizeRecoveryCode)]
pub fn normalize_recovery_code(typed: &str) -> String {
    keys::normalize_recovery_code(typed)
}
