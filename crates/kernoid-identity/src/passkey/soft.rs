// SPDX-License-Identifier: AGPL-3.0-or-later
//! A software passkey for tests – kernoid's own and those of crates on it (feature `soft-passkey`): it answers the
//! options kernoid sends as a browser with an authenticator would, with attestation `none`, keys of aws-lc-rs and a
//! counter that grows by one at each use. Never for anything but tests: its key lives in memory.

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    cbor,
    webauthn::{EDDSA, ES256, PublicKey, RS256, decode, encode},
};

enum Key {
    Es256(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rs256(RsaKeyPair),
}

/// A passkey in memory.
pub struct SoftPasskey {
    key: Key,
    credential_id: Vec<u8>,
    counter: u32,
    /// The user handle `register` was given – a discoverable passkey sends it back.
    user_handle: Option<Vec<u8>>,
    /// The flags it sets besides AT: user present and verified unless a test says otherwise.
    pub flags: u8,
}

impl std::fmt::Debug for SoftPasskey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftPasskey").field("credential_id", &encode(&self.credential_id)).finish_non_exhaustive()
    }
}

impl SoftPasskey {
    /// A new passkey with a key of the COSE algorithm `alg` (ES256 −7, EdDSA −8, RS256 −257).
    pub fn new(alg: i64) -> Self {
        let key = match alg {
            ES256 => {
                Key::Es256(EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).expect("a P-256 key"))
            }
            EDDSA => Key::Ed25519(Ed25519KeyPair::generate().expect("an Ed25519 key")),
            RS256 => Key::Rs256(RsaKeyPair::generate(KeySize::Rsa2048).expect("an RSA key")),
            other => panic!("no software passkey for the algorithm {other}"),
        };
        let mut credential_id = vec![0u8; 32];
        getrandom::fill(&mut credential_id).expect("randomness");
        SoftPasskey { key, credential_id, counter: 0, user_handle: None, flags: 0x01 | 0x04 }
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Sends `handle` as the user handle from now on (as a discoverable passkey does), or none.
    pub fn set_user_handle(&mut self, handle: Option<Vec<u8>>) {
        self.user_handle = handle;
    }

    /// The public key, as kernoid keeps it.
    pub fn public_key(&self) -> PublicKey {
        match &self.key {
            Key::Es256(key) => {
                let point = key.public_key().as_ref();
                PublicKey::Es256 { x: point[1..33].to_vec(), y: point[33..65].to_vec() }
            }
            Key::Ed25519(key) => PublicKey::Ed25519 { x: key.public_key().as_ref().to_vec() },
            Key::Rs256(key) => {
                let public = key.public_key();
                PublicKey::Rs256 {
                    n: public.modulus().big_endian_without_leading_zero().to_vec(),
                    e: public.exponent().big_endian_without_leading_zero().to_vec(),
                }
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let random = SystemRandom::new();
        match &self.key {
            Key::Es256(key) => key.sign(&random, message).expect("signing").as_ref().to_vec(),
            Key::Ed25519(key) => key.sign(message).as_ref().to_vec(),
            Key::Rs256(key) => {
                let mut signed = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &random, message, &mut signed).expect("signing");
                signed
            }
        }
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false }))
            .expect("JSON")
    }

    /// Answers `navigator.credentials.create()` with `options` (as kernoid sends them) on a page of `origin`.
    pub fn register(&mut self, origin: &str, options: &Value) -> Value {
        let options = &options["publicKey"];
        let rp_id = options["rp"]["id"].as_str().expect("an RP ID");
        self.user_handle = Some(decode(options["user"]["id"].as_str().expect("a user id")).expect("base64url"));
        let client_data =
            Self::client_data("webauthn.create", options["challenge"].as_str().expect("a challenge"), origin);
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(self.flags | 0x40);
        data.extend(self.counter.to_be_bytes());
        data.extend([0u8; 16]);
        data.extend((self.credential_id.len() as u16).to_be_bytes());
        data.extend(&self.credential_id);
        data.extend(cbor::encode(&self.public_key().to_cose()));
        let object = cbor::Value::Map(vec![
            (cbor::Value::Text("fmt".into()), cbor::Value::Text("none".into())),
            (cbor::Value::Text("attStmt".into()), cbor::Value::Map(Vec::new())),
            (cbor::Value::Text("authData".into()), cbor::Value::Bytes(data)),
        ]);
        json!({
            "id": encode(&self.credential_id),
            "rawId": encode(&self.credential_id),
            "type": "public-key",
            "response": { "clientDataJSON": encode(&client_data), "attestationObject": encode(&cbor::encode(&object)) },
            "extensions": {},
        })
    }

    /// Answers `navigator.credentials.get()` with `options` on a page of `origin`, whatever credentials they allow.
    pub fn authenticate(&mut self, origin: &str, options: &Value) -> Value {
        let options = &options["publicKey"];
        let rp_id = options["rpId"].as_str().expect("an RP ID");
        self.counter += 1;
        let client_data =
            Self::client_data("webauthn.get", options["challenge"].as_str().expect("a challenge"), origin);
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(self.flags);
        data.extend(self.counter.to_be_bytes());
        let signed = self.sign(&[&data[..], &Sha256::digest(&client_data)].concat());
        json!({
            "id": encode(&self.credential_id),
            "rawId": encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": encode(&client_data),
                "authenticatorData": encode(&data),
                "signature": encode(&signed),
                "userHandle": self.user_handle.as_deref().map(encode),
            },
            "extensions": {},
        })
    }
}
