// SPDX-License-Identifier: MIT
//! Post-quantum hybrid keys (RFC 0010, 6): what the streams of a space are sealed to and signed with. Each half alone
//! must be broken to break the whole – the classical one (X25519, Ed25519) as today, the post-quantum one (ML-KEM-768,
//! ML-DSA-65) against a quantum computer.
//!
//! | Purpose | Algorithm |
//! |---|---|
//! | receiving a key | X-Wing (draft-connolly-cfrg-xwing-kem-11): ML-KEM-768 (FIPS 203) and X25519, combined with SHA3-256 |
//! | sealing to a receiving key | X-Wing, then HKDF-SHA256 and XChaCha20-Poly1305 with a random nonce (a KEM–DEM) |
//! | signing | ML-DSA-65 (FIPS 204, deterministic) and Ed25519 (RFC 8032) over the same labelled message; both must hold |
//! | deriving the halves from one seed | HKDF-SHA256 (RFC 5869), a label per half |
//!
//! X-Wing is built here from ml-kem and x25519-dalek because the X-Wing of the HPKE library needs an ml-kem that rpgp
//! (kernoid-e2e) does not accept yet; it is checked against the draft's test vector. OPEN: the HPKE library's X-Wing
//! once rpgp takes ml-kem 0.3 – the bytes stay the same.

use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::Signer as _;
use kernoid_base::{Sha256Hash, random};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65};
use ml_kem::{EncapsulateDeterministic as _, EncodedSizeUser as _, KemCore as _, MlKem768, kem::Decapsulate as _};
use sha2::{Digest as _, Sha256};
use sha3::{
    Sha3_256, Shake256,
    digest::{ExtendableOutput as _, Update as _, XofReader as _},
};

use crate::{Domain, EncryptionError, derive};

/// `\./` `/^\` – the label X-Wing's combiner ends with.
const XWING_LABEL: &[u8; 6] = b"\\.//^\\";
const MLKEM_PUBLIC: usize = 1184;
const MLKEM_CIPHERTEXT: usize = 1088;

/// The length of an X-Wing encapsulation key: ML-KEM-768's and X25519's.
pub const RECEIVING_KEY_LEN: usize = MLKEM_PUBLIC + 32;
/// The length of an X-Wing ciphertext.
pub const CIPHERTEXT_LEN: usize = MLKEM_CIPHERTEXT + 32;
/// The length of a hybrid verifying key: Ed25519's and ML-DSA-65's.
pub const VERIFYING_KEY_LEN: usize = 32 + 1952;
/// The length of a hybrid signature: Ed25519's and ML-DSA-65's.
pub const SIGNATURE_LEN: usize = 64 + 3309;

/// X-Wing, as draft-connolly-cfrg-xwing-kem-11 specifies it.
pub mod xwing {
    use super::*;

    struct Expanded {
        mlkem: <MlKem768 as ml_kem::KemCore>::DecapsulationKey,
        mlkem_public: <MlKem768 as ml_kem::KemCore>::EncapsulationKey,
        x25519: [u8; 32],
        x25519_public: [u8; 32],
    }

    /// `expandDecapsulationKey`: SHAKE256 of the seed to 96 bytes – ML-KEM-768's `d` and `z`, then X25519's scalar.
    fn expand(seed: &[u8; 32]) -> Expanded {
        let mut expanded = [0u8; 96];
        let mut shake = Shake256::default();
        shake.update(seed);
        shake.finalize_xof().read(&mut expanded);
        let d = ml_kem::B32::try_from(&expanded[0..32]).expect("32 bytes");
        let z = ml_kem::B32::try_from(&expanded[32..64]).expect("32 bytes");
        let (mlkem, mlkem_public) = MlKem768::generate_deterministic(&d, &z);
        let x25519: [u8; 32] = expanded[64..96].try_into().expect("32 bytes");
        let x25519_public = x25519_dalek::x25519(x25519, x25519_dalek::X25519_BASEPOINT_BYTES);
        Expanded { mlkem, mlkem_public, x25519, x25519_public }
    }

    fn combine(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> [u8; 32] {
        let mut hash = Sha3_256::default();
        for part in [ss_m, ss_x, ct_x, pk_x, XWING_LABEL] {
            sha3::Digest::update(&mut hash, part);
        }
        sha3::Digest::finalize(hash).into()
    }

    /// `GenerateKeyPairDerand`: the encapsulation key of a 32-byte decapsulation key.
    pub fn public_key(seed: &[u8; 32]) -> Vec<u8> {
        let expanded = expand(seed);
        let mut public = expanded.mlkem_public.as_bytes().to_vec();
        public.extend_from_slice(&expanded.x25519_public);
        public
    }

    /// `EncapsulateDerand`: the shared secret and the ciphertext, from 64 bytes of randomness.
    pub fn encapsulate_derand(public: &[u8], eseed: &[u8; 64]) -> Result<([u8; 32], Vec<u8>), EncryptionError> {
        if public.len() != RECEIVING_KEY_LEN {
            return Err(EncryptionError::Format("receiving key"));
        }
        let encoded =
            ml_kem::Encoded::<<MlKem768 as ml_kem::KemCore>::EncapsulationKey>::try_from(&public[..MLKEM_PUBLIC])
                .map_err(|_| EncryptionError::Format("receiving key"))?;
        let pk_m = <MlKem768 as ml_kem::KemCore>::EncapsulationKey::from_bytes(&encoded);
        // FIPS 203, 7.2: the key must encode back to the same bytes.
        if pk_m.as_bytes().as_slice() != &public[..MLKEM_PUBLIC] {
            return Err(EncryptionError::Format("receiving key"));
        }
        let pk_x: [u8; 32] = public[MLKEM_PUBLIC..].try_into().expect("32 bytes");
        let ek_x: [u8; 32] = eseed[32..64].try_into().expect("32 bytes");
        let ct_x = x25519_dalek::x25519(ek_x, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ss_x = x25519_dalek::x25519(ek_x, pk_x);
        let m = ml_kem::B32::try_from(&eseed[0..32]).expect("32 bytes");
        let (ct_m, ss_m) = pk_m.encapsulate_deterministic(&m).map_err(|_| EncryptionError::Format("receiving key"))?;
        let mut ciphertext = ct_m.to_vec();
        ciphertext.extend_from_slice(&ct_x);
        Ok((combine(&ss_m, &ss_x, &ct_x, &pk_x), ciphertext))
    }

    /// `Encapsulate`.
    pub fn encapsulate(public: &[u8]) -> Result<([u8; 32], Vec<u8>), EncryptionError> {
        let mut eseed = [0u8; 64];
        eseed[..32].copy_from_slice(&random::<32>());
        eseed[32..].copy_from_slice(&random::<32>());
        encapsulate_derand(public, &eseed)
    }

    /// `Decapsulate`.
    pub fn decapsulate(ciphertext: &[u8], seed: &[u8; 32]) -> Result<[u8; 32], EncryptionError> {
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(EncryptionError::Format("ciphertext"));
        }
        let expanded = expand(seed);
        let ct_m = ml_kem::Ciphertext::<MlKem768>::try_from(&ciphertext[..MLKEM_CIPHERTEXT])
            .map_err(|_| EncryptionError::Format("ciphertext"))?;
        let ct_x: [u8; 32] = ciphertext[MLKEM_CIPHERTEXT..].try_into().expect("32 bytes");
        let ss_m = expanded.mlkem.decapsulate(&ct_m).map_err(|_| EncryptionError::Decrypt)?;
        let ss_x = x25519_dalek::x25519(expanded.x25519, ct_x);
        Ok(combine(&ss_m, &ss_x, &ct_x, &expanded.x25519_public))
    }
}

/// A hybrid public receiving key: X-Wing's encapsulation key, 1216 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridReceivingKey(pub Vec<u8>);

impl fmt::Debug for HybridReceivingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tail = self.0.get(self.0.len().saturating_sub(8)..).unwrap_or_default();
        write!(f, "HybridReceivingKey({})", hex::encode(tail))
    }
}

/// A hybrid public verifying key: Ed25519's 32 bytes, then ML-DSA-65's 1952.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridVerifyingKey(pub Vec<u8>);

impl fmt::Debug for HybridVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridVerifyingKey({})", hex::encode(self.0.get(..8).unwrap_or(&self.0)))
    }
}

impl HybridVerifyingKey {
    /// The key's identity: SHA-256 of its bytes.
    pub fn id(&self) -> Sha256Hash {
        Sha256Hash(Sha256::digest(&self.0).into())
    }

    /// Whether `signature` is this key's over `message` in `domain`: both halves must hold.
    pub fn verify(&self, domain: Domain, message: &[u8], signature: &[u8]) -> bool {
        if self.0.len() != VERIFYING_KEY_LEN || signature.len() != SIGNATURE_LEN {
            return false;
        }
        let represented = represent(domain, message);
        let Ok(ed) = ed25519_dalek::VerifyingKey::from_bytes(self.0[..32].try_into().expect("32 bytes")) else {
            return false;
        };
        let Ok(ed_signature) = ed25519_dalek::Signature::from_slice(&signature[..64]) else { return false };
        if ed.verify_strict(&represented, &ed_signature).is_err() {
            return false;
        }
        let Ok(encoded) = EncodedVerifyingKey::<MlDsa65>::try_from(&self.0[32..]) else { return false };
        let mldsa = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);
        let Ok(encoded) = EncodedSignature::<MlDsa65>::try_from(&signature[64..]) else { return false };
        let Some(mldsa_signature) = ml_dsa::Signature::<MlDsa65>::decode(&encoded) else { return false };
        mldsa.verify_with_context(&represented, domain.label.as_bytes(), &mldsa_signature)
    }
}

/// The message both halves sign: a label of this construction and of the domain, then the message – so that neither
/// half's signature is valid anywhere else.
fn represent(domain: Domain, message: &[u8]) -> Vec<u8> {
    let mut represented = format!("{} hybrid signature v1\0", domain.label).into_bytes();
    represented.extend_from_slice(message);
    represented
}

/// The hybrid keys of one seed: signing (Ed25519 + ML-DSA-65) and receiving (X-Wing).
pub struct HybridKeys {
    domain: Domain,
    seed: [u8; 32],
    ed25519: ed25519_dalek::SigningKey,
    mldsa: Box<ExpandedSigningKey<MlDsa65>>,
    receiving_seed: [u8; 32],
    verifying: HybridVerifyingKey,
    receiving: HybridReceivingKey,
}

impl fmt::Debug for HybridKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridKeys({:?})", self.verifying)
    }
}

impl HybridKeys {
    /// New keys from a new random seed.
    pub fn generate(domain: Domain) -> Self {
        Self::from_seed(domain, random())
    }

    /// The keys of a seed – the same on every device that knows it.
    pub fn from_seed(domain: Domain, seed: [u8; 32]) -> Self {
        let label = domain.label;
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&derive(&seed, &format!("{label} hybrid ed25519")));
        let xi = ml_dsa::Seed::from(derive(&seed, &format!("{label} hybrid ml-dsa-65")));
        let mldsa = Box::new(ExpandedSigningKey::<MlDsa65>::from_seed(&xi));
        let receiving_seed = derive(&seed, &format!("{label} hybrid x-wing"));
        let mut verifying = ed25519.verifying_key().to_bytes().to_vec();
        verifying.extend_from_slice(&mldsa.verifying_key().encode());
        let receiving = HybridReceivingKey(xwing::public_key(&receiving_seed));
        HybridKeys { domain, seed, ed25519, mldsa, receiving_seed, verifying: HybridVerifyingKey(verifying), receiving }
    }

    pub fn domain(&self) -> Domain {
        self.domain
    }

    /// The seed, to keep on the device (or to derive from a recovery code).
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn verifying(&self) -> &HybridVerifyingKey {
        &self.verifying
    }

    pub fn receiving(&self) -> &HybridReceivingKey {
        &self.receiving
    }

    /// Ed25519 and ML-DSA-65 over `message`, labelled with the domain.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let represented = represent(self.domain, message);
        let mut signature = self.ed25519.sign(&represented).to_bytes().to_vec();
        let mldsa = self
            .mldsa
            .sign_deterministic(&represented, self.domain.label.as_bytes())
            .expect("a domain label is shorter than ML-DSA's 255 bytes of context");
        signature.extend_from_slice(&mldsa.encode());
        signature
    }

    /// Opens what [`seal`] sealed to this key with `context`.
    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if sealed.len() < CIPHERTEXT_LEN + 24 {
            return Err(EncryptionError::Format("sealed data"));
        }
        let (encapsulated, rest) = sealed.split_at(CIPHERTEXT_LEN);
        let (nonce, ciphertext) = rest.split_at(24);
        let shared = xwing::decapsulate(encapsulated, &self.receiving_seed)?;
        let key = sealing_key(self.domain, &shared, encapsulated, &self.receiving, context);
        XChaCha20Poly1305::new(&key.into())
            .decrypt(&XNonce::try_from(nonce).expect("24 bytes"), Payload { msg: ciphertext, aad: context })
            .map_err(|_| EncryptionError::Decrypt)
    }
}

fn sealing_key(
    domain: Domain,
    shared: &[u8; 32],
    encapsulated: &[u8],
    receiving: &HybridReceivingKey,
    context: &[u8],
) -> [u8; 32] {
    // The key is bound to the ciphertext and the receiving key besides X-Wing's own binding, and to the context.
    let mut info = format!("{} hybrid seal v1\0", domain.label).into_bytes();
    info.extend_from_slice(&Sha256::digest(encapsulated));
    info.extend_from_slice(&Sha256::digest(&receiving.0));
    info.extend_from_slice(&Sha256::digest(context));
    let mut key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(None, shared).expand(&info, &mut key).expect("32 bytes are a valid HKDF length");
    key
}

/// Seals `plaintext` to a receiving key: X-Wing's ciphertext, a nonce, and the encrypted text. `context` says what it
/// is (a stream and a generation, say) and must be given again to open it.
pub fn seal(
    domain: Domain,
    to: &HybridReceivingKey,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let (shared, encapsulated) = xwing::encapsulate(&to.0)?;
    let key = sealing_key(domain, &shared, &encapsulated, to, context);
    let nonce: [u8; 24] = random();
    let ciphertext = XChaCha20Poly1305::new(&key.into())
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: context })
        .expect("XChaCha20-Poly1305 encrypts any length");
    let mut sealed = encapsulated;
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}
