// SPDX-License-Identifier: AGPL-3.0-or-later
//! Keys of SAML signatures: a provider's certificate (X.509 through `x509-cert`, only its public key is used – kernoid
//! trusts the certificates an administrator configured, not who issued them), the algorithms of the strict profile,
//! and signing with a PKCS #8 key. All cryptography is aws-lc-rs.
//!
//! RSA keys must have at least 2048 bits (PKCS #1 v1.5 signatures); ECDSA keys are P-256, P-384 or P-521. XML
//! signatures carry ECDSA values as `r || s` (XML Signature 1.1, 6.4.3), which is what [`SigningKey`] writes and
//! [`PublicKey::verify`] reads – for the HTTP-Redirect binding too, whose signatures use the same algorithm URIs.

use aws_lc_rs::{rand::SystemRandom, signature};
use x509_cert::{
    Certificate,
    der::{Decode, Encode, asn1::ObjectIdentifier},
};

use super::SamlError;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// A signature algorithm of the profile, by its XML Signature URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaSha256,
    RsaSha384,
    RsaSha512,
    EcdsaSha256,
    EcdsaSha384,
    /// Only in the HTTP-Redirect binding, as before.
    EcdsaSha512,
}

impl SignatureAlgorithm {
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    pub const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// The algorithm of a URI kernoid accepts in the HTTP-Redirect binding: RSA or ECDSA with SHA-256 or more.
    pub fn for_redirect(uri: &str) -> Option<Self> {
        Some(match uri {
            Self::RSA_SHA256 => Self::RsaSha256,
            Self::RSA_SHA384 => Self::RsaSha384,
            Self::RSA_SHA512 => Self::RsaSha512,
            Self::ECDSA_SHA256 => Self::EcdsaSha256,
            Self::ECDSA_SHA384 => Self::EcdsaSha384,
            Self::ECDSA_SHA512 => Self::EcdsaSha512,
            _ => return None,
        })
    }

    /// The algorithm of a URI kernoid accepts in an XML signature: RSA with SHA-256, -384 or -512, ECDSA with SHA-256
    /// or -384. SHA-1, DSA and HMAC are refused.
    pub fn for_xml(uri: &str) -> Option<Self> {
        Self::for_redirect(uri).filter(|algorithm| *algorithm != Self::EcdsaSha512)
    }

    pub fn uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => Self::RSA_SHA256,
            Self::RsaSha384 => Self::RSA_SHA384,
            Self::RsaSha512 => Self::RSA_SHA512,
            Self::EcdsaSha256 => Self::ECDSA_SHA256,
            Self::EcdsaSha384 => Self::ECDSA_SHA384,
            Self::EcdsaSha512 => Self::ECDSA_SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    /// The length of `r` and of `s`.
    fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rsa,
    Ec(Curve),
}

/// The public key of a certificate.
#[derive(Debug, Clone)]
pub struct PublicKey {
    kind: Kind,
    /// SubjectPublicKeyInfo, DER.
    spki: Vec<u8>,
}

impl PublicKey {
    /// The public key of an X.509 certificate (DER): RSA or ECDSA on P-256, P-384 or P-521.
    pub fn from_certificate(der: &[u8]) -> Result<Self, SamlError> {
        let certificate =
            Certificate::from_der(der).map_err(|e| SamlError(format!("not an X.509 certificate: {e}")))?;
        let info = certificate.tbs_certificate.subject_public_key_info;
        let kind = if info.algorithm.oid == RSA_ENCRYPTION {
            Kind::Rsa
        } else if info.algorithm.oid == EC_PUBLIC_KEY {
            let curve = info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                .ok_or_else(|| SamlError("the certificate's EC key names no curve".into()))?;
            Kind::Ec(match curve {
                c if c == P256 => Curve::P256,
                c if c == P384 => Curve::P384,
                c if c == P521 => Curve::P521,
                _ => return Err(SamlError("the certificate's EC key is on a curve kernoid does not accept".into())),
            })
        } else {
            return Err(SamlError("the certificate's key is neither RSA nor ECDSA".into()));
        };
        let spki = info.to_der().map_err(|e| SamlError(format!("the certificate's key cannot be read: {e}")))?;
        let key = Self { kind, spki };
        // Refuse at once what aws-lc-rs would refuse later (short RSA keys, points not on the curve).
        let parsed = match kind {
            Kind::Rsa => aws_lc_rs::rsa::PublicEncryptingKey::from_der(&key.spki)
                .ok()
                .filter(|public| public.key_size_bits() >= 2048)
                .map(|_| ()),
            Kind::Ec(_) => {
                signature::ParsedPublicKey::new(key.ec_algorithm(SignatureAlgorithm::EcdsaSha256)?, &key.spki)
                    .ok()
                    .map(|_| ())
            }
        };
        parsed.ok_or_else(|| SamlError("the certificate's key is not usable (RSA needs 2048 bits or more)".into()))?;
        Ok(key)
    }

    /// The SubjectPublicKeyInfo (DER).
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    fn ec_algorithm(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<&'static signature::EcdsaVerificationAlgorithm, SamlError> {
        use SignatureAlgorithm::{EcdsaSha256, EcdsaSha384, EcdsaSha512};
        Ok(match (self.kind, algorithm) {
            (Kind::Ec(Curve::P256), EcdsaSha256) => &signature::ECDSA_P256_SHA256_ASN1,
            (Kind::Ec(Curve::P256), EcdsaSha384) => &signature::ECDSA_P256_SHA384_ASN1,
            (Kind::Ec(Curve::P256), EcdsaSha512) => &signature::ECDSA_P256_SHA512_ASN1,
            (Kind::Ec(Curve::P384), EcdsaSha256) => &signature::ECDSA_P384_SHA256_ASN1,
            (Kind::Ec(Curve::P384), EcdsaSha384) => &signature::ECDSA_P384_SHA384_ASN1,
            (Kind::Ec(Curve::P384), EcdsaSha512) => &signature::ECDSA_P384_SHA512_ASN1,
            (Kind::Ec(Curve::P521), EcdsaSha256) => &signature::ECDSA_P521_SHA256_ASN1,
            (Kind::Ec(Curve::P521), EcdsaSha384) => &signature::ECDSA_P521_SHA384_ASN1,
            (Kind::Ec(Curve::P521), EcdsaSha512) => &signature::ECDSA_P521_SHA512_ASN1,
            _ => return Err(SamlError("the signature algorithm does not fit the key".into())),
        })
    }

    /// Whether `signature` over `message` verifies with this key and `algorithm`; an algorithm of the other key type
    /// does not.
    pub fn verify(&self, algorithm: SignatureAlgorithm, message: &[u8], value: &[u8]) -> bool {
        use SignatureAlgorithm::{RsaSha256, RsaSha384, RsaSha512};
        match (self.kind, algorithm) {
            (Kind::Rsa, RsaSha256 | RsaSha384 | RsaSha512) => {
                let parameters = match algorithm {
                    RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    RsaSha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    _ => &signature::RSA_PKCS1_2048_8192_SHA512,
                };
                signature::UnparsedPublicKey::new(parameters, &self.spki).verify(message, value).is_ok()
            }
            (Kind::Ec(curve), _) => {
                let Ok(verification) = self.ec_algorithm(algorithm) else { return false };
                let Some(der) = ecdsa_der(value, curve.scalar_len()) else { return false };
                signature::UnparsedPublicKey::new(verification, &self.spki).verify(message, &der).is_ok()
            }
            _ => false,
        }
    }
}

/// `r || s` (each `len` bytes) as the DER `ECDSA-Sig-Value` aws-lc-rs verifies; `None` if the value has another length.
fn ecdsa_der(value: &[u8], len: usize) -> Option<Vec<u8>> {
    if value.len() != 2 * len {
        return None;
    }
    let integer = |bytes: &[u8]| {
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
        let bytes = &bytes[start..];
        let mut out = vec![0x02];
        let pad = bytes[0] & 0x80 != 0;
        push_len(&mut out, bytes.len() + usize::from(pad));
        if pad {
            out.push(0);
        }
        out.extend_from_slice(bytes);
        out
    };
    let body = [integer(&value[..len]), integer(&value[len..])].concat();
    let mut out = vec![0x30];
    push_len(&mut out, body.len());
    out.extend_from_slice(&body);
    Some(out)
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        _ => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
}

enum Signer {
    Rsa(signature::RsaKeyPair),
    Ec(signature::EcdsaKeyPair, SignatureAlgorithm),
}

/// A private key that signs: RSA (RSA-SHA256) or ECDSA on P-256 (ECDSA-SHA256) or P-384 (ECDSA-SHA384), from PKCS #8.
pub struct SigningKey {
    signer: Signer,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").field("algorithm", &self.algorithm()).finish_non_exhaustive()
    }
}

impl SigningKey {
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, SamlError> {
        if let Ok(pair) = signature::RsaKeyPair::from_pkcs8(der) {
            return Ok(Self { signer: Signer::Rsa(pair) });
        }
        for (signing, algorithm) in [
            (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, SignatureAlgorithm::EcdsaSha256),
            (&signature::ECDSA_P384_SHA384_FIXED_SIGNING, SignatureAlgorithm::EcdsaSha384),
        ] {
            if let Ok(pair) = signature::EcdsaKeyPair::from_pkcs8(signing, der) {
                return Ok(Self { signer: Signer::Ec(pair, algorithm) });
            }
        }
        Err(SamlError("not a usable PKCS #8 key (RSA, or ECDSA on P-256 or P-384)".into()))
    }

    /// The algorithm the key signs with.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match &self.signer {
            Signer::Rsa(_) => SignatureAlgorithm::RsaSha256,
            Signer::Ec(_, algorithm) => *algorithm,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SamlError> {
        let failed = |_| SamlError("cannot sign".into());
        let random = SystemRandom::new();
        match &self.signer {
            Signer::Rsa(pair) => {
                let mut out = vec![0; pair.public_modulus_len()];
                pair.sign(&signature::RSA_PKCS1_SHA256, &random, message, &mut out).map_err(failed)?;
                Ok(out)
            }
            Signer::Ec(pair, _) => Ok(pair.sign(&random, message).map_err(failed)?.as_ref().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kernoid_identity::certificate::{Algorithm, KeyPair, Params};

    fn certificate(algorithm: Algorithm) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate(algorithm).unwrap();
        let certificate = Params::new(["idp.example"]).self_signed(&key).unwrap();
        (certificate.der().to_vec(), key.pkcs8_der().to_vec())
    }

    #[test]
    fn rsa_and_ecdsa_round_trips() {
        for algorithm in [Algorithm::EcdsaP256, Algorithm::EcdsaP384] {
            let (certificate, private) = certificate(algorithm);
            let public = PublicKey::from_certificate(&certificate).unwrap();
            let signer = SigningKey::from_pkcs8(&private).unwrap();
            let value = signer.sign(b"message").unwrap();
            assert!(public.verify(signer.algorithm(), b"message", &value));
            assert!(!public.verify(signer.algorithm(), b"massage", &value));
            assert!(!public.verify(SignatureAlgorithm::RsaSha256, b"message", &value));
        }
        let (certificate, private) = certificate(Algorithm::Rsa2048);
        let public = PublicKey::from_certificate(&certificate).unwrap();
        let signer = SigningKey::from_pkcs8(&private).unwrap();
        let value = signer.sign(b"message").unwrap();
        assert_eq!(signer.algorithm(), SignatureAlgorithm::RsaSha256);
        assert!(public.verify(SignatureAlgorithm::RsaSha256, b"message", &value));
        assert!(!public.verify(SignatureAlgorithm::RsaSha384, b"message", &value));
        assert!(!public.verify(SignatureAlgorithm::EcdsaSha256, b"message", &value));
    }

    #[test]
    fn what_is_not_a_certificate_is_refused() {
        assert!(PublicKey::from_certificate(b"no").is_err());
        let (_, private) = certificate(Algorithm::Ed25519);
        assert!(SigningKey::from_pkcs8(&private).is_err());
        let (certificate, _) = certificate(Algorithm::Ed25519);
        assert!(PublicKey::from_certificate(&certificate).unwrap_err().to_string().contains("neither RSA nor ECDSA"));
    }

    #[test]
    fn only_strong_algorithms_are_accepted() {
        for refused in [
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
        ] {
            assert_eq!(SignatureAlgorithm::for_xml(refused), None);
            assert_eq!(SignatureAlgorithm::for_redirect(refused), None);
        }
        assert_eq!(SignatureAlgorithm::for_xml(SignatureAlgorithm::ECDSA_SHA512), None);
        assert_eq!(
            SignatureAlgorithm::for_redirect(SignatureAlgorithm::ECDSA_SHA512),
            Some(SignatureAlgorithm::EcdsaSha512)
        );
    }

    #[test]
    fn ecdsa_values_become_der() {
        let mut value = vec![0u8; 64];
        value[31] = 1;
        value[32] = 0x80;
        let der = ecdsa_der(&value, 32).unwrap();
        assert_eq!(&der[..5], &[0x30, 0x26, 0x02, 0x01, 0x01]);
        assert_eq!(&der[5..8], &[0x02, 0x21, 0x00]);
        assert!(ecdsa_der(&value[1..], 32).is_none());
    }
}
