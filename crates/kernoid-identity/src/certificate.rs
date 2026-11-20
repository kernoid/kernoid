// SPDX-License-Identifier: AGPL-3.0-or-later
//! X.509 certificates and certificate requests that kernoid makes itself (RFC 5280, RFC 2986): the self-signed
//! certificate of an instance's SAML key, the requests of certificates from an ACME CA, and certificates for tests and
//! development. The structures are x509-cert's, encoded in DER; keys and signatures are aws-lc-rs's – ECDSA P-256
//! with SHA-256 or RSA (PKCS #1 v1.5) with SHA-256. Keys are kept as PKCS #8.
//!
//! This builds certificates; it does not read or check them – TLS checks them through rustls, SAML through bergshamra.

use std::time::SystemTime;

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::KeySize,
    signature::{self, EcdsaKeyPair, KeyPair as _, RsaKeyPair},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jiff::{SignedDuration, Timestamp};
use x509_cert::{
    attr::{Attribute, AttributeTypeAndValue},
    der::{
        Any, Decode, Encode,
        asn1::{BitString, Ia5String, ObjectIdentifier, OctetString, SetOfVec, Utf8StringRef},
        oid::AssociatedOid,
    },
    ext::{
        Extension,
        pkix::{BasicConstraints, SubjectAltName, name::GeneralName},
    },
    name::{Name, RdnSequence, RelativeDistinguishedName},
    request::{CertReq, CertReqInfo, ExtensionReq},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
};
use zeroize::Zeroizing;

/// `commonName` (RFC 5280, 4.1.2.4).
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `ecdsa-with-SHA256` (RFC 5758, 3.2).
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `sha256WithRSAEncryption` (RFC 4055, 5).
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

#[derive(Debug, thiserror::Error)]
#[error("certificate: {0}")]
pub struct CertificateError(String);

fn failed(what: &str) -> impl Fn(&dyn std::fmt::Display) -> CertificateError + '_ {
    move |error| CertificateError(format!("{what}: {error}"))
}

/// The kinds of key kernoid makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA on P-256 with SHA-256 – for TLS.
    EcdsaP256,
    /// RSA with 2048 bits, PKCS #1 v1.5 signatures with SHA-256 – for SAML, which every provider reads.
    Rsa2048,
}

/// A private key with its public part.
pub struct KeyPair {
    algorithm: Algorithm,
    pkcs8: Zeroizing<Vec<u8>>,
    /// `SubjectPublicKeyInfo`, DER.
    public: Vec<u8>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").field("algorithm", &self.algorithm).finish_non_exhaustive()
    }
}

impl KeyPair {
    pub fn generate(algorithm: Algorithm) -> Result<Self, CertificateError> {
        let pkcs8 = match algorithm {
            Algorithm::EcdsaP256 => {
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                    .map_err(|e| failed("making a key")(&e))?
                    .as_ref()
                    .to_vec()
            }
            Algorithm::Rsa2048 => RsaKeyPair::generate(KeySize::Rsa2048)
                .and_then(|key| key.as_der())
                .map_err(|e| failed("making a key")(&e))?
                .as_ref()
                .to_vec(),
        };
        Self::from_pkcs8(&pkcs8)
    }

    /// A key stored as PKCS #8 (DER), of either algorithm.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CertificateError> {
        let pkcs8 = Zeroizing::new(der.to_vec());
        if let Ok(key) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, der) {
            let public = key.public_key().as_der().map_err(|e| failed("the public key")(&e))?.as_ref().to_vec();
            return Ok(Self { algorithm: Algorithm::EcdsaP256, pkcs8, public });
        }
        let key = RsaKeyPair::from_pkcs8(der).map_err(|e| failed("not a key kernoid uses")(&e))?;
        let public = key.public_key().as_der().map_err(|e| failed("the public key")(&e))?.as_ref().to_vec();
        Ok(Self { algorithm: Algorithm::Rsa2048, pkcs8, public })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The private key as PKCS #8, DER.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The private key as PKCS #8 in PEM (`PRIVATE KEY`).
    pub fn pkcs8_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(pem("PRIVATE KEY", &self.pkcs8))
    }

    /// The public key as `SubjectPublicKeyInfo`, DER.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public
    }

    fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        match self.algorithm {
            Algorithm::EcdsaP256 => AlgorithmIdentifierOwned { oid: ECDSA_WITH_SHA256, parameters: None },
            // RSA's algorithm identifiers carry NULL parameters (RFC 4055, 5).
            Algorithm::Rsa2048 => AlgorithmIdentifierOwned { oid: SHA256_WITH_RSA, parameters: Some(Any::null()) },
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CertificateError> {
        let rng = SystemRandom::new();
        match self.algorithm {
            Algorithm::EcdsaP256 => {
                let key = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &self.pkcs8)
                    .map_err(|e| failed("the key")(&e))?;
                Ok(key.sign(&rng, message).map_err(|e| failed("signing")(&e))?.as_ref().to_vec())
            }
            Algorithm::Rsa2048 => {
                let key = RsaKeyPair::from_pkcs8(&self.pkcs8).map_err(|e| failed("the key")(&e))?;
                let mut out = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut out).map_err(|e| failed("signing")(&e))?;
                Ok(out)
            }
        }
    }

    fn subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned, CertificateError> {
        SubjectPublicKeyInfoOwned::from_der(&self.public).map_err(|e| failed("the public key")(&e))
    }
}

/// What a certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// The subject's common name; without one, the first DNS name, or `kernoid`.
    pub common_name: Option<String>,
    /// The names it is for (`subjectAltName`, RFC 5280, 4.2.1.6).
    pub dns_names: Vec<String>,
    /// Whether it may sign certificates (`basicConstraints`, critical).
    pub ca: bool,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl Params {
    /// A certificate for `dns_names`, valid from an hour ago for a year.
    pub fn new<Names: IntoIterator<Item = impl Into<String>>>(dns_names: Names) -> Self {
        let now = Timestamp::now();
        Self {
            common_name: None,
            dns_names: dns_names.into_iter().map(Into::into).collect(),
            ca: false,
            not_before: now - SignedDuration::from_hours(1),
            not_after: now + SignedDuration::from_hours(24 * 365),
        }
    }

    /// A CA named `common_name`, for tests and development.
    pub fn ca(common_name: &str) -> Self {
        Self { common_name: Some(common_name.to_owned()), ca: true, ..Self::new(Vec::<String>::new()) }
    }

    fn subject(&self) -> Result<Name, CertificateError> {
        let name = self.common_name.as_deref().or(self.dns_names.first().map(String::as_str)).unwrap_or("kernoid");
        common_name(name)
    }

    fn extensions(&self) -> Result<Vec<Extension>, CertificateError> {
        let mut extensions = Vec::new();
        if self.ca {
            let constraints = BasicConstraints { ca: true, path_len_constraint: None };
            extensions.push(extension(BasicConstraints::OID, true, &constraints)?);
        }
        if !self.dns_names.is_empty() {
            extensions.push(extension(SubjectAltName::OID, false, &alt_names(&self.dns_names)?)?);
        }
        Ok(extensions)
    }

    /// The certificate of `key`, signed by itself.
    pub fn self_signed(&self, key: &KeyPair) -> Result<Certificate, CertificateError> {
        let subject = self.subject()?;
        self.signed(key, subject.clone(), key)
    }

    /// The certificate of `key`, signed by `issuer` with its key.
    pub fn signed_by(
        &self,
        key: &KeyPair,
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> Result<Certificate, CertificateError> {
        self.signed(key, issuer.subject.clone(), issuer_key)
    }

    fn signed(&self, key: &KeyPair, issuer: Name, issuer_key: &KeyPair) -> Result<Certificate, CertificateError> {
        let subject = self.subject()?;
        let extensions = self.extensions()?;
        let tbs = x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: serial()?,
            signature: issuer_key.signature_algorithm(),
            issuer,
            validity: Validity { not_before: time(self.not_before)?, not_after: time(self.not_after)? },
            subject: subject.clone(),
            subject_public_key_info: key.subject_public_key_info()?,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: (!extensions.is_empty()).then_some(extensions),
        };
        let signed = tbs.to_der().map_err(|e| failed("encoding")(&e))?;
        let signature = issuer_key.sign(&signed)?;
        let certificate = x509_cert::Certificate {
            tbs_certificate: tbs,
            signature_algorithm: issuer_key.signature_algorithm(),
            signature: BitString::from_bytes(&signature).map_err(|e| failed("encoding")(&e))?,
        };
        let der = certificate.to_der().map_err(|e| failed("encoding")(&e))?;
        Ok(Certificate { der, subject })
    }
}

/// A certificate kernoid made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
    subject: Name,
}

impl Certificate {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// PEM (`CERTIFICATE`).
    pub fn pem(&self) -> String {
        pem("CERTIFICATE", &self.der)
    }
}

/// A certificate request (PKCS #10, RFC 2986) for `dns_names` with `key`, signed with it, in DER – as ACME's
/// `finalize` takes it (RFC 8555, 7.4): the names in a `subjectAltName` of the requested extensions.
pub fn signing_request(dns_names: &[String], key: &KeyPair) -> Result<Vec<u8>, CertificateError> {
    let first = dns_names.first().ok_or_else(|| CertificateError("a request needs a name".into()))?;
    let requested = ExtensionReq(vec![extension(SubjectAltName::OID, false, &alt_names(dns_names)?)?]);
    let value = Any::encode_from(&requested).map_err(|e| failed("encoding")(&e))?;
    let mut values = SetOfVec::new();
    values.insert(value).map_err(|e| failed("encoding")(&e))?;
    let mut attributes = SetOfVec::new();
    attributes.insert(Attribute { oid: ExtensionReq::OID, values }).map_err(|e| failed("encoding")(&e))?;
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: common_name(first)?,
        public_key: key.subject_public_key_info()?,
        attributes,
    };
    let signature = key.sign(&info.to_der().map_err(|e| failed("encoding")(&e))?)?;
    let request = CertReq {
        info,
        algorithm: key.signature_algorithm(),
        signature: BitString::from_bytes(&signature).map_err(|e| failed("encoding")(&e))?,
    };
    request.to_der().map_err(|e| failed("encoding")(&e))
}

/// `-----BEGIN <label>-----`, base64 in lines of 64 characters, `-----END <label>-----` (RFC 7468).
pub fn pem(label: &str, der: &[u8]) -> String {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// A name of one `commonName` in UTF-8, at most 64 characters (its upper bound, RFC 5280, appendix A.1).
fn common_name(name: &str) -> Result<Name, CertificateError> {
    let name: String = name.chars().take(64).collect();
    let value = Any::encode_from(&Utf8StringRef::new(&name).map_err(|e| failed("the name")(&e))?)
        .map_err(|e| failed("the name")(&e))?;
    let mut rdn = SetOfVec::new();
    rdn.insert(AttributeTypeAndValue { oid: COMMON_NAME, value }).map_err(|e| failed("the name")(&e))?;
    Ok(RdnSequence(vec![RelativeDistinguishedName(rdn)]))
}

fn alt_names(dns_names: &[String]) -> Result<SubjectAltName, CertificateError> {
    let names = dns_names
        .iter()
        .map(|name| Ia5String::new(name).map(GeneralName::DnsName).map_err(|e| failed("a DNS name")(&e)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SubjectAltName(names))
}

fn extension(oid: ObjectIdentifier, critical: bool, value: &impl Encode) -> Result<Extension, CertificateError> {
    let der = value.to_der().map_err(|e| failed("an extension")(&e))?;
    Ok(Extension { extn_id: oid, critical, extn_value: OctetString::new(der).map_err(|e| failed("an extension")(&e))? })
}

/// A random positive serial number of 16 bytes (RFC 5280, 4.1.2.2: at most 20).
fn serial() -> Result<SerialNumber, CertificateError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| failed("a serial number")(&e))?;
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    SerialNumber::new(&bytes).map_err(|e| failed("a serial number")(&e))
}

/// UTCTime until 2049, GeneralizedTime after (RFC 5280, 4.1.2.5), to the second.
fn time(at: Timestamp) -> Result<Time, CertificateError> {
    let seconds = std::time::Duration::from_secs(u64::try_from(at.as_second()).unwrap_or(0));
    Time::try_from(SystemTime::UNIX_EPOCH + seconds).map_err(|e| failed("a time")(&e))
}

#[cfg(test)]
mod tests {
    use x509_cert::der::Decode;

    use super::*;

    #[test]
    fn certificates_are_well_formed_and_signed() {
        for algorithm in [Algorithm::EcdsaP256, Algorithm::Rsa2048] {
            let key = KeyPair::generate(algorithm).unwrap();
            let again = KeyPair::from_pkcs8(key.pkcs8_der()).unwrap();
            assert_eq!((again.algorithm(), again.public_key_der()), (algorithm, key.public_key_der()));
            let params =
                Params { common_name: Some("https://login.firma.de/saml".into()), ..Params::new(["a.example"]) };
            let made = params.self_signed(&key).unwrap();
            let parsed = x509_cert::Certificate::from_der(made.der()).unwrap();
            let tbs = &parsed.tbs_certificate;
            assert_eq!(tbs.subject.to_string(), "CN=https://login.firma.de/saml");
            assert_eq!(tbs.issuer, tbs.subject);
            assert_eq!(tbs.validity.not_after.to_unix_duration().as_secs() as i64, params.not_after.as_second());
            assert_eq!(tbs.subject_public_key_info.to_der().unwrap(), key.public_key_der());
            // The signature checks with the public key.
            let (verify, bits): (&dyn signature::VerificationAlgorithm, _) = match algorithm {
                Algorithm::EcdsaP256 => (&signature::ECDSA_P256_SHA256_ASN1, &tbs.subject_public_key_info),
                Algorithm::Rsa2048 => (&signature::RSA_PKCS1_2048_8192_SHA256, &tbs.subject_public_key_info),
            };
            signature::UnparsedPublicKey::new(verify, bits.subject_public_key.raw_bytes())
                .verify(&tbs.to_der().unwrap(), parsed.signature.raw_bytes())
                .unwrap();
            assert!(made.pem().starts_with("-----BEGIN CERTIFICATE-----\n"));
        }
    }

    #[test]
    fn a_certificate_signed_by_a_ca_is_trusted_by_rustls() {
        let ca_key = KeyPair::generate(Algorithm::EcdsaP256).unwrap();
        let ca = Params::ca("kernoid test CA").self_signed(&ca_key).unwrap();
        let key = KeyPair::generate(Algorithm::EcdsaP256).unwrap();
        let leaf = Params::new(["mail.firma.example"]).signed_by(&key, &ca, &ca_key).unwrap();
        let parsed = x509_cert::Certificate::from_der(leaf.der()).unwrap();
        assert_eq!(parsed.tbs_certificate.issuer.to_string(), "CN=kernoid test CA");
        // The chain as a TLS client checks it: rustls's verifier with the CA as the only root.
        use rustls::{client::danger::ServerCertVerifier, pki_types::CertificateDer};
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(roots.into(), provider).build().unwrap();
        let name = rustls::pki_types::ServerName::try_from("mail.firma.example").unwrap();
        let now = rustls::pki_types::UnixTime::now();
        verifier.verify_server_cert(&CertificateDer::from(leaf.der().to_vec()), &[], &name, &[], now).unwrap();
        let other = rustls::pki_types::ServerName::try_from("other.example").unwrap();
        assert!(
            verifier.verify_server_cert(&CertificateDer::from(leaf.der().to_vec()), &[], &other, &[], now).is_err()
        );
    }

    #[test]
    fn a_signing_request_names_the_domains_and_is_signed() {
        let key = KeyPair::generate(Algorithm::EcdsaP256).unwrap();
        let names = vec!["login.firma.de".to_owned(), "www.firma.de".to_owned()];
        let der = signing_request(&names, &key).unwrap();
        let request = CertReq::from_der(&der).unwrap();
        assert_eq!(request.info.subject.to_string(), "CN=login.firma.de");
        let attribute = request.info.attributes.iter().next().unwrap();
        assert_eq!(attribute.oid, ExtensionReq::OID);
        let requested: ExtensionReq = attribute.values.iter().next().unwrap().decode_as().unwrap();
        let alt = SubjectAltName::from_der(requested.0[0].extn_value.as_bytes()).unwrap();
        let shown: Vec<String> = alt.0.iter().map(|name| format!("{name:?}")).collect();
        assert!(shown[0].contains("login.firma.de") && shown[1].contains("www.firma.de"), "{shown:?}");
        signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            request.info.public_key.subject_public_key.raw_bytes(),
        )
        .verify(&request.info.to_der().unwrap(), request.signature.raw_bytes())
        .unwrap();
    }
}
