// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decrypting an `EncryptedAssertion` (W3C XML Encryption 1.1, SAML 2.0 core 2.3.4) with kernoid's SAML keys, in the
//! strict profile:
//!
//! - one `xenc:EncryptedData` of type Element (or no type), its cipher value inline (no CipherReference);
//! - the content key in an `xenc:EncryptedKey` – inside the data's `ds:KeyInfo` or beside the data in the
//!   EncryptedAssertion –, transported with RSA-OAEP: `xmlenc#rsa-oaep-mgf1p` (SHA-1 digest and MGF1 with SHA-1, as
//!   that algorithm defines) or `xmlenc11#rsa-oaep` with the same SHA-2 for digest and MGF1 (or SHA-1 for both); no
//!   OAEP parameters; RSA PKCS #1 v1.5 key transport is not accepted;
//! - the data AES-128-GCM or AES-256-GCM – or AES-128-CBC or AES-256-CBC, only when the caller says the ciphertext is
//!   authenticated (a verified signature of the provider covers it). Unauthenticated CBC would be a decryption oracle
//!   (Jager and Somorovsky, 2011).
//!
//! When the content key cannot be unwrapped, a random key takes its place, so that a wrong key and wrong data fail
//! alike and at the same point; the caller turns every failure into one error.

use aws_lc_rs::{
    aead,
    cipher::{AES_128, AES_256, DecryptingKey, DecryptionContext, UnboundCipherKey},
    rand,
    rsa::{self, OaepPrivateDecryptingKey, PrivateDecryptingKey},
};
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    SamlError, SpKey,
    dom::{Document, NodeId},
    xmldsig::{DSIG, SHA256, SHA384, SHA512},
};

pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
pub const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
const ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";
const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
/// The most EncryptedKeys tried (one per recipient).
const MAX_KEYS: usize = 4;

fn refuse<T>(message: impl Into<String>) -> Result<T, SamlError> {
    Err(SamlError(format!("the encrypted assertion is refused: {}", message.into())))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Data {
    Gcm(usize),
    Cbc(usize),
}

impl Data {
    fn key_len(self) -> usize {
        match self {
            Self::Gcm(len) | Self::Cbc(len) => len,
        }
    }
}

fn algorithm(doc: &Document, method: NodeId) -> Result<&str, SamlError> {
    doc.attribute(method, "Algorithm").ok_or_else(|| SamlError("an EncryptionMethod names no algorithm".into()))
}

fn only<'a>(doc: &Document, parent: NodeId, namespace: &'a str, local: &'a str) -> Result<NodeId, SamlError> {
    let mut found = doc.children_named(parent, namespace, local);
    match (found.next(), found.next()) {
        (Some(one), None) => Ok(one),
        _ => refuse(format!("expected exactly one {local}")),
    }
}

/// The inline cipher value of a `CipherData`.
fn cipher_value(doc: &Document, parent: NodeId) -> Result<Vec<u8>, SamlError> {
    let data = only(doc, parent, XENC, "CipherData")?;
    let parts: Vec<NodeId> = doc.child_elements(data).collect();
    let [value] = parts.as_slice() else { return refuse("CipherData must hold one CipherValue") };
    if !doc.is(*value, XENC, "CipherValue") || doc.child_elements(*value).next().is_some() {
        return refuse("CipherData must hold one CipherValue");
    }
    let compact: String = doc.text(*value).chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r')).collect();
    STANDARD.decode(compact).or_else(|_| refuse("a CipherValue is not base64"))
}

/// The OAEP variant of an EncryptedKey's method.
fn oaep(doc: &Document, method: NodeId) -> Result<&'static rsa::OaepAlgorithm, SamlError> {
    let uri = algorithm(doc, method)?;
    let digest = || -> Result<&str, SamlError> {
        let mut digests = doc.children_named(method, DSIG, "DigestMethod");
        match (digests.next(), digests.next()) {
            (None, _) => Ok(SHA1),
            (Some(one), None) => algorithm(doc, one),
            _ => refuse("more than one DigestMethod"),
        }
    };
    for child in doc.child_elements(method) {
        let known = doc.is(child, DSIG, "DigestMethod") || (uri == RSA_OAEP && doc.is(child, XENC11, "MGF"));
        if !known {
            return refuse("the key transport has parameters kernoid does not accept");
        }
    }
    match uri {
        RSA_OAEP_MGF1P => match digest()? {
            SHA1 => Ok(&rsa::OAEP_SHA1_MGF1SHA1),
            _ => refuse("rsa-oaep-mgf1p with a digest other than SHA-1 is not accepted"),
        },
        RSA_OAEP => {
            let mgf = match doc.children_named(method, XENC11, "MGF").next() {
                None => "http://www.w3.org/2009/xmlenc11#mgf1sha1",
                Some(mgf) => algorithm(doc, mgf)?,
            };
            match (digest()?, mgf) {
                (SHA1, "http://www.w3.org/2009/xmlenc11#mgf1sha1") => Ok(&rsa::OAEP_SHA1_MGF1SHA1),
                (SHA256, "http://www.w3.org/2009/xmlenc11#mgf1sha256") => Ok(&rsa::OAEP_SHA256_MGF1SHA256),
                (SHA384, "http://www.w3.org/2009/xmlenc11#mgf1sha384") => Ok(&rsa::OAEP_SHA384_MGF1SHA384),
                (SHA512, "http://www.w3.org/2009/xmlenc11#mgf1sha512") => Ok(&rsa::OAEP_SHA512_MGF1SHA512),
                _ => refuse("RSA-OAEP with this digest and mask generation is not accepted"),
            }
        }
        other => refuse(format!("the key transport {other} is not accepted")),
    }
}

/// Whether the EncryptedAssertion's data is encrypted with AES-CBC – accepted only inside a signed Response. This
/// reads only what the sender chose, so it may be told apart from other failures.
pub fn is_cbc(doc: &Document, wrapper: NodeId) -> bool {
    doc.children_named(wrapper, XENC, "EncryptedData")
        .flat_map(|data| doc.children_named(data, XENC, "EncryptionMethod").collect::<Vec<_>>())
        .any(|method| matches!(doc.attribute(method, "Algorithm"), Some(AES128_CBC | AES256_CBC)))
}

/// Decrypts the Assertion in `wrapper` (an `EncryptedAssertion`) with one of `keys` and returns its octets – an XML
/// fragment still to be parsed and verified. `authenticated` says whether a verified signature covers the ciphertext;
/// without one, only AES-GCM is accepted.
pub fn decrypt(doc: &Document, wrapper: NodeId, keys: &[SpKey], authenticated: bool) -> Result<Vec<u8>, SamlError> {
    if !doc.has_only_space_text(wrapper) {
        return refuse("EncryptedAssertion holds text");
    }
    let mut encrypted_data = None;
    let mut encrypted_keys = Vec::new();
    for child in doc.child_elements(wrapper) {
        if doc.is(child, XENC, "EncryptedData") && encrypted_data.is_none() {
            encrypted_data = Some(child);
        } else if doc.is(child, XENC, "EncryptedKey") {
            encrypted_keys.push(child);
        } else {
            return refuse("EncryptedAssertion holds more than one EncryptedData and its EncryptedKeys");
        }
    }
    let Some(data) = encrypted_data else { return refuse("there is no EncryptedData") };
    if doc.attribute(data, "Type").is_some_and(|kind| kind != ELEMENT) {
        return refuse("the EncryptedData is not an element");
    }
    for child in doc.child_elements(data) {
        if !(doc.is(child, XENC, "EncryptionMethod")
            || doc.is(child, DSIG, "KeyInfo")
            || doc.is(child, XENC, "CipherData"))
        {
            return refuse("the EncryptedData holds what kernoid does not accept");
        }
    }
    let method = only(doc, data, XENC, "EncryptionMethod")?;
    let content = match algorithm(doc, method)? {
        AES128_GCM => Data::Gcm(16),
        AES256_GCM => Data::Gcm(32),
        AES128_CBC => Data::Cbc(16),
        AES256_CBC => Data::Cbc(32),
        other => return refuse(format!("the data encryption {other} is not accepted")),
    };
    if matches!(content, Data::Cbc(_)) && !authenticated {
        return refuse(
            "AES-CBC is accepted only when the provider signs the Response around it – sign the Response or use AES-GCM",
        );
    }
    if let Some(key_info) = doc.children_named(data, DSIG, "KeyInfo").next() {
        encrypted_keys.extend(doc.children_named(key_info, XENC, "EncryptedKey"));
    }
    if encrypted_keys.is_empty() {
        return refuse("there is no EncryptedKey");
    }
    if encrypted_keys.len() > MAX_KEYS {
        return refuse("there are too many EncryptedKeys");
    }
    let ciphertext = cipher_value(doc, data)?;

    // Unwrap the content key: every EncryptedKey with every key of kernoid's.
    let mut transports = Vec::new();
    for encrypted_key in &encrypted_keys {
        let method = only(doc, *encrypted_key, XENC, "EncryptionMethod")?;
        transports.push((oaep(doc, method)?, cipher_value(doc, *encrypted_key)?));
    }
    let mut content_key: Option<Vec<u8>> = None;
    for key in keys {
        let Ok(private) = PrivateDecryptingKey::from_pkcs8(&key.private) else { continue };
        let Ok(private) = OaepPrivateDecryptingKey::new(private) else { continue };
        for &(oaep, ref wrapped) in &transports {
            let mut out = zeroize::Zeroizing::new(vec![0u8; private.min_output_size()]);
            if let Ok(unwrapped) = private.decrypt(oaep, wrapped, &mut out, None)
                && unwrapped.len() == content.key_len()
                && content_key.is_none()
            {
                content_key = Some(unwrapped.to_vec());
            }
        }
    }
    let content_key = zeroize::Zeroizing::new(match content_key {
        Some(key) => key,
        None => {
            let mut random = vec![0u8; content.key_len()];
            rand::fill(&mut random).or_else(|_| refuse("no randomness"))?;
            random
        }
    });

    match content {
        Data::Gcm(len) => {
            let algorithm = if len == 16 { &aead::AES_128_GCM } else { &aead::AES_256_GCM };
            if ciphertext.len() < 12 + 16 {
                return refuse("the cipher value is too short");
            }
            let (iv, sealed) = ciphertext.split_at(12);
            let key = aead::LessSafeKey::new(
                aead::UnboundKey::new(algorithm, &content_key).or_else(|_| refuse("the content key is not usable"))?,
            );
            let nonce = aead::Nonce::try_assume_unique_for_key(iv).or_else(|_| refuse("the IV is not usable"))?;
            let mut buffer = sealed.to_vec();
            let plain = key
                .open_in_place(nonce, aead::Aad::empty(), &mut buffer)
                .or_else(|_| refuse("the assertion cannot be decrypted"))?;
            Ok(plain.to_vec())
        }
        Data::Cbc(len) => {
            let algorithm = if len == 16 { &AES_128 } else { &AES_256 };
            if ciphertext.len() < 32 || ciphertext.len() % 16 != 0 {
                return refuse("the cipher value has a wrong length");
            }
            let (iv, encrypted) = ciphertext.split_at(16);
            let iv: [u8; 16] = iv.try_into().or_else(|_| refuse("the IV is not usable"))?;
            let key = DecryptingKey::cbc(
                UnboundCipherKey::new(algorithm, &content_key).or_else(|_| refuse("the content key is not usable"))?,
            )
            .or_else(|_| refuse("the content key is not usable"))?;
            let mut buffer = encrypted.to_vec();
            let plain = key
                .decrypt(&mut buffer, DecryptionContext::Iv128(iv.into()))
                .or_else(|_| refuse("the assertion cannot be decrypted"))?;
            // XML Encryption's padding: the last octet says how many octets were added (their values are arbitrary).
            let pad = usize::from(*plain.last().unwrap_or(&0));
            if pad == 0 || pad > 16 || pad > plain.len() {
                return refuse("the assertion cannot be decrypted");
            }
            let end = plain.len() - pad;
            Ok(plain[..end].to_vec())
        }
    }
}

/// Encrypts `plaintext` for `certificate` as a provider would – for tests: AES-256-GCM (or AES-256-CBC with `cbc`),
/// the key wrapped with `xmlenc#rsa-oaep-mgf1p`.
#[cfg(test)]
pub(crate) fn encrypt_for_tests(plaintext: &[u8], certificate: &[u8], cbc: bool) -> String {
    use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext};
    let mut key = [0u8; 32];
    rand::fill(&mut key).unwrap();
    let cipher = if cbc {
        let mut iv = [0u8; 16];
        rand::fill(&mut iv).unwrap();
        let pad = 16 - plaintext.len() % 16;
        let mut data = plaintext.to_vec();
        data.extend(std::iter::repeat_n(0xAB, pad - 1));
        data.push(u8::try_from(pad).unwrap());
        let encrypting = EncryptingKey::cbc(UnboundCipherKey::new(&AES_256, &key).unwrap()).unwrap();
        encrypting.less_safe_encrypt(&mut data, EncryptionContext::Iv128(iv.into())).unwrap();
        [iv.as_slice(), &data].concat()
    } else {
        let mut iv = [0u8; 12];
        rand::fill(&mut iv).unwrap();
        let sealing = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        let mut data = plaintext.to_vec();
        sealing
            .seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(iv), aead::Aad::empty(), &mut data)
            .unwrap();
        [iv.as_slice(), &data].concat()
    };
    let public = super::keys::PublicKey::from_certificate(certificate).unwrap();
    let public = rsa::OaepPublicEncryptingKey::new(rsa::PublicEncryptingKey::from_der(public.spki()).unwrap()).unwrap();
    let mut wrapped = vec![0; public.ciphertext_size()];
    let wrapped = public.encrypt(&rsa::OAEP_SHA1_MGF1SHA1, &key, &mut wrapped, None).unwrap().to_vec();
    format!(
        concat!(
            r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">"#,
            r#"<xenc:EncryptionMethod Algorithm="{method}"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></xenc:EncryptionMethod>"#,
            r#"<xenc:CipherData><xenc:CipherValue>{key}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"#,
            r#"</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{data}</xenc:CipherValue></xenc:CipherData>"#,
            r#"</xenc:EncryptedData>"#
        ),
        method = if cbc { AES256_CBC } else { AES256_GCM },
        key = STANDARD.encode(wrapped),
        data = STANDARD.encode(cipher),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped(data: &str) -> String {
        format!(
            "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{data}</saml:EncryptedAssertion>"
        )
    }

    fn open(xml: &str, keys: &[SpKey], authenticated: bool) -> Result<Vec<u8>, SamlError> {
        let doc = Document::parse(xml).unwrap();
        decrypt(&doc, doc.root(), keys, authenticated)
    }

    #[test]
    fn gcm_and_cbc() {
        let key = SpKey::generate("https://sp.example").unwrap();
        let keys = [key.clone()];
        let gcm = wrapped(&encrypt_for_tests(b"<saml:Assertion/>", &key.certificate, false));
        assert_eq!(open(&gcm, &keys, false).unwrap(), b"<saml:Assertion/>");
        let cbc = wrapped(&encrypt_for_tests(b"<saml:Assertion/>", &key.certificate, true));
        assert_eq!(open(&cbc, &keys, true).unwrap(), b"<saml:Assertion/>");
        // CBC without a signature around it: refused before anything is decrypted.
        assert!(open(&cbc, &keys, false).unwrap_err().to_string().contains("AES-CBC"));
        // Another key of kernoid's, tried first, does not matter.
        let other = SpKey::generate("https://sp.example").unwrap();
        assert_eq!(open(&gcm, &[other.clone(), key], false).unwrap(), b"<saml:Assertion/>");
        // Only other keys: the content key is replaced by a random one and decryption fails.
        assert!(open(&gcm, &[other], false).unwrap_err().to_string().contains("cannot be decrypted"));
    }

    #[test]
    fn algorithms_outside_the_profile_are_refused() {
        let key = SpKey::generate("https://sp.example").unwrap();
        let keys = [key.clone()];
        let gcm = wrapped(&encrypt_for_tests(b"<a/>", &key.certificate, false));
        for (from, to, why) in [
            (AES256_GCM, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "not accepted"),
            (RSA_OAEP_MGF1P, "http://www.w3.org/2001/04/xmlenc#rsa-1_5", "not accepted"),
            ("http://www.w3.org/2000/09/xmldsig#sha1\"", "http://www.w3.org/2001/04/xmlenc#sha256\"", "SHA-1"),
            (
                "<xenc:CipherData><xenc:CipherValue>",
                "<xenc:CipherData><xenc:CipherReference URI=\"x\"/><xenc:CipherValue>",
                "one CipherValue",
            ),
            (
                "Type=\"http://www.w3.org/2001/04/xmlenc#Element\"",
                "Type=\"http://www.w3.org/2001/04/xmlenc#Content\"",
                "not an element",
            ),
            (
                "</xenc:EncryptionMethod>",
                "<xenc:OAEPparams>AA==</xenc:OAEPparams></xenc:EncryptionMethod>",
                "parameters",
            ),
        ] {
            let changed = gcm.replacen(from, to, 1);
            assert_ne!(changed, gcm, "{from}");
            let error = open(&changed, &keys, true).unwrap_err().to_string();
            assert!(error.contains(why), "{why}: {error}");
        }
    }

    #[test]
    fn a_key_beside_the_data_is_found() {
        let key = SpKey::generate("https://sp.example").unwrap();
        let data = encrypt_for_tests(b"<a/>", &key.certificate, false);
        let start = data.find("<xenc:EncryptedKey>").unwrap();
        let end = data.find("</xenc:EncryptedKey>").unwrap() + "</xenc:EncryptedKey>".len();
        let encrypted_key = data[start..end].replace("<xenc:EncryptedKey>", "<xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">");
        let without = format!("{}{}", &data[..start], &data[end..]);
        let xml = wrapped(&format!("{without}{encrypted_key}"));
        assert_eq!(open(&xml, &[key], false).unwrap(), b"<a/>");
    }
}
