// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enveloped XML signatures (W3C XML Signature 1.1) in the strict profile kernoid accepts from SAML providers, written
//! from the Recommendation and the SAML 2.0 core (5.4) – nothing else is accepted:
//!
//! - exactly one `ds:Signature` as a **child** of the element it signs (a Response, an Assertion, a LogoutRequest);
//! - its `ds:SignedInfo` holds `CanonicalizationMethod`, `SignatureMethod` and exactly **one** `ds:Reference`, whose
//!   `URI` is `#` and the `ID` of exactly that parent element – IDs are unique in the document, or it is refused when
//!   parsed;
//! - the transforms are exactly enveloped-signature and Exclusive XML Canonicalization (with an optional
//!   InclusiveNamespaces PrefixList); canonicalization of SignedInfo is Exclusive XML Canonicalization too;
//! - digests SHA-256, -384 or -512; signatures RSA PKCS #1 v1.5 with SHA-256, -384 or -512 and ECDSA with SHA-256 or
//!   -384 – no SHA-1, DSA or HMAC;
//! - no `ds:Object`, and the key is only ever one of the provider's configured certificates – a `ds:KeyInfo` in the
//!   message is ignored.
//!
//! [`verify`] answers for one element. Against signature wrapping, the caller reads exactly the element it passed in
//! (or its descendants) – never something found again by name or ID.

use aws_lc_rs::{constant_time, digest};
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    SamlError,
    c14n::{canonicalize, prefix_list},
    dom::{Document, NodeId},
    keys::{PublicKey, SignatureAlgorithm, SigningKey},
};

pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// Whether an element carries a signature that verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The element has no `ds:Signature` child.
    Unsigned,
    /// Its signature verified with one of the keys.
    Valid,
}

fn refuse<T>(message: impl Into<String>) -> Result<T, SamlError> {
    Err(SamlError(format!("the signature is refused: {}", message.into())))
}

/// The digest of an algorithm URI of the profile.
fn digest_algorithm(uri: &str) -> Option<&'static digest::Algorithm> {
    match uri {
        SHA256 => Some(&digest::SHA256),
        SHA384 => Some(&digest::SHA384),
        SHA512 => Some(&digest::SHA512),
        _ => None,
    }
}

/// Base64 as signatures carry it: white space (line breaks of Java implementations) is ignored.
fn base64(doc: &Document, id: NodeId, what: &str) -> Result<Vec<u8>, SamlError> {
    if doc.child_elements(id).next().is_some() {
        return refuse(format!("{what} holds elements"));
    }
    let compact: String = doc.text(id).chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r')).collect();
    STANDARD.decode(compact).map_err(|_| SamlError(format!("the signature is refused: {what} is not base64")))
}

/// The element children of `id`, refusing text other than white space.
fn elements(doc: &Document, id: NodeId, what: &str) -> Result<Vec<NodeId>, SamlError> {
    if !doc.has_only_space_text(id) {
        return refuse(format!("{what} holds text"));
    }
    Ok(doc.child_elements(id).collect())
}

/// The algorithm of a `*Method` element, which must hold nothing but – for canonicalization – an InclusiveNamespaces.
fn method(doc: &Document, id: NodeId, what: &str) -> Result<String, SamlError> {
    doc.attribute(id, "Algorithm").map(str::to_owned).ok_or_else(|| SamlError(format!("{what} names no algorithm")))
}

/// An Exclusive XML Canonicalization method: its algorithm must be exc-c14n, and it may hold one InclusiveNamespaces.
fn exclusive(doc: &Document, id: NodeId, what: &str) -> Result<Vec<String>, SamlError> {
    if method(doc, id, what)? != EXC_C14N {
        return refuse(format!("{what} is not Exclusive XML Canonicalization without comments"));
    }
    match elements(doc, id, what)?.as_slice() {
        [] => Ok(Vec::new()),
        [inclusive] if doc.is(*inclusive, EXC_C14N, "InclusiveNamespaces") => {
            if doc.child_elements(*inclusive).next().is_some() {
                return refuse("InclusiveNamespaces holds elements");
            }
            Ok(doc.attribute(*inclusive, "PrefixList").map(prefix_list).unwrap_or_default())
        }
        _ => refuse(format!("{what} holds more than InclusiveNamespaces")),
    }
}

/// Checks the signature of `element` – a child `ds:Signature` – with `keys`. An element without one is
/// [`Outcome::Unsigned`]; a signature outside the profile, or one that does not verify, is an error.
pub fn verify(doc: &Document, element: NodeId, keys: &[PublicKey]) -> Result<Outcome, SamlError> {
    let signatures: Vec<NodeId> = doc.children_named(element, DSIG, "Signature").collect();
    let signature = match signatures.as_slice() {
        [] => return Ok(Outcome::Unsigned),
        [signature] => *signature,
        _ => return refuse("the element carries more than one signature"),
    };
    let Some(id) = doc.attribute(element, "ID").filter(|id| !id.is_empty()) else {
        return refuse("the signed element has no ID");
    };
    // The parser refuses duplicate IDs; this holds all the same.
    if doc.by_id(id) != Some(element) {
        return refuse("the ID does not name the signed element");
    }

    let parts = elements(doc, signature, "Signature")?;
    let (signed_info, value) = match parts.as_slice() {
        [signed_info, value] | [signed_info, value, _] => (*signed_info, *value),
        _ => return refuse("Signature must hold SignedInfo, SignatureValue and at most KeyInfo"),
    };
    if !doc.is(signed_info, DSIG, "SignedInfo") || !doc.is(value, DSIG, "SignatureValue") {
        return refuse("Signature must hold SignedInfo, SignatureValue and at most KeyInfo");
    }
    if let [_, _, key_info] = parts.as_slice()
        && !doc.is(*key_info, DSIG, "KeyInfo")
    {
        return refuse("Signature holds more than SignedInfo, SignatureValue and KeyInfo");
    }

    let info = elements(doc, signed_info, "SignedInfo")?;
    let [canonicalization, signature_method, reference] = info.as_slice() else {
        return refuse("SignedInfo must hold one canonicalization, one signature method and one reference");
    };
    if !doc.is(*canonicalization, DSIG, "CanonicalizationMethod")
        || !doc.is(*signature_method, DSIG, "SignatureMethod")
        || !doc.is(*reference, DSIG, "Reference")
    {
        return refuse("SignedInfo must hold one canonicalization, one signature method and one reference");
    }
    let info_prefixes = exclusive(doc, *canonicalization, "CanonicalizationMethod")?;
    let algorithm_uri = method(doc, *signature_method, "SignatureMethod")?;
    let Some(algorithm) = SignatureAlgorithm::for_xml(&algorithm_uri) else {
        return refuse(format!("the signature algorithm {algorithm_uri} is not accepted"));
    };
    if doc.child_elements(*signature_method).next().is_some() {
        return refuse("SignatureMethod holds elements");
    }

    if doc.attribute(*reference, "URI") != Some(&format!("#{id}")) {
        return refuse("the reference does not name the signed element");
    }
    let reference_parts = elements(doc, *reference, "Reference")?;
    let [transforms, digest_method, digest_value] = reference_parts.as_slice() else {
        return refuse("Reference must hold Transforms, DigestMethod and DigestValue");
    };
    if !doc.is(*transforms, DSIG, "Transforms")
        || !doc.is(*digest_method, DSIG, "DigestMethod")
        || !doc.is(*digest_value, DSIG, "DigestValue")
    {
        return refuse("Reference must hold Transforms, DigestMethod and DigestValue");
    }
    let steps = elements(doc, *transforms, "Transforms")?;
    let [enveloped, exc] = steps.as_slice() else {
        return refuse("the transforms must be enveloped-signature and Exclusive XML Canonicalization");
    };
    if !doc.is(*enveloped, DSIG, "Transform")
        || method(doc, *enveloped, "Transform")? != ENVELOPED
        || doc.child_elements(*enveloped).next().is_some()
        || !doc.is(*exc, DSIG, "Transform")
    {
        return refuse("the transforms must be enveloped-signature and Exclusive XML Canonicalization");
    }
    let reference_prefixes = exclusive(doc, *exc, "the second Transform")?;
    let digest_uri = method(doc, *digest_method, "DigestMethod")?;
    let Some(digest_algorithm) = digest_algorithm(&digest_uri) else {
        return refuse(format!("the digest algorithm {digest_uri} is not accepted"));
    };
    if doc.child_elements(*digest_method).next().is_some() {
        return refuse("DigestMethod holds elements");
    }
    let expected = base64(doc, *digest_value, "DigestValue")?;
    let signature_value = base64(doc, value, "SignatureValue")?;

    let digest = digest::digest(digest_algorithm, &canonicalize(doc, element, Some(signature), &reference_prefixes));
    if constant_time::verify_slices_are_equal(digest.as_ref(), &expected).is_err() {
        return refuse("the digest does not match – the element was changed");
    }
    let octets = canonicalize(doc, signed_info, None, &info_prefixes);
    if keys.iter().any(|key| key.verify(algorithm, &octets, &signature_value)) {
        Ok(Outcome::Valid)
    } else {
        refuse("it does not verify with the provider's certificates")
    }
}

/// How [`sign`] writes a signature – the defaults are the profile's: prefix `ds`, SHA-256, no PrefixList.
#[derive(Debug, Clone)]
pub struct Style {
    /// The prefix of the signature's elements; empty for the default namespace (as Entra ID writes them).
    pub prefix: String,
    /// The PrefixList of the reference's canonicalization (Okta, for instance, lists `xs`).
    pub inclusive_prefixes: Vec<String>,
    pub digest: &'static str,
    /// Written as the SignatureMethod in place of the key's own algorithm – for tests of what is refused.
    pub signature_method: Option<String>,
    /// Written as the transforms in place of the profile's – for tests of what is refused.
    pub transforms: Option<String>,
    /// Written in place of the canonicalization method – for tests of what is refused.
    pub canonicalization: Option<String>,
    /// A `KeyInfo` to add (the message's keys are ignored on verification).
    pub key_info: Option<String>,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            prefix: "ds".into(),
            inclusive_prefixes: Vec::new(),
            digest: SHA256,
            signature_method: None,
            transforms: None,
            canonicalization: None,
            key_info: None,
        }
    }
}

/// Signs the element whose `ID` is `id` with an enveloped signature in the profile and returns the document with
/// the signature in place: right after the element's first child if that is a SAML `Issuer` (where the schemas put
/// it), else as its first child. kernoid itself sends no XML-signed messages yet; providers in tests do.
pub fn sign(xml: &str, id: &str, key: &SigningKey, style: &Style) -> Result<String, SamlError> {
    let doc = Document::parse(xml)?;
    let element = doc.by_id(id).ok_or_else(|| SamlError(format!("no element has the ID {id}")))?;
    if doc.children_named(element, DSIG, "Signature").next().is_some() {
        return Err(SamlError("the element is signed already".into()));
    }
    let digest_algorithm = digest_algorithm(style.digest).ok_or_else(|| SamlError("unknown digest".into()))?;
    let digest = digest::digest(digest_algorithm, &canonicalize(&doc, element, None, &style.inclusive_prefixes));

    let p = if style.prefix.is_empty() { String::new() } else { format!("{}:", style.prefix) };
    let declaration = if style.prefix.is_empty() {
        format!(" xmlns=\"{DSIG}\"")
    } else {
        format!(" xmlns:{}=\"{DSIG}\"", style.prefix)
    };
    let inclusive = |prefixes: &[String]| match prefixes {
        [] => String::new(),
        _ => format!(
            "<ec:InclusiveNamespaces xmlns:ec=\"{EXC_C14N}\" PrefixList=\"{}\"/>",
            super::escape(&prefixes.join(" "))
        ),
    };
    let transforms = style.transforms.clone().unwrap_or_else(|| {
        format!(
            "<{p}Transform Algorithm=\"{ENVELOPED}\"/><{p}Transform Algorithm=\"{EXC_C14N}\">{}</{p}Transform>",
            inclusive(&style.inclusive_prefixes)
        )
    });
    let signed_info = format!(
        concat!(
            "<{p}SignedInfo><{p}CanonicalizationMethod Algorithm=\"{c14n}\"/>",
            "<{p}SignatureMethod Algorithm=\"{method}\"/><{p}Reference URI=\"#{id}\"><{p}Transforms>{transforms}",
            "</{p}Transforms><{p}DigestMethod Algorithm=\"{digest}\"/><{p}DigestValue>{value}</{p}DigestValue>",
            "</{p}Reference></{p}SignedInfo>"
        ),
        p = p,
        c14n = style.canonicalization.as_deref().unwrap_or(EXC_C14N),
        method = style.signature_method.as_deref().unwrap_or(key.algorithm().uri()),
        id = super::escape(id),
        transforms = transforms,
        digest = style.digest,
        value = STANDARD.encode(digest.as_ref()),
    );
    // SignedInfo is canonicalized exclusively: only the namespaces it uses count, so it canonicalizes the same alone
    // as in its place in the document.
    let alone = Document::parse(&format!("<{p}Signature{declaration}>{signed_info}</{p}Signature>"))?;
    let info = alone.child_elements(alone.root()).next().ok_or_else(|| SamlError("no SignedInfo".into()))?;
    let value = key.sign(&canonicalize(&alone, info, None, &[]))?;
    let signature = format!(
        "<{p}Signature{declaration}>{signed_info}<{p}SignatureValue>{}</{p}SignatureValue>{}</{p}Signature>",
        STANDARD.encode(value),
        style.key_info.as_deref().unwrap_or_default(),
    );

    let target = doc.element(element).ok_or_else(|| SamlError("no element".into()))?;
    let at = match doc.child_elements(element).next() {
        Some(first) if doc.is(first, super::ASSERTION, "Issuer") => doc.element(first).map(|issuer| issuer.span.1),
        _ => None,
    }
    .unwrap_or(target.content_start);
    if target.content_start == target.span.1 {
        // `<x/>`: an empty element has nowhere to put a signature.
        return Err(SamlError("the element to sign is empty".into()));
    }
    Ok(format!("{}{signature}{}", &xml[..at], &xml[at..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_INFO: &str =
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";

    struct Party {
        key: SigningKey,
        public: PublicKey,
        certificate: Vec<u8>,
    }

    fn party(algorithm: &'static rcgen::SignatureAlgorithm) -> Party {
        let key = if *algorithm == rcgen::PKCS_RSA_SHA256 {
            rcgen::KeyPair::generate_rsa_for(algorithm, rcgen::RsaKeySize::_2048).unwrap()
        } else {
            rcgen::KeyPair::generate_for(algorithm).unwrap()
        };
        let certificate = rcgen::CertificateParams::new(vec!["idp.example".into()]).unwrap().self_signed(&key).unwrap();
        Party {
            key: SigningKey::from_pkcs8(&key.serialize_der()).unwrap(),
            public: PublicKey::from_certificate(certificate.der()).unwrap(),
            certificate: certificate.der().to_vec(),
        }
    }

    const DOC: &str = concat!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_r\">",
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">idp</saml:Issuer>",
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\">",
        "<saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID>u-1</saml:NameID></saml:Subject></saml:Assertion>",
        "</samlp:Response>"
    );

    fn check(xml: &str, id: &str, keys: &[PublicKey]) -> Result<Outcome, SamlError> {
        let doc = Document::parse(xml)?;
        verify(&doc, doc.by_id(id).unwrap(), keys)
    }

    #[test]
    fn signatures_round_trip_with_rsa_and_ecdsa() {
        for algorithm in [&rcgen::PKCS_RSA_SHA256, &rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ECDSA_P384_SHA384] {
            let signer = party(algorithm);
            for digest in [SHA256, SHA384, SHA512] {
                let style = Style { digest, ..Style::default() };
                let signed = sign(DOC, "_a", &signer.key, &style).unwrap();
                assert_eq!(check(&signed, "_a", std::slice::from_ref(&signer.public)).unwrap(), Outcome::Valid);
                assert_eq!(check(&signed, "_r", std::slice::from_ref(&signer.public)).unwrap(), Outcome::Unsigned);
                // And the Response around it as well.
                let both = sign(&signed, "_r", &signer.key, &style).unwrap();
                assert_eq!(check(&both, "_r", std::slice::from_ref(&signer.public)).unwrap(), Outcome::Valid);
                assert_eq!(check(&both, "_a", std::slice::from_ref(&signer.public)).unwrap(), Outcome::Valid);
            }
        }
    }

    #[test]
    fn a_default_namespace_signature_with_a_prefix_list_verifies() {
        let signer = party(&rcgen::PKCS_ECDSA_P256_SHA256);
        let style = Style { prefix: String::new(), inclusive_prefixes: vec!["saml".into()], ..Style::default() };
        let signed = sign(DOC, "_a", &signer.key, &style).unwrap();
        assert!(signed.contains("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
        assert_eq!(check(&signed, "_a", &[signer.public]).unwrap(), Outcome::Valid);
    }

    #[test]
    fn changes_after_signing_fail() {
        let signer = party(&rcgen::PKCS_ECDSA_P256_SHA256);
        let signed = sign(DOC, "_a", &signer.key, &Style::default()).unwrap();
        for changed in [
            signed.replace(">u-1<", ">admin<"),
            signed.replace(">u-1<", "> u-1<"),
            signed.replace("<saml:Subject>", "<saml:Subject x=\"1\">"),
        ] {
            let error = check(&changed, "_a", std::slice::from_ref(&signer.public)).unwrap_err();
            assert!(error.to_string().contains("digest"), "{error}");
        }
        // A comment changes nothing a signature covers.
        let commented = signed.replace(">u-1<", ">u-<!-- x -->1<");
        assert_eq!(check(&commented, "_a", std::slice::from_ref(&signer.public)).unwrap(), Outcome::Valid);
        // The signature value itself.
        let start = signed.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
        let mut broken = signed.clone();
        broken.replace_range(start..start + 1, if &signed[start..start + 1] == "A" { "B" } else { "A" });
        assert!(check(&broken, "_a", &[signer.public]).unwrap_err().to_string().contains("does not verify"));
    }

    #[test]
    fn only_configured_keys_count() {
        let signer = party(&rcgen::PKCS_ECDSA_P256_SHA256);
        let other = party(&rcgen::PKCS_ECDSA_P256_SHA256);
        // The signer puts its own certificate in KeyInfo: ignored, only the configured key counts.
        let key_info = KEY_INFO.replace("{}", &STANDARD.encode(&signer.certificate));
        let style = Style { key_info: Some(key_info), ..Style::default() };
        let signed = sign(DOC, "_a", &signer.key, &style).unwrap();
        assert!(
            check(&signed, "_a", std::slice::from_ref(&other.public))
                .unwrap_err()
                .to_string()
                .contains("does not verify")
        );
        assert!(check(&signed, "_a", &[]).is_err());
        assert_eq!(check(&signed, "_a", &[other.public, signer.public]).unwrap(), Outcome::Valid);
    }

    #[test]
    fn algorithms_outside_the_profile_are_refused() {
        let signer = party(&rcgen::PKCS_RSA_SHA256);
        let keys = [signer.public];
        let cases: Vec<(Style, &str)> = vec![
            (
                Style {
                    signature_method: Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1".into()),
                    ..Style::default()
                },
                "algorithm",
            ),
            (
                Style {
                    signature_method: Some("http://www.w3.org/2000/09/xmldsig#hmac-sha1".into()),
                    ..Style::default()
                },
                "algorithm",
            ),
            (
                Style {
                    signature_method: Some("http://www.w3.org/2000/09/xmldsig#dsa-sha1".into()),
                    ..Style::default()
                },
                "algorithm",
            ),
            (Style { digest: "http://www.w3.org/2000/09/xmldsig#sha1", ..Style::default() }, "unknown digest"),
            (
                Style {
                    canonicalization: Some("http://www.w3.org/TR/2001/REC-xml-c14n-20010315".into()),
                    ..Style::default()
                },
                "Exclusive",
            ),
            (
                Style {
                    canonicalization: Some("http://www.w3.org/2001/10/xml-exc-c14n#WithComments".into()),
                    ..Style::default()
                },
                "Exclusive",
            ),
            (
                Style { transforms: Some(format!("<ds:Transform Algorithm=\"{ENVELOPED}\"/>")), ..Style::default() },
                "transforms",
            ),
            (
                Style {
                    transforms: Some(format!(
                        "<ds:Transform Algorithm=\"{EXC_C14N}\"/><ds:Transform Algorithm=\"{ENVELOPED}\"/>"
                    )),
                    ..Style::default()
                },
                "transforms",
            ),
            (
                Style {
                    transforms: Some(format!(
                        "<ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>1</ds:XPath></ds:Transform>"
                    )),
                    ..Style::default()
                },
                "Exclusive",
            ),
            (
                Style {
                    transforms: Some(format!(
                        "<ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/>"
                    )),
                    ..Style::default()
                },
                "transforms",
            ),
        ];
        for (style, why) in cases {
            let error = match sign(DOC, "_a", &signer.key, &style) {
                Ok(signed) => check(&signed, "_a", &keys).unwrap_err(),
                Err(error) => error,
            };
            assert!(error.to_string().contains(why), "{why}: {error}");
        }
        // The SHA-1 digest written by hand: refused as well.
        let signed = sign(DOC, "_a", &signer.key, &Style::default()).unwrap();
        let sha1 = signed.replace(SHA256, "http://www.w3.org/2000/09/xmldsig#sha1");
        assert!(check(&sha1, "_a", &keys).unwrap_err().to_string().contains("digest algorithm"));
    }

    #[test]
    fn structures_outside_the_profile_are_refused() {
        let signer = party(&rcgen::PKCS_ECDSA_P256_SHA256);
        let keys = [signer.public];
        let signed = sign(DOC, "_a", &signer.key, &Style::default()).unwrap();
        let cases = [
            // A reference to another element, or to the whole document.
            (signed.replace("URI=\"#_a\"", "URI=\"#_r\""), "does not name"),
            (signed.replace("URI=\"#_a\"", "URI=\"\""), "does not name"),
            // A second reference.
            (
                signed.replace("</ds:Reference>", "</ds:Reference><ds:Reference URI=\"#_r\"></ds:Reference>"),
                "one reference",
            ),
            // An Object (where wrapped content hides).
            (signed.replace("</ds:SignatureValue>", "</ds:SignatureValue><ds:Object/>"), "KeyInfo"),
            // Two signatures on the element.
            (
                signed.replace(
                    "</saml:Subject>",
                    "</saml:Subject><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>",
                ),
                "more than one",
            ),
            // Text where only elements belong.
            (signed.replace("<ds:SignedInfo>", "<ds:SignedInfo>x"), "holds text"),
        ];
        for (xml, why) in cases {
            let error = check(&xml, "_a", &keys).unwrap_err();
            assert!(error.to_string().contains(why), "{why}: {error}");
        }
        // An element without an ID cannot be signed by reference.
        let no_id = signed.replace(" ID=\"_a\"", "");
        let doc = Document::parse(&no_id).unwrap();
        let assertion = doc.child_elements(doc.root()).nth(1).unwrap();
        assert!(verify(&doc, assertion, &keys).unwrap_err().to_string().contains("no ID"));
    }

    #[test]
    fn a_moved_signature_does_not_count_for_its_new_parent() {
        let signer = party(&rcgen::PKCS_ECDSA_P256_SHA256);
        let keys = [signer.public];
        let signed = sign(DOC, "_a", &signer.key, &Style::default()).unwrap();
        // The Assertion's signature put into the Response: it references #_a, not #_r.
        let start = signed.find("<ds:Signature").unwrap();
        let end = signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let signature = &signed[start..end];
        let moved = format!("{}{}", &signed[..start], &signed[end..]).replacen(
            "</saml:Issuer>",
            &format!("</saml:Issuer>{signature}"),
            1,
        );
        assert!(check(&moved, "_r", &keys).unwrap_err().to_string().contains("does not name"));
        assert_eq!(check(&moved, "_a", &keys).unwrap(), Outcome::Unsigned);
    }
}
