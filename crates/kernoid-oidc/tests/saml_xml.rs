// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's XML signatures and encryption against attacks on SAML (signature wrapping, comment injection, foreign
//! keys, entities, sizes, unauthenticated encryption) and against Responses shaped as Keycloak, Entra ID, AD FS, Okta
//! and Google write them (structure from their public documentation and metadata), signed here with test keys.

use base64::{Engine, engine::general_purpose::STANDARD};
use jiff::{SignedDuration, Timestamp};
use kernoid_oidc::saml::{
    Expected, SamlLogin, SpKey,
    keys::{PublicKey, SigningKey},
    verify_response,
    xmldsig::{self, Style},
};

const SP: &str = "https://login.firma.de/idp/saml";
const ACS: &str = "https://login.firma.de/idp/saml/acs";
const REQUEST: &str = "_req-1";

struct Signer {
    certificate: Vec<u8>,
    key: SigningKey,
}

fn ecdsa() -> Signer {
    let made = rcgen::generate_simple_self_signed(vec!["idp.example".to_owned()]).unwrap();
    Signer {
        certificate: made.cert.der().to_vec(),
        key: SigningKey::from_pkcs8(&made.signing_key.serialize_der()).unwrap(),
    }
}

fn rsa() -> Signer {
    let key = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["idp.example".into()]).unwrap().self_signed(&key).unwrap();
    Signer { certificate: certificate.der().to_vec(), key: SigningKey::from_pkcs8(&key.serialize_der()).unwrap() }
}

fn sign(signer: &Signer, xml: &str, id: &str) -> String {
    sign_with(signer, xml, id, &Style::default())
}

fn sign_with(signer: &Signer, xml: &str, id: &str, style: &Style) -> String {
    xmldsig::sign(xml, id, &signer.key, style).unwrap()
}

fn check(idp: &str, xml: &str, certificates: &[Vec<u8>], keys: &[SpKey]) -> Result<SamlLogin, String> {
    let expected = Expected {
        idp_entity_id: idp,
        certificates,
        sp_entity_id: SP,
        acs_url: ACS,
        request_id: REQUEST,
        now: Timestamp::now(),
        decryption_keys: keys,
    };
    verify_response(&STANDARD.encode(xml), expected).map_err(|e| e.to_string())
}

fn times() -> (String, String) {
    let now = Timestamp::now();
    (
        now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
        (now + SignedDuration::from_mins(5)).strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

const IDP: &str = "https://idp.example/saml";

/// A plain Response (`_r1`) with an Assertion (`_a1`) for `name_id`.
fn response(name_id: &str) -> String {
    let (now, ends) = times();
    format!(
        concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
            r#"ID="_r1" Version="2.0" IssueInstant="{now}" Destination="{ACS}" InResponseTo="{REQUEST}">"#,
            r#"<saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion ID="_a1" Version="2.0" IssueInstant="{now}"><saml:Issuer>{IDP}</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>"#,
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData "#,
            r#"InResponseTo="{REQUEST}" NotOnOrAfter="{ends}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="{now}" NotOnOrAfter="{ends}"><saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_s1"><saml:AuthnContext>"#,
            r#"<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"#,
            r#"</saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email">"#,
            r#"<saml:AttributeValue>{name_id}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#
        ),
        now = now,
        ends = ends,
        name_id = name_id,
        ACS = ACS,
        REQUEST = REQUEST,
        IDP = IDP,
        SP = SP,
    )
}

fn assertion_of(xml: &str) -> (usize, usize) {
    let start = xml.find("<saml:Assertion").unwrap();
    let end = xml.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    (start, end)
}

fn signature_of(xml: &str, from: usize) -> (usize, usize) {
    let start = from + xml[from..].find("<ds:Signature").unwrap();
    let end = start + xml[start..].find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    (start, end)
}

#[test]
fn what_must_be_signed() {
    let signer = ecdsa();
    let certificates = [signer.certificate.clone()];
    let plain = response("bob@firma.de");
    // The Assertion signed, the Response not: accepted.
    assert!(check(IDP, &sign(&signer, &plain, "_a1"), &certificates, &[]).is_ok());
    // The Response signed, the Assertion not: accepted – the Response's signature covers it.
    assert!(check(IDP, &sign(&signer, &plain, "_r1"), &certificates, &[]).is_ok());
    // Both: accepted.
    let both = sign(&signer, &sign(&signer, &plain, "_a1"), "_r1");
    assert!(check(IDP, &both, &certificates, &[]).is_ok());
    // Neither: refused.
    assert!(check(IDP, &plain, &certificates, &[]).unwrap_err().contains("not signed"));
    // Both, but the Response changed after signing (a valid Assertion signature does not save it).
    let changed = both.replacen("Version=\"2.0\"", "Version=\"2.0\" Consent=\"x\"", 1);
    assert!(check(IDP, &changed, &certificates, &[]).unwrap_err().contains("response is not signed"));
    // The Response signed, then the Assertion inside it changed.
    let response_signed = sign(&signer, &plain, "_r1");
    let tampered = response_signed.replacen(">bob@firma.de<", ">admin@firma.de<", 1);
    assert!(check(IDP, &tampered, &certificates, &[]).unwrap_err().contains("digest"));
}

#[test]
fn signature_wrapping_fails() {
    let signer = ecdsa();
    let certificates = [signer.certificate.clone()];
    let signed = sign(&signer, &response("bob@firma.de"), "_a1");
    let (start, end) = assertion_of(&signed);
    let genuine = &signed[start..end];
    let evil = genuine.replace("ID=\"_a1\"", "ID=\"_evil\"").replace("bob@firma.de", "admin@firma.de");
    let (s_start, s_end) = signature_of(genuine, 0);
    let (e_start, e_end) = signature_of(&evil, 0);
    let unsigned_evil = format!("{}{}", &evil[..e_start], &evil[e_end..]);
    let close = "</ds:Signature>".len();
    let cases = [
        // XSW3: an evil Assertion before the signed one.
        format!("{}{unsigned_evil}{genuine}{}", &signed[..start], &signed[end..]),
        // XSW4: the signed Assertion inside the evil one.
        format!(
            "{}{}{genuine}</saml:Assertion>{}",
            &signed[..start],
            &unsigned_evil[..unsigned_evil.len() - "</saml:Assertion>".len()],
            &signed[end..]
        ),
        // XSW5: the evil Assertion carries the copied signature, the signed one hides in Extensions.
        format!("{}<samlp:Extensions>{genuine}</samlp:Extensions>{evil}{}", &signed[..start], &signed[end..]),
        // XSW6: the signed Assertion inside the copied signature's Object.
        format!(
            "{}{}<ds:Object>{genuine}</ds:Object>{}{}",
            &signed[..start],
            &evil[..e_end - close],
            &evil[e_end - close..],
            &signed[end..]
        ),
        // XSW7: the signed Assertion in Extensions, an unsigned one where kernoid reads.
        format!("{}<samlp:Extensions>{genuine}</samlp:Extensions>{unsigned_evil}{}", &signed[..start], &signed[end..]),
        // XSW8: the signature, moved onto the Response, with the signed Assertion in its Object.
        format!(
            "{}{}{}",
            signed[..start].replacen(
                "</saml:Issuer>",
                &format!(
                    "</saml:Issuer>{}<ds:Object>{genuine}</ds:Object></ds:Signature>",
                    &genuine[s_start..s_end - close]
                ),
                1
            ),
            unsigned_evil,
            &signed[end..]
        ),
        // An ID collision: the evil Assertion takes the signed one's ID, the signed one hides in Extensions.
        format!(
            "{}<samlp:Extensions>{genuine}</samlp:Extensions>{}{}",
            &signed[..start],
            unsigned_evil.replace("_evil", "_a1"),
            &signed[end..]
        ),
    ];
    const EXPECTED: [&str; 7] = [
        "exactly one assertion",
        "not signed by the provider",
        "does not name",
        "more than SignedInfo",
        "not signed by the provider",
        "more than SignedInfo",
        "same ID",
    ];
    for (number, xml) in cases.iter().enumerate() {
        let error = check(IDP, xml, &certificates, &[]).unwrap_err();
        assert!(error.contains(EXPECTED[number]), "case {number}: {error}");
    }

    // XSW1 and XSW2 against a signed Response: an evil Response around (or beside) the signed one.
    let response_signed = sign(&signer, &response("bob@firma.de"), "_r1");
    let (r_start, r_end) = signature_of(&response_signed, 0);
    let signature = &response_signed[r_start..r_end];
    let evil_response =
        response("admin@firma.de").replace("ID=\"_r1\"", "ID=\"_r2\"").replace("ID=\"_a1\"", "ID=\"_a2\"");
    let inner = &response_signed;
    let xsw1 = evil_response.replacen(
        "</saml:Issuer>",
        &format!(
            "</saml:Issuer>{}<ds:Object>{inner}</ds:Object></ds:Signature>",
            &signature[..signature.len() - "</ds:Signature>".len()]
        ),
        1,
    );
    let xsw2 = evil_response.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}{inner}"), 1);
    for (xml, why) in [(xsw1, "more than SignedInfo"), (xsw2, "does not name")] {
        let error = check(IDP, &xml, &certificates, &[]).unwrap_err();
        assert!(error.contains(why), "{error}");
    }
}

#[test]
fn comments_cannot_shorten_what_was_signed() {
    let signer = ecdsa();
    let certificates = [signer.certificate.clone()];
    // The provider signed the address of an account the attacker registered there …
    let signed = sign(&signer, &response("bob@firma.de.evil.example"), "_a1");
    // … who puts a comment into it: the signature still holds (canonicalization drops comments), and kernoid reads
    // the whole text – not the part before the comment.
    let injected = signed.replace("bob@firma.de.evil.example", "bob@firma.de<!---->.evil.example");
    let login = check(IDP, &injected, &certificates, &[]).unwrap();
    assert_eq!(login.subject, "bob@firma.de.evil.example");
    assert_eq!(login.email(None), Some("bob@firma.de.evil.example"));
    // A CDATA section is text as well.
    let cdata = signed.replacen("bob@firma.de.evil.example", "bob@firma.de<![CDATA[.evil.example]]>", 1);
    assert_eq!(check(IDP, &cdata, &certificates, &[]).unwrap().subject, "bob@firma.de.evil.example");
}

#[test]
fn foreign_keys_and_algorithms_fail() {
    let signer = ecdsa();
    let attacker = ecdsa();
    let certificates = [signer.certificate.clone()];
    // The attacker signs with its own key and puts its certificate into KeyInfo: the message's keys do not count.
    let key_info = format!(
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        STANDARD.encode(&attacker.certificate)
    );
    let forged = sign_with(
        &attacker,
        &response("admin@firma.de"),
        "_a1",
        &Style { key_info: Some(key_info), ..Style::default() },
    );
    assert!(check(IDP, &forged, &certificates, &[]).unwrap_err().contains("does not verify"));
    // SHA-1 as the signature method.
    let sha1 = sign_with(
        &signer,
        &response("bob@firma.de"),
        "_a1",
        &Style { signature_method: Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1".into()), ..Style::default() },
    );
    assert!(check(IDP, &sha1, &certificates, &[]).unwrap_err().contains("not accepted"));
    // HMAC with the certificate as the "secret".
    let hmac = sign_with(
        &signer,
        &response("bob@firma.de"),
        "_a1",
        &Style { signature_method: Some("http://www.w3.org/2000/09/xmldsig#hmac-sha1".into()), ..Style::default() },
    );
    assert!(check(IDP, &hmac, &certificates, &[]).unwrap_err().contains("not accepted"));
}

#[test]
fn entities_and_sizes_fail() {
    let signer = ecdsa();
    let certificates = [signer.certificate.clone()];
    let signed = sign(&signer, &response("bob@firma.de"), "_a1");
    let laughs = concat!(
        "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">",
        "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]>"
    );
    let external = "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>";
    for prefix in [laughs, external] {
        let xml = format!("{prefix}{}", signed.replacen(">bob@firma.de<", ">&lol3;&xxe;<", 1));
        assert!(check(IDP, &xml, &certificates, &[]).unwrap_err().contains("DTD"));
    }
    // An entity without a DTD.
    let undeclared = signed.replacen(">bob@firma.de<", ">&xxe;<", 1);
    assert!(check(IDP, &undeclared, &certificates, &[]).unwrap_err().contains("entity"));
    // A processing instruction.
    let pi = signed.replacen("<saml:Subject>", "<?xml-stylesheet href=\"x\"?><saml:Subject>", 1);
    assert!(check(IDP, &pi, &certificates, &[]).unwrap_err().contains("processing instruction"));
    // Too large, and too deep.
    let large = signed.replacen(
        "<saml:Subject>",
        &format!("<samlp:Extensions>{}</samlp:Extensions><saml:Subject>", " ".repeat(300 * 1024)),
        1,
    );
    assert!(check(IDP, &large, &certificates, &[]).unwrap_err().contains("too large"));
    let deep = signed.replacen(
        "<saml:Subject>",
        &format!("<saml:Advice>{}{}</saml:Advice><saml:Subject>", "<x>".repeat(100), "</x>".repeat(100)),
        1,
    );
    assert!(check(IDP, &deep, &certificates, &[]).unwrap_err().contains("deeply"));
}

/// The Assertion of `xml` replaced by an EncryptedAssertion for `certificate` (AES-256-GCM or -CBC, RSA-OAEP).
fn encrypt(xml: &str, certificate: &[u8], cbc: bool) -> String {
    let (start, end) = assertion_of(xml);
    format!("{}{}{}", &xml[..start], encrypted_assertion(&xml[start..end], certificate, cbc), &xml[end..])
}

/// An EncryptedAssertion of `plaintext` for `certificate`.
fn encrypted_assertion(plaintext: &str, certificate: &[u8], cbc: bool) -> String {
    use aws_lc_rs::{aead, cipher, rand, rsa};
    let plaintext = plaintext.as_bytes();
    let mut key = [0u8; 32];
    rand::fill(&mut key).unwrap();
    let data = if cbc {
        let mut iv = [0u8; 16];
        rand::fill(&mut iv).unwrap();
        let mut data = plaintext.to_vec();
        let pad = 16 - data.len() % 16;
        data.extend(std::iter::repeat_n(0u8, pad - 1));
        data.push(u8::try_from(pad).unwrap());
        let encrypting =
            cipher::EncryptingKey::cbc(cipher::UnboundCipherKey::new(&cipher::AES_256, &key).unwrap()).unwrap();
        encrypting.less_safe_encrypt(&mut data, cipher::EncryptionContext::Iv128(iv.into())).unwrap();
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
    let public = PublicKey::from_certificate(certificate).unwrap();
    let public = rsa::OaepPublicEncryptingKey::new(rsa::PublicEncryptingKey::from_der(public.spki()).unwrap()).unwrap();
    let mut wrapped = vec![0; public.ciphertext_size()];
    let wrapped = public.encrypt(&rsa::OAEP_SHA256_MGF1SHA256, &key, &mut wrapped, None).unwrap().to_vec();
    let method =
        if cbc { "http://www.w3.org/2001/04/xmlenc#aes256-cbc" } else { "http://www.w3.org/2009/xmlenc11#aes256-gcm" };
    format!(
        concat!(
            r#"<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">"#,
            r#"<xenc:EncryptionMethod Algorithm="{method}"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>"#,
            r#"</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>{key}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"#,
            r#"</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{data}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#
        ),
        method = method,
        key = STANDARD.encode(wrapped),
        data = STANDARD.encode(data),
    )
}

#[test]
fn encryption_is_not_authentication() {
    let signer = ecdsa();
    let certificates = [signer.certificate.clone()];
    let sp = SpKey::generate(SP).unwrap();
    let keys = [sp.clone()];
    // Anyone can encrypt for kernoid's certificate: an unsigned Assertion, encrypted, is still unsigned – and every
    // failure inside an unsigned Response reads the same.
    let forged = encrypt(&response("admin@firma.de"), &sp.certificate, false);
    let uniform = check(IDP, &forged, &certificates, &keys).unwrap_err();
    assert!(uniform.contains("cannot be decrypted, or it is not signed"), "{uniform}");
    let mut broken = encrypt(&sign(&signer, &response("bob@firma.de"), "_a1"), &sp.certificate, false);
    let at = broken.rfind("<xenc:CipherValue>").unwrap() + "<xenc:CipherValue>".len() + 20;
    broken.replace_range(at..at + 1, if &broken[at..at + 1] == "A" { "B" } else { "A" });
    assert_eq!(check(IDP, &broken, &certificates, &keys).unwrap_err(), uniform);
    // A plaintext that tries to leave the EncryptedAssertion.
    let plain = response("x");
    let (start, end) = assertion_of(&plain);
    let escape = format!("{}</fragment><fragment><saml:Assertion ID=\"_z\"/>", &plain[start..end]);
    let escaping =
        format!("{}{}{}", &plain[..start], encrypted_assertion(&escape, &sp.certificate, false), &plain[end..]);
    assert_eq!(check(IDP, &escaping, &certificates, &keys).unwrap_err(), uniform);

    // A signed Assertion, encrypted with GCM: accepted.
    let signed = sign(&signer, &response("bob@firma.de"), "_a1");
    assert_eq!(
        check(IDP, &encrypt(&signed, &sp.certificate, false), &certificates, &keys).unwrap().subject,
        "bob@firma.de"
    );
    // CBC is accepted only inside a signed Response (a decryption oracle otherwise).
    let cbc = encrypt(&signed, &sp.certificate, true);
    assert!(check(IDP, &cbc, &certificates, &keys).unwrap_err().contains("AES-CBC"));
    let cbc_signed = sign(&signer, &cbc, "_r1");
    assert_eq!(check(IDP, &cbc_signed, &certificates, &keys).unwrap().subject, "bob@firma.de");
    // Inside a signed Response, an unsigned Assertion is fine – the Response's signature covers the ciphertext.
    let unsigned_inside = sign(&signer, &encrypt(&response("bob@firma.de"), &sp.certificate, true), "_r1");
    assert_eq!(check(IDP, &unsigned_inside, &certificates, &keys).unwrap().subject, "bob@firma.de");
    // … and the ciphertext cannot be swapped under it.
    let swapped = unsigned_inside.replacen(
        &unsigned_inside[unsigned_inside.rfind("<xenc:CipherValue>").unwrap()
            ..unsigned_inside.rfind("</xenc:CipherValue>").unwrap()],
        &format!("<xenc:CipherValue>{}", STANDARD.encode([0u8; 64])),
        1,
    );
    assert!(check(IDP, &swapped, &certificates, &keys).unwrap_err().contains("digest"));
}

// --- Responses as providers write them ------------------------------------------------------------------------

/// Keycloak: `dsig` prefix, Response and Assertion both signed (RSA-SHA256), the Assertion in the default namespace,
/// attribute values typed with `xs:string`.
#[test]
fn keycloak() {
    let signer = rsa();
    let idp = "https://sso.firma.de/realms/firma";
    let (now, ends) = times();
    let xml = format!(
        concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
            r#"Destination="{acs}" ID="ID_7d0c8f0e-1c1d-4a52-9d3b-0b6a9d1e7c11" InResponseTo="{request}" IssueInstant="{now}" Version="2.0">"#,
            r#"<saml:Issuer>{idp}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="ID_3b4b1b6e-5a77-4a43-a2b5-0f4e9a4c6d21" IssueInstant="{now}" Version="2.0">"#,
            r#"<saml:Issuer>{idp}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">"#,
            r#"G-5b2d0f6c-8a3e-4b9f-9c1d-2e7a4b6c8d90</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"#,
            r#"<saml:SubjectConfirmationData InResponseTo="{request}" NotOnOrAfter="{ends}" Recipient="{acs}"/></saml:SubjectConfirmation>"#,
            r#"</saml:Subject><saml:Conditions NotBefore="{now}" NotOnOrAfter="{ends}"><saml:AudienceRestriction><saml:Audience>{sp}</saml:Audience>"#,
            r#"</saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="3f1e7a2c::9b4d2e1f" "#,
            r#"SessionNotOnOrAfter="{ends}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"#,
            r#"</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>"#,
            r#"<saml:Attribute FriendlyName="email" Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">"#,
            r#"<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" "#,
            r#"xsi:type="xs:string">bob@firma.de</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#
        ),
        acs = ACS,
        request = REQUEST,
        now = now,
        ends = ends,
        idp = idp,
        sp = SP,
    );
    let style = Style { prefix: "dsig".into(), ..Style::default() };
    let xml = sign_with(&signer, &xml, "ID_3b4b1b6e-5a77-4a43-a2b5-0f4e9a4c6d21", &style);
    let xml = sign_with(&signer, &xml, "ID_7d0c8f0e-1c1d-4a52-9d3b-0b6a9d1e7c11", &style);
    let login = check(idp, &xml, &[signer.certificate], &[]).unwrap();
    assert_eq!(login.subject, "G-5b2d0f6c-8a3e-4b9f-9c1d-2e7a4b6c8d90");
    assert_eq!(login.email(None), Some("bob@firma.de"));
    assert_eq!(login.session_index.as_deref(), Some("3f1e7a2c::9b4d2e1f"));
}

/// Microsoft Entra ID: the Assertion in the default namespace, its signature unprefixed in the default namespace of
/// XML Signature with the certificate in KeyInfo, times with fractions of a second, claims as attribute names.
#[test]
fn entra_id() {
    let signer = rsa();
    let idp = "https://sts.windows.net/0b6a9d1e-7c11-4a52-9d3b-7d0c8f0e1c1d/";
    let now = Timestamp::now();
    let (now_text, ends) = (
        now.strftime("%Y-%m-%dT%H:%M:%S.123Z"),
        (now + SignedDuration::from_mins(60)).strftime("%Y-%m-%dT%H:%M:%S.123Z"),
    );
    let xml = format!(
        concat!(
            r#"<samlp:Response ID="_9c3a1e2f-1111-4d6b-8e0a-5f2b3c4d5e6f" Version="2.0" IssueInstant="{now}" Destination="{acs}" "#,
            r#"InResponseTo="{request}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{idp}</Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<Assertion ID="_4d1e2f3a-2222-4b5c-9d6e-7f8a9b0c1d2e" IssueInstant="{now}" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">"#,
            r#"<Issuer>{idp}</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@firma.de</NameID>"#,
            r#"<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="{request}" "#,
            r#"NotOnOrAfter="{ends}" Recipient="{acs}"/></SubjectConfirmation></Subject><Conditions NotBefore="{now}" NotOnOrAfter="{ends}">"#,
            r#"<AudienceRestriction><Audience>{sp}</Audience></AudienceRestriction></Conditions><AttributeStatement>"#,
            r#"<Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>0b6a9d1e-7c11-4a52-9d3b-7d0c8f0e1c1d</AttributeValue></Attribute>"#,
            r#"<Attribute Name="http://schemas.microsoft.com/identity/claims/displayname"><AttributeValue>Bob Builder</AttributeValue></Attribute>"#,
            r#"<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>bob@firma.de</AttributeValue></Attribute>"#,
            r#"<Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences"><AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</AttributeValue></Attribute>"#,
            r#"</AttributeStatement><AuthnStatement AuthnInstant="{now}" SessionIndex="_4d1e2f3a-2222-4b5c-9d6e-7f8a9b0c1d2e"><AuthnContext>"#,
            r#"<AuthnContextClassRef>http://schemas.microsoft.com/claims/multipleauthn</AuthnContextClassRef></AuthnContext></AuthnStatement>"#,
            r#"</Assertion></samlp:Response>"#
        ),
        now = now_text,
        ends = ends,
        acs = ACS,
        request = REQUEST,
        idp = idp,
        sp = SP,
    );
    let key_info = format!(
        "<KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo>",
        STANDARD.encode(&signer.certificate)
    );
    let style = Style { prefix: String::new(), key_info: Some(key_info), ..Style::default() };
    let xml = sign_with(&signer, &xml, "_4d1e2f3a-2222-4b5c-9d6e-7f8a9b0c1d2e", &style);
    assert!(xml.contains("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
    let login = check(idp, &xml, &[signer.certificate], &[]).unwrap();
    assert_eq!(login.subject, "bob@firma.de");
    assert_eq!(login.name(None), Some("Bob Builder"));
    assert!(login.multi_factor);
}

/// AD FS: the Response's Issuer in the default namespace, a `ds:` signature, a transient Windows NameID; AES-256-CBC encryption – kernoid accepts it
/// when AD FS signs the message as well (`SamlResponseSignature` MessageAndAssertion), not with the Assertion alone.
#[test]
fn ad_fs() {
    let signer = rsa();
    let sp = SpKey::generate(SP).unwrap();
    let idp = "http://adfs.firma.de/adfs/services/trust";
    let (now, ends) = times();
    let xml = format!(
        concat!(
            r#"<samlp:Response ID="_r-adfs" Version="2.0" IssueInstant="{now}" Destination="{acs}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" "#,
            r#"InResponseTo="{request}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{idp}</Issuer>"#,
            r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#,
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a-adfs" IssueInstant="{now}" Version="2.0"><saml:Issuer>{idp}</saml:Issuer>"#,
            r#"<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">FIRMA\bob</saml:NameID>"#,
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{request}" "#,
            r#"NotOnOrAfter="{ends}" Recipient="{acs}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{now}" "#,
            r#"NotOnOrAfter="{ends}"><saml:AudienceRestriction><saml:Audience>{sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"<saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">"#,
            r#"<saml:AttributeValue>bob@firma.de</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"#,
            r#"<saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_a-adfs"><saml:AuthnContext><saml:AuthnContextClassRef>"#,
            r#"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>"#,
            r#"</saml:AuthnStatement></saml:Assertion></samlp:Response>"#
        ),
        now = now,
        ends = ends,
        acs = ACS,
        request = REQUEST,
        idp = idp,
        sp = SP,
    );
    let signed = sign(&signer, &xml, "_a-adfs");
    let login = check(idp, &signed, std::slice::from_ref(&signer.certificate), &[]).unwrap();
    assert_eq!(login.subject, "FIRMA\\bob");
    assert!(!login.multi_factor);
    let keys = [sp.clone()];
    let encrypted = encrypt(&signed, &sp.certificate, true);
    assert!(check(idp, &encrypted, std::slice::from_ref(&signer.certificate), &keys).unwrap_err().contains("AES-CBC"));
    let message_signed = sign(&signer, &encrypted, "_r-adfs");
    assert_eq!(check(idp, &message_signed, &[signer.certificate], &keys).unwrap().email(None), Some("bob@firma.de"));
}

/// Okta: `saml2p`/`saml2` prefixes, an Issuer with a Format, both signed, the reference's canonicalization with the
/// PrefixList `xs` – the prefix of `xsi:type` values, which only a PrefixList keeps in the signed form.
#[test]
fn okta() {
    let signer = rsa();
    let idp = "http://www.okta.com/exk1fcia6d6EMsf331d8";
    let (now, ends) = times();
    let xml = format!(
        concat!(
            r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" "#,
            r#"Destination="{acs}" ID="id2259412361224521371577163" InResponseTo="{request}" IssueInstant="{now}" Version="2.0">"#,
            r#"<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{idp}</saml2:Issuer>"#,
            r#"<saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#,
            r#"</saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id22594123613216181412468953" "#,
            r#"IssueInstant="{now}" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{idp}</saml2:Issuer>"#,
            r#"<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">bob@firma.de</saml2:NameID>"#,
            r#"<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="{request}" "#,
            r#"NotOnOrAfter="{ends}" Recipient="{acs}"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="{now}" "#,
            r#"NotOnOrAfter="{ends}"><saml2:AudienceRestriction><saml2:Audience>{sp}</saml2:Audience></saml2:AudienceRestriction>"#,
            r#"</saml2:Conditions><saml2:AuthnStatement AuthnInstant="{now}" SessionIndex="id1659459394123.1427186399"><saml2:AuthnContext>"#,
            r#"<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>"#,
            r#"</saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement><saml2:Attribute Name="displayName" "#,
            r#"NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue "#,
            r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Bob</saml2:AttributeValue></saml2:Attribute>"#,
            r#"</saml2:AttributeStatement></saml2:Assertion></saml2p:Response>"#
        ),
        acs = ACS,
        request = REQUEST,
        now = now,
        ends = ends,
        idp = idp,
        sp = SP,
    );
    let style = Style { inclusive_prefixes: vec!["xs".into()], ..Style::default() };
    let xml = sign_with(&signer, &xml, "id22594123613216181412468953", &style);
    let xml = sign_with(&signer, &xml, "id2259412361224521371577163", &style);
    assert!(xml.contains("PrefixList=\"xs\""));
    let login = check(idp, &xml, std::slice::from_ref(&signer.certificate), &[]).unwrap();
    assert_eq!(login.name(None), Some("Bob"));
    // The PrefixList is what protects the meaning of `xs:string`: rebinding xs on the Response breaks the signature.
    let rebound = xml.replacen("xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"", "xmlns:xs=\"urn:evil\"", 1);
    assert!(check(idp, &rebound, &[signer.certificate], &[]).unwrap_err().contains("digest"));
}

/// Google Workspace: `saml2p`/`saml2`, only the Assertion signed (ECDSA here), pretty-printed with CRLF line ends.
#[test]
fn google() {
    let signer = ecdsa();
    let idp = "https://accounts.google.com/o/saml2?idpid=C01abcdef";
    let (now, ends) = times();
    let xml = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\r\n",
            "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"{acs}\" ID=\"_6f1e0c2b9a8d7e6f5a4b3c2d1e0f9a8b\" ",
            "InResponseTo=\"{request}\" IssueInstant=\"{now}\" Version=\"2.0\">\r\n",
            "  <saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">{idp}</saml2:Issuer>\r\n",
            "  <saml2p:Status>\r\n    <saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\r\n  </saml2p:Status>\r\n",
            "  <saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_0a1b2c3d4e5f60718293a4b5c6d7e8f9\" IssueInstant=\"{now}\" Version=\"2.0\">\r\n",
            "    <saml2:Issuer>{idp}</saml2:Issuer>\r\n",
            "    <saml2:Subject>\r\n      <saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">bob@firma.de</saml2:NameID>\r\n",
            "      <saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\r\n",
            "        <saml2:SubjectConfirmationData InResponseTo=\"{request}\" NotOnOrAfter=\"{ends}\" Recipient=\"{acs}\"/>\r\n",
            "      </saml2:SubjectConfirmation>\r\n    </saml2:Subject>\r\n",
            "    <saml2:Conditions NotBefore=\"{now}\" NotOnOrAfter=\"{ends}\">\r\n",
            "      <saml2:AudienceRestriction>\r\n        <saml2:Audience>{sp}</saml2:Audience>\r\n      </saml2:AudienceRestriction>\r\n",
            "    </saml2:Conditions>\r\n",
            "    <saml2:AuthnStatement AuthnInstant=\"{now}\" SessionIndex=\"_0a1b2c3d4e5f60718293a4b5c6d7e8f9\">\r\n",
            "      <saml2:AuthnContext>\r\n        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef>\r\n",
            "      </saml2:AuthnContext>\r\n    </saml2:AuthnStatement>\r\n  </saml2:Assertion>\r\n</saml2p:Response>\r\n"
        ),
        acs = ACS,
        request = REQUEST,
        now = now,
        ends = ends,
        idp = idp,
        sp = SP,
    );
    let xml = sign(&signer, &xml, "_0a1b2c3d4e5f60718293a4b5c6d7e8f9");
    let login = check(idp, &xml, std::slice::from_ref(&signer.certificate), &[]).unwrap();
    assert_eq!(login.subject, "bob@firma.de");
    assert_eq!(login.email(None), Some("bob@firma.de"));
    // The same with LF line ends: line ends are normalized before canonicalization, so the signature still holds.
    assert!(check(idp, &xml.replace("\r\n", "\n"), &[signer.certificate], &[]).is_ok());
}
