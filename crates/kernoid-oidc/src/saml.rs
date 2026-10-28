// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid as a SAML 2.0 service provider (RFC 0001, 7.7): the AuthnRequest it sends (HTTP-Redirect binding, signed
//! if the provider wants it), the Response it accepts (HTTP-POST binding, the Assertion possibly encrypted), and single
//! logout both ways (HTTP-Redirect binding).
//!
//! XML signatures are checked by bergshamra – never by kernoid – with its SAML defaults: only the provider's
//! configured certificates count (no keys from the document), references must sit where the signature can cover them
//! (against XML signature wrapping), duplicate IDs are refused, every reference digest is verified. On top of that,
//! kernoid
//! - refuses documents with a DTD before parsing them;
//! - parses once and reads everything from the same tree it verified, so that no second parser can see a different
//!   document;
//! - takes only the one Assertion of the Response, and only if a valid signature references exactly that Assertion or
//!   the Response around it;
//! - checks the issuer, `InResponseTo`, destination and recipient, the time windows and the audience.
//!
//! An encrypted Assertion is decrypted by bergshamra with kernoid's SAML key; then the same checks apply. A signature
//! over the Response counts when it verifies on the Response as received, before decryption.
//!
//! Redirect-binding signatures (RFC: SAML Bindings 3.4.4.1) are not XML signatures: they sign the URL-encoded query
//! itself. kernoid signs and verifies them through bergshamra's algorithm registry too, RSA and ECDSA with SHA-256 or
//! more – no SHA-1.
use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use bergshamra::{DsigContext, EncContext, KeysManager, VerifyResult, dsig::verify::verify_all_document};
use chrono::{DateTime, Utc};
use uppsala::{Document, NodeId};

const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
/// Largest SAML Response accepted, decoded.
const MAX_RESPONSE: usize = 256 * 1024;
/// Seconds of clock difference accepted.
const LEEWAY: i64 = 120;
/// The signature algorithm kernoid signs with.
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// Signature algorithms kernoid accepts on redirect-binding messages.
const ACCEPTED_SIGNATURES: [&str; 6] = [
    RSA_SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
];
const LOGOUT_USER: &str = "urn:oasis:names:tc:SAML:2.0:logout:user";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SamlError(String);

fn fail<T>(message: impl Into<String>) -> Result<T, SamlError> {
    Err(SamlError(message.into()))
}

/// Text for XML content and attribute values.
fn escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Loads a certificate given as base64 DER (with or without PEM armour).
pub fn certificate(text: &str) -> Result<Vec<u8>, SamlError> {
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = STANDARD.decode(body).map_err(|_| SamlError("a certificate is not base64".into()))?;
    bergshamra::keys::loader::load_x509_cert_der(&der)
        .map_err(|e| SamlError(format!("not a usable certificate: {e}")))?;
    Ok(der)
}

/// kernoid's SAML key of an instance: the private key (PKCS #8 DER) and its self-signed certificate (DER).
#[derive(Clone)]
pub struct SpKey {
    pub private: zeroize::Zeroizing<Vec<u8>>,
    pub certificate: Vec<u8>,
}

impl std::fmt::Debug for SpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpKey").finish_non_exhaustive()
    }
}

impl SpKey {
    /// A new RSA key (2048 bits) with a certificate for `entity_id`, valid for ten years – the certificate only
    /// carries the key; providers trust it because it is in kernoid's metadata, not because of who signed it.
    pub fn generate(entity_id: &str) -> Result<Self, SamlError> {
        use chrono::Datelike;
        let failed = |e: rcgen::Error| SamlError(format!("cannot make kernoid's SAML key: {e}"));
        let key =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).map_err(failed)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(failed)?;
        let name: String = entity_id.chars().take(64).collect();
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        let today = Utc::now();
        let month = u8::try_from(today.month()).unwrap_or(1);
        let day = u8::try_from(today.day().min(28)).unwrap_or(1);
        params.not_before = rcgen::date_time_ymd(today.year(), month, day);
        params.not_after = rcgen::date_time_ymd(today.year() + 10, month, day);
        let certificate = params.self_signed(&key).map_err(failed)?;
        Ok(Self { private: zeroize::Zeroizing::new(key.serialize_der()), certificate: certificate.der().to_vec() })
    }

    /// The key as bergshamra uses it.
    fn key(&self) -> Result<bergshamra::Key, SamlError> {
        // PEM: base64 in lines of 64 characters.
        let encoded = zeroize::Zeroizing::new(STANDARD.encode(self.private.as_slice()));
        let mut pem = zeroize::Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        bergshamra::keys::loader::load_rsa_private_pem(pem.as_bytes())
            .map_err(|e| SamlError(format!("kernoid's SAML key is not usable: {e}")))
    }

    /// Signs the octets of a redirect-binding message with RSA-SHA256.
    fn sign(&self, octets: &[u8]) -> Result<Vec<u8>, SamlError> {
        let failed = |e: bergshamra::Error| SamlError(format!("cannot sign: {e}"));
        let key = self.key()?.software_key().map_err(failed)?.ok_or_else(|| SamlError("no signing key".into()))?;
        bergshamra::crypto::sign::from_uri(RSA_SHA256).map_err(failed)?.sign(&key, octets).map_err(failed)
    }
}

/// A message in the HTTP-Redirect binding: deflated, base64, in the query – signed with `key` if given.
fn redirect_url(
    endpoint: &str,
    parameter: &str,
    xml: &str,
    relay_state: Option<&str>,
    key: Option<&SpKey>,
) -> Result<String, SamlError> {
    let compressed = miniz_oxide::deflate::compress_to_vec(xml.as_bytes(), 6);
    let mut url = url::Url::parse(endpoint).map_err(|e| SamlError(format!("{endpoint:?} is not a URL: {e}")))?;
    // The signature covers exactly these octets, in this order (SAML Bindings 3.4.4.1).
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(parameter, &STANDARD.encode(compressed));
    if let Some(relay_state) = relay_state {
        query.append_pair("RelayState", relay_state);
    }
    if let Some(key) = key {
        query.append_pair("SigAlg", RSA_SHA256);
        let octets = query.finish();
        let signature = key.sign(octets.as_bytes())?;
        let mut query = url::form_urlencoded::Serializer::new(octets);
        query.append_pair("Signature", &STANDARD.encode(signature));
        let signed = query.finish();
        let joined = match url.query() {
            Some(existing) if !existing.is_empty() => format!("{existing}&{signed}"),
            _ => signed,
        };
        url.set_query(Some(&joined));
    } else {
        let message = query.finish();
        let joined = match url.query() {
            Some(existing) if !existing.is_empty() => format!("{existing}&{message}"),
            _ => message,
        };
        url.set_query(Some(&joined));
    }
    Ok(url.into())
}

/// The URL that sends the browser to the provider with an AuthnRequest (HTTP-Redirect binding), signed if `key` is
/// given.
#[allow(clippy::too_many_arguments, reason = "the parts of one request")]
pub fn authn_request_url(
    sso_url: &str,
    request_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    relay_state: &str,
    now: DateTime<Utc>,
    key: Option<&SpKey>,
) -> Result<String, SamlError> {
    let request = format!(
        concat!(
            r#"<samlp:AuthnRequest xmlns:samlp="{protocol}" xmlns:saml="{assertion}" ID="{id}" Version="2.0" "#,
            r#"IssueInstant="{instant}" Destination="{destination}" AssertionConsumerServiceURL="{acs}" "#,
            r#"ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>"#
        ),
        protocol = PROTOCOL,
        assertion = ASSERTION,
        id = escape(request_id),
        instant = now.format("%Y-%m-%dT%H:%M:%SZ"),
        destination = escape(sso_url),
        acs = escape(acs_url),
        issuer = escape(sp_entity_id),
    );
    redirect_url(sso_url, "SAMLRequest", &request, Some(relay_state), key)
}

/// A LogoutRequest kernoid sends when someone logs out who logged in at the provider (HTTP-Redirect binding, signed).
#[derive(Debug)]
pub struct LogoutRequestOut<'a> {
    pub slo_url: &'a str,
    pub request_id: &'a str,
    pub sp_entity_id: &'a str,
    pub name_id: &'a str,
    pub name_id_format: Option<&'a str>,
    pub session_index: Option<&'a str>,
    pub relay_state: &'a str,
    pub now: DateTime<Utc>,
}

pub fn logout_request_url(request: &LogoutRequestOut<'_>, key: &SpKey) -> Result<String, SamlError> {
    let format = request.name_id_format.map(|format| format!(r#" Format="{}""#, escape(format))).unwrap_or_default();
    let index = request
        .session_index
        .map(|index| format!("<samlp:SessionIndex>{}</samlp:SessionIndex>", escape(index)))
        .unwrap_or_default();
    let xml = format!(
        concat!(
            r#"<samlp:LogoutRequest xmlns:samlp="{protocol}" xmlns:saml="{assertion}" ID="{id}" Version="2.0" "#,
            r#"IssueInstant="{instant}" Destination="{destination}" Reason="{reason}">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer><saml:NameID{format}>{name_id}</saml:NameID>{index}"#,
            r#"</samlp:LogoutRequest>"#
        ),
        protocol = PROTOCOL,
        assertion = ASSERTION,
        id = escape(request.request_id),
        instant = request.now.format("%Y-%m-%dT%H:%M:%SZ"),
        destination = escape(request.slo_url),
        reason = LOGOUT_USER,
        issuer = escape(request.sp_entity_id),
        format = format,
        name_id = escape(request.name_id),
        index = index,
    );
    redirect_url(request.slo_url, "SAMLRequest", &xml, Some(request.relay_state), Some(key))
}

/// kernoid's answer to a provider's LogoutRequest (HTTP-Redirect binding, signed).
#[allow(clippy::too_many_arguments, reason = "the parts of one response")]
pub fn logout_response_url(
    slo_url: &str,
    response_id: &str,
    in_response_to: &str,
    sp_entity_id: &str,
    relay_state: Option<&str>,
    now: DateTime<Utc>,
    key: &SpKey,
) -> Result<String, SamlError> {
    let xml = format!(
        concat!(
            r#"<samlp:LogoutResponse xmlns:samlp="{protocol}" xmlns:saml="{assertion}" ID="{id}" Version="2.0" "#,
            r#"IssueInstant="{instant}" Destination="{destination}" InResponseTo="{request}">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{success}"/></samlp:Status>"#,
            r#"</samlp:LogoutResponse>"#
        ),
        protocol = PROTOCOL,
        assertion = ASSERTION,
        id = escape(response_id),
        instant = now.format("%Y-%m-%dT%H:%M:%SZ"),
        destination = escape(slo_url),
        request = escape(in_response_to),
        issuer = escape(sp_entity_id),
        success = SUCCESS,
    );
    redirect_url(slo_url, "SAMLResponse", &xml, relay_state, Some(key))
}

/// A message received in the HTTP-Redirect binding.
#[derive(Debug, Clone)]
pub struct Redirected {
    /// `SAMLRequest` or `SAMLResponse`.
    pub request: bool,
    /// The inflated XML.
    pub xml: String,
    pub relay_state: Option<String>,
    /// What the signature covers, its algorithm and value – if signed.
    signed: Option<(String, String, Vec<u8>)>,
}

/// Reads a redirect-binding message from the raw (still URL-encoded) query.
pub fn read_redirect(raw_query: &str) -> Result<Redirected, SamlError> {
    let raw: Vec<(&str, &str)> = raw_query.split('&').filter_map(|pair| pair.split_once('=')).collect();
    let find = |name: &str| raw.iter().find(|(key, _)| *key == name).map(|(_, value)| *value);
    let decode = |value: &str| {
        url::form_urlencoded::parse(format!("v={value}").as_bytes()).next().map(|(_, value)| value.into_owned())
    };
    let (request, message) = match (find("SAMLRequest"), find("SAMLResponse")) {
        (Some(message), None) => (true, message),
        (None, Some(message)) => (false, message),
        _ => return fail("expected a SAMLRequest or a SAMLResponse"),
    };
    let encoded = decode(message).ok_or_else(|| SamlError("the message is not URL-encoded".into()))?;
    let deflated = STANDARD.decode(encoded.trim()).map_err(|_| SamlError("the message is not base64".into()))?;
    let bytes = miniz_oxide::inflate::decompress_to_vec_with_limit(&deflated, MAX_RESPONSE)
        .map_err(|_| SamlError("the message cannot be inflated".into()))?;
    let xml = String::from_utf8(bytes).map_err(|_| SamlError("the message is not UTF-8".into()))?;
    let relay_state = find("RelayState").and_then(decode);
    let signed = match (find("SigAlg"), find("Signature")) {
        (Some(algorithm), Some(signature)) => {
            let name = if request { "SAMLRequest" } else { "SAMLResponse" };
            let mut octets = format!("{name}={message}");
            if let Some(relay) = find("RelayState") {
                octets.push_str(&format!("&RelayState={relay}"));
            }
            octets.push_str(&format!("&SigAlg={algorithm}"));
            let algorithm = decode(algorithm).ok_or_else(|| SamlError("SigAlg is not URL-encoded".into()))?;
            let signature = decode(signature)
                .and_then(|signature| STANDARD.decode(signature).ok())
                .ok_or_else(|| SamlError("the signature is not base64".into()))?;
            Some((octets, algorithm, signature))
        }
        _ => None,
    };
    Ok(Redirected { request, xml, relay_state, signed })
}

impl Redirected {
    /// Whether one of the provider's certificates verifies the redirect signature; unsigned messages fail.
    pub fn verify(&self, certificates: &[Vec<u8>]) -> Result<(), SamlError> {
        let Some((octets, algorithm, signature)) = &self.signed else { return fail("the message is not signed") };
        if !ACCEPTED_SIGNATURES.contains(&algorithm.as_str()) {
            return fail(format!("the signature algorithm {algorithm} is not accepted"));
        }
        let verifier = bergshamra::crypto::sign::from_uri(algorithm).map_err(|e| SamlError(e.to_string()))?;
        for certificate in certificates {
            let Ok(key) = bergshamra::keys::loader::load_x509_cert_der(certificate) else { continue };
            let Ok(Some(key)) = key.software_key() else { continue };
            if verifier.verify(&key, octets.as_bytes(), signature).unwrap_or(false) {
                return Ok(());
            }
        }
        fail("the signature does not verify with the provider's certificates")
    }
}

/// What kernoid takes from a provider's LogoutRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequestIn {
    pub id: String,
    pub issuer: String,
    pub name_id: String,
    /// Empty: every session of the NameID.
    pub session_indexes: Vec<String>,
}

fn parse_message(xml: &str) -> Result<Document<'_>, SamlError> {
    if xml.to_ascii_uppercase().contains("<!DOCTYPE") {
        return fail("the message contains a DTD");
    }
    uppsala::parse(xml).map_err(|_| SamlError("the message is not well-formed XML".into()))
}

/// Reads a LogoutRequest (after its redirect signature was verified); checks destination and validity.
pub fn read_logout_request(xml: &str, slo_url: &str, now: DateTime<Utc>) -> Result<LogoutRequestIn, SamlError> {
    let doc = parse_message(xml)?;
    let root = doc.document_element().ok_or_else(|| SamlError("the message is empty".into()))?;
    if !element_named(&doc, root, PROTOCOL, "LogoutRequest") {
        return fail("this is not a LogoutRequest");
    }
    if doc.get_attribute(root, "Destination").is_some_and(|destination| destination != slo_url) {
        return fail("the request is meant for another service");
    }
    if time(doc.get_attribute(root, "NotOnOrAfter"))?.is_some_and(|end| end + chrono::Duration::seconds(LEEWAY) <= now)
    {
        return fail("the request has expired");
    }
    let id = doc.get_attribute(root, "ID").ok_or_else(|| SamlError("the request has no ID".into()))?.to_owned();
    let issuer = text(&doc, only_child(&doc, root, ASSERTION, "Issuer")?);
    let name_id = text(&doc, only_child(&doc, root, ASSERTION, "NameID")?);
    let session_indexes = children(&doc, root, PROTOCOL, "SessionIndex").map(|index| text(&doc, index)).collect();
    Ok(LogoutRequestIn { id, issuer, name_id, session_indexes })
}

/// What kernoid takes from a provider's LogoutResponse: whom it answers, from whom, and whether it succeeded.
pub fn read_logout_response(xml: &str) -> Result<(String, String, bool), SamlError> {
    let doc = parse_message(xml)?;
    let root = doc.document_element().ok_or_else(|| SamlError("the message is empty".into()))?;
    if !element_named(&doc, root, PROTOCOL, "LogoutResponse") {
        return fail("this is not a LogoutResponse");
    }
    let in_response_to =
        doc.get_attribute(root, "InResponseTo").ok_or_else(|| SamlError("the response answers nothing".into()))?;
    let issuer = text(&doc, only_child(&doc, root, ASSERTION, "Issuer")?);
    let status = only_child(&doc, root, PROTOCOL, "Status")?;
    let code = only_child(&doc, status, PROTOCOL, "StatusCode")?;
    Ok((in_response_to.to_owned(), issuer, doc.get_attribute(code, "Value") == Some(SUCCESS)))
}

/// kernoid's service provider metadata for an instance – to give a provider's administrator: its key (for signed
/// requests and encrypted assertions), the ACS and the single logout service.
pub fn metadata(sp_entity_id: &str, acs_url: &str, slo_url: &str, certificate: &[u8]) -> String {
    let key = |usage: &str| {
        format!(
            concat!(
                r#"<md:KeyDescriptor use="{usage}"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data>"#,
                r#"</ds:KeyInfo></md:KeyDescriptor>"#
            ),
            usage = usage,
            certificate = STANDARD.encode(certificate),
        )
    };
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">"#,
            r#"<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" "#,
            r#"protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#,
            r#"{signing}{encryption}"#,
            r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" "#,
            r#"Location="{slo}"/>"#,
            r#"<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"#,
            r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" "#,
            r#"Location="{acs}" index="0" isDefault="true"/>"#,
            r#"</md:SPSSODescriptor></md:EntityDescriptor>"#
        ),
        entity = escape(sp_entity_id),
        signing = key("signing"),
        encryption = key("encryption"),
        slo = escape(slo_url),
        acs = escape(acs_url),
    )
}

/// What a Response must match.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The provider's entity ID.
    pub idp_entity_id: &'a str,
    /// The provider's signing certificates (DER).
    pub certificates: &'a [Vec<u8>],
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    /// The ID of kernoid's AuthnRequest.
    pub request_id: &'a str,
    pub now: DateTime<Utc>,
    /// kernoid's SAML key, to decrypt an encrypted Assertion.
    pub decryption_key: Option<&'a SpKey>,
}

/// What kernoid takes from a verified Assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogin {
    /// The NameID: who logged in, at the provider.
    pub subject: String,
    pub name_id_format: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    /// The provider says the login had more than one factor (`AuthnContextClassRef`).
    pub multi_factor: bool,
    /// The provider's session, for single logout (`AuthnStatement/@SessionIndex`).
    pub session_index: Option<String>,
}

fn element_named(doc: &Document<'_>, id: NodeId, namespace: &str, local: &str) -> bool {
    doc.element(id).is_some_and(|element| element.matches_name_ns(namespace, local))
}

fn children<'d>(
    doc: &'d Document<'_>,
    parent: NodeId,
    namespace: &'d str,
    local: &'d str,
) -> impl Iterator<Item = NodeId> + 'd {
    doc.children(parent).into_iter().filter(move |child| element_named(doc, *child, namespace, local))
}

fn only_child(doc: &Document<'_>, parent: NodeId, namespace: &str, local: &str) -> Result<NodeId, SamlError> {
    let mut found = children(doc, parent, namespace, local);
    match (found.next(), found.next()) {
        (Some(one), None) => Ok(one),
        (None, _) => fail(format!("the response has no {local}")),
        (Some(_), Some(_)) => fail(format!("the response has more than one {local}")),
    }
}

fn text(doc: &Document<'_>, id: NodeId) -> String {
    doc.text_content_deep(id).trim().to_owned()
}

fn time(value: Option<&str>) -> Result<Option<DateTime<Utc>>, SamlError> {
    value
        .map(|value| DateTime::parse_from_rfc3339(value).map(|time| time.with_timezone(&Utc)))
        .transpose()
        .map_err(|_| SamlError("a time in the response is not valid".into()))
}

/// Verifies a SAML Response (the base64 `SAMLResponse` of the HTTP-POST binding) and returns the login it carries.
pub fn verify_response(encoded: &str, expected: Expected<'_>) -> Result<SamlLogin, SamlError> {
    let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() > MAX_RESPONSE * 4 / 3 + 4 {
        return fail("the response is too large");
    }
    let bytes = STANDARD.decode(compact).map_err(|_| SamlError("the response is not base64".into()))?;
    let xml = String::from_utf8(bytes).map_err(|_| SamlError("the response is not UTF-8".into()))?;
    if xml.to_ascii_uppercase().contains("<!DOCTYPE") {
        return fail("the response contains a DTD");
    }
    let doc = uppsala::parse(&xml).map_err(|_| SamlError("the response is not well-formed XML".into()))?;
    let response = doc.document_element().ok_or_else(|| SamlError("the response is empty".into()))?;
    if !element_named(&doc, response, PROTOCOL, "Response") {
        return fail("this is not a SAML Response");
    }
    if let Some(destination) = doc.get_attribute(response, "Destination")
        && destination != expected.acs_url
    {
        return fail("the response is meant for another service");
    }
    if doc.get_attribute(response, "InResponseTo") != Some(expected.request_id) {
        return fail("the response answers another request");
    }
    let status = only_child(&doc, response, PROTOCOL, "Status")?;
    let code = only_child(&doc, status, PROTOCOL, "StatusCode")?;
    if doc.get_attribute(code, "Value") != Some(SUCCESS) {
        return fail("the provider did not log the person in");
    }
    for issuer in children(&doc, response, ASSERTION, "Issuer") {
        if text(&doc, issuer) != expected.idp_entity_id {
            return fail("the response comes from another provider");
        }
    }

    let mut keys = KeysManager::new();
    for certificate in expected.certificates {
        let key = bergshamra::keys::loader::load_x509_cert_der(certificate)
            .map_err(|e| SamlError(format!("a configured certificate is not usable: {e}")))?;
        keys.add_key(key);
    }
    let context = DsigContext::new(keys);
    // Whether a valid signature covers one of `nodes`.
    let covers = |doc: &Document<'_>, nodes: &[NodeId]| -> Result<bool, SamlError> {
        let results = match verify_all_document(&context, doc) {
            Ok(results) => results,
            // No signature in the document: nothing covered.
            Err(bergshamra::Error::MissingElement(element)) if element.contains("Signature") => return Ok(false),
            Err(e) => return Err(SamlError(format!("the signature cannot be verified: {e}"))),
        };
        Ok(results.iter().any(|result| {
            result.all_reference_digests_verified()
                && matches!(result, VerifyResult::Valid { references, .. }
                    if references.iter().any(|reference| reference.resolved_node.is_some_and(|node| nodes.contains(&node))))
        }))
    };

    let plain: Vec<NodeId> = children(&doc, response, ASSERTION, "Assertion").collect();
    let encrypted: Vec<NodeId> = children(&doc, response, ASSERTION, "EncryptedAssertion").collect();
    match (plain.as_slice(), encrypted.as_slice()) {
        // The signature must cover this Assertion, or the Response around it.
        ([assertion], []) => {
            if !covers(&doc, &[*assertion, response])? {
                return fail("the assertion is not signed by the provider");
            }
            read_assertion(&doc, *assertion, &expected)
        }
        ([], [_]) => {
            let Some(key) = expected.decryption_key else {
                return fail("the assertion is encrypted, but kernoid has no SAML key");
            };
            let response_signed = covers(&doc, &[response])?;
            let mut keys = KeysManager::new();
            keys.add_key(key.key()?);
            let decrypted = bergshamra::decrypt(&EncContext::new(keys), &xml)
                .map_err(|e| SamlError(format!("the assertion cannot be decrypted: {e}")))?;
            let doc = parse_message(&decrypted)?;
            let response = doc.document_element().ok_or_else(|| SamlError("the response is empty".into()))?;
            let wrapper = only_child(&doc, response, ASSERTION, "EncryptedAssertion")?;
            let assertion = only_child(&doc, wrapper, ASSERTION, "Assertion")?;
            if !response_signed && !covers(&doc, &[assertion])? {
                return fail("the assertion is not signed by the provider");
            }
            read_assertion(&doc, assertion, &expected)
        }
        _ => fail("the response must carry exactly one assertion"),
    }
}

/// The checks of an Assertion whose signature was verified, and what kernoid takes from it.
fn read_assertion(doc: &Document<'_>, assertion: NodeId, expected: &Expected<'_>) -> Result<SamlLogin, SamlError> {
    let issuer = only_child(doc, assertion, ASSERTION, "Issuer")?;
    if text(doc, issuer) != expected.idp_entity_id {
        return fail("the assertion comes from another provider");
    }
    let leeway = chrono::Duration::seconds(LEEWAY);
    let conditions = only_child(doc, assertion, ASSERTION, "Conditions")?;
    if time(doc.get_attribute(conditions, "NotBefore"))?.is_some_and(|not_before| not_before - leeway > expected.now) {
        return fail("the assertion is not valid yet");
    }
    if time(doc.get_attribute(conditions, "NotOnOrAfter"))?.is_none_or(|end| end + leeway <= expected.now) {
        return fail("the assertion has expired");
    }
    let audiences: Vec<String> = children(doc, conditions, ASSERTION, "AudienceRestriction")
        .flat_map(|restriction| {
            children(doc, restriction, ASSERTION, "Audience").map(|audience| text(doc, audience)).collect::<Vec<_>>()
        })
        .collect();
    if !audiences.iter().any(|audience| audience == expected.sp_entity_id) {
        return fail("the assertion is meant for another service");
    }

    let subject = only_child(doc, assertion, ASSERTION, "Subject")?;
    let name_id = only_child(doc, subject, ASSERTION, "NameID")?;
    let confirmed = children(doc, subject, ASSERTION, "SubjectConfirmation").any(|confirmation| {
        let Some(data) = children(doc, confirmation, ASSERTION, "SubjectConfirmationData").next() else {
            return false;
        };
        doc.get_attribute(confirmation, "Method") == Some(BEARER)
            && doc.get_attribute(data, "Recipient") == Some(expected.acs_url)
            && doc.get_attribute(data, "InResponseTo").is_none_or(|request| request == expected.request_id)
            && time(doc.get_attribute(data, "NotOnOrAfter"))
                .ok()
                .flatten()
                .is_some_and(|end| end + leeway > expected.now)
    });
    if !confirmed {
        return fail("the assertion's subject is not confirmed for this service");
    }
    let subject_value = text(doc, name_id);
    if subject_value.is_empty() || subject_value.len() > 255 {
        return fail("the assertion's NameID is empty or too long");
    }

    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for statement in children(doc, assertion, ASSERTION, "AttributeStatement") {
        for attribute in children(doc, statement, ASSERTION, "Attribute") {
            let Some(name) = doc.get_attribute(attribute, "Name") else { continue };
            let values = children(doc, attribute, ASSERTION, "AttributeValue").map(|value| text(doc, value));
            attributes.entry(name.to_owned()).or_default().extend(values);
        }
    }
    let session_index = children(doc, assertion, ASSERTION, "AuthnStatement")
        .find_map(|statement| doc.get_attribute(statement, "SessionIndex"))
        .filter(|index| index.len() <= 255)
        .map(str::to_owned);
    let multi_factor = children(doc, assertion, ASSERTION, "AuthnStatement").any(|statement| {
        children(doc, statement, ASSERTION, "AuthnContext").any(|context| {
            children(doc, context, ASSERTION, "AuthnContextClassRef").any(|class| {
                let class = text(doc, class);
                class.contains("MultiFactor")
                    || class == "http://schemas.microsoft.com/claims/multipleauthn"
                    || class == "https://refeds.org/profile/mfa"
            })
        })
    });
    Ok(SamlLogin {
        subject: subject_value,
        name_id_format: doc.get_attribute(name_id, "Format").map(str::to_owned),
        attributes,
        multi_factor,
        session_index,
    })
}

/// Attribute names providers commonly use for the email address and the display name.
pub const EMAIL_ATTRIBUTES: [&str; 4] = [
    "email",
    "mail",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
];
pub const NAME_ATTRIBUTES: [&str; 4] = [
    "displayName",
    "name",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "urn:oid:2.16.840.1.113730.3.1.241",
];

impl SamlLogin {
    fn first(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|name| self.attributes.get(*name).and_then(|values| values.first())).map(String::as_str)
    }

    /// The email address: the configured attribute, a common one, or an email-format NameID.
    pub fn email(&self, configured: Option<&str>) -> Option<&str> {
        match configured {
            Some(name) => self.first(&[name]),
            None => self.first(&EMAIL_ATTRIBUTES).or_else(|| {
                (self.name_id_format.as_deref() == Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"))
                    .then_some(self.subject.as_str())
            }),
        }
    }

    pub fn name(&self, configured: Option<&str>) -> Option<&str> {
        match configured {
            Some(name) => self.first(&[name]),
            None => self.first(&NAME_ATTRIBUTES),
        }
    }
}
