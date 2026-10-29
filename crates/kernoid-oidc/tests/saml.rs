// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verifying SAML Responses: genuine ones pass; tampered, foreign, wrapped and expired ones do not. Responses are
//! signed with a key and certificate made for the test (rcgen) by bergshamra.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use bergshamra::{DsigContext, KeysManager};
use chrono::{Duration, Utc};
use kernoid_events::EventStore;
use kernoid_identity::{DomainName, Identity, session::ClientMeta};
use kernoid_oidc::{
    Oidc,
    federation::{IdpSettings, SamlSettings},
    saml::{Expected, verify_response},
};
use kernoid_store::{MainKeys, crypto::Key};
use sqlx::PgPool;

const IDP: &str = "https://idp.example/saml";
const SP: &str = "https://login.firma.de/idp/saml";
const ACS: &str = "https://login.firma.de/idp/saml/acs";
const REQUEST: &str = "_req-1";

struct Signer {
    certificate: Vec<u8>,
    context: DsigContext,
    key: bergshamra::Key,
}

fn new_signer() -> Signer {
    let made = rcgen::generate_simple_self_signed(vec!["idp.example".to_owned()]).unwrap();
    let key = bergshamra::keys::loader::load_pem_auto(made.signing_key.serialize_pem().as_bytes(), None).unwrap();
    let mut keys = KeysManager::new();
    keys.add_key(key.clone());
    Signer { certificate: made.cert.der().to_vec(), context: DsigContext::new(keys), key }
}

/// A Response whose Assertion carries an enveloped signature template; `name_id` and `audience` can be varied.
fn template(name_id: &str, audience: &str, in_response_to: &str, ends: chrono::DateTime<Utc>) -> String {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let ends = ends.format("%Y-%m-%dT%H:%M:%SZ");
    format!(
        r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="{now}" Destination="{ACS}" InResponseTo="{in_response_to}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1" Version="2.0" IssueInstant="{now}"><saml:Issuer>{IDP}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#_a1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{name_id}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{in_response_to}" NotOnOrAfter="{ends}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{now}" NotOnOrAfter="{ends}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>http://schemas.microsoft.com/claims/multipleauthn</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>bob@firma.de</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>Bob</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"##
    )
}

fn sign(signer: &Signer, xml: &str) -> String {
    bergshamra::sign(&signer.context, xml).unwrap()
}

fn encode(xml: &str) -> String {
    STANDARD.encode(xml)
}

fn expected<'a>(certificates: &'a [Vec<u8>]) -> Expected<'a> {
    Expected {
        idp_entity_id: IDP,
        certificates,
        sp_entity_id: SP,
        acs_url: ACS,
        request_id: REQUEST,
        now: Utc::now(),
        decryption_keys: &[],
    }
}

fn valid(signer: &Signer) -> String {
    sign(signer, &template("u-123", SP, REQUEST, Utc::now() + Duration::minutes(5)))
}

#[test]
fn a_genuine_response_passes() {
    let signer = new_signer();
    let certificates = [signer.certificate.clone()];
    let login = verify_response(&encode(&valid(&signer)), expected(&certificates)).unwrap();
    assert_eq!(login.subject, "u-123");
    assert_eq!(login.email(None), Some("bob@firma.de"));
    assert_eq!(login.name(None), Some("Bob"));
    assert!(login.multi_factor);
}

#[test]
fn tampered_and_foreign_responses_fail() {
    let signer = new_signer();
    let certificates = [signer.certificate.clone()];
    let signed = valid(&signer);
    // Changed after signing.
    let tampered = signed.replace(">u-123<", ">admin<");
    assert!(verify_response(&encode(&tampered), expected(&certificates)).is_err());
    // Signed by another key than the configured one.
    let other = new_signer();
    assert!(verify_response(&encode(&signed), expected(&[other.certificate])).is_err());
    // Unsigned.
    let unsigned = template("u-123", SP, REQUEST, Utc::now() + Duration::minutes(5));
    assert!(verify_response(&encode(&unsigned), expected(&certificates)).is_err());
}

#[test]
fn wrapped_signatures_fail() {
    let signer = new_signer();
    let certificates = [signer.certificate.clone()];
    let signed = valid(&signer);
    let start = signed.find("<saml:Assertion").unwrap();
    let end = signed.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    let genuine = &signed[start..end];
    let evil = genuine.replace("ID=\"_a1\"", "ID=\"_evil\"").replace(">u-123<", ">admin<");
    // The signed Assertion hidden in Extensions, a forged one where kernoid reads.
    let hidden = format!("{}<samlp:Extensions>{genuine}</samlp:Extensions>{evil}{}", &signed[..start], &signed[end..]);
    let error = verify_response(&encode(&hidden), expected(&certificates)).unwrap_err();
    assert!(error.to_string().contains("not signed"), "{error}");
    // Two Assertions side by side.
    let twice = format!("{}{genuine}{evil}{}", &signed[..start], &signed[end..]);
    assert!(verify_response(&encode(&twice), expected(&certificates)).is_err());
    // A copy with the same ID.
    let duplicate =
        format!("{}{genuine}<samlp:Extensions>{genuine}</samlp:Extensions>{}", &signed[..start], &signed[end..]);
    assert!(verify_response(&encode(&duplicate), expected(&certificates)).is_err());
}

#[test]
fn responses_for_others_or_out_of_time_fail() {
    let signer = new_signer();
    let certificates = [signer.certificate.clone()];
    let in_five = Utc::now() + Duration::minutes(5);
    for (xml, why) in [
        (sign(&signer, &template("u-123", "https://other.example/sp", REQUEST, in_five)), "audience"),
        (sign(&signer, &template("u-123", SP, "_another", in_five)), "request"),
        (sign(&signer, &template("u-123", SP, REQUEST, Utc::now() - Duration::minutes(10))), "expired"),
    ] {
        assert!(verify_response(&encode(&xml), expected(&certificates)).is_err(), "{why}");
    }
    let doctype = format!("<!DOCTYPE x [<!ENTITY e \"u-123\">]>{}", valid(&signer));
    assert!(verify_response(&encode(&doctype), expected(&certificates)).unwrap_err().to_string().contains("DTD"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_saml_login_creates_the_account_once(pool: PgPool) {
    let events = EventStore::new(pool.clone());
    let identity = Identity::new(events.clone());
    let oidc = Oidc::new(events, MainKeys::new(Key::random().unwrap(), Vec::new()), "https");
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let id = identity.add_instance("Firma", &domain("login.firma.de"), "test").await.unwrap();
    let tenant = identity.add_tenant(id, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    let instance = identity.instance_by_host("login.firma.de").await.unwrap().unwrap();
    assert_eq!(oidc.saml_entity_id(&instance.primary_domain), SP);
    assert_eq!(oidc.saml_acs_url(&instance.primary_domain), ACS);

    let signer = new_signer();
    let settings = IdpSettings {
        name: "ADFS".into(),
        issuer: IDP.into(),
        client_id: String::new(),
        scopes: Vec::new(),
        domains: vec!["firma.de".into()],
        auto_create: true,
        auto_link: false,
        sync_profile: false,
        register: false,
        saml: Some(SamlSettings {
            sso_url: "https://idp.example/saml/sso".into(),
            certificates: vec![STANDARD.encode(&signer.certificate)],
            email_attribute: None,
            name_attribute: None,
            sign_requests: false,
            slo_url: None,
        }),
    };
    let idp = oidc.add_identity_provider(tenant, &settings, None, "test").await.unwrap();
    assert_eq!(oidc.identity_provider(idp).await.unwrap().settings.kind(), "saml");

    // The AuthnRequest kernoid sends: deflated, base64, with the RelayState kernoid gets back.
    let start = url::Url::parse(&oidc.start_idp_login(&instance, idp, None, None).await.unwrap()).unwrap();
    assert!(start.as_str().starts_with("https://idp.example/saml/sso?"));
    let query: HashMap<String, String> = start.query_pairs().into_owned().collect();
    let request = miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&query["SAMLRequest"]).unwrap()).unwrap();
    let request = String::from_utf8(request).unwrap();
    assert!(request.contains(&format!("AssertionConsumerServiceURL=\"{ACS}\"")), "{request}");
    let request_id = request.split("ID=\"").nth(1).unwrap().split('"').next().unwrap().to_owned();

    // The provider posts a signed Response for it.
    let response = sign(&signer, &template("ext-bob", SP, &request_id, Utc::now() + Duration::minutes(5)));
    let back = oidc.saml_acs(&instance, Some(&query["RelayState"]), Some(&encode(&response))).await;
    let fragment: HashMap<String, String> =
        url::form_urlencoded::parse(back.split_once('#').unwrap().1.as_bytes()).into_owned().collect();
    let login = fragment.get("login").unwrap_or_else(|| panic!("{fragment:?}"));
    let result = oidc.exchange_idp_login(instance.id, login, None, &ClientMeta::default()).await.unwrap();
    assert_eq!(result.session.account.address, "bob@firma.de");
    assert_eq!(result.session.account.display_name, "Bob");
    let checks = identity.session(instance.id, &result.session.token).await.unwrap().checks;
    assert_eq!(checks, ["idp", "idp_mfa"]);

    // The same Response again is refused: its login is used up.
    let again = oidc.saml_acs(&instance, Some(&query["RelayState"]), Some(&encode(&response))).await;
    assert!(again.contains("error="), "{again}");
    // A Response for another request is refused too.
    let start = url::Url::parse(&oidc.start_idp_login(&instance, idp, None, None).await.unwrap()).unwrap();
    let query: HashMap<String, String> = start.query_pairs().into_owned().collect();
    let replayed = oidc.saml_acs(&instance, Some(&query["RelayState"]), Some(&encode(&response))).await;
    assert!(replayed.contains("error="), "{replayed}");
    let metadata = oidc.saml_metadata(&instance).await.unwrap();
    assert!(metadata.contains(&format!("entityID=\"{SP}\"")) && metadata.contains(ACS));
    let key = oidc.saml_sp_key(&instance).await.unwrap();
    assert!(metadata.contains(&STANDARD.encode(&key.certificate)), "the metadata carries kernoid's certificate");
    assert!(metadata.contains("https://login.firma.de/idp/saml/slo"));
}

/// Encrypts the Assertion of a signed Response for kernoid's certificate, the way providers do: AES-256-GCM for the
/// Assertion, RSA-OAEP for the key – done here with aws-lc-rs, independently of bergshamra.
fn encrypt_assertion(response: &str, certificate: &[u8]) -> String {
    use aws_lc_rs::{aead, rand, rsa};
    let start = response.find("<saml:Assertion").unwrap();
    let end = response.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    rand::fill(&mut key).unwrap();
    rand::fill(&mut iv).unwrap();
    let sealing = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    let mut data = response.as_bytes()[start..end].to_vec();
    sealing.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(iv), aead::Aad::empty(), &mut data).unwrap();
    let cipher = [iv.as_slice(), &data].concat();
    let spki = bergshamra::keys::loader::load_x509_cert_der(certificate).unwrap().data.to_spki_der().unwrap();
    let public = rsa::OaepPublicEncryptingKey::new(rsa::PublicEncryptingKey::from_der(&spki).unwrap()).unwrap();
    let mut wrapped = vec![0; public.ciphertext_size()];
    let wrapped = public.encrypt(&rsa::OAEP_SHA1_MGF1SHA1, &key, &mut wrapped, None).unwrap().to_vec();
    let encrypted = format!(
        concat!(
            r#"<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" "#,
            r#"Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod "#,
            r#"Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></xenc:EncryptionMethod>"#,
            r#"<xenc:CipherData><xenc:CipherValue>{key}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"#,
            r#"</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{data}</xenc:CipherValue></xenc:CipherData>"#,
            r#"</xenc:EncryptedData></saml:EncryptedAssertion>"#
        ),
        key = STANDARD.encode(wrapped),
        data = STANDARD.encode(cipher),
    );
    format!("{}{encrypted}{}", &response[..start], &response[end..])
}

/// A redirect-binding message as a provider sends it: deflated, base64, URL-encoded – signed with `signer` if given.
fn redirect_query(parameter: &str, xml: &str, relay_state: &str, signer: Option<&Signer>) -> String {
    let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let deflated = miniz_oxide::deflate::compress_to_vec(xml.as_bytes(), 6);
    let mut query = format!("{parameter}={}&RelayState={}", encode(&STANDARD.encode(deflated)), encode(relay_state));
    if let Some(signer) = signer {
        let algorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
        query.push_str(&format!("&SigAlg={}", encode(algorithm)));
        let key = signer.key.software_key().unwrap().unwrap();
        let signature = bergshamra::crypto::sign::from_uri(algorithm).unwrap().sign(&key, query.as_bytes()).unwrap();
        query.push_str(&format!("&Signature={}", encode(&STANDARD.encode(signature))));
    }
    query
}

struct SamlSetup {
    oidc: Oidc,
    identity: Identity,
    instance: kernoid_identity::InstanceInfo,
    tenant: uuid::Uuid,
    signer: Signer,
    idp: uuid::Uuid,
}

async fn saml_setup(pool: &PgPool, sign_requests: bool) -> SamlSetup {
    let events = EventStore::new(pool.clone());
    let identity = Identity::new(events.clone());
    let oidc = Oidc::new(events, MainKeys::new(Key::random().unwrap(), Vec::new()), "https");
    let domain = |name: &str| DomainName::parse(name).unwrap();
    let id = identity.add_instance("Firma", &domain("login.firma.de"), "test").await.unwrap();
    let tenant = identity.add_tenant(id, "Firma", "test").await.unwrap();
    identity.add_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    identity.trust_tenant_domain(id, tenant, &domain("firma.de"), "test").await.unwrap();
    let instance = identity.instance_by_host("login.firma.de").await.unwrap().unwrap();
    let signer = new_signer();
    let settings = IdpSettings {
        name: "ADFS".into(),
        issuer: IDP.into(),
        client_id: String::new(),
        scopes: Vec::new(),
        domains: vec!["firma.de".into()],
        auto_create: true,
        auto_link: false,
        sync_profile: false,
        register: false,
        saml: Some(SamlSettings {
            sso_url: "https://idp.example/saml/sso".into(),
            certificates: vec![STANDARD.encode(&signer.certificate)],
            email_attribute: None,
            name_attribute: None,
            sign_requests,
            slo_url: Some("https://idp.example/saml/slo".into()),
        }),
    };
    let idp = oidc.add_identity_provider(tenant, &settings, None, "test").await.unwrap();
    SamlSetup { oidc, identity, instance, tenant, signer, idp }
}

/// A login at the provider with `make` turning the signed Response into what the provider posts; returns the session.
async fn saml_login(s: &SamlSetup, make: impl Fn(String) -> String) -> kernoid_identity::session::NewSession {
    let start = url::Url::parse(&s.oidc.start_idp_login(&s.instance, s.idp, None, None).await.unwrap()).unwrap();
    let query: HashMap<String, String> = start.query_pairs().into_owned().collect();
    let request = miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&query["SAMLRequest"]).unwrap()).unwrap();
    let request = String::from_utf8(request).unwrap();
    let request_id = request.split("ID=\"").nth(1).unwrap().split('"').next().unwrap().to_owned();
    let response = make(sign(&s.signer, &template("ext-bob", SP, &request_id, Utc::now() + Duration::minutes(5))));
    let back = s.oidc.saml_acs(&s.instance, Some(&query["RelayState"]), Some(&encode(&response))).await;
    let fragment: HashMap<String, String> =
        url::form_urlencoded::parse(back.split_once('#').unwrap().1.as_bytes()).into_owned().collect();
    let login = fragment.get("login").unwrap_or_else(|| panic!("{fragment:?}"));
    s.oidc.exchange_idp_login(s.instance.id, login, None, &ClientMeta::default()).await.unwrap().session
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn encrypted_assertions_and_signed_requests(pool: PgPool) {
    let s = saml_setup(&pool, true).await;
    let key = s.oidc.saml_sp_key(&s.instance).await.unwrap();
    // The AuthnRequest is signed with kernoid's key.
    let start = s.oidc.start_idp_login(&s.instance, s.idp, None, None).await.unwrap();
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&start).unwrap().query().unwrap()).unwrap();
    assert!(message.request && message.xml.contains("AuthnRequest"));
    message.verify(std::slice::from_ref(&key.certificate)).unwrap();
    assert!(message.verify(std::slice::from_ref(&s.signer.certificate)).is_err());

    // An encrypted Assertion is decrypted with kernoid's key, then checked as usual.
    let certificate = key.certificate.clone();
    let session = saml_login(&s, |response| encrypt_assertion(&response, &certificate)).await;
    assert_eq!(session.account.address, "bob@firma.de");
    // Encrypted for another key, or tampered: refused.
    let certificates = [s.signer.certificate.clone()];
    let signed = valid(&s.signer);
    let foreign = kernoid_oidc::saml::SpKey::generate("https://other.example/idp/saml").unwrap();
    let for_others = encrypt_assertion(&signed, &foreign.certificate);
    let keys = [key.clone()];
    let with_key = Expected { decryption_keys: &keys, ..expected(&certificates) };
    assert!(verify_response(&encode(&for_others), with_key).is_err());
    let mine = encrypt_assertion(&signed, &key.certificate);
    verify_response(&encode(&mine), with_key).unwrap();
    let start = mine.find("<xenc:CipherValue>").unwrap() + "<xenc:CipherValue>".len() + 10;
    let mut tampered = mine.clone();
    tampered.replace_range(start..start + 1, if &mine[start..start + 1] == "A" { "B" } else { "A" });
    assert!(verify_response(&encode(&tampered), with_key).is_err());
    // Without kernoid's key, an encrypted Assertion cannot be read.
    assert!(verify_response(&encode(&mine), expected(&certificates)).is_err());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn single_logout_both_ways(pool: PgPool) {
    let s = saml_setup(&pool, false).await;
    let key = s.oidc.saml_sp_key(&s.instance).await.unwrap();

    // Logging out at kernoid: the browser goes on to the provider with a signed LogoutRequest.
    let session = saml_login(&s, |response| response).await;
    let next = s.oidc.logout(&s.instance, &session.token).await.unwrap().expect("to the provider");
    assert!(next.starts_with("https://idp.example/saml/slo?"));
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&next).unwrap().query().unwrap()).unwrap();
    message.verify(std::slice::from_ref(&key.certificate)).unwrap();
    assert!(message.xml.contains(">ext-bob</saml:NameID>") && message.xml.contains(">_s1</samlp:SessionIndex>"));
    assert!(s.identity.session(s.instance.id, &session.token).await.is_err());
    let request_id = message.xml.split("ID=\"").nth(1).unwrap().split('"').next().unwrap().to_owned();
    // The provider answers; the browser goes back to the login UI.
    let response = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="{request_id}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#
    );
    let back = s.oidc.saml_slo(&s.instance, &redirect_query("SAMLResponse", &response, "logout", None)).await.unwrap();
    assert_eq!(back.as_deref(), Some("https://login.firma.de/login/account"));
    // Once only.
    assert!(s.oidc.saml_slo(&s.instance, &redirect_query("SAMLResponse", &response, "logout", None)).await.is_err());

    // Logging out at the provider: its signed LogoutRequest ends the sessions of that NameID.
    let session = saml_login(&s, |response| response).await;
    let request = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_idp-lo" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://login.firma.de/idp/saml/slo"><saml:Issuer>{IDP}</saml:Issuer><saml:NameID>ext-bob</saml:NameID><samlp:SessionIndex>_s1</samlp:SessionIndex></samlp:LogoutRequest>"#
    );
    // Unsigned, or signed by someone else: refused, and the session lives on.
    assert!(s.oidc.saml_slo(&s.instance, &redirect_query("SAMLRequest", &request, "r", None)).await.is_err());
    let other = new_signer();
    assert!(s.oidc.saml_slo(&s.instance, &redirect_query("SAMLRequest", &request, "r", Some(&other))).await.is_err());
    s.identity.session(s.instance.id, &session.token).await.unwrap();
    let answer =
        s.oidc.saml_slo(&s.instance, &redirect_query("SAMLRequest", &request, "r", Some(&s.signer))).await.unwrap();
    assert!(s.identity.session(s.instance.id, &session.token).await.is_err(), "the session has ended");
    let answer = answer.expect("a LogoutResponse to the provider");
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&answer).unwrap().query().unwrap()).unwrap();
    message.verify(std::slice::from_ref(&key.certificate)).unwrap();
    assert!(!message.request && message.xml.contains(r#"InResponseTo="_idp-lo""#));
    assert_eq!(message.relay_state.as_deref(), Some("r"));
}

/// A LogoutRequest of the provider with an enveloped signature template, for the HTTP-POST binding.
fn logout_request_template(id: &str) -> String {
    format!(
        r##"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://login.firma.de/idp/saml/slo"><saml:Issuer>{IDP}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature><saml:NameID>ext-bob</saml:NameID><samlp:SessionIndex>_s1</samlp:SessionIndex></samlp:LogoutRequest>"##
    )
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn single_logout_in_the_post_binding(pool: PgPool) {
    let s = saml_setup(&pool, false).await;
    let post = |xml: &str| kernoid_oidc::saml::read_post(Some(&encode(xml)), None, Some("p")).unwrap();
    let session = saml_login(&s, |response| response).await;
    // Unsigned, signed by someone else, or changed after signing: refused, and the session lives on.
    let unsigned = logout_request_template("_post-lo");
    assert!(s.oidc.saml_slo_message(&s.instance, post(&unsigned)).await.is_err());
    let other = new_signer();
    assert!(s.oidc.saml_slo_message(&s.instance, post(&sign(&other, &unsigned))).await.is_err());
    let signed = sign(&s.signer, &unsigned);
    let tampered = signed.replace(">ext-bob<", ">ext-alice<");
    assert!(s.oidc.saml_slo_message(&s.instance, post(&tampered)).await.is_err());
    s.identity.session(s.instance.id, &session.token).await.unwrap();
    // Signed by the provider: the session ends, and kernoid answers in the redirect binding.
    let answer = s.oidc.saml_slo_message(&s.instance, post(&signed)).await.unwrap().expect("a LogoutResponse");
    assert!(s.identity.session(s.instance.id, &session.token).await.is_err(), "the session has ended");
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&answer).unwrap().query().unwrap()).unwrap();
    assert!(!message.request && message.xml.contains(r#"InResponseTo="_post-lo""#));
    assert_eq!(message.relay_state.as_deref(), Some("p"));
    // A message in neither field, or in both, is not one.
    assert!(kernoid_oidc::saml::read_post(None, None, None).is_err());
    assert!(kernoid_oidc::saml::read_post(Some("x"), Some("y"), None).is_err());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_saml_key_changes_with_an_overlap(pool: PgPool) {
    let s = saml_setup(&pool, true).await;
    let old = s.oidc.saml_sp_key(&s.instance).await.unwrap();
    let id = s.oidc.add_saml_key(&s.instance).await.unwrap();
    // Asking again names the waiting key again.
    assert_eq!(s.oidc.add_saml_key(&s.instance).await.unwrap(), id);
    let keys = s.oidc.saml_keys(s.instance.id).await.unwrap();
    let states: Vec<&str> = keys.iter().map(|key| key.state.as_str()).collect();
    assert_eq!(states, ["active", "next"]);
    assert_eq!(keys[0].fingerprint.len(), 64);
    // Both certificates are in the metadata; requests are still signed with the old key.
    let metadata = s.oidc.saml_metadata(&s.instance).await.unwrap();
    assert_eq!(metadata.matches("<md:KeyDescriptor use=\"signing\">").count(), 2);
    assert!(metadata.contains(&STANDARD.encode(&old.certificate)));
    let start = s.oidc.start_idp_login(&s.instance, s.idp, None, None).await.unwrap();
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&start).unwrap().query().unwrap()).unwrap();
    message.verify(std::slice::from_ref(&old.certificate)).unwrap();
    // A provider that took in the new certificate already encrypts for it: decrypted.
    let new_certificate = metadata
        .split("<ds:X509Certificate>")
        .skip(1)
        .map(|rest| STANDARD.decode(rest.split('<').next().unwrap()).unwrap())
        .find(|certificate| *certificate != old.certificate)
        .unwrap();
    let session = saml_login(&s, |response| encrypt_assertion(&response, &new_certificate)).await;
    assert_eq!(session.account.address, "bob@firma.de");

    // Only the waiting key can be activated.
    assert!(s.oidc.activate_saml_key(s.instance.id, keys[0].id).await.is_err());
    s.oidc.activate_saml_key(s.instance.id, id).await.unwrap();
    let new = s.oidc.saml_sp_key(&s.instance).await.unwrap();
    assert_eq!(new.certificate, new_certificate);
    let metadata = s.oidc.saml_metadata(&s.instance).await.unwrap();
    assert_eq!(metadata.matches("<md:KeyDescriptor use=\"signing\">").count(), 1);
    assert!(!metadata.contains(&STANDARD.encode(&old.certificate)));
    let start = s.oidc.start_idp_login(&s.instance, s.idp, None, None).await.unwrap();
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&start).unwrap().query().unwrap()).unwrap();
    message.verify(std::slice::from_ref(&new.certificate)).unwrap();
    // What a provider still encrypts for the retired key is read all the same.
    let old_certificate = old.certificate.clone();
    let session = saml_login(&s, |response| encrypt_assertion(&response, &old_certificate)).await;
    assert_eq!(session.account.address, "bob@firma.de");
    let states: Vec<String> = s.oidc.saml_keys(s.instance.id).await.unwrap().into_iter().map(|key| key.state).collect();
    assert_eq!(states, ["active", "retired"]);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_application_logout_logs_out_at_the_provider_too(pool: PgPool) {
    use kernoid_oidc::{AuthorizeRequest, Authorized, EndSessionRequest, TokenRequest, application::Kind};
    const CALLBACK: &str = "https://app.firma.de/callback";
    const LOGGED_OUT: &str = "https://app.firma.de/logged-out";
    let s = saml_setup(&pool, false).await;
    let session = saml_login(&s, |response| response).await;
    let project = s.identity.add_project(s.tenant, "Project", "test").await.unwrap();
    let (app, secret) = s
        .oidc
        .add_application(s.tenant, project, "App", Kind::Confidential, &[CALLBACK.into()], &[LOGGED_OUT.into()], "test")
        .await
        .unwrap();
    let request = AuthorizeRequest {
        response_type: Some("code".into()),
        client_id: Some(app.to_string()),
        redirect_uri: Some(CALLBACK.into()),
        scope: Some("openid".into()),
        state: Some("xyz".into()),
        nonce: Some("n".into()),
        // PKCE: the challenge of the verifier from RFC 7636, appendix B.
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
        code_challenge_method: Some("S256".into()),
        prompt: None,
        max_age: None,
    };
    let authorized = s.oidc.authorize(&s.instance, &request).await;
    let Ok(Authorized::Login { auth_request, .. }) = authorized else { panic!("expected a login: {authorized:?}") };
    let callback = s.oidc.finish(&s.instance, &auth_request, &session.token, false).await.unwrap();
    let code = url::Url::parse(&callback).unwrap().query_pairs().find(|(k, _)| k == "code").unwrap().1.into_owned();
    let tokens = s
        .oidc
        .token(
            &s.instance,
            &TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(CALLBACK.into()),
                code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into()),
                client_id: Some(app.to_string()),
                client_secret: secret,
                ..TokenRequest::default()
            },
        )
        .await
        .unwrap();

    // The application logs out: the browser goes to the provider first …
    let logout = EndSessionRequest {
        id_token_hint: Some(tokens.id_token.clone()),
        post_logout_redirect_uri: Some(LOGGED_OUT.into()),
        state: Some("bye".into()),
        ..EndSessionRequest::default()
    };
    let ended = s.oidc.end_session(&s.instance, &logout).await.unwrap();
    let next = ended.redirect.expect("to the provider");
    assert!(next.starts_with("https://idp.example/saml/slo?"), "{next}");
    assert!(s.identity.session(s.instance.id, &session.token).await.is_err(), "the session has ended");
    let message = kernoid_oidc::saml::read_redirect(url::Url::parse(&next).unwrap().query().unwrap()).unwrap();
    let request_id = message.xml.split("ID=\"").nth(1).unwrap().split('"').next().unwrap().to_owned();
    // … and, once it answers, back to the application.
    let response = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr2" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" InResponseTo="{request_id}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#
    );
    let back = s.oidc.saml_slo(&s.instance, &redirect_query("SAMLResponse", &response, "logout", None)).await.unwrap();
    assert_eq!(back.as_deref(), Some("https://app.firma.de/logged-out?state=bye"));
}
