// SPDX-License-Identifier: AGPL-3.0-or-later
//! DANE for SMTP (RFC 7672, RFC 0002 10.4). A receiving domain whose MX records are signed with DNSSEC may publish
//! TLSA records (RFC 6698) at `_25._tcp.<host>` for each of its hosts; when they are signed too, kernoid must use TLS
//! with that host and accept only a certificate the records describe.
//!
//! Only the two usages RFC 7672 allows for SMTP count (3.1): DANE-EE (3) names the server's own certificate or key –
//! its names and dates do not matter then – and DANE-TA (2) names a certificate authority in the chain the server
//! sends, from which the chain must hold and name the host. PKIX-TA and PKIX-EE (0, 1) and unknown selectors or
//! matching types make a record unusable and are left out. The resolver that validates DNSSEC is hickory's; the
//! certificates are read with x509-cert and chains checked with rustls-webpki.

use mail_auth::{
    MessageAuthenticator,
    hickory_resolver::proto::{
        dnssec::Proof,
        rr::{
            RData, Record, RecordType,
            rdata::tlsa::{CertUsage, Matching, Selector},
        },
    },
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha512};
use x509_cert::der::{Decode, Encode};

/// How the data of a TLSA record is compared (RFC 6698, 2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaMatching {
    /// The data is the certificate or key itself.
    Full,
    Sha256,
    Sha512,
}

/// One usable TLSA record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaEntry {
    /// DANE-EE (3); otherwise DANE-TA (2).
    pub end_entity: bool,
    /// The public key (SubjectPublicKeyInfo) instead of the whole certificate.
    pub spki: bool,
    pub matching: TlsaMatching,
    pub data: Vec<u8>,
}

/// The usable TLSA records of a host; none usable still means TLS is required (RFC 7672, 2.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tlsa {
    pub entries: Vec<TlsaEntry>,
}

/// What the lookup of a host's TLSA records found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsaLookup {
    /// Signed records: TLS required, the certificate checked against them.
    Secure(Tlsa),
    /// No records, or not signed: DANE does not apply.
    None,
    /// The lookup failed or the signatures do not hold: the host must not be used now (RFC 7672, 2.2).
    Unusable(String),
}

/// The proof DNSSEC gives for a whole answer: the weakest of its records.
fn proof_of(records: &[Record]) -> Proof {
    if records.iter().any(|record| record.proof == Proof::Bogus) {
        Proof::Bogus
    } else if !records.is_empty() && records.iter().all(|record| record.proof == Proof::Secure) {
        Proof::Secure
    } else {
        Proof::Insecure
    }
}

/// `name` as an absolute DNS name.
fn absolute(name: &str) -> String {
    let name = name.trim_end_matches('.');
    format!("{name}.")
}

/// Whether the domain's MX records are signed: only then does DANE apply to its hosts (RFC 7672, 2.2.1).
pub async fn mx_is_secure(resolver: &MessageAuthenticator, domain: &str) -> bool {
    match resolver.resolver().lookup(absolute(domain), RecordType::MX).await {
        Ok(lookup) => {
            let answers: Vec<Record> =
                lookup.answers().iter().filter(|record| record.record_type() == RecordType::MX).cloned().collect();
            proof_of(&answers) == Proof::Secure
        }
        Err(_) => false,
    }
}

/// A TLSA record as kernoid uses it, or `None` if RFC 7672 makes it unusable for SMTP.
fn entry(usage: CertUsage, selector: Selector, matching: Matching, data: &[u8]) -> Option<TlsaEntry> {
    let end_entity = match usage {
        CertUsage::DaneEe => true,
        CertUsage::DaneTa => false,
        _ => return None,
    };
    let spki = match selector {
        Selector::Full => false,
        Selector::Spki => true,
        _ => return None,
    };
    let matching = match matching {
        Matching::Raw => TlsaMatching::Full,
        Matching::Sha256 => TlsaMatching::Sha256,
        Matching::Sha512 => TlsaMatching::Sha512,
        _ => return None,
    };
    let expected_length = match matching {
        TlsaMatching::Full => None,
        TlsaMatching::Sha256 => Some(32),
        TlsaMatching::Sha512 => Some(64),
    };
    if data.is_empty() || expected_length.is_some_and(|length| data.len() != length) {
        return None;
    }
    Some(TlsaEntry { end_entity, spki, matching, data: data.to_vec() })
}

/// The TLSA records of `host` on `port`, as far as DNSSEC vouches for them.
pub async fn lookup(resolver: &MessageAuthenticator, host: &str, port: u16) -> TlsaLookup {
    let name = format!("_{port}._tcp.{}", absolute(host));
    let lookup = match resolver.resolver().lookup(name.as_str(), RecordType::TLSA).await {
        Ok(lookup) => lookup,
        // Denied – and with a validating resolver, a denial that does not hold is an error, not this.
        Err(error) if error.is_no_records_found() || error.is_nx_domain() => return TlsaLookup::None,
        Err(error) => return TlsaLookup::Unusable(format!("looking up {name}: {error}")),
    };
    let records: Vec<Record> =
        lookup.answers().iter().filter(|record| record.record_type() == RecordType::TLSA).cloned().collect();
    if records.is_empty() {
        return TlsaLookup::None;
    }
    match proof_of(&records) {
        Proof::Secure => {}
        Proof::Bogus => return TlsaLookup::Unusable(format!("the signatures of {name} do not hold")),
        _ => return TlsaLookup::None,
    }
    let entries = records
        .iter()
        .filter_map(|record| match &record.data {
            RData::TLSA(tlsa) => entry(tlsa.cert_usage, tlsa.selector, tlsa.matching, &tlsa.cert_data),
            _ => None,
        })
        .collect();
    TlsaLookup::Secure(Tlsa { entries })
}

/// The SubjectPublicKeyInfo of a certificate, DER-encoded.
fn public_key_info(certificate: &[u8]) -> Option<Vec<u8>> {
    let parsed = x509_cert::Certificate::from_der(certificate).ok()?;
    parsed.tbs_certificate.subject_public_key_info.to_der().ok()
}

/// Whether `entry` describes `certificate` (DER).
fn describes(entry: &TlsaEntry, certificate: &[u8]) -> bool {
    let selected = if entry.spki {
        match public_key_info(certificate) {
            Some(info) => info,
            None => return false,
        }
    } else {
        certificate.to_vec()
    };
    match entry.matching {
        TlsaMatching::Full => selected == entry.data,
        TlsaMatching::Sha256 => Sha256::digest(&selected).as_slice() == entry.data.as_slice(),
        TlsaMatching::Sha512 => Sha512::digest(&selected).as_slice() == entry.data.as_slice(),
    }
}

/// Whether the chain from `leaf` holds up to `anchor` (a certificate the server sent) and names one of `names`.
fn chain_holds(
    leaf: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchor: &CertificateDer<'_>,
    names: &[&str],
) -> bool {
    let Ok(anchor) = webpki::anchor_from_trusted_cert(anchor) else { return false };
    let Ok(end_entity) = webpki::EndEntityCert::try_from(leaf) else { return false };
    let algorithms = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.all;
    let anchors = [anchor];
    let verified = end_entity.verify_for_usage(
        algorithms,
        &anchors,
        intermediates,
        UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    );
    let holds = verified.is_ok();
    holds
        && names.iter().any(|name| {
            ServerName::try_from(*name)
                .is_ok_and(|name| end_entity.verify_is_valid_for_subject_name(&name).is_ok())
        })
}

/// Checks the server's certificates against `tlsa`. DANE-EE: the server's own certificate matches, whatever its name
/// and dates (RFC 7672, 3.1.1). DANE-TA: a certificate of the chain matches and the chain up to it holds, for one of
/// `names` (RFC 7672, 3.1.2).
pub fn verify(tlsa: &Tlsa, names: &[&str], certificates: &[CertificateDer<'_>]) -> Result<(), String> {
    // Usable records, none of them: TLS is all they ask for.
    if tlsa.entries.is_empty() {
        return Ok(());
    }
    let Some((leaf, chain)) = certificates.split_first() else {
        return Err("the server sent no certificate".into());
    };
    if tlsa.entries.iter().any(|entry| entry.end_entity && describes(entry, leaf)) {
        return Ok(());
    }
    for (position, candidate) in chain.iter().enumerate() {
        let named = tlsa.entries.iter().any(|entry| !entry.end_entity && describes(entry, candidate));
        if named && chain_holds(leaf, &chain[..position], candidate, names) {
            return Ok(());
        }
    }
    Err("no TLSA record matches the server's certificate".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA and a certificate for `names` it signed: (leaf, CA).
    fn chain(names: &[&str]) -> (CertificateDer<'static>, CertificateDer<'static>) {
        use kernoid_identity::certificate::{Algorithm, KeyPair, Params};
        let ca_key = KeyPair::generate(Algorithm::EcdsaP256).unwrap();
        let ca = Params::ca("kernoid test CA").self_signed(&ca_key).unwrap();
        let key = KeyPair::generate(Algorithm::EcdsaP256).unwrap();
        let leaf = Params::new(names.iter().copied()).signed_by(&key, &ca, &ca_key).unwrap();
        (CertificateDer::from(leaf.der().to_vec()), CertificateDer::from(ca.der().to_vec()))
    }

    fn record(end_entity: bool, spki: bool, matching: TlsaMatching, certificate: &[u8]) -> TlsaEntry {
        let selected = if spki { public_key_info(certificate).unwrap() } else { certificate.to_vec() };
        let data = match matching {
            TlsaMatching::Full => selected,
            TlsaMatching::Sha256 => Sha256::digest(&selected).to_vec(),
            TlsaMatching::Sha512 => Sha512::digest(&selected).to_vec(),
        };
        TlsaEntry { end_entity, spki, matching, data }
    }

    #[test]
    fn dane_ee_names_the_servers_own_certificate_or_key() {
        let (leaf, ca) = chain(&["mx.other.example"]);
        let sent = [leaf.clone(), ca.clone()];
        for spki in [false, true] {
            for matching in [TlsaMatching::Full, TlsaMatching::Sha256, TlsaMatching::Sha512] {
                let tlsa = Tlsa { entries: vec![record(true, spki, matching, &leaf)] };
                // Names do not matter for DANE-EE.
                assert_eq!(verify(&tlsa, &["somewhere.else.example"], &sent), Ok(()), "{spki} {matching:?}");
            }
        }
        // A DANE-EE record of the CA does not make the leaf acceptable.
        let tlsa = Tlsa { entries: vec![record(true, false, TlsaMatching::Sha256, &ca)] };
        assert!(verify(&tlsa, &["mx.other.example"], &sent).is_err());
        // Another server's certificate does not match.
        let (other, _) = chain(&["mx.other.example"]);
        let tlsa = Tlsa { entries: vec![record(true, true, TlsaMatching::Sha256, &other)] };
        assert!(verify(&tlsa, &["mx.other.example"], &sent).is_err());
        assert!(verify(&tlsa, &["mx.other.example"], &[]).is_err());
    }

    #[test]
    fn dane_ta_needs_the_authority_in_the_chain_and_the_name() {
        let (leaf, ca) = chain(&["mx.other.example"]);
        let tlsa = Tlsa { entries: vec![record(false, false, TlsaMatching::Sha256, &ca)] };
        assert_eq!(verify(&tlsa, &["mx.other.example"], &[leaf.clone(), ca.clone()]), Ok(()));
        assert_eq!(verify(&tlsa, &["other.example", "mx.other.example"], &[leaf.clone(), ca.clone()]), Ok(()));
        assert!(verify(&tlsa, &["mx.evil.example"], &[leaf.clone(), ca.clone()]).is_err(), "the name");
        assert!(verify(&tlsa, &["mx.other.example"], std::slice::from_ref(&leaf)).is_err(), "the CA not sent");
        // The key of the authority works as well as its certificate.
        let tlsa = Tlsa { entries: vec![record(false, true, TlsaMatching::Full, &ca)] };
        assert_eq!(verify(&tlsa, &["mx.other.example"], &[leaf.clone(), ca.clone()]), Ok(()));
        // A leaf of another authority, sent with this one: the chain does not hold.
        let (foreign, _) = chain(&["mx.other.example"]);
        assert!(verify(&tlsa, &["mx.other.example"], &[foreign, ca]).is_err());
        // A DANE-TA record of the leaf itself is no authority.
        let tlsa = Tlsa { entries: vec![record(false, false, TlsaMatching::Sha256, &leaf)] };
        assert!(verify(&tlsa, &["mx.other.example"], std::slice::from_ref(&leaf)).is_err());
    }

    #[test]
    fn records_smtp_cannot_use_are_left_out() {
        let digest = vec![7u8; 32];
        assert!(entry(CertUsage::PkixTa, Selector::Full, Matching::Sha256, &digest).is_none());
        assert!(entry(CertUsage::PkixEe, Selector::Full, Matching::Sha256, &digest).is_none());
        assert!(entry(CertUsage::DaneEe, Selector::Unassigned(7), Matching::Sha256, &digest).is_none());
        assert!(entry(CertUsage::DaneEe, Selector::Spki, Matching::Unassigned(9), &digest).is_none());
        assert!(entry(CertUsage::DaneEe, Selector::Spki, Matching::Sha512, &digest).is_none(), "wrong length");
        let usable = entry(CertUsage::DaneTa, Selector::Spki, Matching::Sha256, &digest).unwrap();
        assert!(!usable.end_entity && usable.spki && usable.matching == TlsaMatching::Sha256);
        // Records, none usable: TLS without a check of the certificate.
        assert_eq!(verify(&Tlsa::default(), &["mx.other.example"], &[]), Ok(()));
    }
}
