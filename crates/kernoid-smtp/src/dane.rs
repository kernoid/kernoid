// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! DANE for SMTP (RFC 7672, RFC 0002 10.4): TLSA records of an MX host, signed with DNSSEC, say which certificate
//! it presents. Derived from Stalwart's `crates/smtp/src/outbound/dane` (v0.16.27): the lookup that takes only
//! validated records, and the matching of DANE-EE (3) and DANE-TA (2) records; certificates are read with x509-cert
//! and chains checked with rustls-webpki. DNSSEC itself is validated by hickory's resolver.

use mail_auth::{
    MessageAuthenticator,
    hickory_resolver::proto::{
        dnssec::Proof,
        rr::{
            RData, RecordType,
            rdata::tlsa::{CertUsage, Matching, Selector},
        },
    },
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha512};
use x509_cert::der::{Decode, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaMatching {
    Full,
    Sha256,
    Sha512,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsaLookup {
    /// Signed records: TLS required, the certificate checked against them.
    Secure(Tlsa),
    /// No records, or not signed: DANE does not apply.
    None,
    /// The lookup failed or the signatures do not hold: the host must not be used now (RFC 7672, 2.2).
    Unusable(String),
}

/// Whether the domain's MX records are signed: only then does DANE apply to its hosts (RFC 7672, 2.2.1).
pub async fn mx_is_secure(resolver: &MessageAuthenticator, domain: &str) -> bool {
    match resolver.resolver().lookup(format!("{domain}."), RecordType::MX).await {
        Ok(lookup) => {
            !lookup.answers().is_empty() && lookup.answers().iter().all(|record| record.proof == Proof::Secure)
        }
        Err(_) => false,
    }
}

/// The TLSA records of `host` on `port`, as far as DNSSEC vouches for them.
pub async fn lookup(resolver: &MessageAuthenticator, host: &str, port: u16) -> TlsaLookup {
    let lookup = match resolver.resolver().lookup(format!("_{port}._tcp.{host}."), RecordType::TLSA).await {
        Ok(lookup) => lookup,
        Err(error) if error.is_no_records_found() || error.is_nx_domain() => return TlsaLookup::None,
        Err(error) => return TlsaLookup::Unusable(error.to_string()),
    };
    let mut entries = Vec::new();
    for record in lookup.answers() {
        let RData::TLSA(tlsa) = &record.data else { continue };
        match record.proof {
            Proof::Secure => {}
            Proof::Bogus => return TlsaLookup::Unusable("the TLSA records' signatures do not hold".into()),
            Proof::Insecure | Proof::Indeterminate => return TlsaLookup::None,
        }
        let end_entity = match tlsa.cert_usage {
            CertUsage::DaneEe => true,
            CertUsage::DaneTa => false,
            _ => continue,
        };
        let spki = match tlsa.selector {
            Selector::Spki => true,
            Selector::Full => false,
            _ => continue,
        };
        let matching = match tlsa.matching {
            Matching::Raw => TlsaMatching::Full,
            Matching::Sha256 => TlsaMatching::Sha256,
            Matching::Sha512 => TlsaMatching::Sha512,
            _ => continue,
        };
        entries.push(TlsaEntry { end_entity, spki, matching, data: tlsa.cert_data.clone() });
    }
    if lookup.answers().is_empty() { TlsaLookup::None } else { TlsaLookup::Secure(Tlsa { entries }) }
}

fn spki(der: &[u8]) -> Option<Vec<u8>> {
    let certificate = x509_cert::Certificate::from_der(der).ok()?;
    certificate.tbs_certificate.subject_public_key_info.to_der().ok()
}

fn matches(entry: &TlsaEntry, certificate: &[u8]) -> bool {
    let selected = if entry.spki {
        match spki(certificate) {
            Some(spki) => spki,
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

/// Checks the server's certificates against `tlsa`. DANE-EE: the server's own certificate matches, whatever its name
/// and dates (RFC 7672, 3.1.1). DANE-TA: a certificate of the chain matches and the chain up to it holds, for one of
/// `names` (RFC 7672, 3.1.2).
pub fn verify(tlsa: &Tlsa, names: &[&str], certificates: &[CertificateDer<'_>]) -> Result<(), String> {
    if tlsa.entries.is_empty() {
        return Ok(());
    }
    let Some(leaf) = certificates.first() else { return Err("the server presented no certificate".into()) };
    if tlsa.entries.iter().filter(|entry| entry.end_entity).any(|entry| matches(entry, leaf.as_ref())) {
        return Ok(());
    }
    let anchors: Vec<_> = certificates[1..]
        .iter()
        .filter(|certificate| {
            tlsa.entries.iter().filter(|entry| !entry.end_entity).any(|entry| matches(entry, certificate.as_ref()))
        })
        .filter_map(|certificate| webpki::anchor_from_trusted_cert(certificate).ok().map(|anchor| anchor.to_owned()))
        .collect();
    if !anchors.is_empty()
        && let Ok(end_entity) = webpki::EndEntityCert::try_from(leaf)
        && end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &certificates[1..],
                UnixTime::now(),
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .is_ok()
        && names.iter().any(|name| {
            ServerName::try_from(*name).is_ok_and(|name| end_entity.verify_is_valid_for_subject_name(&name).is_ok())
        })
    {
        return Ok(());
    }
    Err("no certificate matches the TLSA records".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(names: &[&str]) -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn dane_ee_matches_the_servers_own_key_or_certificate() {
        let leaf = certificate(&["mx.example.org"]);
        let other = certificate(&["mx.example.org"]);
        let key_hash = Sha256::digest(spki(leaf.as_ref()).unwrap()).to_vec();
        let by_key = Tlsa {
            entries: vec![TlsaEntry { end_entity: true, spki: true, matching: TlsaMatching::Sha256, data: key_hash }],
        };
        assert!(verify(&by_key, &["mx.example.org"], std::slice::from_ref(&leaf)).is_ok());
        assert!(verify(&by_key, &["mx.example.org"], &[other]).is_err());
        // DANE-EE does not look at the name.
        assert!(verify(&by_key, &["elsewhere.example"], std::slice::from_ref(&leaf)).is_ok());

        let whole = Tlsa {
            entries: vec![TlsaEntry {
                end_entity: true,
                spki: false,
                matching: TlsaMatching::Sha512,
                data: Sha512::digest(leaf.as_ref()).to_vec(),
            }],
        };
        assert!(verify(&whole, &[], std::slice::from_ref(&leaf)).is_ok());
        assert!(verify(&whole, &[], &[]).is_err());
        // Signed records, none usable: TLS without checking.
        assert!(verify(&Tlsa::default(), &[], &[]).is_ok());
    }

    #[test]
    fn dane_ta_needs_the_chain_and_the_name() {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap()).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["mx.example.org".to_owned()]).unwrap();
        let leaf = rcgen::CertifiedIssuer::signed_by(leaf_params, rcgen::KeyPair::generate().unwrap(), &ca).unwrap();
        let chain = [leaf.as_ref().der().clone(), ca.as_ref().der().clone()];
        let tlsa = Tlsa {
            entries: vec![TlsaEntry {
                end_entity: false,
                spki: false,
                matching: TlsaMatching::Sha256,
                data: Sha256::digest(ca.as_ref().der().as_ref()).to_vec(),
            }],
        };
        assert!(verify(&tlsa, &["mx.example.org"], &chain).is_ok());
        assert!(verify(&tlsa, &["other.example.org"], &chain).is_err(), "the name must fit");
        assert!(verify(&tlsa, &["mx.example.org"], &chain[..1]).is_err(), "the anchor must be in the chain");
    }
}
