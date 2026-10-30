// SPDX-License-Identifier: AGPL-3.0-or-later
//! Post-quantum key exchange (RFC 0006, 2): kernoid's TLS prefers the hybrid X25519MLKEM768 over X25519 and still
//! talks to clients without it. A client that offers both sends a key share for each, as browsers do; without
//! rustls's feature `prefer-post-quantum` the server would pick X25519 from them – these tests fail if a build loses
//! it.

use std::sync::Arc;

use kernoid_config::{Http, Tls};
use rustls::{ClientConfig, ClientConnection, NamedGroup, ServerConnection, pki_types::ServerName};

fn server() -> (Arc<rustls::ServerConfig>, rustls::RootCertStore, tempfile::TempDir) {
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate =
        rcgen::CertificateParams::new(vec!["mail.example.org".to_owned()]).unwrap().self_signed(&key).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let tls = Tls { certificate: directory.path().join("cert.pem"), key: directory.path().join("key.pem") };
    std::fs::write(&tls.certificate, certificate.pem()).unwrap();
    std::fs::write(&tls.key, key.serialize_pem()).unwrap();
    let http = Http { tls: Some(tls), ..Http::default() };
    let config = kernoid_server::mail_tls(&http, None, None).unwrap().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.der().clone()).unwrap();
    (config, roots, directory)
}

/// A client with the given key exchange groups, in its order of preference.
fn client(roots: rustls::RootCertStore, groups: &[NamedGroup]) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let all = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS;
    provider.kx_groups = groups.iter().map(|g| *all.iter().find(|k| k.name() == *g).unwrap()).collect();
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Runs a handshake in memory and returns the group both sides agreed on.
fn handshake(server: Arc<rustls::ServerConfig>, client: Arc<ClientConfig>) -> NamedGroup {
    let mut client = ClientConnection::new(client, ServerName::try_from("mail.example.org").unwrap()).unwrap();
    let mut server = ServerConnection::new(server).unwrap();
    let mut buffer = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        buffer.clear();
        while client.wants_write() {
            client.write_tls(&mut buffer).unwrap();
        }
        server.read_tls(&mut buffer.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        buffer.clear();
        while server.wants_write() {
            server.write_tls(&mut buffer).unwrap();
        }
        client.read_tls(&mut buffer.as_slice()).unwrap();
        client.process_new_packets().unwrap();
    }
    let group = server.negotiated_key_exchange_group().unwrap().name();
    assert_eq!(Some(group), client.negotiated_key_exchange_group().map(|g| g.name()));
    group
}

#[test]
fn the_hybrid_key_exchange_is_preferred() {
    let (server, roots, _directory) = server();
    let groups = [NamedGroup::X25519MLKEM768, NamedGroup::X25519];
    assert_eq!(handshake(server, client(roots, &groups)), NamedGroup::X25519MLKEM768);
}

#[test]
fn clients_without_it_still_connect() {
    let (server, roots, _directory) = server();
    assert_eq!(handshake(server, client(roots, &[NamedGroup::X25519])), NamedGroup::X25519);
}

#[test]
fn kernoid_offers_it_first_as_a_client() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    assert_eq!(provider.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
}
