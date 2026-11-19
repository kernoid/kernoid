// SPDX-License-Identifier: AGPL-3.0-or-later
//! Submitting through a relay: a relay in the test, with a certificate of a CA of the test, both ways of TLS.

use std::{sync::Arc, time::Duration};

use kernoid_smtp_client::{Relay, submit_with};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A CA, the relay's certificate for `localhost`, and the client's configuration trusting the CA.
fn certificates() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap().signed_by(&key, &issuer).unwrap();
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_cert.der().to_vec())).unwrap();
    let client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// One SMTP conversation; every line the client sends goes to `lines`.
async fn converse(stream: impl AsyncRead + AsyncWrite + Unpin, lines: &mpsc::UnboundedSender<String>, greet: bool) {
    let mut stream = BufReader::new(stream);
    if greet {
        stream.get_mut().write_all(b"220 relay.test ESMTP\r\n").await.unwrap();
    }
    let mut data = false;
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await.unwrap() == 0 {
            return;
        }
        let line = line.trim_end().to_owned();
        lines.send(line.clone()).unwrap();
        let reply: &[u8] = if data {
            if line == "." {
                data = false;
                b"250 queued\r\n"
            } else {
                continue;
            }
        } else if line.starts_with("EHLO") {
            b"250-relay.test\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 SIZE 1000000\r\n"
        } else if line == "STARTTLS" {
            stream.get_mut().write_all(b"220 go ahead\r\n").await.unwrap();
            return;
        } else if line.starts_with("AUTH PLAIN") {
            b"235 ok\r\n"
        } else if line == "DATA" {
            data = true;
            b"354 go on\r\n"
        } else if line == "QUIT" {
            stream.get_mut().write_all(b"221 bye\r\n").await.unwrap();
            return;
        } else {
            b"250 ok\r\n"
        };
        stream.get_mut().write_all(reply).await.unwrap();
    }
}

#[tokio::test]
async fn messages_go_out_through_a_relay_over_tls() {
    let (server, client) = certificates();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (lines, mut received) = mpsc::unbounded_channel();
    let acceptor = TlsAcceptor::from(server);
    tokio::spawn(async move {
        // Implicit TLS first, then STARTTLS.
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        tls_greet_and_converse(tls, &lines).await;
        let (tcp, _) = listener.accept().await.unwrap();
        let mut plain = tcp;
        plain.write_all(b"220 relay.test ESMTP\r\n").await.unwrap();
        converse(&mut plain, &lines, false).await;
        let tls = acceptor.accept(plain).await.unwrap();
        converse(tls, &lines, false).await;
    });
    let message = b"From: a@x.test\r\nTo: b@y.test\r\nSubject: code\r\n\r\n.a dot first\r\n";
    for implicit_tls in [true, false] {
        let relay = Relay {
            host: "localhost".into(),
            port,
            implicit_tls,
            credentials: Some(("kernoid".into(), "secret".into())),
        };
        submit_with(
            client.clone(),
            &relay,
            "x.test",
            "a@x.test",
            &["b@y.test".to_owned()],
            message,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    }
    let mut all = Vec::new();
    while let Ok(line) = received.try_recv() {
        all.push(line);
    }
    // Both times: logged in, the sender, the recipient, the data with its leading dot doubled.
    assert_eq!(all.iter().filter(|line| line.starts_with("AUTH PLAIN ")).count(), 2);
    assert_eq!(all.iter().filter(|line| *line == "RCPT TO:<b@y.test>").count(), 2);
    assert_eq!(all.iter().filter(|line| *line == "..a dot first").count(), 2);
    assert!(all.contains(&"STARTTLS".to_owned()));
}

async fn tls_greet_and_converse(mut tls: impl AsyncRead + AsyncWrite + Unpin, lines: &mpsc::UnboundedSender<String>) {
    tls.write_all(b"220 relay.test ESMTP\r\n").await.unwrap();
    converse(tls, lines, false).await;
}
