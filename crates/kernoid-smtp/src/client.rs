// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! The SMTP client that delivers the queue (RFC 0002, 10.2). Derived from Stalwart's client
//! (`crates/smtp/src/outbound/client.rs`, v0.16.27): responses read with smtp-proto's parser, `STARTTLS`, the
//! transparency procedure for the data. One command at a time, no pipelining.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use base64::Engine;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use smtp_proto::{EhloResponse, Response, response::parser::ResponseReceiver};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

use crate::session::Io;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("the server's reply could not be read")]
    Unparsable,
    #[error("{}", reply_text(.0))]
    Reply(Response<String>),
    #[error("TLS: {0}")]
    Tls(String),
}

/// `550 5.1.1 Mailbox does not exist`: the code, the enhanced status code if there is one, the text.
fn reply_text(response: &Response<String>) -> String {
    match response.esc {
        [0, 0, 0] => format!("{} {}", response.code, response.message),
        [a, b, c] => format!("{} {a}.{b}.{c} {}", response.code, response.message),
    }
}

impl ClientError {
    /// A `5xx` reply: trying again will not help.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Reply(response) if response.code >= 500)
    }
}

pub(crate) type ClientResult<T> = Result<T, ClientError>;

pub(crate) struct Client {
    stream: Box<dyn Io>,
    timeout: Duration,
}

impl Client {
    pub async fn connect(address: SocketAddr, timeout: Duration) -> ClientResult<Self> {
        let stream =
            tokio::time::timeout(timeout, TcpStream::connect(address)).await.map_err(|_| ClientError::Timeout)??;
        Ok(Self { stream: Box::new(stream), timeout })
    }

    async fn read(&mut self) -> ClientResult<Response<String>> {
        let mut buf = vec![0u8; 8192];
        let mut parser = ResponseReceiver::default();
        loop {
            let read = self.stream.read(&mut buf).await?;
            if read == 0 {
                return Err(ClientError::Unparsable);
            }
            match parser.parse(&mut buf[..read].iter()) {
                Ok(response) => return Ok(response),
                Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
                Err(_) => return Err(ClientError::Unparsable),
            }
        }
    }

    async fn expect(&mut self, codes: std::ops::RangeInclusive<u16>) -> ClientResult<Response<String>> {
        let response = tokio::time::timeout(self.timeout, self.read()).await.map_err(|_| ClientError::Timeout)??;
        if codes.contains(&response.code) { Ok(response) } else { Err(ClientError::Reply(response)) }
    }

    /// Sends one command line and reads the reply.
    pub async fn command(&mut self, line: &str) -> ClientResult<Response<String>> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(line.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream.flush().await?;
            self.read().await
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    async fn command_ok(&mut self, line: &str, codes: std::ops::RangeInclusive<u16>) -> ClientResult<Response<String>> {
        let response = self.command(line).await?;
        if codes.contains(&response.code) { Ok(response) } else { Err(ClientError::Reply(response)) }
    }

    pub async fn greeting(&mut self) -> ClientResult<()> {
        self.expect(220..=220).await.map(drop)
    }

    pub async fn ehlo(&mut self, hostname: &str) -> ClientResult<EhloResponse<String>> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(format!("EHLO {hostname}\r\n").as_bytes()).await?;
            self.stream.flush().await?;
            let mut buf = vec![0u8; 8192];
            let mut collected = Vec::new();
            loop {
                let read = self.stream.read(&mut buf).await?;
                if read == 0 {
                    return Err(ClientError::Unparsable);
                }
                collected.extend_from_slice(&buf[..read]);
                if collected.len() > 64 * 1024 {
                    return Err(ClientError::Unparsable);
                }
                match EhloResponse::parse(&mut collected.iter()) {
                    Ok(response) => return Ok(response),
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
                    Err(smtp_proto::Error::InvalidResponse { code }) => {
                        return match ResponseReceiver::from_code(code).parse(&mut collected.iter()) {
                            Ok(response) => Err(ClientError::Reply(response)),
                            Err(smtp_proto::Error::NeedsMoreData { .. }) => continue,
                            Err(_) => Err(ClientError::Unparsable),
                        };
                    }
                    Err(_) => return Err(ClientError::Unparsable),
                }
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    /// `STARTTLS`, then the handshake with `config`; the server's certificates come back for DANE.
    pub async fn start_tls(
        mut self,
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
    ) -> ClientResult<(Self, Vec<CertificateDer<'static>>)> {
        self.command_ok("STARTTLS", 220..=220).await?;
        self.into_tls(config, name).await
    }

    /// The TLS handshake on the connection as it is (port 465, or after `STARTTLS`).
    pub async fn into_tls(
        self,
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
    ) -> ClientResult<(Self, Vec<CertificateDer<'static>>)> {
        let connector = TlsConnector::from(config);
        let tls = tokio::time::timeout(self.timeout, connector.connect(name, self.stream))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Tls(error.to_string()))?;
        let certificates = tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|certificates| certificates.iter().map(|c| c.clone().into_owned()).collect())
            .unwrap_or_default();
        Ok((Self { stream: Box::new(tls), timeout: self.timeout }, certificates))
    }

    pub async fn auth_plain(&mut self, username: &str, password: &str) -> ClientResult<()> {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
        self.command_ok(&format!("AUTH PLAIN {token}"), 235..=235).await.map(drop)
    }

    pub async fn mail_from(&mut self, from: &str, size: usize, utf8: bool) -> ClientResult<()> {
        let utf8 = if utf8 { " SMTPUTF8" } else { "" };
        self.command_ok(&format!("MAIL FROM:<{from}> SIZE={size}{utf8}"), 250..=259).await.map(drop)
    }

    /// The reply to `RCPT TO`; a refusal is a reply, not an error.
    pub async fn rcpt_to(&mut self, to: &str) -> ClientResult<Response<String>> {
        self.command(&format!("RCPT TO:<{to}>")).await
    }

    pub async fn rset(&mut self) -> ClientResult<()> {
        self.command_ok("RSET", 250..=259).await.map(drop)
    }

    /// `DATA`, the message with the transparency procedure (RFC 5321, 4.5.2), and the final reply.
    pub async fn data(&mut self, message: &[u8]) -> ClientResult<Response<String>> {
        self.command_ok("DATA", 354..=354).await?;
        tokio::time::timeout(self.timeout * 4, async {
            // At the start of the data, as after every line end, a leading dot is doubled.
            let mut line_start = true;
            let mut last = 0;
            for (position, byte) in message.iter().enumerate() {
                if *byte == b'.' && line_start {
                    self.stream.write_all(&message[last..position]).await?;
                    self.stream.write_all(b".").await?;
                    last = position;
                }
                line_start = *byte == b'\n' || *byte == b'\r';
            }
            self.stream.write_all(&message[last..]).await?;
            if !message.ends_with(b"\r\n") {
                self.stream.write_all(b"\r\n").await?;
            }
            self.stream.write_all(b".\r\n").await?;
            self.stream.flush().await?;
            self.read().await
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub async fn quit(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            if self.stream.write_all(b"QUIT\r\n").await.is_ok() && self.stream.flush().await.is_ok() {
                let mut buf = [0u8; 128];
                let _ = self.stream.read(&mut buf).await;
            }
        })
        .await;
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// TLS that checks the certificate against the web's root certificates (MTA-STS, the relay).
pub(crate) fn verified_tls() -> Arc<ClientConfig> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("rustls' default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// TLS that takes any certificate: opportunistic TLS (RFC 7435) – better than plain text, and no worse when the
/// certificate is not checked, since nothing published says what it should be. DANE checks the certificate itself,
/// after the handshake, against the TLSA records.
pub(crate) fn unverified_tls() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("rustls' default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider())))
            .with_no_client_auth(),
    )
}

/// Accepts every certificate, but still checks that the server holds its key (the handshake signatures).
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
