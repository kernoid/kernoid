// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's SMTP client: it delivers the queue of the mail store (RFC 0002, 10.2, in kernoid-smtp) and submits
//! kernoid's own messages – registration codes – through the operator's relay where kernoid runs no mail
//! (`mail.notification_relay`, RFC 0009, 3; [`submit`]).
//!
//! It speaks RFC 5321 one command at a time: every command waits for its reply, so no pipelining (RFC 2920) is
//! needed and a broken reply is found where it happens. Replies are read with smtp-proto's parsers – a reply is
//! complete when smtp-proto says so, an `EHLO` reply is read for its extensions. `STARTTLS` (RFC 3207) refuses a
//! server that sends anything after its `220`, so that nothing said in plain text is taken for what comes over TLS.
//! The message goes with `DATA` and the transparency procedure (RFC 5321, 4.5.2); `SIZE` (RFC 1870) and `SMTPUTF8`
//! (RFC 6531) are given only to servers that offer them.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use base64::Engine;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use smtp_proto::{
    EXT_SIZE, EXT_SMTP_UTF8, EhloResponse, Response,
    response::parser::{MAX_RESPONSE_LENGTH, ResponseReceiver},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

/// The most a reply may take, its lines together – an `EHLO` reply has many.
const MAX_REPLY: usize = 4 * MAX_RESPONSE_LENGTH;

/// How much of the message is written at once.
const WRITE_CHUNK: usize = 64 * 1024;

/// A connection the client talks over: TCP, or TLS on it.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
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

/// A reply as one line for logs and bounces: `550 5.1.1 Mailbox does not exist`, the enhanced status code
/// (RFC 2034) only where the server gave one.
fn reply_text(response: &Response<String>) -> String {
    let message = response.message.replace(['\r', '\n'], " ");
    match response.esc {
        [0, 0, 0] => format!("{} {}", response.code, message.trim()),
        [class, subject, detail] => format!("{} {class}.{subject}.{detail} {}", response.code, message.trim()),
    }
}

impl ClientError {
    /// A `5xx` reply: trying again will not help.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Reply(response) if response.code >= 500)
    }
}

pub type ClientResult<T> = Result<T, ClientError>;

/// A reply made here, for what the client refuses before the server is asked.
fn local_reply(code: u16, esc: [u8; 3], message: &str) -> ClientError {
    ClientError::Reply(Response { code, esc, message: message.to_owned() })
}

/// An SMTP session with one server.
pub struct Client {
    stream: Box<dyn Io>,
    timeout: Duration,
    /// Bytes read from the server that no reply took yet.
    unread: Vec<u8>,
    /// The extensions of the last `EHLO` reply (smtp-proto's `EXT_*`).
    extensions: u32,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("timeout", &self.timeout).finish_non_exhaustive()
    }
}

impl Client {
    fn over(stream: Box<dyn Io>, timeout: Duration) -> Self {
        Self { stream, timeout, unread: Vec::new(), extensions: 0 }
    }

    /// Opens a TCP connection to `address` within `timeout`, which also bounds every command after it.
    pub async fn connect(address: SocketAddr, timeout: Duration) -> ClientResult<Self> {
        let stream =
            tokio::time::timeout(timeout, TcpStream::connect(address)).await.map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        Ok(Self::over(Box::new(stream), timeout))
    }

    /// A session over a connection opened elsewhere – tests talk to a server in memory.
    pub fn with_stream(stream: impl Io + 'static, timeout: Duration) -> Self {
        Self::over(Box::new(stream), timeout)
    }

    async fn write(&mut self, bytes: &[u8]) -> ClientResult<()> {
        tokio::time::timeout(self.timeout, self.stream.write_all(bytes)).await.map_err(|_| ClientError::Timeout)??;
        Ok(())
    }

    async fn flush(&mut self) -> ClientResult<()> {
        tokio::time::timeout(self.timeout, self.stream.flush()).await.map_err(|_| ClientError::Timeout)??;
        Ok(())
    }

    /// Reads more of what the server sends into `unread`.
    async fn fill(&mut self) -> ClientResult<()> {
        let mut buffer = [0u8; 4096];
        let read = tokio::time::timeout(self.timeout, self.stream.read(&mut buffer))
            .await
            .map_err(|_| ClientError::Timeout)??;
        if read == 0 {
            return Err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the server closed the connection").into()
            );
        }
        self.unread.extend_from_slice(&buffer[..read]);
        Ok(())
    }

    /// The next reply, and its bytes as they came.
    async fn reply_with_bytes(&mut self) -> ClientResult<(Response<String>, Vec<u8>)> {
        let mut receiver = ResponseReceiver::default();
        let mut taken = Vec::new();
        loop {
            if !self.unread.is_empty() {
                let mut bytes = self.unread.iter();
                let parsed = receiver.parse(&mut bytes);
                let used = self.unread.len() - bytes.len();
                taken.extend(self.unread.drain(..used));
                match parsed {
                    Ok(response) => {
                        // The rest of the reply's last line belongs to it.
                        if let Some(end) = self.unread.iter().position(|byte| *byte == b'\n') {
                            taken.extend(self.unread.drain(..=end));
                        } else if !self.unread.is_empty() || !taken.ends_with(b"\n") {
                            return Err(ClientError::Unparsable);
                        }
                        return Ok((response, taken));
                    }
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
                    Err(_) => return Err(ClientError::Unparsable),
                }
            }
            if taken.len() + self.unread.len() > MAX_REPLY {
                return Err(ClientError::Unparsable);
            }
            self.fill().await?;
        }
    }

    async fn reply(&mut self) -> ClientResult<Response<String>> {
        Ok(self.reply_with_bytes().await?.0)
    }

    /// Sends one command line and reads the reply.
    pub async fn command(&mut self, line: &str) -> ClientResult<Response<String>> {
        if line.contains(['\r', '\n']) {
            return Err(local_reply(501, [5, 5, 2], "a command is one line"));
        }
        let mut bytes = Vec::with_capacity(line.len() + 2);
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        self.write(&bytes).await?;
        self.flush().await?;
        self.reply().await
    }

    /// A command that must succeed (`2xx`); any other reply is the error.
    async fn expect(&mut self, line: &str) -> ClientResult<Response<String>> {
        let response = self.command(line).await?;
        if (200..300).contains(&response.code) { Ok(response) } else { Err(ClientError::Reply(response)) }
    }

    /// The server's greeting (`220`).
    pub async fn greeting(&mut self) -> ClientResult<()> {
        let response = self.reply().await?;
        if response.code == 220 { Ok(()) } else { Err(ClientError::Reply(response)) }
    }

    /// `EHLO`, or `HELO` with a server that does not know `EHLO` (RFC 5321, 3.2): the extensions the server offers.
    pub async fn ehlo(&mut self, hostname: &str) -> ClientResult<EhloResponse<String>> {
        self.write(format!("EHLO {hostname}\r\n").as_bytes()).await?;
        self.flush().await?;
        let (response, bytes) = self.reply_with_bytes().await?;
        let ehlo = match response.code {
            250 => EhloResponse::parse(&mut bytes.iter()).map_err(|_| ClientError::Unparsable)?,
            500 | 502 => {
                self.expect(&format!("HELO {hostname}")).await?;
                EhloResponse::new(hostname.to_owned())
            }
            _ => return Err(ClientError::Reply(response)),
        };
        self.extensions = ehlo.capabilities;
        Ok(ehlo)
    }

    /// `STARTTLS`, then the handshake with `config`; the server's certificates come back for DANE.
    pub async fn start_tls(
        mut self,
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
    ) -> ClientResult<(Self, Vec<CertificateDer<'static>>)> {
        let response = self.command("STARTTLS").await?;
        if response.code != 220 {
            return Err(ClientError::Reply(response));
        }
        // Whatever came along with the 220 was said in plain text, where anyone could have put it (RFC 3207, 6).
        if !self.unread.is_empty() {
            return Err(ClientError::Tls("the server sent data after its STARTTLS reply".into()));
        }
        self.into_tls(config, name).await
    }

    /// The TLS handshake on the connection as it is (port 465, or after `STARTTLS`).
    pub async fn into_tls(
        self,
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
    ) -> ClientResult<(Self, Vec<CertificateDer<'static>>)> {
        let timeout = self.timeout;
        let connector = TlsConnector::from(config);
        let tls = tokio::time::timeout(timeout, connector.connect(name, self.stream))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Tls(error.to_string()))?;
        let certificates: Vec<CertificateDer<'static>> = tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|certificates| certificates.iter().map(|certificate| certificate.clone().into_owned()).collect())
            .unwrap_or_default();
        // The extensions are asked for again over TLS (RFC 3207, 4.2).
        Ok((Self::over(Box::new(tls), timeout), certificates))
    }

    /// `AUTH PLAIN` (RFC 4954, RFC 4616) with the credentials in the first line.
    pub async fn auth_plain(&mut self, username: &str, password: &str) -> ClientResult<()> {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
        let response = self.command(&format!("AUTH PLAIN {token}")).await?;
        if response.code == 235 { Ok(()) } else { Err(ClientError::Reply(response)) }
    }

    /// `MAIL FROM` with the message's size if the server takes `SIZE`, and `SMTPUTF8` where an address needs it.
    pub async fn mail_from(&mut self, from: &str, size: usize, utf8: bool) -> ClientResult<()> {
        let mut line = format!("MAIL FROM:<{from}>");
        if self.extensions & EXT_SIZE != 0 {
            line.push_str(&format!(" SIZE={size}"));
        }
        if utf8 {
            if self.extensions & EXT_SMTP_UTF8 == 0 {
                return Err(local_reply(553, [5, 6, 7], "the server does not take internationalised addresses"));
            }
            line.push_str(" SMTPUTF8");
        }
        self.expect(&line).await.map(drop)
    }

    /// The reply to `RCPT TO`; a refusal is a reply, not an error.
    pub async fn rcpt_to(&mut self, to: &str) -> ClientResult<Response<String>> {
        self.command(&format!("RCPT TO:<{to}>")).await
    }

    pub async fn rset(&mut self) -> ClientResult<()> {
        self.expect("RSET").await.map(drop)
    }

    /// `DATA`, the message with the transparency procedure (RFC 5321, 4.5.2), and the final reply. A server that
    /// does not answer `DATA` with `354` gives that reply instead.
    pub async fn data(&mut self, message: &[u8]) -> ClientResult<Response<String>> {
        let response = self.command("DATA").await?;
        if response.code != 354 {
            return Ok(response);
        }
        let stuffed = dot_stuffed(message);
        for chunk in stuffed.chunks(WRITE_CHUNK) {
            self.write(chunk).await?;
        }
        self.flush().await?;
        self.reply().await
    }

    /// `QUIT`, and the connection closed; what goes wrong now no longer matters.
    pub async fn quit(mut self) {
        if self.command("QUIT").await.is_ok() {
            let _ = tokio::time::timeout(self.timeout, self.stream.shutdown()).await;
        }
    }
}

/// The message as it goes after `DATA`: every line that starts with a dot gets a second one, lines end in CRLF,
/// and the line with the dot alone ends it (RFC 5321, 4.5.2).
fn dot_stuffed(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + message.len() / 64 + 5);
    let mut line_start = true;
    let mut previous = 0u8;
    for &byte in message {
        if line_start && byte == b'.' {
            out.push(b'.');
        }
        // A bare LF becomes CRLF: it is the only line end SMTP knows.
        if byte == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(byte);
        line_start = byte == b'\n';
        previous = byte;
    }
    if !out.is_empty() && !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// TLS that checks the certificate against the web's root certificates (MTA-STS, the relay).
pub fn verified_tls() -> Arc<ClientConfig> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("AWS-LC supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// TLS that takes any certificate: opportunistic TLS (RFC 7435) – better than plain text, and no worse when the
/// certificate is not checked, since nothing published says what it should be. DANE checks the certificate itself,
/// after the handshake, against the TLSA records.
pub fn unverified_tls() -> Arc<ClientConfig> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("AWS-LC supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    Arc::new(config)
}

/// Accepts every certificate, but still checks that the server holds its key (the handshake signatures).
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
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

/// A relay (smarthost) to submit through.
#[derive(Debug, Clone)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// TLS from the start (port 465) instead of `STARTTLS`.
    pub implicit_tls: bool,
    pub credentials: Option<(String, String)>,
}

/// Submits one message through `relay` – always over TLS with a certificate valid for the relay's host – and logs in
/// if there are credentials. `hostname` is said in `EHLO`.
pub async fn submit(
    relay: &Relay,
    hostname: &str,
    from: &str,
    to: &[String],
    message: &[u8],
    timeout: Duration,
) -> ClientResult<()> {
    submit_with(verified_tls(), relay, hostname, from, to, message, timeout).await
}

/// [`submit`] with a TLS configuration of one's own – for a relay with a certificate of a private CA, and for tests.
#[allow(clippy::too_many_arguments)]
pub async fn submit_with(
    tls: Arc<ClientConfig>,
    relay: &Relay,
    hostname: &str,
    from: &str,
    to: &[String],
    message: &[u8],
    timeout: Duration,
) -> ClientResult<()> {
    let name = ServerName::try_from(relay.host.clone()).map_err(|error| ClientError::Tls(error.to_string()))?;
    let addresses: Vec<SocketAddr> =
        tokio::time::timeout(timeout, tokio::net::lookup_host((relay.host.as_str(), relay.port)))
            .await
            .map_err(|_| ClientError::Timeout)??
            .collect();
    let mut last = None;
    for address in addresses {
        match Client::connect(address, timeout).await {
            Ok(client) => return deliver_to_relay(client, tls, name, relay, hostname, from, to, message).await,
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, format!("{} has no address", relay.host)).into()
    }))
}

/// The session with the relay, once connected.
#[allow(clippy::too_many_arguments)]
async fn deliver_to_relay(
    mut client: Client,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
    relay: &Relay,
    hostname: &str,
    from: &str,
    to: &[String],
    message: &[u8],
) -> ClientResult<()> {
    if relay.implicit_tls {
        client = client.into_tls(tls.clone(), name.clone()).await?.0;
    }
    client.greeting().await?;
    let ehlo = client.ehlo(hostname).await?;
    if !relay.implicit_tls {
        if !ehlo.has_capability(smtp_proto::EXT_START_TLS) {
            return Err(ClientError::Tls(format!("{} offers no STARTTLS", relay.host)));
        }
        client = client.start_tls(tls, name).await?.0;
        client.ehlo(hostname).await?;
    }
    if let Some((username, password)) = &relay.credentials {
        client.auth_plain(username, password).await?;
    }
    let utf8 = !from.is_ascii() || to.iter().any(|address| !address.is_ascii());
    client.mail_from(from, message.len(), utf8).await?;
    for recipient in to {
        let response = client.rcpt_to(recipient).await?;
        if !(200..300).contains(&response.code) {
            return Err(ClientError::Reply(response));
        }
    }
    let response = client.data(message).await?;
    if !(200..300).contains(&response.code) {
        return Err(ClientError::Reply(response));
    }
    client.quit().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream};

    /// A server in memory that answers each line the client sends with the next of `replies`; the lines it got come
    /// back when the client is done.
    fn server(greeting: &str, replies: &[&str]) -> (Client, tokio::task::JoinHandle<Vec<String>>) {
        let (near, far) = tokio::io::duplex(64 * 1024);
        let greeting = greeting.to_owned();
        let replies: Vec<String> = replies.iter().map(|reply| (*reply).to_owned()).collect();
        let task = tokio::spawn(async move { serve(far, greeting, replies).await });
        (Client::with_stream(near, Duration::from_secs(5)), task)
    }

    async fn serve(stream: DuplexStream, greeting: String, replies: Vec<String>) -> Vec<String> {
        let mut stream = BufReader::new(stream);
        let mut lines = Vec::new();
        if !greeting.is_empty() {
            stream.get_mut().write_all(greeting.as_bytes()).await.unwrap();
        }
        let mut replies = replies.into_iter();
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                return lines;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            lines.push(line.clone());
            if in_data && line != "." {
                continue;
            }
            let Some(reply) = replies.next() else { return lines };
            in_data = reply.starts_with("354");
            stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
        }
    }

    const EHLO: &str = "250-mx.other.example\r\n250-SIZE 1000\r\n250-PIPELINING\r\n250 SMTPUTF8\r\n";

    #[tokio::test]
    async fn a_message_goes_with_its_dots_doubled() {
        let (mut client, task) =
            server("220 mx ESMTP\r\n", &[EHLO, "250 ok\r\n", "250 ok\r\n", "354 go on\r\n", "250 2.0.0 queued\r\n"]);
        client.greeting().await.unwrap();
        let ehlo = client.ehlo("kernoid.example").await.unwrap();
        assert!(ehlo.has_capability(smtp_proto::EXT_SIZE));
        client.mail_from("a@kernoid.example", 42, false).await.unwrap();
        assert_eq!(client.rcpt_to("b@other.example").await.unwrap().code, 250);
        let reply = client.data(b"Subject: x\r\n\r\n.starts with a dot\nbare line end").await.unwrap();
        assert_eq!((reply.code, reply.esc), (250, [2, 0, 0]));
        drop(client);
        let lines = task.await.unwrap();
        assert_eq!(lines[1], "MAIL FROM:<a@kernoid.example> SIZE=42");
        assert!(lines.contains(&"..starts with a dot".to_owned()));
        assert!(lines.contains(&"bare line end".to_owned()));
        assert_eq!(lines.last().unwrap(), ".");
    }

    #[tokio::test]
    async fn refusals_are_replies_and_say_whether_they_are_permanent() {
        let (mut client, _task) = server(
            "220 mx\r\n",
            &[
                "250 mx\r\n",
                "250 ok\r\n",
                "550-5.1.1 No such\r\n550 5.1.1 user\r\n",
                "451 4.3.0 later\r\n",
                "554 no data for you\r\n",
            ],
        );
        client.greeting().await.unwrap();
        client.ehlo("kernoid.example").await.unwrap();
        // Without SIZE offered, no SIZE given; and no SMTPUTF8 to a server that lacks it.
        let error = client.mail_from("ä@kernoid.example", 10, true).await.unwrap_err();
        assert!(error.is_permanent(), "{error}");
        client.mail_from("a@kernoid.example", 10, false).await.unwrap();
        let refused = client.rcpt_to("nobody@other.example").await.unwrap();
        let error = ClientError::Reply(refused);
        assert!(error.is_permanent());
        assert_eq!(error.to_string(), "550 5.1.1 No such user");
        let later = ClientError::Reply(client.rcpt_to("busy@other.example").await.unwrap());
        assert!(!later.is_permanent());
        assert_eq!(later.to_string(), "451 4.3.0 later");
        // DATA refused: the reply, not an error.
        assert_eq!(client.data(b"x").await.unwrap().code, 554);
    }

    #[tokio::test]
    async fn broken_servers_are_errors() {
        // Not SMTP at all.
        let (mut client, _task) = server("HTTP/1.1 400 Bad Request\r\n", &[]);
        assert!(matches!(client.greeting().await, Err(ClientError::Unparsable)));
        // A greeting that refuses.
        let (mut client, _task) = server("554 go away\r\n", &[]);
        assert!(matches!(client.greeting().await, Err(ClientError::Reply(reply)) if reply.code == 554));
        // Gone in the middle of a command.
        let (mut client, _task) = server("220 mx\r\n", &[]);
        client.greeting().await.unwrap();
        assert!(matches!(client.command("NOOP").await, Err(ClientError::Io(_))));
        // Silent: the timeout.
        let (near, _far) = tokio::io::duplex(1024);
        let mut client = Client::with_stream(near, Duration::from_millis(50));
        assert!(matches!(client.greeting().await, Err(ClientError::Timeout)));
        // A command must be one line.
        let (mut client, _task) = server("220 mx\r\n", &[]);
        assert!(client.rcpt_to("a@b.example>\r\nDATA").await.is_err());
    }

    #[tokio::test]
    async fn helo_when_ehlo_is_unknown_and_starttls_with_trailing_data_is_refused() {
        let (mut client, task) = server("220 old\r\n", &["502 what\r\n", "250 hello\r\n"]);
        client.greeting().await.unwrap();
        let ehlo = client.ehlo("kernoid.example").await.unwrap();
        assert_eq!(ehlo.capabilities, 0);
        drop(client);
        assert_eq!(task.await.unwrap(), ["EHLO kernoid.example", "HELO kernoid.example"]);

        let (mut client, _task) = server("220 mx\r\n", &["220 go ahead\r\n250 injected\r\n"]);
        client.greeting().await.unwrap();
        let result = client.start_tls(unverified_tls(), ServerName::try_from("mx.other.example").unwrap()).await;
        assert!(matches!(result, Err(ClientError::Tls(_))));
    }

    #[test]
    fn transparency() {
        assert_eq!(dot_stuffed(b".\r\n..\r\nend"), b"..\r\n...\r\nend\r\n.\r\n");
        assert_eq!(dot_stuffed(b"line\r\n"), b"line\r\n.\r\n");
        assert_eq!(dot_stuffed(b""), b".\r\n");
    }
}
