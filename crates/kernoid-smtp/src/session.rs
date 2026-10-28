// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! An SMTP session of the MX (RFC 0002, 9.1) or of submission (10.1, `submission.rs`). Derived from Stalwart's inbound session (`crates/smtp/src/inbound`,
//! v0.16.27: `session.rs`, `ehlo.rs`, `mail.rs`, `rcpt.rs`): requests parsed by smtp-proto's receivers, responses
//! gathered while the client pipelines and written when its input is used up, `STARTTLS` that forgets everything
//! said before it.

use std::{net::IpAddr, sync::Arc};

use kernoid_identity::DomainName;
use kernoid_mail::Recipient;
use mail_auth::{IprevOutput, SpfOutput, spf::verify::SpfParameters};
use smtp_proto::{
    EXT_8BIT_MIME, EXT_CHUNKING, EXT_ENHANCED_STATUS_CODES, EXT_PIPELINING, EXT_SIZE, EXT_SMTP_UTF8, EXT_START_TLS,
    EhloResponse, Error as ProtoError, MailFrom as ProtoMailFrom, RcptTo, Request,
    request::receiver::{BdatReceiver, DataReceiver, DummyDataReceiver, RequestReceiver},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::Inner;

/// A connection, plain or upgraded to TLS.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) enum State {
    Request(RequestReceiver),
    Data(DataReceiver),
    /// A chunk of `BDAT`, and whether it is the last.
    Bdat(BdatReceiver, bool),
    /// Data that is read but not kept, then answered with the response.
    Skip(DummyDataReceiver, &'static str),
    /// A line of an `AUTH` exchange, gathered until its end.
    Sasl(crate::submission::Sasl, Vec<u8>),
}

/// What the session does after a batch of input.
enum Flow {
    Continue,
    StartTls,
    Quit,
}

pub(crate) struct MailFrom {
    /// Lower case; empty for bounces.
    pub address: String,
    pub domain: String,
    pub spf: Option<SpfOutput>,
}

pub(crate) struct Rcpt {
    /// As the client gave it, lower case, the domain in ASCII.
    pub address: String,
    pub accounts: Vec<Uuid>,
    /// For another server (submission only): it goes through the queue.
    pub remote: bool,
}

pub(crate) struct Session {
    pub inner: Arc<Inner>,
    pub remote: IpAddr,
    stream: Box<dyn Io>,
    /// Protocol and cipher, once TLS is up.
    pub tls: Option<String>,
    pub helo: Option<String>,
    pub iprev: Option<IprevOutput>,
    pub spf_ehlo: Option<SpfOutput>,
    pub mail_from: Option<MailFrom>,
    pub rcpts: Vec<Rcpt>,
    pub message: Vec<u8>,
    /// Who logged in (submission).
    pub account: Option<kernoid_identity::account::AccountInfo>,
    out: String,
}

impl Session {
    pub(crate) fn new(inner: Arc<Inner>, stream: Box<dyn Io>, remote: IpAddr) -> Self {
        Self {
            inner,
            remote,
            stream,
            tls: None,
            helo: None,
            iprev: None,
            spf_ehlo: None,
            mail_from: None,
            rcpts: Vec::new(),
            message: Vec::new(),
            account: None,
            out: String::new(),
        }
    }

    pub(crate) fn reply(&mut self, line: impl AsRef<str>) {
        self.out.push_str(line.as_ref());
        self.out.push_str("\r\n");
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            let out = std::mem::take(&mut self.out);
            tokio::time::timeout(self.inner.settings.timeout, self.stream.write_all(out.as_bytes()))
                .await
                .map_err(|_| std::io::ErrorKind::TimedOut)??;
            self.stream.flush().await?;
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpts.clear();
        self.message = Vec::new();
    }

    pub(crate) async fn run(mut self) {
        match &self.inner.submission {
            // Port 465: TLS before anything is said.
            Some(submission) if submission.implicit_tls => {
                if !self.start_tls().await {
                    return;
                }
            }
            Some(_) => {}
            None => {
                let iprev = self.inner.dns.authenticator.verify_iprev(self.inner.dns.parameters(self.remote)).await;
                self.iprev = Some(iprev);
            }
        }
        let greeting = format!("220 {} ESMTP kernoid", self.inner.settings.hostname);
        self.reply(greeting);
        let mut state = State::Request(RequestReceiver::default());
        let mut buf = vec![0u8; 8192];
        loop {
            if self.flush().await.is_err() {
                return;
            }
            let read = tokio::time::timeout(self.inner.settings.timeout, self.stream.read(&mut buf)).await;
            let n = match read {
                Ok(Ok(0)) | Ok(Err(_)) => return,
                Ok(Ok(n)) => n,
                Err(_) => {
                    self.reply("421 4.4.2 Timeout, closing the connection");
                    let _ = self.flush().await;
                    return;
                }
            };
            match self.ingest(&buf[..n], &mut state).await {
                Flow::Continue => {}
                Flow::Quit => {
                    let _ = self.flush().await;
                    let _ = self.stream.shutdown().await;
                    return;
                }
                Flow::StartTls => {
                    if self.flush().await.is_err() || !self.start_tls().await {
                        return;
                    }
                    // RFC 3207, 4.2: what was said before counts for nothing; pipelined input before the handshake
                    // was dropped with the rest of this read.
                    self.helo = None;
                    self.spf_ehlo = None;
                    self.account = None;
                    self.reset();
                    state = State::Request(RequestReceiver::default());
                }
            }
        }
    }

    async fn start_tls(&mut self) -> bool {
        let Some(acceptor) = self.inner.tls.clone() else { return false };
        let plain = std::mem::replace(&mut self.stream, Box::new(tokio::io::duplex(1).0));
        match tokio::time::timeout(self.inner.settings.timeout, acceptor.accept(plain)).await {
            Ok(Ok(tls)) => {
                let (_, connection) = tls.get_ref();
                self.tls = Some(format!(
                    "{} with cipher {}",
                    connection.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default(),
                    connection
                        .negotiated_cipher_suite()
                        .map(|suite| format!("{:?}", suite.suite()))
                        .unwrap_or_default(),
                ));
                self.stream = Box::new(tls);
                true
            }
            _ => false,
        }
    }

    async fn ingest(&mut self, bytes: &[u8], state: &mut State) -> Flow {
        let mut iter = bytes.iter();
        loop {
            match state {
                State::Request(receiver) => match receiver.ingest(&mut iter) {
                    Ok(request) => {
                        let request = request.into_owned();
                        match self.request(request, state).await {
                            Flow::Continue => {}
                            other => return other,
                        }
                    }
                    Err(ProtoError::NeedsMoreData { .. }) => return Flow::Continue,
                    Err(error) => self.protocol_error(error),
                },
                State::Data(receiver) => {
                    if receiver.ingest(&mut iter, &mut self.message) {
                        let response = if self.message.len() > self.inner.settings.max_message_size {
                            "552 5.3.4 Message too big for system".to_owned()
                        } else {
                            self.finish().await
                        };
                        self.reply(response);
                        self.reset();
                        *state = State::Request(RequestReceiver::default());
                    } else if self.message.len() > self.inner.settings.max_message_size {
                        let skip = DummyDataReceiver::new_data(receiver);
                        self.message = Vec::new();
                        *state = State::Skip(skip, "552 5.3.4 Message too big for system");
                    } else {
                        return Flow::Continue;
                    }
                }
                State::Bdat(receiver, last) => {
                    if receiver.ingest(&mut iter, &mut self.message) {
                        if *last {
                            let response = self.finish().await;
                            self.reply(response);
                            self.reset();
                        } else {
                            self.reply("250 2.6.0 Chunk accepted");
                        }
                        *state = State::Request(RequestReceiver::default());
                    } else {
                        return Flow::Continue;
                    }
                }
                State::Skip(receiver, response) => {
                    if receiver.ingest(&mut iter) {
                        let response = *response;
                        self.reply(response);
                        *state = State::Request(RequestReceiver::default());
                    } else {
                        return Flow::Continue;
                    }
                }
                State::Sasl(step, line) => {
                    let rest = iter.as_slice();
                    match rest.iter().position(|&b| b == b'\n') {
                        Some(end) => {
                            line.extend_from_slice(&rest[..end]);
                            iter = rest[end + 1..].iter();
                            let (step, line) = (step.clone(), std::mem::take(line));
                            *state = self.sasl(step, &line).await;
                        }
                        None if line.len() + rest.len() > 4096 => {
                            self.reply("500 5.5.6 Line too long");
                            *state = State::Request(RequestReceiver::default());
                            return Flow::Continue;
                        }
                        None => {
                            line.extend_from_slice(rest);
                            return Flow::Continue;
                        }
                    }
                }
            }
        }
    }

    fn protocol_error(&mut self, error: ProtoError) {
        let response = match error {
            ProtoError::UnknownCommand => "500 5.5.1 Invalid command".to_owned(),
            ProtoError::InvalidSenderAddress => "501 5.1.8 Bad sender's address syntax".to_owned(),
            ProtoError::InvalidRecipientAddress => "501 5.1.3 Bad recipient address syntax".to_owned(),
            ProtoError::SyntaxError { syntax } => format!("501 5.5.2 Syntax error, expected: {syntax}"),
            ProtoError::InvalidParameter { param } => format!("501 5.5.4 Invalid parameter {param:?}"),
            ProtoError::UnsupportedParameter { param } => format!("504 5.5.4 Unsupported parameter {param:?}"),
            ProtoError::ResponseTooLong => "500 5.5.6 Line too long".to_owned(),
            ProtoError::NeedsMoreData { .. } | ProtoError::InvalidResponse { .. } => {
                "500 5.5.1 Invalid command".to_owned()
            }
        };
        self.reply(response);
    }

    async fn request(&mut self, request: Request<String>, state: &mut State) -> Flow {
        match request {
            Request::Ehlo { host } => self.ehlo(host, true).await,
            Request::Helo { host } => self.ehlo(host, false).await,
            Request::Lhlo { .. } => self.reply("502 5.5.1 This is SMTP, not LMTP"),
            Request::Mail { from } if self.inner.submission.is_some() => self.submission_mail_from(from).await,
            Request::Rcpt { to } if self.inner.submission.is_some() => self.submission_rcpt_to(to).await,
            Request::Mail { from } => self.mail_from(from).await,
            Request::Rcpt { to } => self.rcpt_to(to).await,
            Request::Data => {
                if let Some(response) = self.can_send_data() {
                    self.reply(response);
                } else {
                    self.reply("354 Start mail input; end with <CRLF>.<CRLF>");
                    self.message = Vec::with_capacity(1024);
                    *state = State::Data(DataReceiver::new());
                }
            }
            Request::Bdat { chunk_size, is_last } => {
                if let Some(response) = self.can_send_data() {
                    *state = State::Skip(DummyDataReceiver::new_bdat(chunk_size), response);
                } else if chunk_size.saturating_add(self.message.len()) > self.inner.settings.max_message_size {
                    self.message = Vec::new();
                    *state =
                        State::Skip(DummyDataReceiver::new_bdat(chunk_size), "552 5.3.4 Message too big for system");
                } else {
                    self.message.reserve(chunk_size);
                    *state = State::Bdat(BdatReceiver::new(chunk_size, is_last), is_last);
                }
            }
            Request::StartTls => {
                if self.tls.is_some() {
                    self.reply("504 5.7.4 Already in TLS mode");
                } else if self.inner.tls.is_none() {
                    self.reply("502 5.5.1 TLS is not available");
                } else {
                    self.reply("220 2.0.0 Ready to start TLS");
                    return Flow::StartTls;
                }
            }
            Request::Rset => {
                self.reset();
                self.reply("250 2.0.0 OK");
            }
            Request::Noop { .. } => self.reply("250 2.0.0 OK"),
            Request::Vrfy { .. } => self.reply("252 2.5.1 Cannot verify the address, but will try delivery"),
            Request::Help { .. } => self.reply("214 2.0.0 See RFC 5321"),
            Request::Auth { mechanism, initial_response } if self.inner.submission.is_some() => {
                if let Some(next) = self.auth(mechanism, initial_response).await {
                    *state = next;
                }
            }
            Request::Auth { .. } => self.reply("503 5.5.1 AUTH is not allowed here; use submission"),
            Request::Quit => {
                self.reply("221 2.0.0 Bye");
                return Flow::Quit;
            }
            Request::Expn { .. } | Request::Etrn { .. } | Request::Atrn { .. } | Request::Burl { .. } => {
                self.reply("502 5.5.1 Command not implemented");
            }
        }
        Flow::Continue
    }

    async fn ehlo(&mut self, host: String, extended: bool) {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        if host.is_empty() {
            self.reply("501 5.5.4 A host name is required");
            return;
        }
        // An address literal has no SPF record to check; submission checks the login instead.
        if self.inner.submission.is_none() && !host.starts_with('[') && host.parse::<IpAddr>().is_err() {
            let spf = self
                .inner
                .dns
                .authenticator
                .verify_spf(self.inner.dns.parameters(SpfParameters::verify_ehlo(
                    self.remote,
                    &host,
                    &self.inner.settings.hostname,
                )))
                .await;
            self.spf_ehlo = Some(spf);
        } else {
            self.spf_ehlo = None;
        }
        self.helo = Some(host);
        self.reset();
        if !extended {
            let response = format!("250 {}", self.inner.settings.hostname);
            self.reply(response);
            return;
        }
        let mut ehlo = EhloResponse::new(self.inner.settings.hostname.as_str());
        ehlo.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_PIPELINING | EXT_SMTP_UTF8 | EXT_SIZE | EXT_CHUNKING;
        if self.tls.is_none() && self.inner.tls.is_some() {
            ehlo.capabilities |= EXT_START_TLS;
        }
        // Logging in only over TLS (RFC 8314).
        if self.inner.submission.is_some() && self.tls.is_some() && self.account.is_none() {
            ehlo.capabilities |= smtp_proto::EXT_AUTH;
            ehlo.auth_mechanisms = smtp_proto::AUTH_PLAIN | smtp_proto::AUTH_LOGIN;
        }
        ehlo.size = self.inner.settings.max_message_size;
        let mut written = Vec::new();
        ehlo.write(&mut written).expect("writing to memory");
        self.out.push_str(&String::from_utf8_lossy(&written));
    }

    async fn mail_from(&mut self, from: ProtoMailFrom<String>) {
        let Some(helo) = self.helo.clone() else {
            self.reply("503 5.5.1 Polite people say EHLO first");
            return;
        };
        if self.mail_from.is_some() {
            self.reply("503 5.5.1 Multiple MAIL commands are not allowed");
            return;
        }
        if from.size > self.inner.settings.max_message_size {
            self.reply("552 5.3.4 Message too big for system");
            return;
        }
        let address = from.address.trim().to_lowercase();
        let domain = address.rsplit_once('@').map(|(_, domain)| domain.to_owned()).unwrap_or_default();
        let spf = if address.is_empty() {
            None
        } else {
            Some(
                self.inner
                    .dns
                    .authenticator
                    .verify_spf(self.inner.dns.parameters(SpfParameters::verify_mail_from(
                        self.remote,
                        &helo,
                        &self.inner.settings.hostname,
                        &address,
                    )))
                    .await,
            )
        };
        self.mail_from = Some(MailFrom { address, domain, spf });
        self.reply("250 2.1.0 OK");
    }

    async fn rcpt_to(&mut self, to: RcptTo<String>) {
        if self.mail_from.is_none() {
            self.reply("503 5.5.1 MAIL is required first");
            return;
        }
        if self.rcpts.len() >= self.inner.settings.max_recipients {
            self.reply("452 4.5.3 Too many recipients");
            return;
        }
        let Some(address) = normalize(&to.address) else {
            self.reply("501 5.1.3 Bad recipient address syntax");
            return;
        };
        if self.rcpts.iter().any(|rcpt| rcpt.address == address) {
            self.reply("250 2.1.5 OK");
            return;
        }
        let accounts = match self.inner.mail.resolve_recipient(&address).await {
            Ok(Recipient::Account { account, .. }) => match self.inner.mail.over_quota(account, 0).await {
                Ok(false) => vec![account],
                Ok(true) => {
                    self.reply("452 4.2.2 Mailbox full, try again later");
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, "checking a quota");
                    self.reply("451 4.3.0 Temporary failure, try again later");
                    return;
                }
            },
            Ok(Recipient::Group { members, .. }) => members,
            Ok(Recipient::Disabled) => {
                self.reply("550 5.2.1 Mailbox disabled");
                return;
            }
            Ok(Recipient::Unknown) => {
                self.reply("550 5.1.1 Mailbox does not exist");
                return;
            }
            Ok(Recipient::NotLocal) => {
                self.reply("550 5.7.1 Relaying not allowed");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "resolving a recipient");
                self.reply("451 4.3.0 Temporary failure, try again later");
                return;
            }
        };
        self.rcpts.push(Rcpt { address, accounts, remote: false });
        self.reply("250 2.1.5 OK");
    }

    fn can_send_data(&self) -> Option<&'static str> {
        if self.mail_from.is_none() {
            Some("503 5.5.1 MAIL is required first")
        } else if self.rcpts.is_empty() {
            Some("503 5.5.1 RCPT is required first")
        } else {
            None
        }
    }
}

/// `local@domain` in lower case with the domain in ASCII, or `None` if it is not an address.
pub(crate) fn normalize(address: &str) -> Option<String> {
    let (local, domain) = address.trim().rsplit_once('@')?;
    if local.is_empty() {
        return None;
    }
    let domain = DomainName::parse(&idna::domain_to_ascii(domain).ok()?).ok()?;
    Some(format!("{}@{}", local.to_lowercase(), domain.as_str()))
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn addresses_are_normalized() {
        assert_eq!(normalize("Alice+X@Firma.Example").as_deref(), Some("alice+x@firma.example"));
        assert_eq!(normalize("bob@bücher.example").as_deref(), Some("bob@xn--bcher-kva.example"));
        assert_eq!(normalize("no-domain"), None);
        assert_eq!(normalize("@firma.example"), None);
    }
}
