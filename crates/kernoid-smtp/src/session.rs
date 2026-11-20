// SPDX-License-Identifier: AGPL-3.0-or-later
//! An SMTP session (RFC 5321) of the MX (RFC 0002, 9.1) or of submission (10.1, `submission.rs`).
//!
//! The session reads what the client sends in batches and hands each batch to the receiver of the state it is in:
//! commands to the request receiver of `proto`, the message to its `DATA` or `BDAT` receiver (RFC 3030), an `AUTH`
//! exchange line by line. Replies are collected while a batch lasts and written when it is used up, so that a
//! client that pipelines (RFC 2920) gets them in one write, in order. `STARTTLS` (RFC 3207) drops whatever the
//! client sent after it and starts the session over – nothing said in plain text survives into TLS.
//!
//! The order of a transaction is checked here: `EHLO` before `MAIL`, `MAIL` before `RCPT`, a recipient before the
//! data, and the size of the message against `SIZE` (RFC 1870) while it is read.

use std::{net::IpAddr, sync::Arc};

use crate::{
    auth::{IprevOutput, SpfOutput, iprev, spf, spf::SpfParameters},
    proto::{
        BdatReceiver, DataReceiver, Discard, Error as ProtoError, MailFrom as ProtoMailFrom, RcptTo, Request,
        RequestReceiver,
    },
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::{Inner, submission::Sasl};

/// A connection, plain or upgraded to TLS.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// How much is read from the client at once.
const READ_SIZE: usize = 8 * 1024;

/// The longest line of an `AUTH` exchange: room for an access token.
const MAX_SASL_LINE: usize = 16 * 1024;

/// Commands the session refuses before it gives up on the client.
const MAX_ERRORS: usize = 10;

/// What the session expects next from the client.
pub(crate) enum State {
    /// A command.
    Request(RequestReceiver),
    /// The message after `DATA`, up to the line with a dot alone.
    Data(DataReceiver),
    /// A chunk of `BDAT`.
    Bdat(BdatReceiver),
    /// Data that is read but not kept – after `DATA`, its end; after `BDAT`, its size –, then answered with this.
    Discard(Discard, String),
    /// A line of an `AUTH` exchange, gathered until its end.
    Sasl(Sasl, Vec<u8>),
}

/// What the session does after a batch of input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    /// Read on.
    Continue,
    /// Answer, then switch to TLS; what the client sent after `STARTTLS` is dropped.
    StartTls,
    /// Answer, then close the connection.
    Close,
}

/// The sender of the current transaction.
pub(crate) struct MailFrom {
    /// Lower case; empty for bounces.
    pub address: String,
    /// The domain of the address – for a bounce, the `HELO` name, which SPF and DMARC take in its place.
    pub domain: String,
    pub spf: Option<SpfOutput>,
}

/// A recipient of the current transaction.
pub(crate) struct Rcpt {
    /// As the client gave it, lower case, the domain in ASCII.
    pub address: String,
    pub accounts: Vec<Uuid>,
    /// For another server (submission only): it goes through the queue.
    pub remote: bool,
    /// An SRS address (RFC 0002, 10.6): the bounce goes on to this original sender, through this tenant's queue.
    pub bounce_to: Option<(String, Uuid)>,
}

pub(crate) struct Session {
    pub inner: Arc<Inner>,
    pub remote: IpAddr,
    stream: Option<Box<dyn Io>>,
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
    /// Replies not written yet.
    replies: Vec<u8>,
    /// `BDAT` has begun the message: `DATA` may not follow.
    chunking: bool,
    errors: usize,
}

impl Session {
    pub(crate) fn new(inner: Arc<Inner>, stream: Box<dyn Io>, remote: IpAddr) -> Self {
        Self {
            inner,
            remote,
            stream: Some(stream),
            tls: None,
            helo: None,
            iprev: None,
            spf_ehlo: None,
            mail_from: None,
            rcpts: Vec::new(),
            message: Vec::new(),
            account: None,
            replies: Vec::new(),
            chunking: false,
            errors: 0,
        }
    }

    /// Queues a reply line (without its line end); it is written when the client's input is used up.
    pub(crate) fn reply(&mut self, line: impl AsRef<str>) {
        self.replies.extend_from_slice(line.as_ref().as_bytes());
        self.replies.extend_from_slice(b"\r\n");
    }

    /// Ends the transaction: sender, recipients and data are forgotten (RFC 5321, 4.1.1.5).
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpts.clear();
        self.message = Vec::new();
        self.chunking = false;
    }

    fn hostname(&self) -> &str {
        &self.inner.settings.hostname
    }

    async fn write_replies(&mut self) -> bool {
        if self.replies.is_empty() {
            return true;
        }
        let replies = std::mem::take(&mut self.replies);
        let timeout = self.inner.settings.timeout;
        let Some(stream) = self.stream.as_mut() else { return false };
        let written = tokio::time::timeout(timeout, async {
            stream.write_all(&replies).await?;
            stream.flush().await
        })
        .await;
        matches!(written, Ok(Ok(())))
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Option<usize> {
        let timeout = self.inner.settings.timeout;
        let stream = self.stream.as_mut()?;
        match tokio::time::timeout(timeout, stream.read(buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => None,
            Ok(Ok(read)) => Some(read),
            Err(_) => {
                let line = format!("421 4.4.2 {} Timeout, closing the connection", self.hostname());
                self.reply(line);
                self.write_replies().await;
                None
            }
        }
    }

    /// The TLS handshake on the connection as it is; afterwards the session starts over (RFC 3207, 4.2).
    async fn handshake(&mut self) -> bool {
        let (Some(acceptor), Some(stream)) = (self.inner.tls.clone(), self.stream.take()) else { return false };
        let timeout = self.inner.settings.timeout;
        let Ok(Ok(tls)) = tokio::time::timeout(timeout, acceptor.accept(stream)).await else { return false };
        let connection = tls.get_ref().1;
        let version = connection.protocol_version().map(|version| format!("{version:?}")).unwrap_or_default();
        let cipher =
            connection.negotiated_cipher_suite().map(|suite| format!("{:?}", suite.suite())).unwrap_or_default();
        self.tls = Some(format!("{version} with cipher {cipher}"));
        self.stream = Some(Box::new(tls));
        self.helo = None;
        self.spf_ehlo = None;
        self.account = None;
        self.reset();
        true
    }

    /// Runs the session until the client quits, the connection breaks or a command times out.
    pub(crate) async fn run(mut self) {
        let implicit_tls = self.inner.submission.as_ref().is_some_and(|submission| submission.implicit_tls);
        if implicit_tls && !self.handshake().await {
            return;
        }
        let greeting = format!("220 {} ESMTP kernoid", self.hostname());
        self.reply(greeting);
        if !self.write_replies().await {
            return;
        }
        let mut state = State::Request(RequestReceiver::default());
        let mut buffer = vec![0u8; READ_SIZE];
        loop {
            let Some(read) = self.read(&mut buffer).await else { break };
            let next = self.ingest(&mut state, &buffer[..read]).await;
            if !self.write_replies().await {
                break;
            }
            match next {
                Next::Continue => {}
                Next::Close => break,
                Next::StartTls => {
                    if !self.handshake().await {
                        break;
                    }
                    state = State::Request(RequestReceiver::default());
                }
            }
        }
        if let Some(mut stream) = self.stream.take() {
            let _ = tokio::time::timeout(self.inner.settings.timeout, stream.shutdown()).await;
        }
    }

    /// Hands a batch of input to the states it passes through.
    async fn ingest(&mut self, state: &mut State, input: &[u8]) -> Next {
        let mut bytes: &[u8] = input;
        loop {
            match state {
                State::Request(receiver) => {
                    if bytes.is_empty() {
                        return Next::Continue;
                    }
                    let request = match receiver.ingest(&mut bytes) {
                        Ok(request) => request,
                        Err(ProtoError::NeedsMoreData) => return Next::Continue,
                        Err(error) => {
                            self.errors += 1;
                            if self.errors >= MAX_ERRORS {
                                self.reply("421 4.7.0 Too many errors, closing the connection");
                                return Next::Close;
                            }
                            self.protocol_error(error);
                            continue;
                        }
                    };
                    match self.request(request).await {
                        Ok(Some(next)) => *state = next,
                        Ok(None) => {}
                        Err(next) => return next,
                    }
                }
                State::Data(receiver) => {
                    let done = receiver.ingest(&mut bytes, &mut self.message);
                    if done {
                        let reply = if self.message.len() > self.inner.settings.max_message_size {
                            "552 5.3.4 Message too big for system".into()
                        } else {
                            self.finish().await
                        };
                        self.reply(reply);
                        self.reset();
                        *state = State::Request(RequestReceiver::default());
                    } else if self.message.len() > self.inner.settings.max_message_size {
                        // Read to its end, keep nothing, refuse it then.
                        let discard = Discard::Data(receiver.clone());
                        self.message = Vec::new();
                        *state = State::Discard(discard, "552 5.3.4 Message too big for system".into());
                    } else {
                        return Next::Continue;
                    }
                }
                State::Bdat(receiver) => {
                    if !receiver.ingest(&mut bytes, &mut self.message) {
                        return Next::Continue;
                    }
                    let reply = if receiver.is_last { self.finish_chunks().await } else { self.chunk_done() };
                    self.reply(reply);
                    *state = State::Request(RequestReceiver::default());
                }
                State::Discard(receiver, reply) => {
                    if !receiver.ingest(&mut bytes) {
                        return Next::Continue;
                    }
                    let reply = std::mem::take(reply);
                    self.reply(reply);
                    *state = State::Request(RequestReceiver::default());
                }
                State::Sasl(step, line) => {
                    let rest = bytes;
                    let Some(end) = rest.iter().position(|byte| *byte == b'\n') else {
                        line.extend_from_slice(rest);
                        if line.len() > MAX_SASL_LINE {
                            self.reply("500 5.5.6 Authentication exchange line is too long");
                            *state = State::Request(RequestReceiver::default());
                        }
                        return Next::Continue;
                    };
                    line.extend_from_slice(&rest[..end]);
                    bytes = &rest[end + 1..];
                    let (step, line) = (step.clone(), std::mem::take(line));
                    *state = if line.len() > MAX_SASL_LINE {
                        self.reply("500 5.5.6 Authentication exchange line is too long");
                        State::Request(RequestReceiver::default())
                    } else {
                        self.sasl(step, &line).await
                    };
                }
            }
        }
    }

    /// One command. `Ok` with the state to go on in, if not the next command; `Err` ends the batch.
    async fn request(&mut self, request: Request) -> Result<Option<State>, Next> {
        match request {
            Request::Ehlo { host } => self.ehlo(host, true).await,
            Request::Helo { host } => self.ehlo(host, false).await,
            Request::Lhlo { .. } => self.reply("502 5.5.1 LHLO is for LMTP, this is SMTP"),
            Request::Mail { from } => self.mail_from(from).await,
            Request::Rcpt { to } => self.rcpt_to(to).await,
            Request::Data => return Ok(self.data()),
            Request::Bdat { chunk_size, is_last } => return Ok(self.bdat(chunk_size, is_last).await),
            Request::Auth { mechanism, initial_response } => {
                if self.inner.submission.is_none() {
                    self.reply("503 5.5.1 AUTH is not allowed here; use submission");
                } else if self.mail_from.is_some() {
                    self.reply("503 5.5.1 AUTH is not allowed during a mail transaction");
                } else {
                    return Ok(self.auth(mechanism, initial_response).await);
                }
            }
            Request::StartTls => {
                if self.inner.tls.is_none() {
                    self.reply("502 5.5.1 TLS is not available");
                } else if self.tls.is_some() {
                    self.reply("503 5.5.1 TLS is already active");
                } else {
                    self.reply("220 2.0.0 Ready to start TLS");
                    return Err(Next::StartTls);
                }
            }
            Request::Rset => {
                self.reset();
                self.reply("250 2.0.0 OK");
            }
            Request::Noop => self.reply("250 2.0.0 OK"),
            Request::Quit => {
                self.reply("221 2.0.0 Bye");
                return Err(Next::Close);
            }
            Request::Vrfy { .. } => self.reply("252 2.5.2 Cannot verify the user, but will take mail for it"),
            Request::Help { .. } => self.reply("214 2.0.0 See RFC 5321"),
            Request::Expn { .. } | Request::Etrn | Request::Atrn | Request::Burl => {
                self.reply("502 5.5.1 Command not implemented")
            }
        }
        Ok(None)
    }

    fn protocol_error(&mut self, error: ProtoError) {
        match error {
            ProtoError::NeedsMoreData => {}
            ProtoError::UnknownCommand => self.reply("500 5.5.1 Command not recognized"),
            ProtoError::InvalidSenderAddress => self.reply("501 5.1.7 Bad sender address syntax"),
            ProtoError::InvalidRecipientAddress => self.reply("501 5.1.3 Bad recipient address syntax"),
            ProtoError::SyntaxError { syntax } => self.reply(format!("501 5.5.2 Syntax error, expected {syntax}")),
            ProtoError::InvalidParameter { param } => self.reply(format!("501 5.5.4 Invalid parameter {param}")),
            ProtoError::UnsupportedParameter { param } => {
                let param: String = param.chars().filter(|c| !c.is_control()).take(64).collect();
                self.reply(format!("504 5.5.4 Unsupported parameter {param}"));
            }
            ProtoError::LineTooLong => self.reply("500 5.5.6 Line too long"),
        }
    }

    /// `EHLO` (with the extensions) or `HELO`: a new start, and the checks of the client – iprev once, SPF of the
    /// name it gives (MX only).
    async fn ehlo(&mut self, host: String, extended: bool) {
        self.reset();
        if self.inner.submission.is_none() {
            let dns = &self.inner.dns;
            if self.iprev.is_none() {
                self.iprev = Some(iprev::verify(dns, self.remote).await);
            }
            let hostname = self.inner.settings.hostname.clone();
            let params = SpfParameters::helo(self.remote, &host, &hostname);
            self.spf_ehlo = Some(spf::verify(dns, &params).await);
        }
        let hostname = self.hostname().to_owned();
        if !extended {
            self.reply(format!("250 {hostname} Hello {host}"));
            self.helo = Some(host);
            return;
        }
        let mut lines = vec![format!("{hostname} Hello {host}")];
        lines.extend(["PIPELINING", "8BITMIME", "SMTPUTF8", "CHUNKING", "ENHANCEDSTATUSCODES"].map(String::from));
        lines.push(format!("SIZE {}", self.inner.settings.max_message_size));
        if self.inner.tls.is_some() && self.tls.is_none() {
            lines.push("STARTTLS".into());
        }
        // Logging in only where it is allowed: submission, over TLS (RFC 0002, 10.1).
        if self.inner.submission.is_some() && self.tls.is_some() && self.account.is_none() {
            lines.push("AUTH PLAIN LOGIN OAUTHBEARER XOAUTH2".into());
        }
        let last = lines.len() - 1;
        for (index, line) in lines.into_iter().enumerate() {
            let separator = if index == last { ' ' } else { '-' };
            self.reply(format!("250{separator}{line}"));
        }
        self.helo = Some(host);
    }

    async fn mail_from(&mut self, from: ProtoMailFrom) {
        if self.inner.submission.is_some() {
            return self.submission_mail_from(from).await;
        }
        let Some(helo) = self.helo.clone() else {
            return self.reply("503 5.5.1 Polite people say EHLO first");
        };
        if self.mail_from.is_some() {
            return self.reply("503 5.5.1 Multiple MAIL commands are not allowed");
        }
        if from.size > self.inner.settings.max_message_size {
            return self.reply("552 5.3.4 Message too big for system");
        }
        let (address, domain) = if from.address.is_empty() {
            (String::new(), helo.to_lowercase())
        } else {
            let Some(address) = normalize(&from.address) else {
                return self.reply("501 5.1.7 Bad sender address syntax");
            };
            let domain = address.rsplit_once('@').map(|(_, domain)| domain.to_owned()).unwrap_or_default();
            (address, domain)
        };
        let dns = &self.inner.dns;
        let hostname = self.inner.settings.hostname.clone();
        let params = SpfParameters::mail_from(self.remote, &helo, &hostname, &address);
        let spf = spf::verify(dns, &params).await;
        self.mail_from = Some(MailFrom { address, domain, spf: Some(spf) });
        self.reply("250 2.1.0 OK");
    }

    async fn rcpt_to(&mut self, to: RcptTo) {
        if self.inner.submission.is_some() {
            return self.submission_rcpt_to(to).await;
        }
        let Some(sender_is_empty) = self.mail_from.as_ref().map(|from| from.address.is_empty()) else {
            return self.reply("503 5.5.1 MAIL is required first");
        };
        if self.rcpts.len() >= self.inner.settings.max_recipients {
            return self.reply("452 4.5.3 Too many recipients");
        }
        let Some(address) = normalize(&to.address) else {
            return self.reply("501 5.1.3 Bad recipient address syntax");
        };
        if self.rcpts.iter().any(|rcpt| rcpt.address == address) {
            return self.reply("250 2.1.5 OK");
        }
        use kernoid_mail::Recipient;
        let mail = &self.inner.mail;
        let rcpt = match mail.resolve_recipient(&address).await {
            Ok(Recipient::Account { account, .. }) => match mail.over_quota(account, 0).await {
                Ok(false) => Rcpt { address, accounts: vec![account], remote: false, bounce_to: None },
                Ok(true) => return self.reply("452 4.2.2 Mailbox full, try again later"),
                Err(error) => {
                    tracing::warn!(%error, "checking a recipient's quota");
                    return self.reply("451 4.3.0 Temporary failure, try again later");
                }
            },
            Ok(Recipient::Group { members, .. }) => Rcpt { address, accounts: members, remote: false, bounce_to: None },
            Ok(Recipient::Forwarded { to, tenant }) => {
                if !sender_is_empty {
                    return self.reply("550 5.7.1 Only bounces go to this address");
                }
                Rcpt { address, accounts: Vec::new(), remote: false, bounce_to: Some((to, tenant)) }
            }
            Ok(Recipient::Disabled) => return self.reply("550 5.2.1 Mailbox disabled"),
            Ok(Recipient::Unknown) => return self.reply("550 5.1.1 Mailbox does not exist"),
            Ok(Recipient::NotLocal) => return self.reply("550 5.7.1 Relaying not allowed"),
            Err(error) => {
                tracing::warn!(%error, "resolving a recipient");
                return self.reply("451 4.3.0 Temporary failure, try again later");
            }
        };
        self.rcpts.push(rcpt);
        self.reply("250 2.1.5 OK");
    }

    /// The reply that refuses the data, if the transaction is not ready for it.
    fn can_send_data(&self) -> Option<&'static str> {
        if self.mail_from.is_none() {
            Some("503 5.5.1 MAIL is required first")
        } else if self.rcpts.is_empty() {
            Some("503 5.5.1 RCPT is required first")
        } else {
            None
        }
    }

    fn data(&mut self) -> Option<State> {
        if let Some(refusal) = self.can_send_data() {
            self.reply(refusal);
            return None;
        }
        if self.chunking {
            self.reply("503 5.5.1 DATA cannot follow BDAT");
            return None;
        }
        self.message = Vec::new();
        self.reply("354 Start mail input; end with <CRLF>.<CRLF>");
        Some(State::Data(DataReceiver::new()))
    }

    /// `BDAT` (RFC 3030): the chunk follows the command at once, so even a refused chunk is read – and dropped.
    async fn bdat(&mut self, size: usize, last: bool) -> Option<State> {
        let refusal = if let Some(refusal) = self.can_send_data() {
            Some(refusal)
        } else if self.message.len().saturating_add(size) > self.inner.settings.max_message_size {
            self.reset();
            Some("552 5.3.4 Message too big for system")
        } else {
            None
        };
        if let Some(refusal) = refusal {
            if size == 0 {
                self.reply(refusal);
                return None;
            }
            return Some(State::Discard(Discard::Bdat(size), refusal.into()));
        }
        self.chunking = true;
        if size > 0 {
            return Some(State::Bdat(BdatReceiver::new(size, last)));
        }
        let reply = if last { self.finish_chunks().await } else { self.chunk_done() };
        self.reply(reply);
        None
    }

    fn chunk_done(&self) -> String {
        "250 2.6.0 Chunk accepted".into()
    }

    async fn finish_chunks(&mut self) -> String {
        let reply = self.finish().await;
        self.reset();
        reply
    }
}

/// `local@domain` in lower case with the domain in ASCII, or `None` if it is not an address.
pub(crate) fn normalize(address: &str) -> Option<String> {
    let address = address.trim();
    let (local, domain) = address.rsplit_once('@')?;
    let domain = domain.trim_end_matches('.');
    if local.is_empty()
        || domain.is_empty()
        || local.len() > 64
        || address.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>'))
    {
        return None;
    }
    let domain = idna::domain_to_ascii(domain).ok().filter(|domain| !domain.is_empty() && domain.len() <= 253)?;
    if domain.split('.').any(str::is_empty) {
        return None;
    }
    Some(format!("{}@{domain}", local.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn addresses_are_normalized() {
        assert_eq!(normalize("Alice+News@Firma.Example").as_deref(), Some("alice+news@firma.example"));
        assert_eq!(normalize("bob@bücher.example.").as_deref(), Some("bob@xn--bcher-kva.example"));
        assert_eq!(normalize("Jörg@firma.example").as_deref(), Some("jörg@firma.example"));
        for invalid in ["", "alice", "@firma.example", "alice@", "a b@firma.example", "alice@firma..example"] {
            assert_eq!(normalize(invalid), None, "{invalid}");
        }
        assert_eq!(normalize(&format!("{}@firma.example", "x".repeat(65))), None);
    }
}
