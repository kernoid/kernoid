// SPDX-License-Identifier: AGPL-3.0-or-later
//! An IMAP session (RFC 9051): requests read by the receiver taken over from Stalwart, answered in order; the
//! untagged updates of the selected mailbox go out before a command completes – except during `FETCH`, `STORE` and
//! `SEARCH` by sequence number, which must not see sequence numbers move (RFC 9051, 7.5.1).

use std::{net::IpAddr, sync::Arc};

use base64::Engine;
use kernoid_identity::IdentityError;
use kernoid_mail::MailError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};
use uuid::Uuid;

use crate::{
    Inner, Io,
    proto::{
        Command, ResponseCode, StatusResponse,
        protocol::{
            ImapResponse, ProtocolVersion, SerializeResponse,
            authenticate::Mechanism,
            capability::{self, Capability, QuotaResourceName},
            enable, namespace,
        },
        receiver::{self, Receiver, Request},
    },
    selected::Selected,
};

/// What the session reads next.
enum State {
    Command(Receiver<Command>),
    /// The client's response to `AUTHENTICATE`'s `+`.
    Sasl {
        tag: String,
        line: Vec<u8>,
    },
    /// Waiting for `DONE`, sending updates as they happen.
    Idle {
        tag: String,
        line: Vec<u8>,
    },
}

/// What the session does after a command.
pub(crate) enum Flow {
    Continue,
    StartTls,
    Logout,
    Sasl(String),
    Idle(String),
}

pub(crate) struct Session {
    pub inner: Arc<Inner>,
    remote: IpAddr,
    stream: Box<dyn Io>,
    tls: bool,
    pub account: Option<Uuid>,
    pub tenant: Option<Uuid>,
    pub version: ProtocolVersion,
    pub is_utf8: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub selected: Option<Selected>,
    events: broadcast::Receiver<Uuid>,
    pub out: Vec<u8>,
    /// The mechanism of an `AUTHENTICATE` waiting for the client's response.
    sasl_mechanism: Mechanism,
}

/// A failure of the store as the client sees it.
pub(crate) fn mail_error(error: MailError) -> StatusResponse {
    match error {
        MailError::NotFound(what) => {
            StatusResponse::no(format!("{what} does not exist")).with_code(ResponseCode::NonExistent)
        }
        MailError::Exists(what) => {
            StatusResponse::no(format!("{what} exists already")).with_code(ResponseCode::AlreadyExists)
        }
        MailError::Invalid(message) => StatusResponse::no(message).with_code(ResponseCode::Cannot),
        MailError::TooLarge { limit } => {
            StatusResponse::no(format!("the message is larger than {limit} bytes")).with_code(ResponseCode::Limit)
        }
        MailError::OverQuota => StatusResponse::no("over quota").with_code(ResponseCode::OverQuota),
        MailError::MailboxHasChild => {
            StatusResponse::no("the mailbox has child mailboxes").with_code(ResponseCode::HasChildren)
        }
        MailError::Unparsable => StatusResponse::no("the message could not be parsed").with_code(ResponseCode::Parse),
        MailError::Refused(refused @ kernoid_store::scan::Refused::Infected(_)) => {
            StatusResponse::no(refused.to_string()).with_code(ResponseCode::Cannot)
        }
        MailError::Refused(refused) => StatusResponse::no(refused.to_string()).with_code(ResponseCode::Unavailable),
        error => {
            tracing::warn!(%error, "an IMAP command failed");
            StatusResponse::database_failure()
        }
    }
}

impl Session {
    pub(crate) fn new(inner: Arc<Inner>, stream: Box<dyn Io>, remote: IpAddr) -> Self {
        let events = inner.events.subscribe();
        Self {
            inner,
            remote,
            stream,
            tls: false,
            account: None,
            tenant: None,
            version: ProtocolVersion::Rev1,
            is_utf8: false,
            condstore: false,
            qresync: false,
            selected: None,
            events,
            sasl_mechanism: Mechanism::Plain,
            out: Vec::new(),
        }
    }

    fn receiver(&self) -> Receiver<Command> {
        // Room for the largest message plus the command around it.
        Receiver::with_max_request_size(self.inner.settings.max_message_size.saturating_add(64 * 1024))
    }

    pub(crate) fn write(&mut self, bytes: impl AsRef<[u8]>) {
        self.out.extend_from_slice(bytes.as_ref());
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            let out = std::mem::take(&mut self.out);
            tokio::time::timeout(self.inner.settings.timeout, self.stream.write_all(&out))
                .await
                .map_err(|_| std::io::ErrorKind::TimedOut)??;
            self.stream.flush().await?;
        }
        Ok(())
    }

    fn capabilities(&self) -> Vec<Capability> {
        let mut capabilities = vec![
            Capability::IMAP4rev2,
            Capability::IMAP4rev1,
            Capability::Enable,
            Capability::SASLIR,
            Capability::LiteralPlus,
            Capability::Id,
            Capability::Utf8Accept,
        ];
        if self.account.is_some() {
            capabilities.extend([
                Capability::Idle,
                Capability::Namespace,
                Capability::Children,
                Capability::MultiAppend,
                Capability::Binary,
                Capability::Unselect,
                Capability::UIDPlus,
                Capability::ESearch,
                Capability::Within,
                Capability::SearchRes,
                Capability::ListExtended,
                Capability::ListStatus,
                Capability::SpecialUse,
                Capability::Move,
                Capability::CondStore,
                Capability::QResync,
                Capability::StatusSize,
                Capability::ACL,
                Capability::Rights,
                Capability::Sort,
                Capability::SortDisplay,
                Capability::Thread,
                Capability::Quota,
                Capability::QuotaResource(QuotaResourceName::Storage),
            ]);
        } else if self.tls {
            capabilities.extend([
                Capability::Auth(Mechanism::Plain),
                Capability::Auth(Mechanism::OAuthBearer),
                Capability::Auth(Mechanism::XOauth2),
            ]);
        } else {
            capabilities.extend([Capability::StartTLS, Capability::LoginDisabled]);
        }
        capabilities
    }

    pub(crate) async fn run(mut self) {
        if self.inner.implicit_tls {
            let plain = std::mem::replace(&mut self.stream, Box::new(tokio::io::duplex(1).0));
            match crate::start_tls(&self.inner, plain).await {
                Some(tls) => {
                    self.stream = tls;
                    self.tls = true;
                }
                None => return,
            }
        }
        let mut greeting = Vec::from(&b"* OK ["[..]);
        ResponseCode::Capability { capabilities: self.capabilities() }.serialize(&mut greeting);
        greeting.extend_from_slice(b"] kernoid ready\r\n");
        self.write(greeting);
        let mut state = State::Command(self.receiver());
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if self.flush().await.is_err() {
                return;
            }
            let idle = matches!(state, State::Idle { .. });
            let read = tokio::select! {
                read = tokio::time::timeout(self.inner.settings.timeout, self.stream.read(&mut buf)) => read,
                changed = self.events.recv(), if idle => {
                    let ours = match changed {
                        Ok(account) => {
                            Some(account) == self.account
                                || self.selected.as_ref().is_some_and(|selected| selected.owner == account)
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => true,
                        Err(broadcast::error::RecvError::Closed) => false,
                    };
                    if ours {
                        self.sync().await;
                    }
                    continue;
                }
            };
            let n = match read {
                Ok(Ok(0)) | Ok(Err(_)) => return,
                Ok(Ok(n)) => n,
                Err(_) => {
                    self.write(StatusResponse::bye("Autologout; idle for too long").into_bytes());
                    let _ = self.flush().await;
                    return;
                }
            };
            let mut rest = &buf[..n];
            while !rest.is_empty() {
                let (next, flow, left) = self.ingest(state, rest).await;
                state = next;
                rest = left;
                match flow {
                    Flow::Continue | Flow::Sasl(_) | Flow::Idle(_) => {}
                    Flow::Logout => {
                        let _ = self.flush().await;
                        let _ = self.stream.shutdown().await;
                        return;
                    }
                    Flow::StartTls => {
                        if self.flush().await.is_err() {
                            return;
                        }
                        let plain = std::mem::replace(&mut self.stream, Box::new(tokio::io::duplex(1).0));
                        match crate::start_tls(&self.inner, plain).await {
                            Some(tls) => {
                                self.stream = tls;
                                self.tls = true;
                            }
                            None => return,
                        }
                        // RFC 9051, 6.2.1: what the client sent after STARTTLS before the handshake is dropped.
                        state = State::Command(self.receiver());
                        break;
                    }
                }
            }
        }
    }

    /// Reads `bytes` in `state`; returns the next state, what happened, and the bytes not read yet.
    async fn ingest<'b>(&mut self, state: State, bytes: &'b [u8]) -> (State, Flow, &'b [u8]) {
        match state {
            State::Command(mut receiver) => {
                let mut iter = bytes.iter();
                loop {
                    match receiver.parse(&mut iter) {
                        Ok(request) => {
                            let flow = self.request(request).await;
                            let rest = iter.as_slice();
                            return match flow {
                                Flow::Sasl(tag) => {
                                    (State::Sasl { tag: tag.clone(), line: Vec::new() }, Flow::Sasl(tag), rest)
                                }
                                Flow::Idle(tag) => {
                                    (State::Idle { tag: tag.clone(), line: Vec::new() }, Flow::Idle(tag), rest)
                                }
                                flow => (State::Command(receiver), flow, rest),
                            };
                        }
                        Err(receiver::Error::NeedsMoreData) => return (State::Command(receiver), Flow::Continue, &[]),
                        Err(receiver::Error::NeedsLiteral { .. }) => {
                            self.write(b"+ Ready for literal data\r\n");
                            if iter.as_slice().is_empty() {
                                return (State::Command(receiver), Flow::Continue, &[]);
                            }
                        }
                        Err(receiver::Error::Error { response }) => self.write(response.serialize()),
                    }
                }
            }
            State::Sasl { tag, mut line } => match take_line(&mut line, bytes) {
                Some(rest) => {
                    self.sasl(&tag, &line).await;
                    (State::Command(self.receiver()), Flow::Continue, rest)
                }
                None if line.len() > 8192 => {
                    self.write(StatusResponse::bad("Line too long").with_tag(tag).into_bytes());
                    (State::Command(self.receiver()), Flow::Continue, &[])
                }
                None => (State::Sasl { tag, line }, Flow::Continue, &[]),
            },
            State::Idle { tag, mut line } => match take_line(&mut line, bytes) {
                Some(rest) => {
                    let done = line.trim_ascii().eq_ignore_ascii_case(b"DONE");
                    let response = if done {
                        StatusResponse::completed(Command::Idle)
                    } else {
                        StatusResponse::bad("Expected DONE")
                    };
                    self.write(response.with_tag(tag).into_bytes());
                    (State::Command(self.receiver()), Flow::Continue, rest)
                }
                None if line.len() > 1024 => {
                    self.write(StatusResponse::bad("Expected DONE").with_tag(tag).into_bytes());
                    (State::Command(self.receiver()), Flow::Continue, &[])
                }
                None => (State::Idle { tag, line }, Flow::Continue, &[]),
            },
        }
    }

    async fn request(&mut self, request: Request<Command>) -> Flow {
        let tag = request.tag.clone();
        let command = request.command;
        let mut flow = Flow::Continue;
        let response = match command {
            Command::Capability => {
                let capabilities = self.capabilities();
                self.write(capability::Response { capabilities }.serialize());
                StatusResponse::completed(command)
            }
            Command::Noop | Command::Check => StatusResponse::completed(command),
            Command::Logout => {
                self.write(StatusResponse::bye("kernoid logging out").into_bytes());
                flow = Flow::Logout;
                StatusResponse::completed(command)
            }
            Command::Id => {
                self.write(b"* ID (\"name\" \"kernoid\")\r\n");
                StatusResponse::completed(command)
            }
            Command::StartTls if self.tls => StatusResponse::bad("TLS is already active"),
            Command::StartTls => {
                flow = Flow::StartTls;
                StatusResponse::ok("Begin TLS negotiation now")
            }
            Command::Login | Command::Authenticate if self.account.is_some() => {
                StatusResponse::bad("Already logged in")
            }
            Command::Login | Command::Authenticate if !self.tls => {
                StatusResponse::no("Log in over TLS only").with_code(ResponseCode::PrivacyRequired)
            }
            Command::Login => match request.parse_login() {
                Ok(arguments) => self.login(&arguments.username, &arguments.password).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Authenticate => match request.parse_authenticate() {
                Ok(arguments)
                    if !matches!(
                        arguments.mechanism,
                        Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2
                    ) =>
                {
                    StatusResponse::no("Use AUTHENTICATE PLAIN, OAUTHBEARER or XOAUTH2").with_code(ResponseCode::Cannot)
                }
                Ok(arguments) => {
                    self.sasl_mechanism = arguments.mechanism;
                    match arguments.params.first() {
                        // SASL-IR: the response came with the command; `=` is an empty one.
                        Some(initial) => {
                            let initial = if initial == "=" { "" } else { initial.as_str() };
                            self.sasl_response(initial.as_bytes()).await
                        }
                        None => {
                            self.write(b"+ \r\n");
                            return Flow::Sasl(tag);
                        }
                    }
                }
                Err(error) => return self.parse_error(error),
            },
            _ if self.account.is_none() => StatusResponse::bad("Log in first"),
            Command::Enable => match request.parse_enable() {
                Ok(arguments) => self.enable(arguments),
                Err(error) => return self.parse_error(error),
            },
            Command::Namespace => {
                let shared_prefix = Some(format!("{}{}", crate::folders::SHARED, crate::folders::SEPARATOR));
                self.write(namespace::Response { shared_prefix }.serialize());
                StatusResponse::completed(command)
            }
            Command::Idle => {
                self.sync().await;
                self.write(b"+ idling\r\n");
                return Flow::Idle(tag);
            }
            Command::Select | Command::Examine => {
                let is_utf8 = self.is_utf8;
                match request.parse_select(is_utf8) {
                    Ok(arguments) => self.select(arguments, command == Command::Examine).await,
                    Err(error) => return self.parse_error(error),
                }
            }
            Command::List | Command::Lsub => {
                let is_utf8 = self.is_utf8;
                let arguments =
                    if command == Command::List { request.parse_list(is_utf8) } else { request.parse_lsub(is_utf8) };
                match arguments {
                    Ok(arguments) => self.list(arguments, command == Command::Lsub).await,
                    Err(error) => return self.parse_error(error),
                }
            }
            Command::Status => match request.parse_status(self.is_utf8) {
                Ok(arguments) => self.status(arguments).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Create => match request.parse_create(self.is_utf8) {
                Ok(arguments) => self.create(&arguments.mailbox_name).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Delete => match request.parse_delete(self.is_utf8) {
                Ok(arguments) => self.delete(&arguments.mailbox_name).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Rename => match request.parse_rename(self.is_utf8) {
                Ok(arguments) => self.rename(&arguments.mailbox_name, &arguments.new_mailbox_name).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Subscribe | Command::Unsubscribe => match request.parse_subscribe(self.is_utf8) {
                Ok(arguments) => self.subscribe(&arguments.mailbox_name, command == Command::Subscribe).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Append => match request.parse_append(self.is_utf8) {
                Ok(arguments) => self.append(arguments).await,
                Err(error) => return self.parse_error(error),
            },
            Command::GetAcl | Command::SetAcl | Command::DeleteAcl | Command::ListRights | Command::MyRights => {
                match request.parse_acl(self.is_utf8) {
                    Ok(arguments) => self.acl(command, arguments).await,
                    Err(error) => return self.parse_error(error),
                }
            }
            _ if self.selected.is_none() => StatusResponse::bad("No mailbox selected"),
            Command::Close | Command::Unselect => {
                if command == Command::Close {
                    self.expunge(None, false).await;
                }
                self.selected = None;
                StatusResponse::completed(command)
            }
            Command::Expunge(is_uid) => {
                let sequence = if is_uid {
                    let set = request.tokens.into_iter().next().map(receiver::Token::unwrap_bytes);
                    match set.as_deref().map(crate::proto::parser::parse_sequence_set) {
                        Some(Ok(sequence)) => Some(sequence),
                        _ => {
                            self.write(
                                StatusResponse::bad("UID EXPUNGE needs a set of UIDs").with_tag(tag).into_bytes(),
                            );
                            return Flow::Continue;
                        }
                    }
                } else {
                    None
                };
                self.expunge(sequence, true).await
            }
            Command::Fetch(is_uid) => match request.parse_fetch() {
                Ok(arguments) => self.fetch(arguments, is_uid).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Store(is_uid) => match request.parse_store() {
                Ok(arguments) => self.store(arguments, is_uid).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Search(is_uid) => match request.parse_search(self.version) {
                Ok(arguments) => self.search(arguments, is_uid).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Sort(is_uid) => match request.parse_sort() {
                Ok(arguments) => self.sort(arguments, is_uid).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Thread(is_uid) => match request.parse_thread() {
                Ok(arguments) => self.thread(arguments, is_uid).await,
                Err(error) => return self.parse_error(error),
            },
            Command::GetQuotaRoot => match request.parse_get_quota_root(self.is_utf8) {
                Ok(arguments) => self.get_quota_root(arguments).await,
                Err(error) => return self.parse_error(error),
            },
            Command::GetQuota => match request.parse_get_quota() {
                Ok(arguments) => self.get_quota(arguments).await,
                Err(error) => return self.parse_error(error),
            },
            Command::Copy(is_uid) | Command::Move(is_uid) => match request.parse_copy_move(self.is_utf8) {
                Ok(arguments) => self.copy_move(arguments, is_uid, matches!(command, Command::Move(_))).await,
                Err(error) => return self.parse_error(error),
            },
            _ => StatusResponse::bad("Command not supported"),
        };
        // RFC 9051, 7.5.1: no EXPUNGE while a command refers to messages by sequence number.
        let keeps_numbers = matches!(
            command,
            Command::Fetch(false)
                | Command::Store(false)
                | Command::Search(false)
                | Command::Sort(false)
                | Command::Thread(false)
        );
        if self.selected.is_some()
            && !keeps_numbers
            && !matches!(command, Command::Select | Command::Examine | Command::Logout)
        {
            self.sync().await;
        }
        self.write(response.with_tag(tag).into_bytes());
        flow
    }

    fn parse_error(&mut self, error: crate::proto::Error) -> Flow {
        self.write(error.serialize());
        Flow::Continue
    }

    fn enable(&mut self, arguments: enable::Arguments) -> StatusResponse {
        let mut enabled = Vec::new();
        for capability in arguments.capabilities {
            match capability {
                Capability::IMAP4rev2 => self.version = ProtocolVersion::Rev2,
                Capability::CondStore => self.condstore = true,
                Capability::QResync => {
                    self.qresync = true;
                    self.condstore = true;
                }
                Capability::Utf8Accept => self.is_utf8 = true,
                _ => continue,
            }
            enabled.push(capability);
        }
        self.write(enable::Response { enabled }.serialize());
        StatusResponse::completed(Command::Enable)
    }

    async fn login(&mut self, user: &str, password: &str) -> StatusResponse {
        let result = self.inner.identity.mail_login(user, password, Some(self.remote)).await;
        self.logged_in(result).await
    }

    async fn logged_in(
        &mut self,
        result: Result<kernoid_identity::account::AccountInfo, IdentityError>,
    ) -> StatusResponse {
        match result {
            Ok(account) => {
                if let Err(error) = self.inner.mail.ensure_account(account.id).await {
                    return mail_error(error);
                }
                self.account = Some(account.id);
                self.tenant = Some(account.tenant);
                StatusResponse::ok("Logged in")
                    .with_code(ResponseCode::Capability { capabilities: self.capabilities() })
            }
            Err(IdentityError::TooManyAttempts { .. }) => {
                StatusResponse::no("Too many attempts, try again later").with_code(ResponseCode::Unavailable)
            }
            Err(IdentityError::AccountDeactivated | IdentityError::InvalidCredentials) => {
                StatusResponse::no("Authentication failed").with_code(ResponseCode::AuthenticationFailed)
            }
            Err(error) => {
                tracing::warn!(%error, "checking a mail login");
                StatusResponse::no("Temporary authentication failure").with_code(ResponseCode::Unavailable)
            }
        }
    }

    async fn sasl_response(&mut self, encoded: &[u8]) -> StatusResponse {
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim_ascii()).ok();
        match self.sasl_mechanism {
            Mechanism::OAuthBearer | Mechanism::XOauth2 => {
                match decoded.as_deref().and_then(kernoid_identity::app_password::sasl_bearer) {
                    Some((user, token)) => {
                        let result = self.inner.identity.token_login(&token, user.as_deref()).await;
                        self.logged_in(result).await
                    }
                    None => StatusResponse::bad("Invalid AUTHENTICATE response"),
                }
            }
            _ => match decoded.as_deref().and_then(crate::sasl_plain) {
                Some((user, password)) => self.login(&user, &password).await,
                None => StatusResponse::bad("Invalid AUTHENTICATE PLAIN response"),
            },
        }
    }

    async fn sasl(&mut self, tag: &str, line: &[u8]) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let response =
            if line == b"*" { StatusResponse::bad("Authentication cancelled") } else { self.sasl_response(line).await };
        self.write(response.with_tag(tag).into_bytes());
    }
}

/// Adds `bytes` to `line` up to its end; the bytes after the line, once it is complete.
fn take_line<'b>(line: &mut Vec<u8>, bytes: &'b [u8]) -> Option<&'b [u8]> {
    match bytes.iter().position(|&b| b == b'\n') {
        Some(end) => {
            line.extend_from_slice(&bytes[..end]);
            Some(&bytes[end + 1..])
        }
        None => {
            line.extend_from_slice(bytes);
            None
        }
    }
}
