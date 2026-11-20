// SPDX-License-Identifier: AGPL-3.0-or-later
//! An IMAP session (RFC 9051): commands read by the framer and the parser of `proto`, answered in order, with the
//! states not authenticated, authenticated and selected. Before a command completes, the client hears what changed in
//! the selected mailbox – except during `FETCH`, `STORE`, `SEARCH`, `SORT` and `THREAD` by sequence number, which
//! must not see sequence numbers move (RFC 9051, 7.5.1).

use std::{net::IpAddr, sync::Arc};

use base64::Engine;
use kernoid_identity::{IdentityError, account::AccountInfo};
use kernoid_mail::MailError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast::error::RecvError,
};
use uuid::Uuid;

use crate::{
    Inner, Io,
    proto::{
        frame::{Framer, Next},
        parse::{Bad, parse},
        request::{Command, Request},
        response::{Code, Status},
    },
    selected::Selected,
};

/// What all states offer.
const BASE: &str = "IMAP4rev2 IMAP4rev1 ENABLE SASL-IR LITERAL+ ID UTF8=ACCEPT";
/// What logging in brings (RFC 0002, 11.2).
const AUTHENTICATED: &str = "IDLE NAMESPACE CHILDREN MULTIAPPEND BINARY UNSELECT UIDPLUS ESEARCH WITHIN SEARCHRES \
     LIST-EXTENDED LIST-STATUS SPECIAL-USE MOVE CONDSTORE QRESYNC STATUS=SIZE ACL RIGHTS=texk SORT SORT=DISPLAY \
     THREAD=ORDEREDSUBJECT THREAD=REFERENCES QUOTA QUOTA=RES-STORAGE";

/// Output is sent once it grows past this, even in the middle of a command.
const FLUSH_AT: usize = 1024 * 1024;

/// What the session does after a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Close,
}

pub(crate) struct Session {
    pub inner: Arc<Inner>,
    stream: Box<dyn Io>,
    remote: IpAddr,
    tls: bool,
    framer: Framer,
    pub account: Option<Uuid>,
    pub tenant: Option<Uuid>,
    /// `ENABLE IMAP4rev2`.
    pub rev2: bool,
    /// Mailbox names and strings in UTF-8: `ENABLE UTF8=ACCEPT` or IMAP4rev2.
    pub utf8: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub selected: Option<Selected>,
    /// The tag of the command being answered (for `ESEARCH`).
    pub tag: String,
    out: Vec<u8>,
}

/// A failure of the store as the client sees it.
pub(crate) fn mail_error(error: MailError) -> Status {
    match error {
        MailError::NotFound(what) => Status::no(format!("{what} does not exist")).with_code(Code::NonExistent),
        MailError::Exists(what) => Status::no(format!("{what} exists already")).with_code(Code::AlreadyExists),
        MailError::Invalid(reason) => Status::no(reason).with_code(Code::Cannot),
        MailError::TooLarge { limit } => {
            Status::no(format!("The message is larger than {limit} bytes")).with_code(Code::TooBig)
        }
        MailError::OverQuota => Status::no("The quota does not leave room for it").with_code(Code::OverQuota),
        MailError::MailboxHasChild => Status::no("The mailbox has child mailboxes").with_code(Code::HasChildren),
        MailError::MailboxHasEmail => Status::no("The mailbox has messages").with_code(Code::Cannot),
        MailError::Unparsable => Status::no("The message could not be parsed").with_code(Code::Cannot),
        MailError::Refused(refused) => Status::no(refused.to_string()).with_code(Code::Cannot),
        error => {
            tracing::warn!(%error, "an IMAP command failed in the store");
            Status::unavailable()
        }
    }
}

impl Session {
    pub(crate) fn new(inner: Arc<Inner>, stream: Box<dyn Io>, remote: IpAddr) -> Self {
        let framer = Framer::new(inner.settings.max_message_size);
        Self {
            inner,
            stream,
            remote,
            tls: false,
            framer,
            account: None,
            tenant: None,
            rev2: false,
            utf8: false,
            condstore: false,
            qresync: false,
            selected: None,
            tag: String::new(),
            out: Vec::new(),
        }
    }

    pub(crate) fn write(&mut self, bytes: impl AsRef<[u8]>) {
        self.out.extend_from_slice(bytes.as_ref());
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let out = std::mem::take(&mut self.out);
        tokio::time::timeout(self.inner.settings.timeout, self.stream.write_all(&out))
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)??;
        self.stream.flush().await
    }

    /// Sends what is waiting if it is a lot – for long `FETCH` responses.
    pub(crate) async fn flush_if_large(&mut self) -> std::io::Result<()> {
        if self.out.len() >= FLUSH_AT { self.flush().await } else { Ok(()) }
    }

    fn capabilities(&self) -> String {
        let mut capabilities = BASE.to_owned();
        if self.account.is_some() {
            capabilities.push(' ');
            capabilities.push_str(AUTHENTICATED);
        } else if self.tls {
            capabilities.push_str(" AUTH=PLAIN AUTH=OAUTHBEARER AUTH=XOAUTH2");
        } else {
            capabilities.push_str(" STARTTLS LOGINDISABLED");
        }
        capabilities
    }

    /// Reads more of what the client sends; `false` if the connection ended or was idle too long.
    async fn read_more(&mut self) -> bool {
        let mut buffer = [0u8; 16 * 1024];
        match tokio::time::timeout(self.inner.settings.timeout, self.stream.read(&mut buffer)).await {
            Ok(Ok(0) | Err(_)) => false,
            Ok(Ok(read)) => {
                self.framer.push(&buffer[..read]);
                true
            }
            Err(_) => {
                self.write(Status::bye("Autologout; idle for too long").line(None));
                let _ = self.flush().await;
                false
            }
        }
    }

    /// A line outside a command (a response to `AUTHENTICATE`'s `+`); `None` if the session must end.
    async fn read_line(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.framer.line() {
                Some(Ok(line)) => return Some(line),
                Some(Err(())) => {
                    self.write(Status::bye("Line too long").line(None));
                    return None;
                }
                None => {
                    if self.flush().await.is_err() || !self.read_more().await {
                        return None;
                    }
                }
            }
        }
    }

    async fn upgrade(&mut self) -> bool {
        let plain = std::mem::replace(&mut self.stream, Box::new(tokio::io::duplex(1).0));
        match crate::start_tls(&self.inner, plain).await {
            Some(tls) => {
                self.stream = tls;
                self.tls = true;
                true
            }
            None => false,
        }
    }

    pub(crate) async fn run(mut self) {
        if self.inner.implicit_tls && !self.upgrade().await {
            return;
        }
        let greeting = Status::ok("kernoid ready").with_code(Code::Capability(self.capabilities()));
        self.write(greeting.line(None));
        loop {
            loop {
                match self.framer.next() {
                    Next::More => break,
                    Next::Continue => self.write(b"+ Ready for literal data\r\n"),
                    Next::Refused { tag, text } => {
                        self.write(Status::no(text).with_code(Code::TooBig).line(tag.as_deref()));
                    }
                    Next::Fatal(text) => {
                        self.write(Status::bye(text).line(None));
                        let _ = self.flush().await;
                        return;
                    }
                    Next::Command(frame) => {
                        let flow = match parse(&frame, self.utf8) {
                            Ok(request) => self.request(request).await,
                            Err(bad) => {
                                self.bad_request(bad);
                                Flow::Continue
                            }
                        };
                        if flow == Flow::Close {
                            let _ = self.flush().await;
                            let _ = self.stream.shutdown().await;
                            return;
                        }
                    }
                }
            }
            if self.flush().await.is_err() || !self.read_more().await {
                return;
            }
        }
    }

    fn bad_request(&mut self, bad: Bad) {
        let status = match bad.text.strip_prefix("BADCHARSET ") {
            Some(charset) => Status::no(format!("Unsupported charset {charset}")).with_code(Code::BadCharset),
            None => Status::bad(bad.text),
        };
        self.write(status.line(bad.tag.as_deref()));
    }

    async fn request(&mut self, Request { tag, command }: Request) -> Flow {
        let name = command.name();
        self.tag.clone_from(&tag);
        // Commands that must not see sequence numbers move, and those after which nothing is selected.
        let quiet = matches!(
            command,
            Command::Fetch { uid: false, .. }
                | Command::Store { uid: false, .. }
                | Command::Search { uid: false, .. }
                | Command::Sort { uid: false, .. }
                | Command::Thread { uid: false, .. }
                | Command::Select { .. }
                | Command::Close
                | Command::Unselect
        );
        let status = match command {
            Command::Capability => {
                let line = format!("* CAPABILITY {}\r\n", self.capabilities());
                self.write(line);
                Status::done()
            }
            Command::Noop => Status::done(),
            Command::Id => {
                self.write(b"* ID (\"name\" \"kernoid\")\r\n");
                Status::done()
            }
            Command::Logout => {
                self.write(Status::bye("kernoid logging out").line(None));
                self.write(Status::ok(format!("{name} completed")).line(Some(&tag)));
                return Flow::Close;
            }
            Command::StartTls if self.tls => Status::bad("TLS is already active"),
            Command::StartTls if self.account.is_some() => Status::bad("Already logged in"),
            Command::StartTls => {
                self.write(Status::ok("Begin TLS negotiation now").line(Some(&tag)));
                if self.flush().await.is_err() {
                    return Flow::Close;
                }
                // Nothing the client sent before the handshake counts (RFC 9051, 11.1).
                self.framer.clear();
                return if self.upgrade().await { Flow::Continue } else { Flow::Close };
            }
            Command::Login { .. } | Command::Authenticate { .. } if self.account.is_some() => {
                Status::bad("Already logged in")
            }
            Command::Login { .. } | Command::Authenticate { .. } if !self.tls => {
                Status::no("Log in over TLS only").with_code(Code::PrivacyRequired)
            }
            Command::Login { user, password } => {
                let result = self.inner.identity.mail_login(&user, &password, Some(self.remote)).await;
                self.logged_in(result).await
            }
            Command::Authenticate { mechanism, initial } => match self.authenticate(&mechanism, initial).await {
                Some(status) => status,
                None => return Flow::Close,
            },
            _ if self.account.is_none() => Status::bad("Log in first"),
            Command::Enable(capabilities) => self.enable(&capabilities),
            Command::Namespace => {
                self.write(b"* NAMESPACE ((\"\" \"/\")) ((\"Shared/\" \"/\")) NIL\r\n");
                Status::done()
            }
            Command::Select { mailbox, read_only, condstore, qresync } => {
                self.select(&mailbox, read_only, condstore, qresync).await
            }
            Command::Create(mailbox) => self.create(&mailbox).await,
            Command::Delete(mailbox) => self.delete(&mailbox).await,
            Command::Rename { from, to } => self.rename(&from, &to).await,
            Command::Subscribe { mailbox, subscribe } => self.subscribe(&mailbox, subscribe).await,
            Command::List(list) => self.list(list).await,
            Command::Lsub { reference, pattern } => self.lsub(&reference, &pattern).await,
            Command::Status { mailbox, items } => self.status(&mailbox, &items).await,
            Command::Append { mailbox, messages } => self.append(&mailbox, messages).await,
            Command::Idle => match self.idle().await {
                Some(status) => status,
                None => return Flow::Close,
            },
            Command::GetAcl(mailbox) => self.get_acl(&mailbox).await,
            Command::MyRights(mailbox) => self.my_rights(&mailbox).await,
            Command::ListRights { mailbox, identifier } => self.list_rights(&mailbox, &identifier).await,
            Command::SetAcl { mailbox, identifier, change } => self.set_acl(&mailbox, &identifier, Some(change)).await,
            Command::DeleteAcl { mailbox, identifier } => self.set_acl(&mailbox, &identifier, None).await,
            Command::GetQuota(root) => self.get_quota(&root).await,
            Command::GetQuotaRoot(mailbox) => self.get_quota_root(&mailbox).await,
            Command::SetQuota => Status::no("Quotas are set by the administrators").with_code(Code::NoPerm),
            _ if self.selected.is_none() => Status::bad("No mailbox selected"),
            Command::Check => Status::done(),
            Command::Close => {
                // The silent expunge of `CLOSE` (RFC 9051, 6.4.1).
                let status = self.expunge(None, false).await;
                self.selected = None;
                if status.is_ok() { Status::done() } else { status }
            }
            Command::Unselect => {
                self.selected = None;
                Status::done()
            }
            Command::Expunge(uids) => self.expunge(uids, true).await,
            Command::Search { uid, search } => self.search(search, uid).await,
            Command::Sort { uid, criteria, search } => self.sort(&criteria, search, uid).await,
            Command::Thread { uid, algorithm, search } => self.thread(algorithm, search, uid).await,
            Command::Fetch { uid, fetch } => self.fetch(fetch, uid).await,
            Command::Store { uid, store } => self.store(store, uid).await,
            Command::Copy { uid, is_move, set, mailbox } => self.copy_move(&set, &mailbox, uid, is_move).await,
        };
        if !quiet && self.selected.is_some() {
            self.sync().await;
        }
        let status = if status.is_ok() && status.text.is_empty() {
            Status { text: format!("{name} completed"), ..status }
        } else {
            status
        };
        self.write(status.line(Some(&tag)));
        Flow::Continue
    }

    fn enable(&mut self, capabilities: &[String]) -> Status {
        let mut enabled = Vec::new();
        for capability in capabilities {
            let flag = match capability.as_str() {
                "CONDSTORE" => &mut self.condstore,
                "QRESYNC" => {
                    self.condstore = true;
                    &mut self.qresync
                }
                "UTF8=ACCEPT" => &mut self.utf8,
                "IMAP4REV2" => {
                    self.utf8 = true;
                    &mut self.rev2
                }
                // Unknown capabilities are ignored (RFC 5161, 3.1).
                _ => continue,
            };
            if !*flag {
                *flag = true;
                enabled.push(if capability == "IMAP4REV2" { "IMAP4rev2" } else { capability.as_str() });
            }
        }
        let mut line = String::from("* ENABLED");
        for capability in enabled {
            line.push(' ');
            line.push_str(capability);
        }
        line.push_str("\r\n");
        self.write(line);
        Status::done()
    }

    /// `AUTHENTICATE` (RFC 9051, 6.2.2) with PLAIN (RFC 4616), OAUTHBEARER (RFC 7628) and XOAUTH2; `None` if the
    /// session must end.
    async fn authenticate(&mut self, mechanism: &str, initial: Option<Vec<u8>>) -> Option<Status> {
        if !matches!(mechanism, "PLAIN" | "OAUTHBEARER" | "XOAUTH2") {
            return Some(Status::bad(format!(
                "Unsupported mechanism {}",
                mechanism.chars().take(32).collect::<String>()
            )));
        }
        let response = match initial {
            Some(initial) if initial == b"=" => Vec::new(),
            Some(initial) => initial,
            None => {
                self.write(b"+ \r\n");
                let line = self.read_line().await?;
                if line == b"*" {
                    return Some(Status::bad("Authentication cancelled"));
                }
                line
            }
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(response.trim_ascii()) else {
            return Some(Status::bad("Invalid AUTHENTICATE response"));
        };
        let result = if mechanism == "PLAIN" {
            match crate::sasl_plain(&decoded) {
                Some((user, password)) => self.inner.identity.mail_login(&user, &password, Some(self.remote)).await,
                None => return Some(Status::bad("Invalid AUTHENTICATE response")),
            }
        } else {
            match kernoid_identity::app_password::sasl_bearer(&decoded) {
                Some((user, token)) => self.inner.identity.token_login(&token, user.as_deref()).await,
                None => return Some(Status::bad("Invalid AUTHENTICATE response")),
            }
        };
        Some(self.logged_in(result).await)
    }

    async fn logged_in(&mut self, result: Result<AccountInfo, IdentityError>) -> Status {
        let account = match result {
            Ok(account) => account,
            Err(IdentityError::TooManyAttempts { .. }) => {
                return Status::no("Too many attempts; try again later").with_code(Code::Unavailable);
            }
            Err(IdentityError::InvalidCredentials | IdentityError::AccountDeactivated) => {
                return Status::no("Authentication failed").with_code(Code::AuthenticationFailed);
            }
            Err(error) => {
                tracing::warn!(%error, "checking an IMAP login");
                return Status::unavailable();
            }
        };
        if let Err(error) = self.inner.mail.ensure_account(account.id).await {
            return mail_error(error);
        }
        self.account = Some(account.id);
        self.tenant = Some(account.tenant);
        Status::ok("Logged in").with_code(Code::Capability(self.capabilities()))
    }

    /// `IDLE` (RFC 2177): updates as they happen until `DONE`; `None` if the session must end.
    async fn idle(&mut self) -> Option<Status> {
        let mut events = self.inner.events.subscribe();
        self.write(b"+ idling\r\n");
        loop {
            match self.framer.line() {
                Some(Ok(line)) if line.eq_ignore_ascii_case(b"DONE") => return Some(Status::done()),
                Some(Ok(_)) => return Some(Status::bad("Expected DONE")),
                Some(Err(())) => {
                    self.write(Status::bye("Line too long").line(None));
                    return None;
                }
                None => {}
            }
            if self.flush().await.is_err() {
                return None;
            }
            let mut buffer = [0u8; 4096];
            let timeout = self.inner.settings.timeout;
            tokio::select! {
                read = tokio::time::timeout(timeout, self.stream.read(&mut buffer)) => match read {
                    Ok(Ok(0) | Err(_)) => return None,
                    Ok(Ok(read)) => self.framer.push(&buffer[..read]),
                    Err(_) => {
                        self.write(Status::bye("Autologout; idle for too long").line(None));
                        return None;
                    }
                },
                event = events.recv() => {
                    let watched = self.selected.as_ref().map(|selected| selected.owner);
                    match event {
                        Ok(account) if Some(account) == watched => self.sync().await,
                        Err(RecvError::Lagged(_)) => self.sync().await,
                        Ok(_) => {}
                        // No more events: only the client ends the wait.
                        Err(RecvError::Closed) => events = self.inner.events.subscribe(),
                    }
                }
            }
        }
    }
}
