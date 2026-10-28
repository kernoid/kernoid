// SPDX-License-Identifier: AGPL-3.0-or-later
//! POP3 for the inbox (RFC 0002, 11.3; RFC 1939, with CAPA from RFC 2449, STLS from RFC 2595 and SASL PLAIN from
//! RFC 5034). The maildrop is the inbox as it was at login; `UIDL` is the email id; `DELE`d messages leave the inbox
//! at `QUIT` – an email in no other mailbox is destroyed.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use base64::Engine;
use kernoid_identity::IdentityError;
use kernoid_mail::{MailError, MailboxEntry, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{Inner, Io};

/// The longest command line taken (RFC 2449, 4: 255 octets; room for an `AUTH` response).
const MAX_LINE: usize = 4096;

struct Maildrop {
    account: Uuid,
    inbox: Uuid,
    entries: Vec<MailboxEntry>,
    deleted: BTreeSet<usize>,
}

pub(crate) struct Session {
    inner: Arc<Inner>,
    remote: IpAddr,
    stream: Box<dyn Io>,
    tls: bool,
    user: Option<String>,
    /// `AUTH PLAIN` waits for its response.
    sasl: bool,
    maildrop: Option<Maildrop>,
    out: Vec<u8>,
}

enum Flow {
    Continue,
    StartTls,
    Quit,
}

impl Session {
    pub(crate) fn new(inner: Arc<Inner>, stream: Box<dyn Io>, remote: IpAddr) -> Self {
        Self { inner, remote, stream, tls: false, user: None, sasl: false, maildrop: None, out: Vec::new() }
    }

    fn reply(&mut self, line: impl AsRef<str>) {
        self.out.extend_from_slice(line.as_ref().as_bytes());
        self.out.extend_from_slice(b"\r\n");
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
        self.reply("+OK kernoid POP3 ready");
        let mut line = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            if self.flush().await.is_err() {
                return;
            }
            let n = match tokio::time::timeout(self.inner.settings.timeout, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(n)) => n,
            };
            let mut rest = &buf[..n];
            while let Some(end) = rest.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&rest[..end]);
                rest = &rest[end + 1..];
                let command = std::mem::take(&mut line);
                let command = command.strip_suffix(b"\r").unwrap_or(&command);
                match self.command(command).await {
                    Flow::Continue => {}
                    Flow::Quit => {
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
                        rest = &[];
                    }
                }
            }
            line.extend_from_slice(rest);
            if line.len() > MAX_LINE {
                self.reply("-ERR Line too long");
                let _ = self.flush().await;
                return;
            }
        }
    }

    async fn command(&mut self, line: &[u8]) -> Flow {
        if self.sasl {
            self.sasl = false;
            if line == b"*" {
                self.reply("-ERR Authentication cancelled");
            } else {
                self.auth_plain(line).await;
            }
            return Flow::Continue;
        }
        let line = String::from_utf8_lossy(line);
        let mut words = line.split_ascii_whitespace();
        let command = words.next().unwrap_or_default().to_ascii_uppercase();
        let arguments: Vec<&str> = words.collect();
        match (command.as_str(), self.maildrop.is_some()) {
            ("CAPA", _) => {
                self.reply("+OK Capability list follows");
                for capability in ["TOP", "UIDL", "RESP-CODES", "PIPELINING", "IMPLEMENTATION kernoid"] {
                    self.reply(capability);
                }
                if self.maildrop.is_none() {
                    if self.tls {
                        self.reply("USER");
                        self.reply("SASL PLAIN");
                    } else {
                        self.reply("STLS");
                    }
                }
                self.reply(".");
            }
            ("QUIT", _) => {
                self.quit().await;
                return Flow::Quit;
            }
            ("NOOP", true) => self.reply("+OK"),
            ("STLS", false) if !self.tls => {
                self.reply("+OK Begin TLS negotiation");
                return Flow::StartTls;
            }
            ("USER" | "PASS" | "AUTH", false) if !self.tls => self.reply("-ERR [AUTH] Log in over TLS only; use STLS"),
            ("USER", false) => match arguments.first() {
                Some(user) => {
                    self.user = Some((*user).to_owned());
                    self.reply("+OK");
                }
                None => self.reply("-ERR USER needs a name"),
            },
            ("PASS", false) => match self.user.take() {
                // The password may contain spaces.
                Some(user) => {
                    let password = line.get(5..).unwrap_or_default().to_owned();
                    self.login(&user, &password).await;
                }
                None => self.reply("-ERR USER first"),
            },
            ("AUTH", false) => match arguments.as_slice() {
                [mechanism, ..] if !mechanism.eq_ignore_ascii_case("PLAIN") => self.reply("-ERR Use AUTH PLAIN"),
                [_, initial] => {
                    let initial = if *initial == "=" { "" } else { initial };
                    self.auth_plain(initial.as_bytes()).await;
                }
                [_] => {
                    self.sasl = true;
                    self.reply("+ ");
                }
                _ => self.reply("-ERR AUTH needs a mechanism"),
            },
            ("STAT", true) => {
                let maildrop = self.maildrop.as_ref().expect("in the transaction state");
                let (count, size) = maildrop
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(position, _)| !maildrop.deleted.contains(position))
                    .fold((0, 0), |(count, size), (_, entry)| (count + 1, size + entry.size));
                self.reply(format!("+OK {count} {size}"));
            }
            ("LIST" | "UIDL", true) => {
                let uidl = command == "UIDL";
                let maildrop = self.maildrop.as_ref().expect("in the transaction state");
                let value = |entry: &MailboxEntry| if uidl { entry.email.to_string() } else { entry.size.to_string() };
                match arguments.first() {
                    Some(number) => match self.message(number) {
                        Ok(position) => {
                            let line = format!("+OK {} {}", position + 1, value(&maildrop.entries[position]));
                            self.reply(line);
                        }
                        Err(error) => self.reply(error),
                    },
                    None => {
                        let lines: Vec<String> = maildrop
                            .entries
                            .iter()
                            .enumerate()
                            .filter(|(position, _)| !maildrop.deleted.contains(position))
                            .map(|(position, entry)| format!("{} {}", position + 1, value(entry)))
                            .collect();
                        self.reply("+OK");
                        for line in lines {
                            self.reply(line);
                        }
                        self.reply(".");
                    }
                }
            }
            ("RETR" | "TOP", true) => {
                let lines = if command == "TOP" {
                    match arguments.get(1).map(|lines| lines.parse::<usize>()) {
                        Some(Ok(lines)) => Some(lines),
                        _ => {
                            self.reply("-ERR TOP needs a message and a number of lines");
                            return Flow::Continue;
                        }
                    }
                } else {
                    None
                };
                match arguments.first().map(|number| self.message(number)) {
                    Some(Ok(position)) => self.retrieve(position, lines).await,
                    Some(Err(error)) => self.reply(error),
                    None => self.reply("-ERR Which message?"),
                }
            }
            ("DELE", true) => match arguments.first().map(|number| self.message(number)) {
                Some(Ok(position)) => {
                    self.maildrop.as_mut().expect("in the transaction state").deleted.insert(position);
                    self.reply(format!("+OK message {} deleted", position + 1));
                }
                Some(Err(error)) => self.reply(error),
                None => self.reply("-ERR Which message?"),
            },
            ("RSET", true) => {
                self.maildrop.as_mut().expect("in the transaction state").deleted.clear();
                self.reply("+OK");
            }
            _ => self.reply("-ERR Unknown command or wrong state"),
        }
        Flow::Continue
    }

    /// The position of message `number`, if it exists and is not deleted.
    fn message(&self, number: &str) -> Result<usize, &'static str> {
        let maildrop = self.maildrop.as_ref().expect("in the transaction state");
        let position = number.parse::<usize>().ok().and_then(|n| n.checked_sub(1)).ok_or("-ERR No such message")?;
        if position >= maildrop.entries.len() {
            return Err("-ERR No such message");
        }
        if maildrop.deleted.contains(&position) {
            return Err("-ERR Message is deleted");
        }
        Ok(position)
    }

    async fn auth_plain(&mut self, encoded: &[u8]) {
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim_ascii()).ok();
        match decoded.as_deref().and_then(crate::sasl_plain) {
            Some((user, password)) => self.login(&user, &password).await,
            None => self.reply("-ERR Invalid AUTH PLAIN response"),
        }
    }

    async fn login(&mut self, user: &str, password: &str) {
        let account = match self.inner.identity.mail_login(user, password, Some(self.remote)).await {
            Ok(account) => account.id,
            Err(IdentityError::TooManyAttempts { .. }) => return self.reply("-ERR [SYS/TEMP] Too many attempts"),
            Err(IdentityError::AccountDeactivated | IdentityError::InvalidCredentials) => {
                return self.reply("-ERR [AUTH] Authentication failed");
            }
            Err(error) => {
                tracing::warn!(%error, "checking a mail login");
                return self.reply("-ERR [SYS/TEMP] Temporary authentication failure");
            }
        };
        let mail = &self.inner.mail;
        let maildrop = async {
            mail.ensure_account(account).await?;
            let inbox = mail.mailbox_with_role(account, Role::Inbox).await?;
            let entries = mail.mailbox_entries(account, inbox).await?;
            Ok::<_, MailError>(Maildrop { account, inbox, entries, deleted: BTreeSet::new() })
        };
        match maildrop.await {
            Ok(maildrop) => {
                let count = maildrop.entries.len();
                self.maildrop = Some(maildrop);
                self.reply(format!("+OK {count} messages"));
            }
            Err(error) => {
                tracing::warn!(%error, "opening a POP3 maildrop");
                self.reply("-ERR [SYS/TEMP] The maildrop cannot be opened");
            }
        }
    }

    /// `RETR`, or `TOP` with the header and `lines` lines of the body; dot-stuffed, lines ending in CRLF.
    async fn retrieve(&mut self, position: usize, lines: Option<usize>) {
        let maildrop = self.maildrop.as_ref().expect("in the transaction state");
        let (account, email) = (maildrop.account, maildrop.entries[position].email);
        let raw = match self.inner.mail.raw_email(account, email).await {
            Ok(raw) => raw,
            Err(MailError::NotFound(_)) => return self.reply("-ERR The message was removed meanwhile"),
            Err(error) => {
                tracing::warn!(%error, "reading a message for POP3");
                return self.reply("-ERR [SYS/TEMP] The message cannot be read");
            }
        };
        self.reply("+OK");
        let mut in_body = false;
        let mut body_lines = 0;
        for line in raw.split_inclusive(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if in_body {
                if lines.is_some_and(|lines| body_lines >= lines) {
                    break;
                }
                body_lines += 1;
            } else if line.is_empty() {
                in_body = true;
            }
            if line.first() == Some(&b'.') {
                self.out.push(b'.');
            }
            self.out.extend_from_slice(line);
            self.out.extend_from_slice(b"\r\n");
        }
        self.reply(".");
    }

    /// `QUIT`: in the transaction state, the `DELE`d messages leave the inbox (RFC 1939, 6).
    async fn quit(&mut self) {
        let Some(maildrop) = self.maildrop.take() else {
            return self.reply("+OK Bye");
        };
        let uids: BTreeSet<u32> = maildrop.deleted.iter().map(|&position| maildrop.entries[position].uid).collect();
        if uids.is_empty() {
            return self.reply("+OK Bye");
        }
        match self.inner.mail.remove_from_mailbox(maildrop.account, maildrop.inbox, &uids).await {
            Ok(removed) => self.reply(format!("+OK Bye; {} messages deleted", removed.len())),
            Err(error) => {
                tracing::warn!(%error, "deleting POP3 messages");
                self.reply("-ERR [SYS/TEMP] Some deleted messages were not removed");
            }
        }
    }
}
