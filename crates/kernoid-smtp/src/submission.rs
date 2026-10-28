// SPDX-License-Identifier: AGPL-3.0-or-later
//! Submission (RFC 0002, 10.1): accounts log in over TLS (`AUTH PLAIN`, `AUTH LOGIN`) with an app password – or
//! their password, if they need no second factor – and send as one of their own addresses, or of an account they may
//! send as (12.2). Local recipients get the message at once; everyone else through the queue, which signs it with
//! DKIM on the way out.

use std::collections::BTreeSet;

use base64::Engine;
use bytes::Bytes;
use kernoid_identity::{Identity, IdentityError};
use kernoid_mail::{Delivered, Delivery, MailError, Outgoing, Recipient};
use mail_parser::MessageParser;
use smtp_proto::{AUTH_LOGIN, AUTH_PLAIN, MailFrom as ProtoMailFrom, RcptTo, request::receiver::RequestReceiver};

use crate::session::{MailFrom, Rcpt, Session, State, normalize};

/// What a submission listener needs besides the MX.
#[derive(Clone)]
pub struct Submission {
    pub identity: Identity,
    /// Port 465: TLS from the start; otherwise `STARTTLS` (port 587).
    pub implicit_tls: bool,
    /// How long the queue tries outgoing mail.
    pub queue_lifetime: chrono::Duration,
}

impl std::fmt::Debug for Submission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Submission").field("implicit_tls", &self.implicit_tls).finish_non_exhaustive()
    }
}

/// Where an `AUTH` exchange stands.
#[derive(Debug, Clone)]
pub(crate) enum Sasl {
    Plain,
    LoginUser,
    LoginPassword(String),
}

fn decode(line: &[u8]) -> Option<String> {
    let line = std::str::from_utf8(line).ok()?.trim();
    let bytes = base64::engine::general_purpose::STANDARD.decode(line).ok()?;
    String::from_utf8(bytes).ok()
}

/// Whether `account` may send as `address`: one of its own, or of an account it may send as (RFC 0002, 12.2).
async fn is_own(mail: &kernoid_mail::Mail, account: uuid::Uuid, address: &str) -> bool {
    match mail.resolve_recipient(address).await {
        Ok(Recipient::Account { account: owner, .. }) if owner == account => true,
        Ok(Recipient::Account { account: owner, .. }) => {
            mail.access(account, owner).await.is_ok_and(|access| access.send_as)
        }
        _ => false,
    }
}

/// `authzid NUL authcid NUL password` (RFC 4616); an authzid must be the authcid or empty.
fn plain(token: &str) -> Option<(String, String)> {
    let mut parts = token.split('\0');
    let (authzid, user, password) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || (!authzid.is_empty() && authzid != user) {
        return None;
    }
    Some((user.to_owned(), password.to_owned()))
}

impl Session {
    /// Starts `AUTH`; the state to read the client's next line in, if the exchange goes on.
    pub(crate) async fn auth(&mut self, mechanism: u64, initial: String) -> Option<State> {
        if self.tls.is_none() {
            self.reply("538 5.7.11 Encryption required for requested authentication mechanism");
            return None;
        }
        if self.account.is_some() {
            self.reply("503 5.5.1 Already authenticated");
            return None;
        }
        match mechanism {
            AUTH_PLAIN if initial.is_empty() => {
                self.reply("334 ");
                Some(State::Sasl(Sasl::Plain, Vec::new()))
            }
            AUTH_PLAIN => {
                match decode(initial.as_bytes()).and_then(|token| plain(&token)) {
                    Some((user, password)) => self.login(&user, &password).await,
                    None => self.reply("501 5.5.2 Invalid AUTH PLAIN response"),
                }
                None
            }
            AUTH_LOGIN if initial.is_empty() => {
                self.reply("334 VXNlcm5hbWU6");
                Some(State::Sasl(Sasl::LoginUser, Vec::new()))
            }
            AUTH_LOGIN => match decode(initial.as_bytes()) {
                Some(user) => {
                    self.reply("334 UGFzc3dvcmQ6");
                    Some(State::Sasl(Sasl::LoginPassword(user), Vec::new()))
                }
                None => {
                    self.reply("501 5.5.2 Invalid AUTH LOGIN response");
                    None
                }
            },
            _ => {
                self.reply("504 5.5.4 Mechanism not supported; use PLAIN or LOGIN");
                None
            }
        }
    }

    /// A line of the `AUTH` exchange; the state to go on in.
    pub(crate) async fn sasl(&mut self, step: Sasl, line: &[u8]) -> State {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line == b"*" {
            self.reply("501 5.7.0 Authentication cancelled");
            return State::Request(RequestReceiver::default());
        }
        match (step, decode(line)) {
            (Sasl::Plain, Some(token)) => match plain(&token) {
                Some((user, password)) => self.login(&user, &password).await,
                None => self.reply("501 5.5.2 Invalid AUTH PLAIN response"),
            },
            (Sasl::LoginUser, Some(user)) => {
                self.reply("334 UGFzc3dvcmQ6");
                return State::Sasl(Sasl::LoginPassword(user), Vec::new());
            }
            (Sasl::LoginPassword(user), Some(password)) => self.login(&user, &password).await,
            (_, None) => self.reply("501 5.5.2 Invalid base64"),
        }
        State::Request(RequestReceiver::default())
    }

    async fn login(&mut self, user: &str, password: &str) {
        let Some(submission) = self.inner.submission.clone() else { return };
        match submission.identity.mail_login(user, password, Some(self.remote)).await {
            Ok(account) => {
                self.account = Some(account);
                self.reply("235 2.7.0 Authentication successful");
            }
            Err(IdentityError::TooManyAttempts { .. }) => self.reply("454 4.7.0 Too many attempts, try again later"),
            Err(IdentityError::AccountDeactivated) => self.reply("535 5.7.8 The account is deactivated"),
            Err(IdentityError::InvalidCredentials) => self.reply("535 5.7.8 Authentication credentials invalid"),
            Err(error) => {
                tracing::warn!(%error, "checking a mail login");
                self.reply("454 4.7.0 Temporary authentication failure");
            }
        }
    }

    pub(crate) async fn submission_mail_from(&mut self, from: ProtoMailFrom<String>) {
        if self.helo.is_none() {
            self.reply("503 5.5.1 Polite people say EHLO first");
            return;
        }
        let Some(account) = self.account.as_ref().map(|account| account.id) else {
            self.reply("530 5.7.0 Authentication required");
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
        let Some(address) = normalize(&from.address) else {
            self.reply("553 5.7.1 Send as one of your own addresses");
            return;
        };
        if !is_own(&self.inner.mail, account, &address).await {
            self.reply("553 5.7.1 Send as one of your own addresses");
            return;
        }
        let domain = address.rsplit_once('@').map(|(_, domain)| domain.to_owned()).unwrap_or_default();
        self.mail_from = Some(MailFrom { address, domain, spf: None });
        self.reply("250 2.1.0 OK");
    }

    pub(crate) async fn submission_rcpt_to(&mut self, to: RcptTo<String>) {
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
        let (accounts, remote) = match self.inner.mail.resolve_recipient(&address).await {
            Ok(Recipient::Account { account, .. }) => (vec![account], false),
            Ok(Recipient::Group { members, .. }) => (members, false),
            Ok(Recipient::NotLocal) => (Vec::new(), true),
            Ok(Recipient::Disabled) => {
                self.reply("550 5.2.1 Mailbox disabled");
                return;
            }
            Ok(Recipient::Unknown) => {
                self.reply("550 5.1.1 Mailbox does not exist");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "resolving a recipient");
                self.reply("451 4.3.0 Temporary failure, try again later");
                return;
            }
        };
        self.rcpts.push(Rcpt { address, accounts, remote });
        self.reply("250 2.1.5 OK");
    }

    /// The message of a logged-in account: its `From` checked, completed, delivered locally and queued for the rest.
    pub(crate) async fn finish_submission(&mut self) -> String {
        let raw = std::mem::take(&mut self.message);
        let (Some(account), Some(from), Some(submission)) = (
            self.account.clone(),
            self.mail_from.as_ref().map(|from| from.address.clone()),
            self.inner.submission.clone(),
        ) else {
            return "503 5.5.1 MAIL is required first".into();
        };
        let Some(message) = MessageParser::new().parse_headers(&raw[..]) else {
            return "550 5.6.0 The message could not be parsed".into();
        };
        let senders: Vec<String> = message
            .from()
            .map(|from| from.iter().filter_map(|addr| addr.address()).map(str::to_lowercase).collect())
            .unwrap_or_default();
        if senders.is_empty() {
            return "550 5.6.0 The message has no From".into();
        }
        for sender in &senders {
            if !is_own(&self.inner.mail, account.id, sender).await {
                return format!("550 5.7.1 You may not send as {sender}");
            }
        }
        let has_date = message.date().is_some();
        let has_message_id = message.message_id().is_some();
        drop(message);

        let hostname = &self.inner.settings.hostname;
        let helo = self.helo.clone().unwrap_or_default();
        let mut full = format!(
            "Received: from {helo} ([{remote}])\r\n\tby {hostname} (kernoid) with ESMTPSA;\r\n\t{date}\r\n",
            remote = self.remote,
            date = chrono::Utc::now().to_rfc2822(),
        );
        if !has_date {
            full.push_str(&format!("Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
        }
        if !has_message_id {
            full.push_str(&format!("Message-ID: <{}@{hostname}>\r\n", uuid::Uuid::now_v7()));
        }
        let mut full = full.into_bytes();
        full.extend_from_slice(&raw);
        let full = Bytes::from(full);

        // Local recipients first: when they fail for now, nothing is queued yet, and the retry skips who has it.
        let mut seen = BTreeSet::new();
        for rcpt in self.rcpts.iter().filter(|rcpt| !rcpt.remote) {
            for recipient in &rcpt.accounts {
                if !seen.insert(*recipient) {
                    continue;
                }
                let delivery = Delivery { from: &from, to: &rcpt.address, junk: false };
                match self.inner.mail.deliver(*recipient, full.clone(), delivery).await {
                    Ok(Delivered::Stored(_)) => {
                        // The sender is logged in and may use its `From` (RFC 0002, 10.1).
                        if let Some(groupware) = &self.inner.groupware {
                            groupware.receive_imip(*recipient, &full, true).await;
                        }
                    }
                    Ok(Delivered::Duplicate | Delivered::Discarded) => {}
                    Err(MailError::OverQuota) => {
                        return "452 4.2.2 A recipient's mailbox is full, try again later".into();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "delivering a submitted message");
                        return "451 4.3.0 Temporary failure, try again later".into();
                    }
                }
            }
        }
        let remote: Vec<String> =
            self.rcpts.iter().filter(|rcpt| rcpt.remote).map(|rcpt| rcpt.address.clone()).collect();
        if !remote.is_empty() {
            let outgoing = Outgoing {
                tenant: account.tenant,
                account: Some(account.id),
                from: &from,
                recipients: &remote,
                raw: full,
                lifetime: submission.queue_lifetime,
            };
            if let Err(error) = self.inner.mail.enqueue(outgoing).await {
                tracing::warn!(%error, "queueing a submitted message");
                return "451 4.3.0 Temporary failure, try again later".into();
            }
        }
        "250 2.0.0 Message accepted".into()
    }
}

#[cfg(test)]
mod tests {
    use super::plain;

    #[test]
    fn plain_tokens() {
        assert_eq!(plain("\0alice@firma.example\0secret"), Some(("alice@firma.example".into(), "secret".into())));
        assert_eq!(
            plain("alice@firma.example\0alice@firma.example\0secret").map(|(u, _)| u).as_deref(),
            Some("alice@firma.example")
        );
        assert_eq!(plain("bob@firma.example\0alice@firma.example\0secret"), None, "acting as someone else");
        assert_eq!(plain("only-one-part"), None);
    }
}
