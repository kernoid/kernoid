// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP4rev2 and IMAP4rev1 on the mail store (RFC 0002, 11.2), and POP3 for the inbox (11.3) – the protocol, the
//! sessions and the servers all kernoid's own. Accounts log in over TLS with an app password, an access token – or
//! their password, if they need no second factor.

mod acl;
mod flags;
mod folders;
mod mailboxes;
mod message;
pub mod pop3;
mod proto;
mod search;
mod selected;
mod session;
mod sort;

use std::{net::IpAddr, sync::Arc, time::Duration};

use kernoid_identity::Identity;
use kernoid_mail::{Mail, MailEvents};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::Semaphore,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

/// A connection, plain or upgraded to TLS.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The server's settings, from `[imap]` and `[mail]`.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The largest message `APPEND` takes.
    pub max_message_size: usize,
    /// How long a session may say nothing; `IDLE` included (RFC 9051, 5.4: at least 30 minutes).
    pub timeout: Duration,
}

impl Settings {
    pub fn from_config(imap: &kernoid_config::Imap, mail: &kernoid_config::Mail) -> Self {
        Self {
            max_message_size: usize::try_from(mail.max_message_size).unwrap_or(usize::MAX),
            timeout: Duration::from_secs(imap.timeout_seconds),
        }
    }
}

/// What every session of a listener shares.
pub(crate) struct Inner {
    pub settings: Settings,
    pub mail: Mail,
    pub identity: Identity,
    pub events: MailEvents,
    pub tls: TlsAcceptor,
    /// Ports 993 and 995: TLS before anything is said; otherwise `STARTTLS`/`STLS`.
    pub implicit_tls: bool,
}

/// An IMAP or POP3 listener.
#[derive(Clone)]
pub struct Server(Arc<Inner>);

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("implicit_tls", &self.0.implicit_tls).finish_non_exhaustive()
    }
}

/// Which protocol a listener speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Imap,
    Pop3,
}

impl Server {
    /// Logging in needs TLS, so there is no server without certificates.
    pub fn new(
        settings: Settings,
        mail: Mail,
        identity: Identity,
        events: MailEvents,
        tls: Arc<rustls::ServerConfig>,
        implicit_tls: bool,
    ) -> Self {
        Self(Arc::new(Inner { settings, mail, identity, events, tls: TlsAcceptor::from(tls), implicit_tls }))
    }

    /// Accepts connections until `shutdown`, at most `max_connections` sessions at once.
    pub async fn serve(
        &self,
        protocol: Protocol,
        listener: TcpListener,
        max_connections: usize,
        shutdown: CancellationToken,
    ) {
        let slots = Arc::new(Semaphore::new(max_connections.max(1)));
        loop {
            let slot = tokio::select! {
                () = shutdown.cancelled() => return,
                slot = slots.clone().acquire_owned() => match slot {
                    Ok(slot) => slot,
                    Err(_) => return,
                },
            };
            let (stream, remote) = tokio::select! {
                () = shutdown.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, ?protocol, "accepting a mail client");
                        continue;
                    }
                },
            };
            let _ = stream.set_nodelay(true);
            let server = self.clone();
            let stop = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = stop.cancelled() => {}
                    () = server.session(protocol, stream, remote.ip()) => {}
                }
                drop(slot);
            });
        }
    }

    /// One session on `stream` from `remote` – for the listener, and for tests over an in-memory stream.
    pub async fn session(&self, protocol: Protocol, stream: impl Io + 'static, remote: IpAddr) {
        let stream: Box<dyn Io> = Box::new(stream);
        match protocol {
            Protocol::Imap => session::Session::new(self.0.clone(), stream, remote).run().await,
            Protocol::Pop3 => pop3::Session::new(self.0.clone(), stream, remote).run().await,
        }
    }
}

/// Upgrades a connection to TLS; `None` if the handshake fails or takes too long.
pub(crate) async fn start_tls(inner: &Inner, plain: Box<dyn Io>) -> Option<Box<dyn Io>> {
    match tokio::time::timeout(Duration::from_secs(30), inner.tls.accept(plain)).await {
        Ok(Ok(tls)) => Some(Box::new(tls)),
        Ok(Err(error)) => {
            tracing::debug!(%error, "TLS handshake of a mail client failed");
            None
        }
        Err(_) => None,
    }
}

/// `authzid NUL authcid NUL password` (RFC 4616); an authzid must be the authcid or empty.
pub(crate) fn sasl_plain(token: &[u8]) -> Option<(String, String)> {
    let mut fields = token.split(|&b| b == 0);
    let (authzid, authcid, password) = (fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some() || authcid.is_empty() || (!authzid.is_empty() && authzid != authcid) {
        return None;
    }
    Some((String::from_utf8(authcid.to_vec()).ok()?, String::from_utf8(password.to_vec()).ok()?))
}

#[cfg(test)]
mod tests {
    use super::sasl_plain;

    #[test]
    fn plain_responses() {
        assert_eq!(sasl_plain(b"\0alice\0secret"), Some(("alice".into(), "secret".into())));
        assert_eq!(sasl_plain(b"alice\0alice\0secret"), Some(("alice".into(), "secret".into())));
        assert_eq!(sasl_plain(b"bob\0alice\0secret"), None);
        assert_eq!(sasl_plain(b"\0\0secret"), None);
        assert_eq!(sasl_plain(b"\0alice"), None);
        assert_eq!(sasl_plain(b"\0alice\0a\0b"), None);
    }
}
