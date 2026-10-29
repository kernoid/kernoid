// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP4rev2 and IMAP4rev1 on the mail store (RFC 0002, 11.2), and POP3 for the inbox (11.3): the protocol taken
//! over from Stalwart (`proto`), the servers kernoid's own. Accounts log in over TLS with an app password – or their
//! password, if they need no second factor.

#[allow(clippy::all, missing_debug_implementations, unused, reason = "taken over from Stalwart as it is")]
pub mod proto;

mod acl;
mod flags;
mod folders;
mod mailboxes;
mod message;
pub mod pop3;
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
        self,
        protocol: Protocol,
        listener: TcpListener,
        max_connections: usize,
        shutdown: CancellationToken,
    ) {
        let sessions = Arc::new(Semaphore::new(max_connections.max(1)));
        loop {
            let permit = tokio::select! {
                () = shutdown.cancelled() => return,
                permit = sessions.clone().acquire_owned() => permit.expect("the semaphore stays open"),
            };
            let accepted = tokio::select! {
                () = shutdown.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, remote)) => {
                    let server = self.clone();
                    let stop = shutdown.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            () = stop.cancelled() => {}
                            () = server.session(protocol, stream, remote.ip()) => {}
                        }
                        drop(permit);
                    });
                }
                Err(error) => tracing::warn!(%error, "accepting a mail client connection"),
            }
        }
    }

    /// One session on `stream` from `remote` – for the listener, and for tests over an in-memory stream.
    pub async fn session(&self, protocol: Protocol, stream: impl Io + 'static, remote: IpAddr) {
        let stream = Box::new(stream);
        match protocol {
            Protocol::Imap => session::Session::new(self.0.clone(), stream, remote).run().await,
            Protocol::Pop3 => pop3::Session::new(self.0.clone(), stream, remote).run().await,
        }
    }
}

/// Upgrades a connection to TLS; `None` if the handshake fails or takes too long.
pub(crate) async fn start_tls(inner: &Inner, plain: Box<dyn Io>) -> Option<Box<dyn Io>> {
    match tokio::time::timeout(Duration::from_secs(60), inner.tls.accept(plain)).await {
        Ok(Ok(tls)) => Some(Box::new(tls)),
        _ => None,
    }
}

/// `authzid NUL authcid NUL password` (RFC 4616); an authzid must be the authcid or empty.
pub(crate) fn sasl_plain(token: &[u8]) -> Option<(String, String)> {
    let token = std::str::from_utf8(token).ok()?;
    let mut parts = token.split('\0');
    let (authzid, user, password) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || (!authzid.is_empty() && authzid != user) {
        return None;
    }
    Some((user.to_owned(), password.to_owned()))
}
