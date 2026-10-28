// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid as the MX of its tenants' domains (RFC 0002, 9): an SMTP server that accepts mail for their addresses,
//! checks it (iprev, SPF, DKIM, ARC, DMARC, a basic spam filter) and stores it at once. It relays nothing.

mod client;
pub mod dane;
pub mod dkim;
pub mod dns;
pub mod dns_check;
pub mod dsn;
mod message;
pub mod mta_sts;
pub mod outbound;
mod session;
pub mod spam;
mod submission;

use std::{net::IpAddr, sync::Arc, time::Duration};

use kernoid_mail::Mail;
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

pub use dns::Dns;
pub use session::Io;
pub use submission::Submission;

/// The server's settings, from `[smtp]` and `[mail]`.
#[derive(Debug, Clone)]
pub struct Settings {
    pub hostname: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_received: usize,
    pub junk_score: f32,
    pub timeout: Duration,
}

impl Settings {
    pub fn from_config(smtp: &kernoid_config::Smtp, mail: &kernoid_config::Mail) -> Self {
        Self {
            hostname: smtp.hostname.trim_end_matches('.').to_lowercase(),
            max_message_size: usize::try_from(mail.max_message_size).unwrap_or(usize::MAX),
            max_recipients: smtp.max_recipients,
            max_received: smtp.max_received,
            junk_score: smtp.junk_score,
            timeout: Duration::from_secs(smtp.timeout_seconds),
        }
    }
}

pub(crate) struct Inner {
    pub settings: Settings,
    pub mail: Mail,
    pub dns: Dns,
    pub tls: Option<TlsAcceptor>,
    /// Set for a submission listener; the MX has none.
    pub submission: Option<Submission>,
    /// Calendars, for invitations that arrive by mail (RFC 0004, 7).
    pub groupware: Option<kernoid_groupware::Groupware>,
}

#[derive(Clone)]
pub struct Server(Arc<Inner>);

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("hostname", &self.0.settings.hostname).finish_non_exhaustive()
    }
}

impl Server {
    /// `tls` offers `STARTTLS` with these certificates; without, mail arrives in plain text only.
    pub fn new(settings: Settings, mail: Mail, dns: Dns, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        Self(Arc::new(Inner {
            settings,
            mail,
            dns,
            tls: tls.map(TlsAcceptor::from),
            submission: None,
            groupware: None,
        }))
    }

    /// A submission listener (RFC 0002, 10.1): it needs TLS, since logging in is allowed only over it.
    pub fn submission(
        settings: Settings,
        mail: Mail,
        dns: Dns,
        tls: Arc<rustls::ServerConfig>,
        submission: Submission,
    ) -> Self {
        Self(Arc::new(Inner {
            settings,
            mail,
            dns,
            tls: Some(TlsAcceptor::from(tls)),
            submission: Some(submission),
            groupware: None,
        }))
    }

    /// Applies invitations in delivered mail to the recipients' calendars; call right after `new` or `submission`.
    pub fn with_groupware(mut self, groupware: kernoid_groupware::Groupware) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.0) {
            inner.groupware = Some(groupware);
        }
        self
    }

    /// Accepts connections until `shutdown`, at most `max_connections` sessions at once.
    pub async fn serve(self, listener: TcpListener, max_connections: usize, shutdown: CancellationToken) {
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
                            () = server.session(stream, remote.ip()) => {}
                        }
                        drop(permit);
                    });
                }
                Err(error) => tracing::warn!(%error, "accepting an SMTP connection"),
            }
        }
    }

    /// One session on `stream` from `remote` – for the listener, and for tests over an in-memory stream.
    pub async fn session(&self, stream: impl Io + 'static, remote: IpAddr) {
        session::Session::new(self.0.clone(), Box::new(stream), remote).run().await;
    }
}
