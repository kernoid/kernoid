// SPDX-License-Identifier: AGPL-3.0-or-later
//! The directory over LDAPv3 (RFC 4511; RFC 0003, 8) for software that reads one: each tenant's people and groups,
//! read only. Messages are parsed and written by ldap3_proto (MPL-2.0, from Kanidm); the server is kernoid's own.
//!
//! An account binds over TLS – LDAPS, or after `StartTLS` – with its address or its DN and an app password, or its
//! password if it needs no second factor; failures count like failed logins. A bound account reads its tenant's
//! tree (`tree`); without a bind, only the root DSE. What would change the directory is refused: the directory is
//! kept with kernoid's API, SCIM or the web app.

pub mod tree;

use std::{net::IpAddr, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use kernoid_identity::{Identity, IdentityError};
use ldap3_proto::{
    LdapCodec,
    control::LdapControl,
    proto::{
        LdapBindCred, LdapBindResponse, LdapExtendedResponse, LdapMsg, LdapOp, LdapResult, LdapResultCode,
        LdapSearchRequest, LdapSearchScope,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::Semaphore,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{codec::Framed, sync::CancellationToken};
use uuid::Uuid;

/// A connection, plain or upgraded to TLS.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The server's settings, from `[ldap]`.
#[derive(Debug, Clone)]
pub struct Settings {
    /// How long a session may say nothing.
    pub timeout: Duration,
    /// The most entries one search returns.
    pub max_entries: usize,
}

impl Settings {
    pub fn from_config(ldap: &kernoid_config::Ldap) -> Self {
        Self { timeout: Duration::from_secs(ldap.timeout_seconds), max_entries: ldap.max_entries }
    }
}

struct Inner {
    settings: Settings,
    identity: Identity,
    tls: TlsAcceptor,
    /// Port 636: TLS before anything is said; otherwise `StartTLS`.
    implicit_tls: bool,
}

/// An LDAP listener.
#[derive(Clone)]
pub struct Server(Arc<Inner>);

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("implicit_tls", &self.0.implicit_tls).finish_non_exhaustive()
    }
}

impl Server {
    /// Binding needs TLS, so there is no server without certificates.
    pub fn new(settings: Settings, identity: Identity, tls: Arc<rustls::ServerConfig>, implicit_tls: bool) -> Self {
        Self(Arc::new(Inner { settings, identity, tls: TlsAcceptor::from(tls), implicit_tls }))
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
                Err(error) => tracing::warn!(%error, "accepting an LDAP connection"),
            }
        }
    }

    /// One session on `stream` from `remote` – for the listener, and for tests over an in-memory stream.
    pub async fn session(&self, stream: impl Io + 'static, remote: IpAddr) {
        let mut stream: Box<dyn Io> = Box::new(stream);
        if self.0.implicit_tls {
            match self.start_tls(stream).await {
                Some(tls) => stream = tls,
                None => return,
            }
        }
        Session { inner: self.0.clone(), remote, tls: self.0.implicit_tls, bound: None }.run(stream).await;
    }

    async fn start_tls(&self, plain: Box<dyn Io>) -> Option<Box<dyn Io>> {
        match tokio::time::timeout(Duration::from_secs(60), self.0.tls.accept(plain)).await {
            Ok(Ok(tls)) => Some(Box::new(tls)),
            _ => None,
        }
    }
}

/// Who is bound.
#[derive(Debug, Clone)]
struct Bound {
    tenant: Uuid,
    dn: String,
}

struct Session {
    inner: Arc<Inner>,
    remote: IpAddr,
    tls: bool,
    bound: Option<Bound>,
}

fn done(code: LdapResultCode, message: &str) -> LdapResult {
    LdapResult { code, matcheddn: String::new(), message: message.to_owned(), referral: Vec::new() }
}

fn success() -> LdapResult {
    done(LdapResultCode::Success, "")
}

/// What a session does after a message.
enum Next {
    Continue,
    StartTls,
    Close,
}

impl Session {
    async fn run(mut self, stream: Box<dyn Io>) {
        let mut framed = Framed::new(stream, LdapCodec::default());
        loop {
            let message = match tokio::time::timeout(self.inner.settings.timeout, framed.next()).await {
                Ok(Some(Ok(message))) => message,
                // A message that does not parse ends the session (RFC 4511, 4.1.1): there is no telling where
                // the next one starts.
                Ok(Some(Err(_))) | Ok(None) | Err(_) => return,
            };
            let msgid = message.msgid;
            let (responses, controls, next) = self.handle(message).await;
            let count = responses.len();
            for (index, op) in responses.into_iter().enumerate() {
                let mut response = LdapMsg::new(msgid, op);
                if index + 1 == count {
                    response.ctrl = controls.clone();
                }
                if framed.send(response).await.is_err() {
                    return;
                }
            }
            match next {
                Next::Continue => {}
                Next::Close => return,
                Next::StartTls => {
                    // Nothing the client sent after StartTLS may be read as plain text.
                    if !framed.read_buffer().is_empty() {
                        return;
                    }
                    let plain = framed.into_inner();
                    match Server(self.inner.clone()).start_tls(plain).await {
                        Some(tls) => {
                            self.tls = true;
                            framed = Framed::new(tls, LdapCodec::default());
                        }
                        None => return,
                    }
                }
            }
        }
    }

    /// The responses to a message, the controls of the last, and what comes next.
    async fn handle(&mut self, message: LdapMsg) -> (Vec<LdapOp>, Vec<LdapControl>, Next) {
        if let LdapOp::SearchRequest(request) = &message.op {
            let (responses, controls) = self.search(request, &message.ctrl).await;
            return (responses, controls, Next::Continue);
        }
        let (responses, next) = self.handle_other(message).await;
        (responses, Vec::new(), next)
    }

    async fn handle_other(&mut self, message: LdapMsg) -> (Vec<LdapOp>, Next) {
        match message.op {
            LdapOp::BindRequest(request) => {
                let result = self.bind(&request.dn, request.cred).await;
                (vec![LdapOp::BindResponse(LdapBindResponse { res: result, saslcreds: None })], Next::Continue)
            }
            LdapOp::UnbindRequest => (Vec::new(), Next::Close),
            LdapOp::ExtendedRequest(request) => match request.name.as_str() {
                tree::OID_START_TLS if self.tls => {
                    (vec![extended(done(LdapResultCode::OperationsError, "TLS is up already"), None)], Next::Continue)
                }
                tree::OID_START_TLS => (vec![extended(success(), Some(tree::OID_START_TLS))], Next::StartTls),
                tree::OID_WHOAMI => {
                    let who = self.bound.as_ref().map(|bound| format!("dn:{}", bound.dn)).unwrap_or_default();
                    let mut response = LdapExtendedResponse { res: success(), name: None, value: None };
                    response.value = Some(who.into_bytes());
                    (vec![LdapOp::ExtendedResponse(response)], Next::Continue)
                }
                _ => (
                    vec![extended(done(LdapResultCode::ProtocolError, "unsupported extended operation"), None)],
                    Next::Continue,
                ),
            },
            LdapOp::AbandonRequest(_) => (Vec::new(), Next::Continue),
            op => {
                let refused = done(LdapResultCode::UnwillingToPerform, "the directory is read only");
                let response = match op {
                    LdapOp::ModifyRequest(_) => LdapOp::ModifyResponse(refused),
                    LdapOp::AddRequest(_) => LdapOp::AddResponse(refused),
                    LdapOp::DelRequest(_) => LdapOp::DelResponse(refused),
                    LdapOp::ModifyDNRequest(_) => LdapOp::ModifyDNResponse(refused),
                    LdapOp::CompareRequest(_) => LdapOp::CompareResult(refused),
                    // A response from a client: not something a client sends.
                    _ => return (Vec::new(), Next::Close),
                };
                (vec![response], Next::Continue)
            }
        }
    }

    /// A simple bind (RFC 4513, 5.1): anonymous, or an account with its password – over TLS only.
    async fn bind(&mut self, dn: &str, cred: LdapBindCred) -> LdapResult {
        self.bound = None;
        let LdapBindCred::Simple(password) = cred else {
            return done(LdapResultCode::AuthMethodNotSupported, "only simple binds");
        };
        match (dn.is_empty(), password.is_empty()) {
            (true, true) => return success(),
            // An unauthenticated bind (RFC 4513, 5.1.2) would look like a successful one to careless software.
            (false, true) => return done(LdapResultCode::UnwillingToPerform, "a bind needs a password"),
            (true, false) => return done(LdapResultCode::InvalidCredentials, "invalid credentials"),
            (false, false) => {}
        }
        if !self.tls {
            return done(LdapResultCode::ConfidentialityRequired, "bind over TLS: LDAPS or StartTLS");
        }
        let login = tree::bind_login(dn).unwrap_or_else(|| dn.trim().to_owned());
        match self.inner.identity.program_login(&login, &password, Some(self.remote), &[], None).await {
            Ok(account) => {
                self.bound =
                    Some(Bound { tenant: account.tenant, dn: tree::person_dn(account.tenant, &account.address) });
                success()
            }
            Err(IdentityError::InvalidCredentials | IdentityError::AccountDeactivated) => {
                done(LdapResultCode::InvalidCredentials, "invalid credentials")
            }
            Err(IdentityError::TooManyAttempts { .. }) => {
                done(LdapResultCode::Busy, "too many attempts; try again later")
            }
            Err(error) => {
                tracing::warn!(%error, "an LDAP bind");
                done(LdapResultCode::Other, "try again later")
            }
        }
    }

    /// A search: its entries and result, and the controls of the result.
    async fn search(&self, request: &LdapSearchRequest, controls: &[LdapControl]) -> (Vec<LdapOp>, Vec<LdapControl>) {
        let paged = controls.iter().any(|control| matches!(control, LdapControl::SimplePagedResults { .. }));
        let finish = |result: LdapResult, mut out: Vec<LdapOp>| {
            out.push(LdapOp::SearchResultDone(result));
            // Every entry comes on the first page; the empty cookie says there is no other (RFC 2696).
            let controls =
                if paged { vec![LdapControl::SimplePagedResults { size: 0, cookie: Vec::new() }] } else { Vec::new() };
            (out, controls)
        };
        let base = tree::normalize(&request.base);
        if base.is_empty() && request.scope == LdapSearchScope::Base {
            let context = self.bound.as_ref().map(|bound| tree::base_dn(bound.tenant));
            let entry = tree::root_dse(context);
            let mut out = Vec::new();
            if tree::matches(&entry, &request.filter) {
                out.push(LdapOp::SearchResultEntry(tree::result(&entry, &request.attrs, request.typesonly)));
            }
            return finish(success(), out);
        }
        let Some(bound) = &self.bound else {
            return finish(done(LdapResultCode::InsufficentAccessRights, "bind first"), Vec::new());
        };
        let directory = match self.inner.identity.directory(bound.tenant).await {
            Ok(directory) => directory,
            Err(error) => {
                tracing::warn!(%error, "an LDAP search");
                return finish(done(LdapResultCode::Other, "try again later"), Vec::new());
            }
        };
        let entries = tree::entries(bound.tenant, &directory);
        let tenant_base = tree::normalize(&tree::base_dn(bound.tenant));
        let exists = entries.iter().any(|entry| tree::normalize(&entry.dn) == base);
        if !exists {
            let matched =
                if base.ends_with(&format!(",{tenant_base}")) { tree::base_dn(bound.tenant) } else { String::new() };
            let mut result = done(LdapResultCode::NoSuchObject, "no such entry");
            result.matcheddn = matched;
            return finish(result, Vec::new());
        }
        let limit = match usize::try_from(request.sizelimit) {
            Ok(asked) if asked > 0 => asked.min(self.inner.settings.max_entries),
            _ => self.inner.settings.max_entries,
        };
        let mut out = Vec::new();
        for entry in &entries {
            if !tree::in_scope(&tree::normalize(&entry.dn), &base, &request.scope)
                || !tree::matches(entry, &request.filter)
            {
                continue;
            }
            if out.len() == limit {
                return finish(done(LdapResultCode::SizeLimitExceeded, "more entries than the limit"), out);
            }
            out.push(LdapOp::SearchResultEntry(tree::result(entry, &request.attrs, request.typesonly)));
        }
        finish(success(), out)
    }
}

fn extended(result: LdapResult, name: Option<&str>) -> LdapOp {
    LdapOp::ExtendedResponse(LdapExtendedResponse { res: result, name: name.map(str::to_owned), value: None })
}
