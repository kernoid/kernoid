// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid as an OpenID Connect provider (RFC 0001, section 7): applications, signing keys, the authorization code
//! flow with PKCE, ID and access tokens, userinfo.
//!
//! The flow: an application sends the browser to `authorize`; kernoid checks the client and its redirect URI, parks
//! an **auth request** and sends the browser to the login UI. The UI logs the person in (a session) and **finishes**
//! the auth request with that session; kernoid answers with the callback URL, which carries a one-time **code**. The
//! application exchanges the code, with the PKCE verifier, at the **token** endpoint for an ID token (a JWT signed with
//! the instance's active key) and an access token for **userinfo**.
//!
//! Secrets – client secrets, codes, access tokens – are stored only as SHA-256 hashes, private keys only sealed with
//! the main key; none of them ever goes into an event. PKCE (S256) is required for every client, as in OAuth 2.1.

mod admin;
pub mod application;
pub mod external;
pub mod federation;
mod flow;
mod jwt;
pub mod keys;
pub mod logout;
pub mod outbound;
pub mod saml;

pub use flow::{
    AuthRequestInfo, AuthorizeRequest, Authorized, Claims, Cleaned, EndSession, EndSessionRequest, OFFLINE_SCOPE,
    PROMPTS, ROLES_CLAIM, ROLES_SCOPE, TokenRequest, TokenResponse, UI_ERRORS, discovery,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kernoid_events::EventStore;
use kernoid_identity::{Identity, IdentityError};
use kernoid_store::MainKeys;
use sha2::{Digest, Sha256};

/// Lifetimes of what the flow hands out.
pub mod lifetime {
    use std::time::Duration;

    pub const AUTH_REQUEST: Duration = Duration::from_secs(10 * 60);
    pub const CODE: Duration = Duration::from_secs(60);
    pub const ID_TOKEN: Duration = Duration::from_secs(60 * 60);
    pub const ACCESS_TOKEN: Duration = Duration::from_secs(60 * 60);
    /// An offline refresh token not used for this long expires; each use starts it again.
    pub const OFFLINE_REFRESH: Duration = Duration::from_secs(30 * 24 * 60 * 60);
    /// A logout token is valid this long.
    pub const LOGOUT_TOKEN: Duration = Duration::from_secs(2 * 60);
}

/// What can go wrong. Errors of the `authorize` step that concern the client itself (`InvalidClient`,
/// `InvalidRedirectUri`) are shown to the user and never sent to an unchecked redirect URI.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("unknown client or wrong client credentials")]
    InvalidClient,
    #[error("the redirect URI is not registered for this client")]
    InvalidRedirectUri,
    #[error("{0}")]
    InvalidRequest(String),
    #[error("{0}")]
    InvalidGrant(String),
    #[error("only the authorization_code and refresh_token grants are supported")]
    UnsupportedGrantType,
    #[error("more scopes asked for than were granted")]
    InvalidScope,
    /// The session is older than `prompt=login` or `max_age` allow: the login UI must log the person in again.
    #[error("a fresh login is required")]
    LoginRequired,
    /// The tenant or the application requires a second factor the session has not passed: the login UI asks for
    /// one (or has it set up) and finishes again.
    #[error("a second factor is required")]
    MfaRequired,
    /// The application needs the person's consent (it requires it, or asks for `offline_access`): the login UI
    /// shows what it asks for and finishes again with the consent.
    #[error("the application needs consent")]
    ConsentRequired,
    #[error("{0}")]
    AccessDenied(String),
    /// Unknown, expired or already used.
    #[error("the auth request is not valid")]
    AuthRequestNotFound,
    #[error("the access token is not valid")]
    InvalidToken,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("{0}")]
    Internal(String),
}

pub(crate) type Result<T> = std::result::Result<T, OidcError>;

pub(crate) fn internal(error: impl std::fmt::Display) -> OidcError {
    OidcError::Internal(error.to_string())
}

pub(crate) fn sha256(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// `prefix` and 256 random bits, base64url.
pub(crate) fn random_secret(prefix: &str) -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(internal)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Equal in time whatever the contents.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Clone)]
pub struct Oidc {
    events: EventStore,
    identity: Identity,
    main: MainKeys,
    /// `https` in production; `http` only for trying kernoid out without TLS.
    scheme: String,
    /// `:port` where instances are reached on a port other than the scheme's own (`http.public_port`), else empty.
    port: String,
    keys: keys::KeyCache,
    /// For requests to external identity providers (`outbound`).
    outbound: reqwest::Client,
    allow_private: bool,
}

impl Oidc {
    pub fn new(events: EventStore, main: MainKeys, scheme: &str) -> Self {
        Self {
            identity: Identity::new(events.clone()),
            events,
            main,
            scheme: scheme.to_owned(),
            port: String::new(),
            keys: keys::KeyCache::default(),
            outbound: outbound::client(false),
            allow_private: false,
        }
    }

    /// Instances are reached on this port, not the scheme's own (`http.public_port`): issuer and links name it.
    pub fn public_port(mut self, port: Option<u16>) -> Self {
        self.port = port.map(|port| format!(":{port}")).unwrap_or_default();
        self
    }

    /// Allows requests to identity providers at private addresses and over plain HTTP
    /// (`outbound.allow_private_networks`).
    pub fn allow_private_networks(mut self, allow: bool) -> Self {
        self.outbound = outbound::client(allow);
        self.allow_private = allow;
        self
    }

    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        self.events.pool()
    }

    /// The issuer of an instance: its primary domain – never taken from a request.
    pub fn issuer(&self, primary_domain: &str) -> String {
        format!("{}://{primary_domain}{}", self.scheme, self.port)
    }

    /// Where logins happen: the instance's own login UI, or kernoid's at `/login`; without a trailing slash.
    pub fn login_url(&self, instance: &kernoid_identity::InstanceInfo) -> String {
        match &instance.login_ui {
            Some(url) => url.trim_end_matches('/').to_owned(),
            None => format!("{}/login", self.issuer(&instance.primary_domain)),
        }
    }
}
