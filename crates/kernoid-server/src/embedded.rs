// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's identity built into another program's server (RFC 0009, 3): the program starts kernoid with its
//! configuration, merges kernoid's router into its own, and asks [`Session`] who is logged in. Built without the
//! features `mail`, `calendars` and `files`, nothing of those is compiled in.
//!
//! ```no_run
//! # async fn example(config: kernoid_config::Config) -> Result<(), Box<dyn std::error::Error>> {
//! use axum::{Router, routing::get};
//! use kernoid_server::embedded::{Embedded, Session};
//!
//! let shutdown = tokio_util::sync::CancellationToken::new();
//! let kernoid = Embedded::start(config, shutdown.clone()).await?;
//! let program = Router::new()
//!     .route("/music/me", get(|session: Session| async move { session.account.display_name }))
//!     .with_state(kernoid.state().clone());
//! let app = kernoid.router(program);
//! # let _ = app; Ok(()) }
//! ```

use std::sync::Arc;

use axum::{
    Router,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::{IntoResponse, Response},
};
use kernoid_config::Config;
use kernoid_events::EventStore;
use kernoid_identity::{Identity, InstanceInfo, account::AccountInfo};
use kernoid_oidc::Oidc;
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{AppState, instance::CurrentInstance, jobs, sessions::SessionToken};

#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    #[error("encryption.main_key: {0}")]
    MainKey(String),
    #[error("migrating kernoid's schema: {0}")]
    Migrate(#[from] kernoid_store::MigrateError),
    #[error("connecting to PostgreSQL: {0}")]
    Database(#[from] sqlx::Error),
    #[error("object storage: {0}")]
    Blob(#[from] kernoid_store::BlobError),
}

/// kernoid's identity, running in a program's process.
#[derive(Debug, Clone)]
pub struct Embedded {
    state: AppState,
    config: Arc<Config>,
}

impl Embedded {
    /// Migrates kernoid's schema, connects, and starts identity's background work (as the role `worker` would) until
    /// `shutdown`. The services of `config` that this build does not have stay off.
    pub async fn start(mut config: Config, shutdown: CancellationToken) -> Result<Self, EmbedError> {
        config.services = crate::compiled_services(config.services);
        let main_keys = main_keys(&config)?;
        kernoid_store::migrate(&config.database).await?;
        let db = kernoid_store::connect(&config.database).await?;
        let keys = Arc::new(TenantKeys::with_main_keys(db.clone(), main_keys.clone()));
        let blobs = BlobStore::open(&config.blob, keys, db.clone())?;
        let events = EventStore::new(db.clone());
        let oidc = Oidc::new(events.clone(), main_keys.clone(), config.http.public_scheme.as_str())
            .public_port(config.http.public_port)
            .allow_private_networks(config.outbound.allow_private_networks);
        let mut state =
            AppState::new(db.clone(), blobs, Identity::with_secrets(events.clone(), main_keys), oidc.clone())
                .with_services(config.services);
        if let Some(from) = &config.mail.notification_from {
            state = state.with_notifications(from.clone());
        }
        if let Some(relay) = &config.mail.notification_relay {
            state = state.with_notification_relay(relay);
        }
        if let Ok(dns) = crate::DnsResolver::from_system() {
            state = state.with_dns(dns);
        }
        tokio::spawn(jobs::clean_up(Identity::new(events), oidc.clone(), shutdown.clone()));
        tokio::spawn(jobs::logout_notifications(oidc.clone(), shutdown.clone()));
        if config.oidc.key_rotation_days > 0 {
            tokio::spawn(jobs::rotate_keys(oidc, db, config.oidc.clone(), shutdown));
        }
        Ok(Self { state, config: Arc::new(config) })
    }

    /// What kernoid's handlers share – give it to the program's router as its state, so that [`Session`] works there.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// kernoid's routes – the login UI, the web app's account and administration, the REST and GraphQL API,
    /// OpenID Connect, SAML and SCIM – together with the `program`'s own: all behind kernoid's layers (the client
    /// through trusted proxies, which [`Session`] needs to find the instance; request ids, tracing, limits). kernoid's
    /// paths are its own (RFC 0009, 3); the program's must be others.
    pub fn router(&self, program: Router) -> Router {
        crate::router(self.state.clone(), program, &self.config.http)
    }
}

fn main_keys(config: &Config) -> Result<MainKeys, EmbedError> {
    let current =
        Key::from_hex(config.encryption.main_key.expose()).map_err(|error| EmbedError::MainKey(error.to_string()))?;
    let previous = config
        .encryption
        .previous_main_keys
        .iter()
        .map(|key| Key::from_hex(key.expose()).map_err(|error| EmbedError::MainKey(error.to_string())))
        .collect::<Result<_, _>>()?;
    Ok(MainKeys::new(current, previous))
}

/// Who is logged in, for a handler of the program: the account of a valid session of the request's instance – the
/// cookie of kernoid's login UI (with its protection against cross-site requests) or a bearer token. Anyone else gets
/// `401`.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub account: AccountInfo,
    pub instance: InstanceInfo,
    identity: Identity,
}

impl Session {
    /// The account's roles in the program's `project` (RFC 0001: projects and their roles, per tenant).
    #[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
    pub async fn project_roles(&self, project: Uuid) -> Result<std::collections::BTreeSet<String>, Response> {
        self.identity.account_project_roles(project, self.account.id).await.map_err(crate::sessions::problem)
    }

    /// Whether the account holds `role` in `project`.
    #[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
    pub async fn has_project_role(&self, project: Uuid, role: &str) -> Result<bool, Response> {
        Ok(self.project_roles(project).await?.contains(role))
    }
}

impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = AppState::from_ref(state);
        let CurrentInstance(instance) =
            CurrentInstance::from_request_parts(parts, state).await.map_err(IntoResponse::into_response)?;
        let SessionToken(token) =
            SessionToken::from_request_parts(parts, state).await.map_err(IntoResponse::into_response)?;
        let session = app.identity.session(instance.id, &token).await.map_err(crate::sessions::problem)?;
        Ok(Self { id: session.id, account: session.account, instance, identity: app.identity.clone() })
    }
}
