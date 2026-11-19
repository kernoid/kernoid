// SPDX-License-Identifier: AGPL-3.0-or-later
//! Logging in with kernoid – or any OpenID provider – for the servers of other programs (RFC 0009, 2): the program is
//! a relying party ([`relying`]), keeps its own sessions ([`sessions`]) and, on axum, takes the routes and the
//! extractor of [`web`]. Written against OpenID Connect, not against kernoid: kernoid's tenant and project roles are
//! read where a token has them. kernoid itself uses [`provider`] and [`outbound`] for the providers of its tenants.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use axum::{Router, routing::get};
//! use kernoid_auth::{relying::{RelyingParty, Settings}, sessions::MemorySessions, web::{Auth, Authenticated}};
//!
//! let settings: Settings = serde_json::from_value(serde_json::json!({
//!     "issuer": "https://id.example.org",
//!     "client_id": "0193…",
//!     "redirect_uri": "https://music.example.org/auth/callback",
//! }))?;
//! let auth = Auth::new(RelyingParty::new(settings)?, Arc::new(MemorySessions::new()));
//! let app: Router = Router::new()
//!     .route("/me", get(|Authenticated(who): Authenticated| async move { who.subject }))
//!     .merge(Auth::routes())
//!     .with_state(auth);
//! # let _ = app; Ok(()) }
//! ```

pub mod outbound;
pub mod provider;
pub mod relying;
pub mod sessions;
#[cfg(feature = "axum")]
pub mod web;
