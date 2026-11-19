// SPDX-License-Identifier: AGPL-3.0-or-later
//! What this installation runs (RFC 0008, 4), for apps and other servers to ask before they offer something.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::AppState;

/// Whether the installation runs what an account's service gives (RFC 0003, 4): `mail` brings mail and calendars,
/// `files` files.
pub(crate) fn runs(services: kernoid_config::Services, service: kernoid_identity::services::Service) -> bool {
    match service {
        kernoid_identity::services::Service::Mail => services.mail_store(),
        kernoid_identity::services::Service::Files => services.files,
    }
}

/// The services of this installation; identity is always there.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ServicesView {
    /// Mail: JMAP Mail, SMTP, IMAP.
    mail: bool,
    /// Calendars and contacts: JMAP, CalDAV, CardDAV.
    calendars: bool,
    /// Files: JMAP FileNode, WebDAV, links.
    files: bool,
}

/// The services this installation runs; anyone may ask.
#[utoipa::path(get, path = "/v1/services", tag = "meta", responses((status = 200, body = ServicesView)))]
pub(crate) async fn list(State(state): State<AppState>) -> Json<ServicesView> {
    let services = state.services;
    Json(ServicesView { mail: services.mail, calendars: services.calendars, files: services.files })
}
