// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay of kernoid's foundation in the server (RFC 0010, 4): who founds a space – an account of the instance, by
//! its session or app token in `kernoid-session` – and the administration of a tenant's spaces.

use axum::{
    Json,
    extract::{Path, State},
    http::{Extensions, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use kernoid_identity::{Identity, IdentityError, role::Permission};
use kernoid_relay::{BoxFuture, FOUNDER_HEADER, Founder, Founders, SpaceInfo};
use serde::Serialize;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{AppState, Client, Problem, admin::AdminSession, admin::tenant::TenantHeader};

/// Accounts of the instance a request is for, by their sessions and app tokens (`Identity::settings_account`).
#[derive(Debug, Clone)]
pub struct AccountFounders {
    identity: Identity,
}

impl AccountFounders {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }
}

impl Founders for AccountFounders {
    fn founder<'a>(&'a self, extensions: &'a Extensions, headers: &'a HeaderMap) -> BoxFuture<'a, Option<Founder>> {
        Box::pin(async move {
            let token = headers.get(FOUNDER_HEADER)?.to_str().ok()?;
            let instance = crate::instance::of_request(&self.identity, extensions.get::<Client>()).await.ok()??;
            let account = self.identity.settings_account(instance.id, token, true).await.ok()?;
            Some(Founder { tenant: account.tenant, account: account.id })
        })
    }
}

/// The REST routes of the relay's administration.
pub(crate) fn rest() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(spaces)).routes(routes!(remove_space))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RelaySpaceView {
    space: String,
    /// The program whose space it is: `kernoid`, `aktujo` …
    domain: String,
    /// The account that founded it.
    founder: Option<String>,
    /// What its envelopes take, in bytes – encrypted.
    bytes: i64,
    created_at: jiff::Timestamp,
    written_at: jiff::Timestamp,
}

impl From<SpaceInfo> for RelaySpaceView {
    fn from(info: SpaceInfo) -> Self {
        Self {
            space: info.space,
            domain: info.domain,
            founder: info.founder.map(|id| id.to_string()),
            bytes: info.bytes,
            created_at: info.created_at,
            written_at: info.written_at,
        }
    }
}

#[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
fn relay(state: &AppState) -> Result<&kernoid_relay::Relay, Response> {
    state.relay.as_ref().ok_or_else(|| Problem::new(StatusCode::NOT_FOUND).detail("no relay here").into_response())
}

fn store(error: sqlx::Error) -> Response {
    crate::sessions::problem(IdentityError::Store(error.into()))
}

/// The tenant's end-to-end encrypted spaces on this relay, newest first (needs `directory.read`). kernoid sees who
/// founded them and how large they are – never what is in them.
#[utoipa::path(get, path = "/v1/relay/spaces", tag = "relay", params(TenantHeader),
    responses((status = 200, body = [RelaySpaceView]), (status = 403, body = Problem)))]
pub(crate) async fn spaces(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    if let Err(error) = admin.require(Permission::DirectoryRead) {
        return crate::sessions::problem(error);
    }
    let relay = match relay(&state) {
        Ok(relay) => relay,
        Err(response) => return response,
    };
    match relay.spaces(admin.tenant()).await {
        Ok(spaces) => Json(spaces.into_iter().map(RelaySpaceView::from).collect::<Vec<_>>()).into_response(),
        Err(error) => store(error),
    }
}

/// Removes a space of the tenant with everything it holds (needs `tenant.manage`). Its members' devices keep their
/// copies.
#[utoipa::path(delete, path = "/v1/relay/spaces/{space}", tag = "relay", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn remove_space(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(space): Path<String>,
) -> Response {
    if let Err(error) = admin.require(Permission::TenantManage) {
        return crate::sessions::problem(error);
    }
    let relay = match relay(&state) {
        Ok(relay) => relay,
        Err(response) => return response,
    };
    match relay.remove_space(admin.tenant(), &space).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => Problem::new(StatusCode::NOT_FOUND).detail("no such space").into_response(),
        Err(error) => store(error),
    }
}
