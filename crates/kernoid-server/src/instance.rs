// SPDX-License-Identifier: AGPL-3.0-or-later
//! The instance a request is for, found by the host it asked for (RFC 0001, section 2). The host comes from
//! [`Client`], which believes forwarded headers only from trusted proxies. A host no instance is reached under gets
//! `404`; there is no fallback instance.

use axum::{
    Json,
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use kernoid_identity::{Identity, InstanceInfo};
use serde::Serialize;

use crate::{AppState, Client, Problem};

/// Extracts the instance of the request, or answers with a problem.
#[derive(Debug, Clone)]
pub struct CurrentInstance(pub InstanceInfo);

/// The instance of a request's host, if any.
pub(crate) async fn of_request(identity: &Identity, client: Option<&Client>) -> Result<Option<InstanceInfo>, Problem> {
    let Some(host) = client.and_then(|client| client.host.as_deref()) else { return Ok(None) };
    identity.instance_by_host(host).await.map_err(|error| {
        tracing::error!(%error, "looking up the instance");
        Problem::new(StatusCode::SERVICE_UNAVAILABLE)
    })
}

impl<S> FromRequestParts<S> for CurrentInstance
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Problem> {
        let state = AppState::from_ref(state);
        match of_request(&state.identity, parts.extensions.get::<Client>()).await? {
            Some(instance) => Ok(Self(instance)),
            None => Err(Problem::new(StatusCode::NOT_FOUND).detail("no instance is reached under this host")),
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct InstanceView {
    id: String,
    name: String,
    primary_domain: String,
}

impl From<InstanceInfo> for InstanceView {
    fn from(info: InstanceInfo) -> Self {
        Self { id: info.id.to_string(), name: info.name, primary_domain: info.primary_domain }
    }
}

/// The instance reached under the host of this request.
#[utoipa::path(get, path = "/v1/instance", tag = "instance", responses(
    (status = 200, body = InstanceView),
    (status = 404, description = "no instance is reached under this host", body = Problem),
))]
pub(crate) async fn current(CurrentInstance(instance): CurrentInstance) -> Json<InstanceView> {
    Json(instance.into())
}
