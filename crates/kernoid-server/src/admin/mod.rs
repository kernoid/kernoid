// SPDX-License-Identifier: AGPL-3.0-or-later
//! The administration API (RFC 0001, section 7.4): tenants, accounts, groups, roles, projects, applications and the
//! instance. The session token says who acts; the tenant administered is the account's own, or – for instance
//! administrators – the one named by the `kernoid-tenant` header (like ZITADEL's `x-zitadel-orgid`). Every operation
//! checks its permission in `kernoid_identity::admin` or `kernoid_oidc`'s admin functions, the same for GraphQL.

pub(crate) mod accounts;
pub(crate) mod applications;
pub(crate) mod audit;
pub(crate) mod collections;
pub(crate) mod directory;
pub(crate) mod files;
pub(crate) mod identity_providers;
pub(crate) mod instance;
pub(crate) mod logins;
pub(crate) mod mail;
pub(crate) mod projects;
pub(crate) mod provisioning;
pub(crate) mod tenant;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use kernoid_identity::{IdentityError, role::Admin};
use kernoid_oidc::OidcError;
use serde::Serialize;
use uuid::Uuid;

use crate::{AppState, CurrentInstance, oidc, sessions};

/// The header naming the tenant an instance administrator acts on.
pub const TENANT_HEADER: &str = "kernoid-tenant";

/// The tenant a request names in [`TENANT_HEADER`]; a value that is not a tenant id names no tenant there is.
pub(crate) fn target_tenant(headers: &HeaderMap) -> Result<Option<Uuid>, IdentityError> {
    match headers.get(TENANT_HEADER) {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| Uuid::parse_str(value.trim()).ok())
            .map(Some)
            .ok_or(IdentityError::NotFound("the tenant")),
    }
}

/// The administrator of a request: its bearer token at the instance of its host, for the tenant it names.
#[derive(Debug)]
pub struct AdminSession(pub Admin);

impl<S> FromRequestParts<S> for AdminSession
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let CurrentInstance(instance) =
            CurrentInstance::from_request_parts(parts, state).await.map_err(IntoResponse::into_response)?;
        let state = AppState::from_ref(state);
        let token = crate::cookie::session_token(&state, &parts.method, &parts.headers, Some(&instance))?;
        let tenant = target_tenant(&parts.headers).map_err(sessions::problem)?;
        state.identity.admin(instance.id, &token, tenant).await.map(Self).map_err(sessions::problem)
    }
}

pub(crate) fn respond<T>(result: Result<T, IdentityError>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => sessions::problem(error),
    }
}

pub(crate) fn respond_oidc<T>(result: Result<T, OidcError>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => oidc::problem(error),
    }
}

pub(crate) fn id(value: &str, what: &'static str) -> Result<Uuid, IdentityError> {
    Uuid::parse_str(value).map_err(|_| IdentityError::NotFound(what))
}

pub(crate) fn no_content<T>(_: T) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct Created {
    id: String,
}

pub(crate) fn created(id: Uuid) -> Response {
    (StatusCode::CREATED, axum::Json(Created { id: id.to_string() })).into_response()
}

/// A role assignment or authorization: who holds which role.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AssignmentView {
    role: String,
    /// `account` or `group`.
    principal_kind: String,
    principal_id: String,
}

impl AssignmentView {
    pub(crate) fn new(principal: kernoid_identity::role::Principal, role: impl ToString) -> Self {
        Self {
            role: role.to_string(),
            principal_kind: principal.kind().into(),
            principal_id: principal.id().to_string(),
        }
    }
}

pub(crate) fn principal(kind: &str, value: &str) -> Result<kernoid_identity::role::Principal, IdentityError> {
    kernoid_identity::role::Principal::new(kind, id(value, "the principal")?)
}
