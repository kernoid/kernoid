// SPDX-License-Identifier: AGPL-3.0-or-later
//! Files of the tenant administered (RFC 0005, 10–12): an account's usage and quota, the tenant's default quota, who
//! may use whose files, and the tenant's drives.

use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use kernoid_identity::{files_quota::FileGrant, role::Principal};
use serde::{Deserialize, Serialize};

use super::{AdminSession, created, id, no_content, principal, tenant::TenantHeader};
use crate::{
    AppState, Problem,
    files_admin::{self, FilesAdminError, problem},
};

fn respond<T>(result: Result<T, FilesAdminError>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct FilesOverviewView {
    used_bytes: u64,
    /// The account's own quota; null when the tenant's default holds.
    quota: Option<u64>,
    /// What holds: the account's own quota or the tenant's default; null for no limit.
    effective_quota: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct FilesQuota {
    /// Bytes; null for none (the tenant's default, or no limit).
    bytes: Option<u64>,
}

/// An account's files: usage and quota (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/files", tag = "files", params(TenantHeader),
    responses((status = 200, body = FilesOverviewView), (status = 404, body = Problem)))]
pub(crate) async fn overview(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { files_admin::overview(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, |overview| {
        Json(FilesOverviewView {
            used_bytes: overview.used_bytes,
            quota: overview.quota,
            effective_quota: overview.effective_quota,
        })
        .into_response()
    })
}

/// Sets an account's files quota; null for the tenant's default (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/files/quota", tag = "files", params(TenantHeader),
    request_body = FilesQuota, responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn set_quota(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<FilesQuota>,
) -> Response {
    let result = async { files_admin::set_quota(&state, &admin, id(&account, "the account")?, body.bytes).await }.await;
    respond(result, no_content)
}

/// The tenant's default files quota (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/files-quota", tag = "files", params(TenantHeader),
    responses((status = 200, body = FilesQuota)))]
pub(crate) async fn default_quota(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(files_admin::default_quota(&state, &admin).await, |bytes| Json(FilesQuota { bytes }).into_response())
}

/// Sets the tenant's default files quota, for every account without its own; null for no limit (needs
/// `tenant.manage`).
#[utoipa::path(put, path = "/v1/tenant/files-quota", tag = "files", params(TenantHeader), request_body = FilesQuota,
    responses((status = 204)))]
pub(crate) async fn set_default_quota(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<FilesQuota>,
) -> Response {
    respond(files_admin::set_default_quota(&state, &admin, body.bytes).await, no_content)
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct DriveView {
    id: String,
    name: String,
    active: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewDrive {
    name: String,
}

/// The tenant's drives: file stores that belong to the tenant, not to a person (needs `directory.read`).
#[utoipa::path(get, path = "/v1/drives", tag = "files", params(TenantHeader), responses((status = 200, body = [DriveView])))]
pub(crate) async fn drives(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(files_admin::drives(&state, &admin).await, |drives| {
        let list: Vec<DriveView> = drives
            .into_iter()
            .map(|drive| DriveView { id: drive.id.to_string(), name: drive.name, active: drive.active })
            .collect();
        Json(list).into_response()
    })
}

/// Creates a drive of the tenant; people reach it through grants (needs `accounts.manage`).
#[utoipa::path(post, path = "/v1/drives", tag = "files", params(TenantHeader), request_body = NewDrive,
    responses((status = 201, body = super::Created), (status = 400, body = Problem)))]
pub(crate) async fn add_drive(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewDrive>,
) -> Response {
    respond(files_admin::add_drive(&state, &admin, &body.name).await, created)
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct FileGrantView {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// The account's address, or `$` and the group's name.
    grantee_name: String,
    /// A directory; null: the whole store.
    node: Option<String>,
    /// Letters of `randws`: read, add, rename, delete, write content, share.
    rights: String,
}

impl From<FileGrant> for FileGrantView {
    fn from(grant: FileGrant) -> Self {
        let (kind, id) = match grant.grantee {
            Principal::Account(id) => ("account", id),
            Principal::Group(id) => ("group", id),
        };
        Self {
            grantee_kind: kind.into(),
            grantee_id: id.to_string(),
            grantee_name: grant.grantee_name,
            node: grant.node.map(|node| node.to_string()),
            rights: grant.rights,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct FileGrantChange {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// A directory of the account; leave out for the whole store.
    node: Option<String>,
    /// Letters of `randws`: read, add, rename, delete, write content, share.
    rights: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct FileGrantQuery {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// The directory of the grant; leave out for the grant on the whole store.
    node: Option<String>,
}

fn node_id(value: Option<&str>) -> Result<Option<uuid::Uuid>, FilesAdminError> {
    value.map(|value| id(value, "the directory")).transpose().map_err(FilesAdminError::from)
}

/// Who may use an account's files or a drive (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/files/access", tag = "files", params(TenantHeader),
    responses((status = 200, body = [FileGrantView]), (status = 404, body = Problem)))]
pub(crate) async fn access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { files_admin::access(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, |list| Json(list.into_iter().map(FileGrantView::from).collect::<Vec<_>>()).into_response())
}

/// Grants an account or a group of the tenant rights on an account's files or a drive – a directory and what lies
/// below it, or the whole store – replacing an earlier grant there (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/files/access", tag = "files", params(TenantHeader),
    request_body = FileGrantChange,
    responses((status = 204), (status = 400, body = Problem), (status = 404, body = Problem)))]
pub(crate) async fn set_access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<FileGrantChange>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let grantee = principal(&body.grantee_kind, &body.grantee_id)?;
        let node = node_id(body.node.as_deref())?;
        files_admin::set_access(&state, &admin, owner, node, grantee, &body.rights).await
    }
    .await;
    respond(result, no_content)
}

/// Removes a grant on an account's files or a drive (needs `accounts.manage`).
#[utoipa::path(delete, path = "/v1/accounts/{id}/files/access", tag = "files", params(TenantHeader, FileGrantQuery),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn remove_access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Query(query): Query<FileGrantQuery>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let grantee = principal(&query.grantee_kind, &query.grantee_id)?;
        let node = node_id(query.node.as_deref())?;
        files_admin::remove_access(&state, &admin, owner, node, grantee).await
    }
    .await;
    respond(result, no_content)
}
