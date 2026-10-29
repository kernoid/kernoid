// SPDX-License-Identifier: AGPL-3.0-or-later
//! Administration of files (RFC 0005, 10), for REST and GraphQL alike: the quota is an event and goes through
//! `kernoid_identity::files_quota`, which checks its permissions; the usage is file data, read once the
//! administrator may manage the account.

use kernoid_files::{Files, FilesError};
use kernoid_identity::{
    IdentityError,
    files_quota::{DriveInfo, FileGrant},
    role::{Admin, Principal},
};
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FilesAdminError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Files(#[from] FilesError),
    #[error("this installation does not handle files")]
    NoFiles,
}

pub(crate) type Result<T> = std::result::Result<T, FilesAdminError>;

/// An account's files as its administrators see them.
#[derive(Debug, Clone)]
pub(crate) struct FilesOverview {
    pub used_bytes: u64,
    /// The account's own quota; `None` when the tenant's default holds.
    pub quota: Option<u64>,
    /// What holds: the account's own quota, or else the tenant's default.
    pub effective_quota: Option<u64>,
}

fn files(state: &AppState) -> Result<&Files> {
    state.jmap.as_ref().and_then(kernoid_jmap::Jmap::files).ok_or(FilesAdminError::NoFiles)
}

pub(crate) async fn overview(state: &AppState, admin: &Admin, account: Uuid) -> Result<FilesOverview> {
    let quota = state.identity.admin_files_quota(admin, account).await?;
    let (used_bytes, effective_quota) = files(state)?.usage(account).await?;
    Ok(FilesOverview { used_bytes, quota, effective_quota })
}

pub(crate) async fn set_quota(state: &AppState, admin: &Admin, account: Uuid, bytes: Option<u64>) -> Result<()> {
    Ok(state.identity.admin_set_files_quota(admin, account, bytes).await?)
}

pub(crate) async fn default_quota(state: &AppState, admin: &Admin) -> Result<Option<u64>> {
    Ok(state.identity.admin_default_files_quota(admin).await?)
}

pub(crate) async fn set_default_quota(state: &AppState, admin: &Admin, bytes: Option<u64>) -> Result<()> {
    Ok(state.identity.admin_set_default_files_quota(admin, bytes).await?)
}

pub(crate) async fn retention(state: &AppState, admin: &Admin) -> Result<Option<u32>> {
    Ok(state.identity.admin_files_retention(admin).await?)
}

pub(crate) async fn set_retention(state: &AppState, admin: &Admin, trash_days: Option<u32>) -> Result<()> {
    Ok(state.identity.admin_set_files_retention(admin, trash_days).await?)
}

pub(crate) async fn drives(state: &AppState, admin: &Admin) -> Result<Vec<DriveInfo>> {
    Ok(state.identity.admin_drives(admin).await?)
}

pub(crate) async fn add_drive(state: &AppState, admin: &Admin, name: &str) -> Result<Uuid> {
    Ok(state.identity.admin_add_drive(admin, name).await?)
}

pub(crate) async fn access(state: &AppState, admin: &Admin, owner: Uuid) -> Result<Vec<FileGrant>> {
    Ok(state.identity.admin_file_access(admin, owner).await?)
}

/// Grants access to an account's files and records it as a change of what it covers (RFC 0005, 11).
pub(crate) async fn set_access(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    node: Option<Uuid>,
    grantee: Principal,
    rights: &str,
) -> Result<()> {
    state.identity.admin_set_file_access(admin, owner, node, grantee, rights).await?;
    files(state)?.touch(owner, node).await?;
    Ok(())
}

pub(crate) async fn remove_access(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    node: Option<Uuid>,
    grantee: Principal,
) -> Result<()> {
    state.identity.admin_remove_file_access(admin, owner, node, grantee).await?;
    files(state)?.touch(owner, node).await?;
    Ok(())
}

/// The problem details of an error, never with internal details.
pub(crate) fn problem(error: FilesAdminError) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    match error {
        FilesAdminError::Identity(error) => crate::sessions::problem(error),
        FilesAdminError::NoFiles => {
            crate::Problem::new(StatusCode::BAD_REQUEST).detail(FilesAdminError::NoFiles.to_string()).into_response()
        }
        FilesAdminError::Files(FilesError::NotFound(what)) => {
            crate::Problem::new(StatusCode::NOT_FOUND).detail(format!("{what} does not exist")).into_response()
        }
        FilesAdminError::Files(error) => {
            tracing::error!(%error, "file store");
            crate::Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response()
        }
    }
}
