// SPDX-License-Identifier: AGPL-3.0-or-later
//! Files in GraphQL (RFC 0005, 10) – the same operations and checks as the REST routes in `crate::admin::files`,
//! both through `crate::files_admin`.

use async_graphql::{Context, ErrorExtensions, Object, SimpleObject};
use kernoid_files::FilesError;
use kernoid_identity::role::Principal;

use super::{
    admin::{admin, principal, uuid},
    error,
};
use crate::{
    AppState,
    files_admin::{self, FilesAdminError},
};

/// A files administration error as a GraphQL error with a code.
fn files_error(failure: FilesAdminError) -> async_graphql::Error {
    let code = match failure {
        FilesAdminError::Identity(identity) => return error(identity),
        FilesAdminError::NoFiles => "BAD_REQUEST",
        FilesAdminError::Files(FilesError::NotFound(_)) => "NOT_FOUND",
        FilesAdminError::Files(store) => {
            tracing::error!(error = %store, "file store");
            return async_graphql::Error::new("unavailable").extend_with(|_, e| e.set("code", "UNAVAILABLE"));
        }
    };
    async_graphql::Error::new(failure.to_string()).extend_with(|_, extensions| extensions.set("code", code))
}

fn state<'a>(context: &'a Context<'_>) -> async_graphql::Result<&'a AppState> {
    context.data::<AppState>()
}

/// An account's files as its administrators see them.
#[derive(SimpleObject)]
pub struct FilesOverview {
    used_bytes: u64,
    /// The account's own quota; null when the tenant's default holds.
    quota: Option<u64>,
    /// What holds: the account's own quota or the tenant's default; null for no limit.
    effective_quota: Option<u64>,
}

/// A drive: a file store of the tenant, reached through grants.
#[derive(SimpleObject)]
pub struct DriveObject {
    id: String,
    name: String,
    active: bool,
}

/// A grant on an account's files or a drive.
#[derive(SimpleObject)]
pub struct FileGrantObject {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    grantee_name: String,
    /// A directory; null: the whole store.
    node: Option<String>,
    /// Letters of `randws`.
    rights: String,
}

fn node(value: Option<&str>) -> async_graphql::Result<Option<uuid::Uuid>> {
    value.map(|value| uuid(value, "the directory")).transpose()
}

#[derive(Debug, Default)]
pub struct FilesQuery;

#[Object]
impl FilesQuery {
    /// An account's files: usage and quota (needs `accounts.manage`).
    async fn account_files(&self, context: &Context<'_>, account: String) -> async_graphql::Result<FilesOverview> {
        let (_, admin) = admin(context).await?;
        let overview = files_admin::overview(state(context)?, &admin, uuid(&account, "the account")?)
            .await
            .map_err(files_error)?;
        Ok(FilesOverview {
            used_bytes: overview.used_bytes,
            quota: overview.quota,
            effective_quota: overview.effective_quota,
        })
    }

    /// The tenant's default files quota (needs `directory.read`).
    async fn tenant_files_quota(&self, context: &Context<'_>) -> async_graphql::Result<Option<u64>> {
        let (_, admin) = admin(context).await?;
        files_admin::default_quota(state(context)?, &admin).await.map_err(files_error)
    }

    /// Days what is in the accounts' file trash stays; null keeps it (needs `directory.read`).
    async fn files_retention(&self, context: &Context<'_>) -> async_graphql::Result<Option<u32>> {
        let (_, admin) = admin(context).await?;
        files_admin::retention(state(context)?, &admin).await.map_err(files_error)
    }

    /// The tenant's drives (needs `directory.read`).
    async fn drives(&self, context: &Context<'_>) -> async_graphql::Result<Vec<DriveObject>> {
        let (_, admin) = admin(context).await?;
        let drives = files_admin::drives(state(context)?, &admin).await.map_err(files_error)?;
        Ok(drives
            .into_iter()
            .map(|drive| DriveObject { id: drive.id.to_string(), name: drive.name, active: drive.active })
            .collect())
    }

    /// Who may use an account's files or a drive (needs `accounts.manage`).
    async fn file_access(&self, context: &Context<'_>, account: String) -> async_graphql::Result<Vec<FileGrantObject>> {
        let (_, admin) = admin(context).await?;
        let grants =
            files_admin::access(state(context)?, &admin, uuid(&account, "the account")?).await.map_err(files_error)?;
        Ok(grants
            .into_iter()
            .map(|grant| {
                let (kind, id) = match grant.grantee {
                    Principal::Account(id) => ("account", id),
                    Principal::Group(id) => ("group", id),
                };
                FileGrantObject {
                    grantee_kind: kind.into(),
                    grantee_id: id.to_string(),
                    grantee_name: grant.grantee_name,
                    node: grant.node.map(|node| node.to_string()),
                    rights: grant.rights,
                }
            })
            .collect())
    }
}

#[derive(Debug, Default)]
pub struct FilesMutation;

#[Object]
impl FilesMutation {
    /// Sets an account's files quota; null for the tenant's default (needs `accounts.manage`).
    async fn set_files_quota(
        &self,
        context: &Context<'_>,
        account: String,
        bytes: Option<u64>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        files_admin::set_quota(state(context)?, &admin, uuid(&account, "the account")?, bytes)
            .await
            .map_err(files_error)?;
        Ok(true)
    }

    /// Creates a drive of the tenant (needs `accounts.manage`); its id.
    async fn add_drive(&self, context: &Context<'_>, name: String) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let id = files_admin::add_drive(state(context)?, &admin, &name).await.map_err(files_error)?;
        Ok(id.to_string())
    }

    /// Grants rights on an account's files or a drive – a directory, or the whole store when `node` is null –
    /// replacing an earlier grant there (needs `accounts.manage`).
    async fn set_file_access(
        &self,
        context: &Context<'_>,
        account: String,
        grantee_kind: String,
        grantee_id: String,
        node: Option<String>,
        rights: String,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let grantee = principal(&grantee_kind, &grantee_id)?;
        files_admin::set_access(state(context)?, &admin, owner, self::node(node.as_deref())?, grantee, &rights)
            .await
            .map_err(files_error)?;
        Ok(true)
    }

    /// Removes a grant on an account's files or a drive (needs `accounts.manage`).
    async fn remove_file_access(
        &self,
        context: &Context<'_>,
        account: String,
        grantee_kind: String,
        grantee_id: String,
        node: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let grantee = principal(&grantee_kind, &grantee_id)?;
        files_admin::remove_access(state(context)?, &admin, owner, self::node(node.as_deref())?, grantee)
            .await
            .map_err(files_error)?;
        Ok(true)
    }

    /// Sets how many days (1 to 3650) what is in the accounts' file trash stays; null keeps it (needs
    /// `tenant.manage`).
    async fn set_files_retention(&self, context: &Context<'_>, trash_days: Option<u32>) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        files_admin::set_retention(state(context)?, &admin, trash_days).await.map_err(files_error)?;
        Ok(true)
    }

    /// Sets the tenant's default files quota; null for no limit (needs `tenant.manage`).
    async fn set_tenant_files_quota(&self, context: &Context<'_>, bytes: Option<u64>) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        files_admin::set_default_quota(state(context)?, &admin, bytes).await.map_err(files_error)?;
        Ok(true)
    }
}
