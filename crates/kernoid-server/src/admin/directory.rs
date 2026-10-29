// SPDX-License-Identifier: AGPL-3.0-or-later
//! Groups and tenant roles of the tenant administered.

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use kernoid_identity::{
    IdentityError,
    group::GroupInfo,
    role::{Permission, Role, RoleInfo},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AdminSession, AssignmentView, accounts::address, created, id, no_content, principal, respond, tenant::TenantHeader,
};
use crate::{AppState, Problem};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct GroupView {
    id: String,
    name: String,
    /// Account ids.
    members: Vec<String>,
    /// Addresses mail to the group arrives at; it goes to every member.
    addresses: Vec<String>,
    /// The members may send from these addresses.
    members_send_as: bool,
}

impl From<GroupInfo> for GroupView {
    fn from(group: GroupInfo) -> Self {
        Self {
            id: group.id.to_string(),
            name: group.name,
            members: group.members.iter().map(Uuid::to_string).collect(),
            addresses: group.addresses,
            members_send_as: group.members_send_as,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct GroupName {
    name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RoleView {
    /// E.g. `tenant_admin`, or a name the tenant chose.
    name: String,
    permissions: Vec<String>,
    /// Built in (the same in every tenant), or defined by the tenant.
    builtin: bool,
}

impl From<RoleInfo> for RoleView {
    fn from(info: RoleInfo) -> Self {
        Self {
            name: info.role.to_string(),
            permissions: info.permissions.iter().map(ToString::to_string).collect(),
            builtin: info.builtin,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RolesView {
    /// The roles there are: built in and the tenant's own.
    roles: Vec<RoleView>,
    /// Who holds which role in the tenant.
    assignments: Vec<AssignmentView>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct RoleDefinition {
    /// Tenant permissions, e.g. `directory.read`.
    permissions: Vec<String>,
}

pub(crate) fn permissions(names: &[String]) -> Result<BTreeSet<Permission>, IdentityError> {
    names.iter().map(|name| name.parse()).collect()
}

/// The tenant's groups with their members (needs `directory.read`).
#[utoipa::path(get, path = "/v1/groups", tag = "groups", params(TenantHeader), responses((status = 200, body = [GroupView])))]
pub(crate) async fn groups(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_groups(&admin).await, |list| {
        Json(list.into_iter().map(GroupView::from).collect::<Vec<_>>()).into_response()
    })
}

/// Creates a group (needs `groups.manage`).
#[utoipa::path(post, path = "/v1/groups", tag = "groups", params(TenantHeader), request_body = GroupName,
    responses((status = 201, body = super::Created), (status = 403, body = Problem)))]
pub(crate) async fn add_group(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<GroupName>,
) -> Response {
    respond(state.identity.admin_add_group(&admin, &body.name).await, created)
}

/// Renames a group (needs `groups.manage`).
#[utoipa::path(patch, path = "/v1/groups/{id}", tag = "groups", params(TenantHeader), request_body = GroupName,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn rename_group(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(group): Path<String>,
    Json(body): Json<GroupName>,
) -> Response {
    let result = async { state.identity.admin_rename_group(&admin, id(&group, "the group")?, &body.name).await }.await;
    respond(result, no_content)
}

/// Lets the group's members send from its addresses, or stops it (needs `groups.manage`).
#[utoipa::path(put, path = "/v1/groups/{id}/send-as", tag = "groups", params(TenantHeader), request_body = super::tenant::Switch,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn set_send_as(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(group): Path<String>,
    Json(body): Json<super::tenant::Switch>,
) -> Response {
    let result =
        async { state.identity.admin_set_group_send_as(&admin, id(&group, "the group")?, body.enabled).await }.await;
    respond(result, no_content)
}

/// Removes a group; refused while it holds roles (needs `groups.manage`).
#[utoipa::path(delete, path = "/v1/groups/{id}", tag = "groups", params(TenantHeader),
    responses((status = 204), (status = 400, description = "the group holds roles", body = Problem)))]
pub(crate) async fn remove_group(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(group): Path<String>,
) -> Response {
    let result = async { state.identity.admin_remove_group(&admin, id(&group, "the group")?).await }.await;
    respond(result, no_content)
}

/// Adds an account to a group (needs `groups.manage`, and for a group holding roles the permission to assign them).
#[utoipa::path(put, path = "/v1/groups/{id}/members/{account}", tag = "groups", params(TenantHeader), responses(
    (status = 204),
    (status = 403, description = "needs groups.manage, and roles.manage etc. for a group with roles", body = Problem),
))]
pub(crate) async fn add_member(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((group, account)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (group, account) = (id(&group, "the group")?, id(&account, "the account")?);
        state.identity.admin_add_group_member(&admin, group, account).await
    }
    .await;
    respond(result, no_content)
}

/// Removes an account from a group (needs the same as adding one).
#[utoipa::path(delete, path = "/v1/groups/{id}/members/{account}", tag = "groups", params(TenantHeader),
    responses((status = 204)))]
pub(crate) async fn remove_member(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((group, account)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (group, account) = (id(&group, "the group")?, id(&account, "the account")?);
        state.identity.admin_remove_group_member(&admin, group, account).await
    }
    .await;
    respond(result, no_content)
}

/// Gives a group an address on a verified domain of the tenant; mail to it goes to every member (needs
/// `groups.manage`).
#[utoipa::path(put, path = "/v1/groups/{id}/addresses/{address}", tag = "groups", params(TenantHeader),
    responses((status = 204), (status = 409, description = "the address is taken", body = Problem)))]
pub(crate) async fn add_address(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((group, value)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (group, value) = (id(&group, "the group")?, address(&value)?);
        state.identity.admin_add_group_address(&admin, group, &value).await
    }
    .await;
    respond(result, no_content)
}

/// Removes an address of a group (needs `groups.manage`).
#[utoipa::path(delete, path = "/v1/groups/{id}/addresses/{address}", tag = "groups", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn remove_address(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((group, value)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (group, value) = (id(&group, "the group")?, address(&value)?);
        state.identity.admin_remove_group_address(&admin, group, &value).await
    }
    .await;
    respond(result, no_content)
}

/// The roles there are, and who holds which in the tenant (needs `directory.read`).
#[utoipa::path(get, path = "/v1/roles", tag = "roles", params(TenantHeader), responses((status = 200, body = RolesView)))]
pub(crate) async fn roles(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    let result = async {
        let roles = state.identity.admin_tenant_roles(&admin).await?;
        let assignments = state.identity.admin_role_assignments(&admin).await?;
        Ok(RolesView {
            roles: roles.into_iter().map(RoleView::from).collect(),
            assignments: assignments.into_iter().map(|a| AssignmentView::new(a.principal, a.role)).collect(),
        })
    }
    .await;
    respond(result, |view| Json(view).into_response())
}

/// Defines a role of the tenant's own, or changes its permissions (needs `roles.manage`).
#[utoipa::path(put, path = "/v1/roles/{role}", tag = "roles", params(TenantHeader), request_body = RoleDefinition,
    responses((status = 204), (status = 400, description = "a built-in role, or not tenant permissions", body = Problem)))]
pub(crate) async fn define_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(role): Path<String>,
    Json(body): Json<RoleDefinition>,
) -> Response {
    let result = async {
        state.identity.admin_define_role(&admin, &Role::parse(&role)?, &permissions(&body.permissions)?).await
    }
    .await;
    respond(result, no_content)
}

/// Deletes a role of the tenant's own, once nobody holds it (needs `roles.manage`).
#[utoipa::path(delete, path = "/v1/roles/{role}", tag = "roles", params(TenantHeader),
    responses((status = 204), (status = 400, description = "still assigned", body = Problem)))]
pub(crate) async fn delete_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(role): Path<String>,
) -> Response {
    let result = async { state.identity.admin_delete_role(&admin, &Role::parse(&role)?).await }.await;
    respond(result, no_content)
}

/// Assigns a role to an account or a group of the tenant (needs `roles.manage`).
#[utoipa::path(put, path = "/v1/roles/{role}/{kind}/{id}", tag = "roles", params(
    TenantHeader,
    ("role" = String, Path, description = "e.g. `user_manager`"),
    ("kind" = String, Path, description = "`account` or `group`"),
    ("id" = String, Path),
), responses((status = 204), (status = 403, description = "needs roles.manage", body = Problem)))]
pub(crate) async fn grant_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((role, kind, holder)): Path<(String, String, String)>,
) -> Response {
    let result = async {
        let role = Role::parse(&role)?;
        state.identity.admin_grant_role(&admin, principal(&kind, &holder)?, &role).await
    }
    .await;
    respond(result, no_content)
}

/// Takes a role back; the tenant's last `tenant_admin` assignment cannot be revoked (needs `roles.manage`).
#[utoipa::path(delete, path = "/v1/roles/{role}/{kind}/{id}", tag = "roles", params(
    TenantHeader, ("role" = String, Path), ("kind" = String, Path), ("id" = String, Path),
), responses((status = 204), (status = 400, description = "the last tenant_admin assignment", body = Problem)))]
pub(crate) async fn revoke_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((role, kind, holder)): Path<(String, String, String)>,
) -> Response {
    let result = async {
        let role = Role::parse(&role)?;
        state.identity.admin_revoke_role(&admin, principal(&kind, &holder)?, &role).await
    }
    .await;
    respond(result, no_content)
}
