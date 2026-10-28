// SPDX-License-Identifier: AGPL-3.0-or-later
//! Projects of the tenant administered, their roles and who holds them (RFC 0001, section 7.5).

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use std::collections::BTreeSet;

use kernoid_identity::project::{ProjectAuthorization, ProjectGrant, ProjectInfo, ProjectRole};
use serde::{Deserialize, Serialize};

use super::{AdminSession, created, id, no_content, principal, respond, tenant::TenantHeader};
use crate::{AppState, Problem};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ProjectRoleView {
    key: String,
    display_name: String,
    group: Option<String>,
}

impl From<ProjectRole> for ProjectRoleView {
    fn from(role: ProjectRole) -> Self {
        Self { key: role.key, display_name: role.display_name, group: role.group }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ProjectView {
    id: String,
    name: String,
    /// Project roles go into ID tokens and userinfo (`urn:kernoid:project:roles`).
    role_assertion: bool,
    /// Only accounts with a role in the project may log in to its applications.
    role_check: bool,
    roles: Vec<ProjectRoleView>,
}

impl From<ProjectInfo> for ProjectView {
    fn from(project: ProjectInfo) -> Self {
        Self {
            id: project.id.to_string(),
            name: project.name,
            role_assertion: project.role_assertion,
            role_check: project.role_check,
            roles: project.roles.into_iter().map(ProjectRoleView::from).collect(),
        }
    }
}

/// A project role held by an account or group.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AuthorizationView {
    role: String,
    /// The tenant that gave it: the project's own, or one it is granted to.
    tenant: String,
    /// `account` or `group`.
    principal_kind: String,
    principal_id: String,
}

impl From<ProjectAuthorization> for AuthorizationView {
    fn from(authorization: ProjectAuthorization) -> Self {
        Self {
            role: authorization.role,
            tenant: authorization.tenant.to_string(),
            principal_kind: authorization.principal.kind().into(),
            principal_id: authorization.principal.id().to_string(),
        }
    }
}

/// A project granted to another tenant.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct GrantView {
    project: String,
    project_name: String,
    /// The project's own tenant.
    owner: String,
    /// The tenant it is granted to.
    tenant: String,
    tenant_name: String,
    /// The roles that tenant may give its accounts and groups.
    roles: Vec<String>,
}

impl From<ProjectGrant> for GrantView {
    fn from(grant: ProjectGrant) -> Self {
        Self {
            project: grant.project.to_string(),
            project_name: grant.project_name,
            owner: grant.owner.to_string(),
            tenant: grant.tenant.to_string(),
            tenant_name: grant.tenant_name,
            roles: grant.roles,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct GrantRoles {
    roles: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewProject {
    name: String,
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct ProjectChange {
    name: Option<String>,
    role_assertion: Option<bool>,
    role_check: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ProjectRoleDefinition {
    display_name: String,
    group: Option<String>,
}

/// The tenant's projects with their roles (needs `directory.read`).
#[utoipa::path(get, path = "/v1/projects", tag = "projects", params(TenantHeader),
    responses((status = 200, body = [ProjectView])))]
pub(crate) async fn list(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_projects(&admin).await, |list| {
        Json(list.into_iter().map(ProjectView::from).collect::<Vec<_>>()).into_response()
    })
}

/// Creates a project (needs `projects.manage`).
#[utoipa::path(post, path = "/v1/projects", tag = "projects", params(TenantHeader), request_body = NewProject,
    responses((status = 201, body = super::Created)))]
pub(crate) async fn add(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewProject>,
) -> Response {
    respond(state.identity.admin_add_project(&admin, &body.name).await, created)
}

/// One project (needs `directory.read`).
#[utoipa::path(get, path = "/v1/projects/{id}", tag = "projects", params(TenantHeader),
    responses((status = 200, body = ProjectView), (status = 404, body = Problem)))]
pub(crate) async fn get(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(project): Path<String>,
) -> Response {
    let result = async { state.identity.admin_project(&admin, id(&project, "the project")?).await }.await;
    respond(result, |project| Json(ProjectView::from(project)).into_response())
}

/// Renames a project or changes its settings (needs `projects.manage`).
#[utoipa::path(patch, path = "/v1/projects/{id}", tag = "projects", params(TenantHeader), request_body = ProjectChange,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn change(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(project): Path<String>,
    Json(body): Json<ProjectChange>,
) -> Response {
    let result = async {
        let project = id(&project, "the project")?;
        if let Some(name) = &body.name {
            state.identity.admin_rename_project(&admin, project, name).await?;
        }
        if body.role_assertion.is_some() || body.role_check.is_some() {
            let current = state.identity.admin_project(&admin, project).await?;
            let assertion = body.role_assertion.unwrap_or(current.role_assertion);
            let check = body.role_check.unwrap_or(current.role_check);
            state.identity.admin_set_project_settings(&admin, project, assertion, check).await?;
        }
        Ok(())
    }
    .await;
    respond(result, no_content)
}

/// Removes a project – once it has no applications and nobody holds its roles (needs `projects.manage`).
#[utoipa::path(delete, path = "/v1/projects/{id}", tag = "projects", params(TenantHeader),
    responses((status = 204), (status = 400, description = "applications or authorizations left", body = Problem)))]
pub(crate) async fn remove(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(project): Path<String>,
) -> Response {
    let result = async { state.identity.admin_remove_project(&admin, id(&project, "the project")?).await }.await;
    respond(result, no_content)
}

/// Adds a role to the project, or changes its display name and group (needs `projects.manage`).
#[utoipa::path(put, path = "/v1/projects/{id}/roles/{key}", tag = "projects", params(TenantHeader),
    request_body = ProjectRoleDefinition, responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn set_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((project, key)): Path<(String, String)>,
    Json(body): Json<ProjectRoleDefinition>,
) -> Response {
    let result = async {
        let project = id(&project, "the project")?;
        state.identity.admin_set_project_role(&admin, project, &key, &body.display_name, body.group.as_deref()).await
    }
    .await;
    respond(result, no_content)
}

/// Removes a role from the project, once nobody holds it (needs `projects.manage`).
#[utoipa::path(delete, path = "/v1/projects/{id}/roles/{key}", tag = "projects", params(TenantHeader),
    responses((status = 204), (status = 400, description = "still assigned", body = Problem)))]
pub(crate) async fn remove_role(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((project, key)): Path<(String, String)>,
) -> Response {
    let result =
        async { state.identity.admin_remove_project_role(&admin, id(&project, "the project")?, &key).await }.await;
    respond(result, no_content)
}

/// Who holds which role of the project – for a granted project only the tenant's own (needs `directory.read`).
#[utoipa::path(get, path = "/v1/projects/{id}/authorizations", tag = "projects", params(TenantHeader),
    responses((status = 200, body = [AuthorizationView])))]
pub(crate) async fn authorizations(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(project): Path<String>,
) -> Response {
    let result =
        async { state.identity.admin_project_authorizations(&admin, id(&project, "the project")?).await }.await;
    respond(result, |list| Json(list.into_iter().map(AuthorizationView::from).collect::<Vec<_>>()).into_response())
}

/// Gives an account or group of the tenant a role of the project – of its own, or one granted to it (needs
/// `authorizations.manage`).
#[utoipa::path(put, path = "/v1/projects/{id}/authorizations/{role}/{kind}/{principal}", tag = "projects",
    params(TenantHeader), responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn grant(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((project, role, kind, holder)): Path<(String, String, String, String)>,
) -> Response {
    let result = async {
        let project = id(&project, "the project")?;
        state.identity.admin_grant_project_role(&admin, project, principal(&kind, &holder)?, &role).await
    }
    .await;
    respond(result, no_content)
}

/// Takes a project role back (needs `authorizations.manage`).
#[utoipa::path(delete, path = "/v1/projects/{id}/authorizations/{role}/{kind}/{principal}", tag = "projects",
    params(TenantHeader), responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn revoke(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((project, role, kind, holder)): Path<(String, String, String, String)>,
) -> Response {
    let result = async {
        let project = id(&project, "the project")?;
        state.identity.admin_revoke_project_role(&admin, project, principal(&kind, &holder)?, &role).await
    }
    .await;
    respond(result, no_content)
}

/// The tenants the project is granted to (needs `directory.read`).
#[utoipa::path(get, path = "/v1/projects/{id}/grants", tag = "projects", params(TenantHeader),
    responses((status = 200, body = [GrantView])))]
pub(crate) async fn grants(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(project): Path<String>,
) -> Response {
    let result = async { state.identity.admin_project_grants(&admin, id(&project, "the project")?).await }.await;
    respond(result, |list| Json(list.into_iter().map(GrantView::from).collect::<Vec<_>>()).into_response())
}

/// Grants the project to another tenant of the instance – named by its id or a verified mail domain – with some of
/// its roles, or changes them (needs `projects.manage`).
#[utoipa::path(put, path = "/v1/projects/{id}/grants/{tenant}", tag = "projects", params(TenantHeader),
    request_body = GrantRoles, responses((status = 204), (status = 400, body = Problem), (status = 404, body = Problem)))]
pub(crate) async fn grant_project(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((project, tenant)): Path<(String, String)>,
    Json(body): Json<GrantRoles>,
) -> Response {
    let result = async {
        let project = id(&project, "the project")?;
        let grantee = state.identity.admin_find_tenant(&admin, &tenant).await?;
        let roles: BTreeSet<String> = body.roles.into_iter().collect();
        state.identity.admin_grant_project(&admin, project, grantee, &roles).await
    }
    .await;
    respond(result, no_content)
}

/// Takes a grant back, once that tenant holds none of the project's roles (needs `projects.manage`).
#[utoipa::path(delete, path = "/v1/projects/{id}/grants/{tenant}", tag = "projects", params(TenantHeader),
    responses((status = 204), (status = 400, description = "roles still held", body = Problem)))]
pub(crate) async fn revoke_project_grant(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((project, tenant)): Path<(String, String)>,
) -> Response {
    let result = async {
        let project = id(&project, "the project")?;
        let grantee = state.identity.admin_find_tenant(&admin, &tenant).await?;
        state.identity.admin_revoke_project_grant(&admin, project, grantee).await
    }
    .await;
    respond(result, no_content)
}

/// The projects other tenants have granted to this one, with the roles it may give (needs `directory.read`).
#[utoipa::path(get, path = "/v1/granted-projects", tag = "projects", params(TenantHeader),
    responses((status = 200, body = [GrantView])))]
pub(crate) async fn granted(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_granted_projects(&admin).await, |list| {
        Json(list.into_iter().map(GrantView::from).collect::<Vec<_>>()).into_response()
    })
}
