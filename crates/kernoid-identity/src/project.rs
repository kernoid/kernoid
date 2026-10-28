// SPDX-License-Identifier: AGPL-3.0-or-later
//! Projects (RFC 0001, section 7.5): as in ZITADEL, a project of a tenant holds applications and the roles those
//! applications understand. Project roles are assigned to accounts and groups of the tenant ("authorizations"); with
//! the project's settings they go into tokens (`role_assertion`) or decide who may log in at all (`role_check`).
//!
//! - The `project` aggregate (owned by the tenant) holds name, settings and roles.
//! - The `authorization` aggregate holds the project roles of one account or group in one project, so that projects
//!   with many members do not grow one aggregate without end.

use std::collections::{BTreeMap, BTreeSet};

use kernoid_events::{
    Error, Event,
    aggregate::{Aggregate, CommandError, DomainEvent},
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Identity, IdentityError, Result, role::Principal, valid_name};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ProjectEvent {
    #[serde(rename = "project.added")]
    Added { name: String },
    #[serde(rename = "project.renamed")]
    Renamed { name: String },
    #[serde(rename = "project.settings_set")]
    SettingsSet { role_assertion: bool, role_check: bool },
    #[serde(rename = "project.role_added")]
    RoleAdded { key: String, display_name: String, group: Option<String> },
    #[serde(rename = "project.role_changed")]
    RoleChanged { key: String, display_name: String, group: Option<String> },
    #[serde(rename = "project.role_removed")]
    RoleRemoved { key: String },
    #[serde(rename = "project.removed")]
    Removed,
    /// Granted to another tenant of the instance with these roles, or the roles of a grant changed.
    #[serde(rename = "project.granted")]
    Granted { tenant: Uuid, roles: BTreeSet<String> },
    #[serde(rename = "project.grant_revoked")]
    GrantRevoked { tenant: Uuid },
}

impl DomainEvent for ProjectEvent {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRole {
    pub key: String,
    pub display_name: String,
    pub group: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Project {
    pub exists: bool,
    pub name: String,
    pub role_assertion: bool,
    pub role_check: bool,
    pub roles: BTreeMap<String, ProjectRole>,
    /// Tenants the project is granted to, with the roles they may give.
    pub grants: BTreeMap<Uuid, BTreeSet<String>>,
}

impl Aggregate for Project {
    const TYPE: &'static str = "project";
    type Event = ProjectEvent;

    fn apply(&mut self, event: ProjectEvent) {
        match event {
            ProjectEvent::Added { name } => *self = Self { exists: true, name, ..Self::default() },
            ProjectEvent::Renamed { name } => self.name = name,
            ProjectEvent::SettingsSet { role_assertion, role_check } => {
                self.role_assertion = role_assertion;
                self.role_check = role_check;
            }
            ProjectEvent::RoleAdded { key, display_name, group }
            | ProjectEvent::RoleChanged { key, display_name, group } => {
                self.roles.insert(key.clone(), ProjectRole { key, display_name, group });
            }
            ProjectEvent::RoleRemoved { key } => {
                self.roles.remove(&key);
            }
            ProjectEvent::Removed => *self = Self::default(),
            ProjectEvent::Granted { tenant, roles } => {
                self.grants.insert(tenant, roles);
            }
            ProjectEvent::GrantRevoked { tenant } => {
                self.grants.remove(&tenant);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AuthorizationEvent {
    #[serde(rename = "authorization.granted")]
    Granted { project: Uuid, principal: Principal, role: String },
    #[serde(rename = "authorization.revoked")]
    Revoked { project: Uuid, principal: Principal, role: String },
}

impl DomainEvent for AuthorizationEvent {}

/// The project roles of one account or group in one project.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub roles: BTreeSet<String>,
}

impl Aggregate for Authorization {
    const TYPE: &'static str = "authorization";
    type Event = AuthorizationEvent;

    fn apply(&mut self, event: AuthorizationEvent) {
        match event {
            AuthorizationEvent::Granted { role, .. } => {
                self.roles.insert(role);
            }
            AuthorizationEvent::Revoked { role, .. } => {
                self.roles.remove(&role);
            }
        }
    }
}

fn decode_id(event: &Event) -> std::result::Result<Uuid, Error> {
    Uuid::parse_str(&event.aggregate.aggregate_id).map_err(|error| Error::Decode {
        event_type: event.event_type.clone(),
        revision: event.revision,
        message: format!("project id: {error}"),
    })
}

async fn project_projection(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        let tenant = event.owner;
        let id = decode_id(event)?;
        match ProjectEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            ProjectEvent::Added { name } => {
                sqlx::query!("INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)", id, tenant, name)
                    .execute(&mut *connection)
                    .await?;
            }
            ProjectEvent::Renamed { name } => {
                sqlx::query!("UPDATE projects SET name = $2 WHERE id = $1", id, name).execute(&mut *connection).await?;
            }
            ProjectEvent::SettingsSet { role_assertion, role_check } => {
                sqlx::query!(
                    "UPDATE projects SET role_assertion = $2, role_check = $3 WHERE id = $1",
                    id,
                    role_assertion,
                    role_check,
                )
                .execute(&mut *connection)
                .await?;
            }
            ProjectEvent::RoleAdded { key, display_name, group } => {
                sqlx::query!(
                    "INSERT INTO project_roles (project_id, key, display_name, role_group) VALUES ($1, $2, $3, $4)",
                    id,
                    key,
                    display_name,
                    group,
                )
                .execute(&mut *connection)
                .await?;
            }
            ProjectEvent::RoleChanged { key, display_name, group } => {
                sqlx::query!(
                    "UPDATE project_roles SET display_name = $3, role_group = $4 WHERE project_id = $1 AND key = $2",
                    id,
                    key,
                    display_name,
                    group,
                )
                .execute(&mut *connection)
                .await?;
            }
            ProjectEvent::RoleRemoved { key } => {
                sqlx::query!("DELETE FROM project_roles WHERE project_id = $1 AND key = $2", id, key)
                    .execute(&mut *connection)
                    .await?;
            }
            ProjectEvent::Removed => {
                sqlx::query!("DELETE FROM projects WHERE id = $1", id).execute(&mut *connection).await?;
            }
            ProjectEvent::Granted { tenant: grantee, roles } => {
                let roles: Vec<String> = roles.into_iter().collect();
                sqlx::query!(
                    "INSERT INTO project_grants (project_id, tenant_id, roles) VALUES ($1, $2, $3)
                     ON CONFLICT (project_id, tenant_id) DO UPDATE SET roles = excluded.roles",
                    id,
                    grantee,
                    &roles,
                )
                .execute(&mut *connection)
                .await?;
            }
            ProjectEvent::GrantRevoked { tenant: grantee } => {
                sqlx::query!("DELETE FROM project_grants WHERE project_id = $1 AND tenant_id = $2", id, grantee)
                    .execute(&mut *connection)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn authorization_projection(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        match AuthorizationEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            AuthorizationEvent::Granted { project, principal, role } => {
                sqlx::query!(
                    "INSERT INTO project_authorizations (project_id, tenant_id, principal_kind, principal_id, role)
                     VALUES ($1, $2, $3, $4, $5)",
                    project,
                    event.owner,
                    principal.kind(),
                    principal.id(),
                    role,
                )
                .execute(&mut *connection)
                .await?;
            }
            AuthorizationEvent::Revoked { project, principal, role } => {
                sqlx::query!(
                    "DELETE FROM project_authorizations
                     WHERE project_id = $1 AND principal_kind = $2 AND principal_id = $3 AND role = $4",
                    project,
                    principal.kind(),
                    principal.id(),
                    role,
                )
                .execute(&mut *connection)
                .await?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectInfo {
    pub id: Uuid,
    pub tenant: Uuid,
    pub name: String,
    pub role_assertion: bool,
    pub role_check: bool,
    pub roles: Vec<ProjectRole>,
}

/// One project role held by an account or group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectAuthorization {
    /// The tenant that gave it and that the account or group belongs to.
    pub tenant: Uuid,
    pub principal: Principal,
    pub role: String,
}

/// A project granted to another tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectGrant {
    pub project: Uuid,
    pub project_name: String,
    /// The project's own tenant.
    pub owner: Uuid,
    /// The tenant it is granted to.
    pub tenant: Uuid,
    pub tenant_name: String,
    pub roles: Vec<String>,
}

/// How a tenant sees a project: as its own, or granted with some of its roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectAccess {
    Own,
    Granted(BTreeSet<String>),
}

fn command_error(error: CommandError<IdentityError>) -> IdentityError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn existing(project: &Project) -> Result<()> {
    if project.exists { Ok(()) } else { Err(IdentityError::NotFound("the project")) }
}

/// A role key: 1 to 100 characters of letters, digits, `_`, `.`, `:` and `-`.
fn valid_key(key: &str) -> Result<String> {
    let valid = !key.is_empty()
        && key.len() <= 100
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
    if valid {
        Ok(key.to_owned())
    } else {
        Err(IdentityError::Refused("a role key has 1 to 100 letters, digits, _, ., : or -".into()))
    }
}

fn valid_group(group: Option<&str>) -> Result<Option<String>> {
    group.map(str::trim).filter(|group| !group.is_empty()).map(valid_name).transpose()
}

impl Identity {
    async fn project_command(
        &self,
        tenant: Uuid,
        project: Uuid,
        creator: &str,
        decide: impl Fn(&Project) -> Result<Vec<ProjectEvent>>,
    ) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.events
            .execute_with(instance, tenant, &project.to_string(), creator, decide, |c, e| {
                Box::pin(project_projection(c, e))
            })
            .await
            .map(drop)
            .map_err(command_error)
    }

    /// Refuses a project of another tenant as if it did not exist.
    pub async fn project_of(&self, tenant: Uuid, project: Uuid) -> Result<()> {
        let owner = sqlx::query_scalar!("SELECT tenant_id FROM projects WHERE id = $1", project)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?;
        if owner == Some(tenant) { Ok(()) } else { Err(IdentityError::NotFound("the project")) }
    }

    pub async fn add_project(&self, tenant: Uuid, name: &str, creator: &str) -> Result<Uuid> {
        let name = valid_name(name)?;
        let id = Uuid::now_v7();
        self.project_command(tenant, id, creator, |project| {
            if project.exists {
                return Err(IdentityError::Exists("the project"));
            }
            Ok(vec![ProjectEvent::Added { name: name.clone() }])
        })
        .await?;
        Ok(id)
    }

    pub async fn rename_project(&self, tenant: Uuid, project: Uuid, name: &str, creator: &str) -> Result<()> {
        let name = valid_name(name)?;
        self.project_of(tenant, project).await?;
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            Ok(if state.name == name { Vec::new() } else { vec![ProjectEvent::Renamed { name: name.clone() }] })
        })
        .await
    }

    /// `role_assertion`: project roles go into ID tokens and userinfo. `role_check`: only accounts with a role in
    /// the project may log in to its applications.
    pub async fn set_project_settings(
        &self,
        tenant: Uuid,
        project: Uuid,
        role_assertion: bool,
        role_check: bool,
        creator: &str,
    ) -> Result<()> {
        self.project_of(tenant, project).await?;
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            Ok(if (state.role_assertion, state.role_check) == (role_assertion, role_check) {
                Vec::new()
            } else {
                vec![ProjectEvent::SettingsSet { role_assertion, role_check }]
            })
        })
        .await
    }

    /// Adds a role to the project, or changes its display name and group.
    pub async fn set_project_role(
        &self,
        tenant: Uuid,
        project: Uuid,
        key: &str,
        display_name: &str,
        group: Option<&str>,
        creator: &str,
    ) -> Result<()> {
        let key = valid_key(key)?;
        let display_name = valid_name(display_name)?;
        let group = valid_group(group)?;
        self.project_of(tenant, project).await?;
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            let role = ProjectRole { key: key.clone(), display_name: display_name.clone(), group: group.clone() };
            Ok(match state.roles.get(&key) {
                None => {
                    vec![ProjectEvent::RoleAdded { key: role.key, display_name: role.display_name, group: role.group }]
                }
                Some(held) if *held == role => Vec::new(),
                Some(_) => {
                    vec![ProjectEvent::RoleChanged {
                        key: role.key,
                        display_name: role.display_name,
                        group: role.group,
                    }]
                }
            })
        })
        .await
    }

    /// Removes a role from the project – once nobody holds it.
    pub async fn remove_project_role(&self, tenant: Uuid, project: Uuid, key: &str, creator: &str) -> Result<()> {
        self.project_of(tenant, project).await?;
        let held = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM project_authorizations WHERE project_id = $1 AND role = $2) AS "held!""#,
            project,
            key,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        if held {
            return Err(IdentityError::Refused(format!("the role {key} is assigned; revoke it first")));
        }
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            if !state.roles.contains_key(key) {
                return Err(IdentityError::NotFound("the project role"));
            }
            if state.grants.values().any(|roles| roles.contains(key)) {
                return Err(IdentityError::Refused(format!("the role {key} is granted to other tenants")));
            }
            Ok(vec![ProjectEvent::RoleRemoved { key: key.to_owned() }])
        })
        .await
    }

    /// Removes a project – once it has no applications and nobody holds its roles.
    pub async fn remove_project(&self, tenant: Uuid, project: Uuid, creator: &str) -> Result<()> {
        self.project_of(tenant, project).await?;
        let used = sqlx::query!(
            r#"SELECT EXISTS (SELECT 1 FROM applications WHERE project_id = $1) AS "applications!",
                      EXISTS (SELECT 1 FROM project_authorizations WHERE project_id = $1) AS "authorizations!""#,
            project,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        if used.applications {
            return Err(IdentityError::Refused("the project has applications; remove or move them first".into()));
        }
        if used.authorizations {
            return Err(IdentityError::Refused("the project's roles are assigned; revoke them first".into()));
        }
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            if !state.grants.is_empty() {
                return Err(IdentityError::Refused(
                    "the project is granted to other tenants; revoke that first".into(),
                ));
            }
            let mut events: Vec<_> =
                state.roles.keys().map(|key| ProjectEvent::RoleRemoved { key: key.clone() }).collect();
            events.push(ProjectEvent::Removed);
            Ok(events)
        })
        .await
    }

    pub async fn project(&self, project: Uuid) -> Result<ProjectInfo> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, name, role_assertion, role_check FROM projects WHERE id = $1",
            project,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the project"))?;
        Ok(ProjectInfo {
            id: row.id,
            tenant: row.tenant_id,
            name: row.name,
            role_assertion: row.role_assertion,
            role_check: row.role_check,
            roles: self.project_roles(project).await?,
        })
    }

    pub async fn projects(&self, tenant: Uuid) -> Result<Vec<ProjectInfo>> {
        let ids = sqlx::query_scalar!("SELECT id FROM projects WHERE tenant_id = $1 ORDER BY name, id", tenant)
            .fetch_all(self.pool())
            .await
            .map_err(store_error)?;
        let mut projects = Vec::with_capacity(ids.len());
        for id in ids {
            projects.push(self.project(id).await?);
        }
        Ok(projects)
    }

    async fn project_roles(&self, project: Uuid) -> Result<Vec<ProjectRole>> {
        let rows = sqlx::query!(
            "SELECT key, display_name, role_group FROM project_roles WHERE project_id = $1 ORDER BY key",
            project,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| ProjectRole { key: row.key, display_name: row.display_name, group: row.role_group })
            .collect())
    }

    // Authorizations

    async fn authorization_command(
        &self,
        tenant: Uuid,
        project: Uuid,
        principal: Principal,
        creator: &str,
        decide: impl Fn(&Authorization) -> Result<Vec<AuthorizationEvent>>,
    ) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        let id = format!("{project}/{}/{}", principal.kind(), principal.id());
        self.events
            .execute_with(instance, tenant, &id, creator, decide, |c, e| Box::pin(authorization_projection(c, e)))
            .await
            .map(drop)
            .map_err(command_error)
    }

    /// Gives an account or group of the tenant a role of one of its projects; giving it twice changes nothing.
    pub async fn grant_project_role(
        &self,
        tenant: Uuid,
        project: Uuid,
        principal: Principal,
        role: &str,
        creator: &str,
    ) -> Result<()> {
        self.principal_of(tenant, principal).await?;
        let known = match self.project_access(tenant, project).await? {
            ProjectAccess::Own => self.project(project).await?.roles.iter().any(|held| held.key == role),
            ProjectAccess::Granted(roles) => roles.contains(role),
        };
        if !known {
            return Err(IdentityError::NotFound("the project role"));
        }
        self.authorization_command(tenant, project, principal, creator, |state| {
            Ok(if state.roles.contains(role) {
                Vec::new()
            } else {
                vec![AuthorizationEvent::Granted { project, principal, role: role.to_owned() }]
            })
        })
        .await
    }

    pub async fn revoke_project_role(
        &self,
        tenant: Uuid,
        project: Uuid,
        principal: Principal,
        role: &str,
        creator: &str,
    ) -> Result<()> {
        self.project_access(tenant, project).await?;
        self.authorization_command(tenant, project, principal, creator, |state| {
            if !state.roles.contains(role) {
                return Err(IdentityError::NotFound("the authorization"));
            }
            Ok(vec![AuthorizationEvent::Revoked { project, principal, role: role.to_owned() }])
        })
        .await
    }

    /// Who holds which role of a project – every tenant's authorizations, or with `tenant` only that tenant's.
    pub async fn project_authorizations(
        &self,
        project: Uuid,
        tenant: Option<Uuid>,
    ) -> Result<Vec<ProjectAuthorization>> {
        let rows = sqlx::query!(
            "SELECT tenant_id, principal_kind, principal_id, role FROM project_authorizations
             WHERE project_id = $1 AND ($2::uuid IS NULL OR tenant_id = $2)
             ORDER BY role, tenant_id, principal_kind, principal_id",
            project,
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some(ProjectAuthorization {
                    tenant: row.tenant_id,
                    principal: Principal::new(&row.principal_kind, row.principal_id).ok()?,
                    role: row.role,
                })
            })
            .collect())
    }

    // Grants

    /// Whether `tenant` may use a project: its own, or granted to it. Any other project is unknown.
    pub async fn project_access(&self, tenant: Uuid, project: Uuid) -> Result<ProjectAccess> {
        let row = sqlx::query!(
            r#"SELECT p.tenant_id, g.roles AS "roles?"
               FROM projects p LEFT JOIN project_grants g ON g.project_id = p.id AND g.tenant_id = $2
               WHERE p.id = $1"#,
            project,
            tenant,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the project"))?;
        match (row.tenant_id == tenant, row.roles) {
            (true, _) => Ok(ProjectAccess::Own),
            (false, Some(roles)) => Ok(ProjectAccess::Granted(roles.into_iter().collect())),
            (false, None) => Err(IdentityError::NotFound("the project")),
        }
    }

    /// Grants a project to another tenant of the instance with some of its roles, or changes the roles of a grant.
    /// Roles taken away from a grant must no longer be held in that tenant.
    pub async fn grant_project(
        &self,
        tenant: Uuid,
        project: Uuid,
        grantee: Uuid,
        roles: &BTreeSet<String>,
        creator: &str,
    ) -> Result<()> {
        self.project_of(tenant, project).await?;
        if grantee == tenant {
            return Err(IdentityError::Refused("a project is the own tenant's already".into()));
        }
        if self.tenant_instance(grantee).await? != self.tenant_instance(tenant).await? {
            return Err(IdentityError::NotFound("the tenant"));
        }
        if roles.is_empty() {
            return Err(IdentityError::Refused("a grant has at least one role".into()));
        }
        let held: BTreeSet<String> = self
            .project_authorizations(project, Some(grantee))
            .await?
            .into_iter()
            .map(|authorization| authorization.role)
            .collect();
        if let Some(role) = held.difference(roles).next() {
            return Err(IdentityError::Refused(format!("the role {role} is held in that tenant; revoke it first")));
        }
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            if let Some(unknown) = roles.iter().find(|role| !state.roles.contains_key(*role)) {
                return Err(IdentityError::Refused(format!("the project has no role {unknown}")));
            }
            Ok(if state.grants.get(&grantee) == Some(roles) {
                Vec::new()
            } else {
                vec![ProjectEvent::Granted { tenant: grantee, roles: roles.clone() }]
            })
        })
        .await
    }

    /// Takes a grant back – once the tenant holds none of the project's roles any more.
    pub async fn revoke_project_grant(&self, tenant: Uuid, project: Uuid, grantee: Uuid, creator: &str) -> Result<()> {
        self.project_of(tenant, project).await?;
        if !self.project_authorizations(project, Some(grantee)).await?.is_empty() {
            return Err(IdentityError::Refused("the tenant holds roles of the project; revoke them first".into()));
        }
        self.project_command(tenant, project, creator, |state| {
            existing(state)?;
            if !state.grants.contains_key(&grantee) {
                return Err(IdentityError::NotFound("the grant"));
            }
            Ok(vec![ProjectEvent::GrantRevoked { tenant: grantee }])
        })
        .await
    }

    /// The grants of a project.
    pub async fn project_grants(&self, project: Uuid) -> Result<Vec<ProjectGrant>> {
        let rows = sqlx::query!(
            "SELECT g.project_id, p.name AS project_name, p.tenant_id AS owner, g.tenant_id, t.name AS tenant_name,
                    g.roles
             FROM project_grants g JOIN projects p ON p.id = g.project_id JOIN tenants t ON t.id = g.tenant_id
             WHERE g.project_id = $1 ORDER BY t.name, t.id",
            project,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| ProjectGrant {
                project: row.project_id,
                project_name: row.project_name,
                owner: row.owner,
                tenant: row.tenant_id,
                tenant_name: row.tenant_name,
                roles: row.roles,
            })
            .collect())
    }

    /// The projects other tenants have granted to `tenant`.
    pub async fn granted_projects(&self, tenant: Uuid) -> Result<Vec<ProjectGrant>> {
        let rows = sqlx::query!(
            "SELECT g.project_id, p.name AS project_name, p.tenant_id AS owner, g.tenant_id, t.name AS tenant_name,
                    g.roles
             FROM project_grants g JOIN projects p ON p.id = g.project_id JOIN tenants t ON t.id = g.tenant_id
             WHERE g.tenant_id = $1 ORDER BY p.name, p.id",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| ProjectGrant {
                project: row.project_id,
                project_name: row.project_name,
                owner: row.owner,
                tenant: row.tenant_id,
                tenant_name: row.tenant_name,
                roles: row.roles,
            })
            .collect())
    }

    /// The roles an account holds in a project, directly and through its groups.
    pub async fn account_project_roles(&self, project: Uuid, account: Uuid) -> Result<BTreeSet<String>> {
        let roles = sqlx::query_scalar!(
            "SELECT DISTINCT role FROM project_authorizations
             WHERE project_id = $1
               AND ((principal_kind = 'account' AND principal_id = $2)
                 OR (principal_kind = 'group'
                     AND principal_id IN (SELECT group_id FROM group_members WHERE account_id = $2)))",
            project,
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(roles.into_iter().collect())
    }
}
