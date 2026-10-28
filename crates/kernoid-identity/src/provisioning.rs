// SPDX-License-Identifier: AGPL-3.0-or-later
//! Provisioning by a tenant's directory (RFC 0001, 7.8): SCIM tokens, the directory's identifiers (`externalId`), and
//! what SCIM may change. A SCIM token acts with `directory.read`, `accounts.manage` and `groups.manage` – no more: it
//! cannot deactivate an account that holds other permissions, nor change the members of a group that holds roles.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use kernoid_events::{InlineFuture, inline};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::{AccountEvent, AccountInfo},
    group::GroupEvent,
    role::{Admin, Permission},
    tenant::TenantEvent,
};

/// What a SCIM token may do.
pub const SCIM_PERMISSIONS: [Permission; 3] =
    [Permission::DirectoryRead, Permission::AccountsManage, Permission::GroupsManage];

const TOKEN_PREFIX: &str = "kscim1.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimTokenInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// The tenant a SCIM request acts for, found by its token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimClient {
    pub instance: Uuid,
    pub tenant: Uuid,
    pub token: Uuid,
}

impl ScimClient {
    /// Who the events of this client name as their creator.
    pub fn creator(&self) -> String {
        format!("scim:{}", self.token)
    }
}

/// An account as SCIM shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimUser {
    pub account: AccountInfo,
    pub external_id: Option<String>,
    /// Every address, the primary one first.
    pub addresses: Vec<String>,
    pub meta: ScimMeta,
}

/// When a resource was made and last changed, and its version – the sequence of its last event (SCIM `meta`, ETags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimMeta {
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub version: i64,
}

impl ScimMeta {
    /// The weak ETag (RFC 7644, 3.14).
    pub fn etag(&self) -> String {
        format!("W/\"{}\"", self.version)
    }
}

/// How SCIM lists are sorted (`sortBy`, `sortOrder`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScimSort {
    /// In the order they were made.
    #[default]
    Created,
    UserName,
    DisplayName,
    ExternalId,
}

impl ScimSort {
    /// The attribute named in `sortBy`; `None` for one kernoid does not sort by.
    pub fn parse(attribute: &str) -> Option<Self> {
        match attribute.to_ascii_lowercase().as_str() {
            "meta.created" | "id" => Some(Self::Created),
            "username" | "emails" | "emails.value" => Some(Self::UserName),
            "displayname" | "name.formatted" => Some(Self::DisplayName),
            "externalid" => Some(Self::ExternalId),
            _ => None,
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::UserName => "username",
            Self::DisplayName => "displayname",
            Self::ExternalId => "externalid",
        }
    }
}

/// A group as SCIM shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimGroup {
    pub id: Uuid,
    pub name: String,
    pub external_id: Option<String>,
    pub members: Vec<(Uuid, String)>,
    pub meta: ScimMeta,
}

/// A filter of the form `attribute eq "value"` – what directories use to find what they provisioned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimFilter {
    UserName(String),
    ExternalId(String),
    DisplayName(String),
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn valid_external_id(external_id: Option<&str>) -> Result<Option<String>> {
    match external_id {
        Some(value) if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) => {
            Err(IdentityError::Refused("an externalId has 1 to 255 characters".into()))
        }
        other => Ok(other.map(str::to_owned)),
    }
}

impl Identity {
    // Tokens

    /// A new SCIM token for the tenant; returns its id and the token – shown once.
    pub async fn add_scim_token(&self, tenant: Uuid, name: &str, creator: &str) -> Result<(Uuid, String)> {
        let name = crate::valid_name(name)?;
        let instance = self.tenant_instance(tenant).await?;
        let id = Uuid::now_v7();
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
        let token = format!("{TOKEN_PREFIX}{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let token_hash = hash(&token);
        let stored_name = name.clone();
        let store = inline(move |connection, events| {
            let name = stored_name.clone();
            Box::pin(async move {
                crate::tenant::project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO scim_tokens (id, tenant_id, name, token_hash) VALUES ($1, $2, $3, $4)",
                    id,
                    tenant,
                    name,
                    &token_hash[..],
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                tenant,
                &tenant.to_string(),
                creator,
                |state: &crate::tenant::Tenant| {
                    crate::existing_tenant(state)?;
                    Ok(vec![TenantEvent::ScimTokenAdded { id, name: name.clone() }])
                },
                store,
            )
            .await
            .map_err(|error| match error {
                kernoid_events::aggregate::CommandError::Refused(error) => error,
                kernoid_events::aggregate::CommandError::Store(error) => IdentityError::Store(error),
            })?;
        Ok((id, token))
    }

    pub async fn remove_scim_token(&self, tenant: Uuid, id: Uuid, creator: &str) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            crate::existing_tenant(state)?;
            if !state.scim_tokens.contains(&id) {
                return Err(IdentityError::NotFound("the SCIM token"));
            }
            Ok(vec![TenantEvent::ScimTokenRemoved { id }])
        })
        .await
    }

    pub async fn scim_tokens(&self, tenant: Uuid) -> Result<Vec<ScimTokenInfo>> {
        let rows = sqlx::query!(
            "SELECT id, name, created_at, last_used_at FROM scim_tokens WHERE tenant_id = $1 ORDER BY created_at",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| ScimTokenInfo {
                id: row.id,
                name: row.name,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    /// The tenant of a SCIM token at `instance`, if the token is valid and its tenant active.
    pub async fn scim_client(&self, instance: Uuid, token: &str) -> Result<Option<ScimClient>> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Ok(None);
        }
        let row = sqlx::query!(
            "UPDATE scim_tokens s SET last_used_at = now()
             FROM tenants t
             WHERE s.token_hash = $1 AND t.id = s.tenant_id AND t.instance_id = $2 AND t.active
             RETURNING s.id, s.tenant_id",
            &hash(token)[..],
            instance,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        Ok(row.map(|row| ScimClient { instance, tenant: row.tenant_id, token: row.id }))
    }

    pub async fn admin_scim_tokens(&self, admin: &Admin) -> Result<Vec<ScimTokenInfo>> {
        admin.require(Permission::DirectoryRead)?;
        self.scim_tokens(admin.tenant()).await
    }

    pub async fn admin_add_scim_token(&self, admin: &Admin, name: &str) -> Result<(Uuid, String)> {
        admin.require(Permission::ProvisioningManage)?;
        self.add_scim_token(admin.tenant(), name, &admin.creator()).await
    }

    pub async fn admin_remove_scim_token(&self, admin: &Admin, id: Uuid) -> Result<()> {
        admin.require(Permission::ProvisioningManage)?;
        self.remove_scim_token(admin.tenant(), id, &admin.creator()).await
    }

    // Identifiers of the directory

    pub async fn set_account_external_id(&self, account: Uuid, external_id: Option<&str>, creator: &str) -> Result<()> {
        let external_id = valid_external_id(external_id)?;
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            Ok(if state.external_id == external_id {
                Vec::new()
            } else {
                vec![AccountEvent::ExternalIdSet { external_id: external_id.clone() }]
            })
        })
        .await
    }

    pub async fn set_group_external_id(
        &self,
        tenant: Uuid,
        group: Uuid,
        external_id: Option<&str>,
        creator: &str,
    ) -> Result<()> {
        let external_id = valid_external_id(external_id)?;
        self.group_of(tenant, group).await?;
        self.group_command(tenant, group, creator, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the group"));
            }
            Ok(if state.external_id == external_id {
                Vec::new()
            } else {
                vec![GroupEvent::ExternalIdSet { external_id: external_id.clone() }]
            })
        })
        .await
    }

    // What SCIM reads

    /// Accounts of a tenant for SCIM, filtered and paged (`start` from 1); returns the total and the page.
    #[allow(clippy::too_many_arguments, reason = "the parts of a SCIM list request")]
    pub async fn scim_users(
        &self,
        tenant: Uuid,
        filter: Option<&ScimFilter>,
        start: i64,
        count: i64,
        sort: ScimSort,
        descending: bool,
    ) -> Result<(i64, Vec<ScimUser>)> {
        let (user_name, external_id) = match filter {
            Some(ScimFilter::UserName(value)) => (Some(value.to_lowercase()), None),
            Some(ScimFilter::ExternalId(value)) => (None, Some(value.clone())),
            Some(ScimFilter::DisplayName(_)) => return Ok((0, Vec::new())),
            None => (None, None),
        };
        let rows = sqlx::query!(
            r#"SELECT a.id, count(*) OVER () AS "total!"
               FROM accounts a
               WHERE a.tenant_id = $1
                 AND ($2::text IS NULL OR EXISTS (SELECT 1 FROM addresses ad WHERE ad.account_id = a.id AND ad.address = $2))
                 AND ($3::text IS NULL OR a.external_id = $3)
               ORDER BY
                 CASE WHEN $6 = 'username' AND NOT $7 THEN lower(a.primary_address) END ASC,
                 CASE WHEN $6 = 'username' AND $7 THEN lower(a.primary_address) END DESC,
                 CASE WHEN $6 = 'displayname' AND NOT $7 THEN lower(a.display_name) END ASC,
                 CASE WHEN $6 = 'displayname' AND $7 THEN lower(a.display_name) END DESC,
                 CASE WHEN $6 = 'externalid' AND NOT $7 THEN a.external_id END ASC,
                 CASE WHEN $6 = 'externalid' AND $7 THEN a.external_id END DESC,
                 CASE WHEN $6 = 'created' AND $7 THEN a.created_at END DESC,
                 a.created_at, a.id
               OFFSET $4 LIMIT $5"#,
            tenant,
            user_name,
            external_id,
            (start.max(1) - 1),
            count.clamp(0, 200),
            sort.key(),
            descending,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let total = match rows.first() {
            Some(row) => row.total,
            None => self.scim_count_users(tenant, filter).await?,
        };
        let mut users = Vec::with_capacity(rows.len());
        for row in rows {
            users.push(self.scim_user(tenant, row.id).await?);
        }
        Ok((total, users))
    }

    async fn scim_count_users(&self, tenant: Uuid, filter: Option<&ScimFilter>) -> Result<i64> {
        if filter.is_some() {
            return Ok(0);
        }
        sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM accounts WHERE tenant_id = $1"#, tenant)
            .fetch_one(self.pool())
            .await
            .map_err(store_error)
    }

    /// One account of the tenant for SCIM.
    pub async fn scim_user(&self, tenant: Uuid, account: Uuid) -> Result<ScimUser> {
        let info = self.account(account).await?;
        if info.tenant != tenant {
            return Err(IdentityError::NotFound("the account"));
        }
        let external_id = sqlx::query_scalar!("SELECT external_id FROM accounts WHERE id = $1", account)
            .fetch_one(self.pool())
            .await
            .map_err(store_error)?;
        let addresses = sqlx::query_scalar!(
            "SELECT address FROM addresses WHERE account_id = $1 ORDER BY is_primary DESC, address",
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let meta = self.scim_meta(info.instance, "account", account).await?;
        Ok(ScimUser { account: info, external_id, addresses, meta })
    }

    /// The `meta` of a resource, from the events of its aggregate.
    async fn scim_meta(&self, instance: Uuid, aggregate: &str, id: Uuid) -> Result<ScimMeta> {
        let row = sqlx::query!(
            r#"SELECT min(created_at) AS "created!", max(created_at) AS "modified!", max(sequence) AS "version!"
               FROM events WHERE instance_id = $1 AND aggregate_type = $2 AND aggregate_id = $3"#,
            instance,
            aggregate,
            id.to_string(),
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        Ok(ScimMeta { created: row.created, last_modified: row.modified, version: row.version })
    }

    /// Groups of a tenant for SCIM, filtered and paged.
    #[allow(clippy::too_many_arguments, reason = "the parts of a SCIM list request")]
    pub async fn scim_groups(
        &self,
        tenant: Uuid,
        filter: Option<&ScimFilter>,
        start: i64,
        count: i64,
        sort: ScimSort,
        descending: bool,
    ) -> Result<(i64, Vec<ScimGroup>)> {
        let (name, external_id) = match filter {
            Some(ScimFilter::DisplayName(value)) => (Some(value.clone()), None),
            Some(ScimFilter::ExternalId(value)) => (None, Some(value.clone())),
            Some(ScimFilter::UserName(_)) => return Ok((0, Vec::new())),
            None => (None, None),
        };
        let rows = sqlx::query!(
            r#"SELECT id, count(*) OVER () AS "total!" FROM groups
               WHERE tenant_id = $1 AND ($2::text IS NULL OR name = $2) AND ($3::text IS NULL OR external_id = $3)
               ORDER BY
                 CASE WHEN $6 = 'displayname' AND NOT $7 THEN lower(name) END ASC,
                 CASE WHEN $6 = 'displayname' AND $7 THEN lower(name) END DESC,
                 CASE WHEN $6 = 'externalid' AND NOT $7 THEN external_id END ASC,
                 CASE WHEN $6 = 'externalid' AND $7 THEN external_id END DESC,
                 CASE WHEN $6 IN ('created', 'username') AND $7 THEN created_at END DESC,
                 created_at, id
               OFFSET $4 LIMIT $5"#,
            tenant,
            name,
            external_id,
            (start.max(1) - 1),
            count.clamp(0, 200),
            sort.key(),
            descending,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let total = rows.first().map(|row| row.total).unwrap_or(0);
        let mut groups = Vec::with_capacity(rows.len());
        for row in rows {
            groups.push(self.scim_group(tenant, row.id).await?);
        }
        Ok((total, groups))
    }

    pub async fn scim_group(&self, tenant: Uuid, group: Uuid) -> Result<ScimGroup> {
        let row = sqlx::query!(
            "SELECT g.name, g.external_id, t.instance_id FROM groups g JOIN tenants t ON t.id = g.tenant_id
             WHERE g.id = $1 AND g.tenant_id = $2",
            group,
            tenant,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the group"))?;
        let members = sqlx::query!(
            "SELECT a.id, coalesce(a.primary_address, a.username, a.email, '') AS \"primary_address!\" FROM group_members m JOIN accounts a ON a.id = m.account_id
             WHERE m.group_id = $1 ORDER BY a.primary_address",
            group,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let meta = self.scim_meta(row.instance_id, "group", group).await?;
        Ok(ScimGroup {
            id: group,
            name: row.name,
            external_id: row.external_id,
            members: members.into_iter().map(|member| (member.id, member.primary_address)).collect(),
            meta,
        })
    }

    // What SCIM may change

    /// An account SCIM may deactivate or change the credentials of: one holding no permission beyond SCIM's own.
    pub async fn scim_may_manage(&self, tenant: Uuid, account: Uuid) -> Result<()> {
        let held = self.permissions(tenant, account).await?;
        let allowed: BTreeSet<Permission> = SCIM_PERMISSIONS.into_iter().collect();
        match held.difference(&allowed).next() {
            Some(missing) => Err(IdentityError::Forbidden(*missing)),
            None => Ok(()),
        }
    }

    /// A group whose members SCIM may change: one that holds no role.
    pub async fn scim_may_change_members(&self, group: Uuid) -> Result<()> {
        if self.group_holdings(group).await?.any() {
            return Err(IdentityError::Forbidden(Permission::RolesManage));
        }
        Ok(())
    }
}
