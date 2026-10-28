// SPDX-License-Identifier: AGPL-3.0-or-later
//! Groups: accounts of one tenant together – holders of roles, distribution lists with addresses of their own
//! (RFC 0002, 9.2), owners of shared folders later (RFC 0001). A group is owned by its tenant.

use std::collections::BTreeSet;

use kernoid_events::{
    Error, Event,
    aggregate::{Aggregate, CommandError, DomainEvent},
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Address, Identity, IdentityError, Result, account::on_verified_domain, role::Principal, valid_name};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum GroupEvent {
    #[serde(rename = "group.added")]
    Added { name: String },
    #[serde(rename = "group.renamed")]
    Renamed { name: String },
    #[serde(rename = "group.member_added")]
    MemberAdded { account: Uuid },
    #[serde(rename = "group.member_removed")]
    MemberRemoved { account: Uuid },
    #[serde(rename = "group.removed")]
    Removed,
    /// The identifier a directory knows the group by (SCIM `externalId`).
    #[serde(rename = "group.external_id_set")]
    ExternalIdSet { external_id: Option<String> },
    /// Mail to this address goes to every member.
    #[serde(rename = "group.address_added")]
    AddressAdded { address: Address },
    #[serde(rename = "group.address_removed")]
    AddressRemoved { address: Address },
}

impl DomainEvent for GroupEvent {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Group {
    pub exists: bool,
    pub name: String,
    pub members: BTreeSet<Uuid>,
    pub external_id: Option<String>,
    pub addresses: BTreeSet<Address>,
}

impl Aggregate for Group {
    const TYPE: &'static str = "group";
    type Event = GroupEvent;

    fn apply(&mut self, event: GroupEvent) {
        match event {
            GroupEvent::Added { name } => *self = Self { exists: true, name, ..Self::default() },
            GroupEvent::Renamed { name } => self.name = name,
            GroupEvent::MemberAdded { account } => {
                self.members.insert(account);
            }
            GroupEvent::MemberRemoved { account } => {
                self.members.remove(&account);
            }
            GroupEvent::Removed => *self = Self::default(),
            GroupEvent::ExternalIdSet { external_id } => self.external_id = external_id,
            GroupEvent::AddressAdded { address } => {
                self.addresses.insert(address);
            }
            GroupEvent::AddressRemoved { address } => {
                self.addresses.remove(&address);
            }
        }
    }
}

async fn project(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        let tenant = event.owner;
        let id = Uuid::parse_str(&event.aggregate.aggregate_id).map_err(|error| Error::Decode {
            event_type: event.event_type.clone(),
            revision: event.revision,
            message: format!("group id: {error}"),
        })?;
        match GroupEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            GroupEvent::Added { name } => {
                sqlx::query!("INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, $3)", id, tenant, name)
                    .execute(&mut *connection)
                    .await?;
            }
            GroupEvent::Renamed { name } => {
                sqlx::query!("UPDATE groups SET name = $2 WHERE id = $1", id, name).execute(&mut *connection).await?;
            }
            GroupEvent::MemberAdded { account } => {
                sqlx::query!("INSERT INTO group_members (group_id, account_id) VALUES ($1, $2)", id, account)
                    .execute(&mut *connection)
                    .await?;
            }
            GroupEvent::MemberRemoved { account } => {
                sqlx::query!("DELETE FROM group_members WHERE group_id = $1 AND account_id = $2", id, account)
                    .execute(&mut *connection)
                    .await?;
            }
            GroupEvent::Removed => {
                sqlx::query!("DELETE FROM groups WHERE id = $1", id).execute(&mut *connection).await?;
            }
            GroupEvent::ExternalIdSet { external_id } => {
                sqlx::query!("UPDATE groups SET external_id = $2 WHERE id = $1", id, external_id)
                    .execute(&mut *connection)
                    .await?;
            }
            GroupEvent::AddressAdded { address } => {
                let domain = address.domain();
                sqlx::query!(
                    "INSERT INTO addresses (address, tenant_id, group_id, is_primary, domain) VALUES ($1, $2, $3, false, $4)",
                    address.as_str(),
                    tenant,
                    id,
                    domain.as_str(),
                )
                .execute(&mut *connection)
                .await?;
            }
            GroupEvent::AddressRemoved { address } => {
                sqlx::query!("DELETE FROM addresses WHERE address = $1 AND group_id = $2", address.as_str(), id)
                    .execute(&mut *connection)
                    .await?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub id: Uuid,
    pub tenant: Uuid,
    pub name: String,
    pub members: Vec<Uuid>,
    /// Addresses mail to the group arrives at.
    pub addresses: Vec<String>,
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

fn existing(group: &Group) -> Result<()> {
    if group.exists { Ok(()) } else { Err(IdentityError::NotFound("the group")) }
}

impl Identity {
    pub(crate) async fn group_command(
        &self,
        tenant: Uuid,
        group: Uuid,
        creator: &str,
        decide: impl Fn(&Group) -> Result<Vec<GroupEvent>>,
    ) -> Result<()> {
        self.group_command_for(tenant, group, creator, None, decide).await
    }

    /// As `group_command`; a unique violation on `address` means it is taken.
    async fn group_command_for(
        &self,
        tenant: Uuid,
        group: Uuid,
        creator: &str,
        address: Option<&Address>,
        decide: impl Fn(&Group) -> Result<Vec<GroupEvent>>,
    ) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        let result = self
            .events
            .execute_with(instance, tenant, &group.to_string(), creator, decide, |c, e| Box::pin(project(c, e)))
            .await
            .map(drop);
        match address {
            Some(address) => result.map_err(|error| crate::account::address_error(error, Some(address))),
            None => result.map_err(command_error),
        }
    }

    /// Refuses a group of another tenant as if it did not exist.
    pub(crate) async fn group_of(&self, tenant: Uuid, group: Uuid) -> Result<()> {
        if self.group_tenant(group).await? == tenant { Ok(()) } else { Err(IdentityError::NotFound("the group")) }
    }

    /// The tenant a group belongs to.
    pub async fn group_tenant(&self, group: Uuid) -> Result<Uuid> {
        sqlx::query_scalar!("SELECT tenant_id FROM groups WHERE id = $1", group)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the group"))
    }

    pub async fn add_group(&self, tenant: Uuid, name: &str, creator: &str) -> Result<Uuid> {
        let name = valid_name(name)?;
        let id = Uuid::now_v7();
        self.group_command(tenant, id, creator, |group| {
            if group.exists {
                return Err(IdentityError::Exists("the group"));
            }
            Ok(vec![GroupEvent::Added { name: name.clone() }])
        })
        .await?;
        Ok(id)
    }

    pub async fn rename_group(&self, tenant: Uuid, group: Uuid, name: &str, creator: &str) -> Result<()> {
        let name = valid_name(name)?;
        self.group_of(tenant, group).await?;
        self.group_command(tenant, group, creator, |state| {
            existing(state)?;
            Ok(vec![GroupEvent::Renamed { name: name.clone() }])
        })
        .await
    }

    /// Adds an account of the same tenant to the group; adding a member twice changes nothing.
    pub async fn add_group_member(&self, tenant: Uuid, group: Uuid, account: Uuid, creator: &str) -> Result<()> {
        self.group_of(tenant, group).await?;
        let (_, account_tenant) = self.account_owner(account).await?;
        if account_tenant != tenant {
            return Err(IdentityError::NotFound("the account"));
        }
        self.group_command(tenant, group, creator, |state| {
            existing(state)?;
            Ok(if state.members.contains(&account) { Vec::new() } else { vec![GroupEvent::MemberAdded { account }] })
        })
        .await
    }

    pub async fn remove_group_member(&self, tenant: Uuid, group: Uuid, account: Uuid, creator: &str) -> Result<()> {
        self.group_of(tenant, group).await?;
        let instance = self.tenant_instance(tenant).await?;
        self.keep_an_admin(Some(tenant), instance, |held| {
            held.principal == Principal::Group(group) && held.account == account
        })
        .await?;
        self.group_command(tenant, group, creator, |state| {
            existing(state)?;
            if !state.members.contains(&account) {
                return Err(IdentityError::NotFound("the member"));
            }
            Ok(vec![GroupEvent::MemberRemoved { account }])
        })
        .await
    }

    /// Removes a group – only once it holds no roles, so that no permission disappears unnoticed.
    pub async fn remove_group(&self, tenant: Uuid, group: Uuid, creator: &str) -> Result<()> {
        self.group_of(tenant, group).await?;
        if self.group_holdings(group).await?.any() {
            return Err(IdentityError::Refused("the group holds roles; revoke them first".into()));
        }
        self.group_command(tenant, group, creator, |state| {
            existing(state)?;
            let mut events: Vec<_> =
                state.members.iter().map(|account| GroupEvent::MemberRemoved { account: *account }).collect();
            events
                .extend(state.addresses.iter().map(|address| GroupEvent::AddressRemoved { address: address.clone() }));
            events.push(GroupEvent::Removed);
            Ok(events)
        })
        .await
    }

    /// Gives the group an address on a verified domain of the tenant: mail to it goes to every member.
    pub async fn add_group_address(&self, tenant: Uuid, group: Uuid, address: &Address, creator: &str) -> Result<()> {
        self.group_of(tenant, group).await?;
        let instance = self.tenant_instance(tenant).await?;
        on_verified_domain(&self.tenant(instance, tenant).await?.state, address)?;
        self.group_command_for(tenant, group, creator, Some(address), |state| {
            existing(state)?;
            if state.addresses.contains(address) {
                return Err(IdentityError::Exists("the address"));
            }
            Ok(vec![GroupEvent::AddressAdded { address: address.clone() }])
        })
        .await
    }

    pub async fn remove_group_address(
        &self,
        tenant: Uuid,
        group: Uuid,
        address: &Address,
        creator: &str,
    ) -> Result<()> {
        self.group_of(tenant, group).await?;
        self.group_command(tenant, group, creator, |state| {
            existing(state)?;
            if !state.addresses.contains(address) {
                return Err(IdentityError::NotFound("the address"));
            }
            Ok(vec![GroupEvent::AddressRemoved { address: address.clone() }])
        })
        .await
    }

    pub async fn groups(&self, tenant: Uuid) -> Result<Vec<GroupInfo>> {
        let rows = sqlx::query!(
            r#"SELECT g.id, g.tenant_id, g.name,
                      coalesce(array_agg(m.account_id ORDER BY m.account_id) FILTER (WHERE m.account_id IS NOT NULL), '{}')
                          AS "members!: Vec<Uuid>",
                      array(SELECT ad.address FROM addresses ad WHERE ad.group_id = g.id ORDER BY ad.address)
                          AS "addresses!"
               FROM groups g LEFT JOIN group_members m ON m.group_id = g.id
               WHERE g.tenant_id = $1
               GROUP BY g.id ORDER BY g.name"#,
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| GroupInfo {
                id: row.id,
                tenant: row.tenant_id,
                name: row.name,
                members: row.members,
                addresses: row.addresses,
            })
            .collect())
    }
}
