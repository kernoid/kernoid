// SPDX-License-Identifier: AGPL-3.0-or-later
//! A tenant's directory as software that reads one sees it (LDAP, RFC 0003, 8): its active people – accounts that
//! log in, not shared mailboxes or drives – with their addresses, and its groups with their addresses and members.
//! Read from the read models, never from events.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::{Identity, IdentityError, Result};

/// A person in the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub id: Uuid,
    /// What it logs in with: the primary address, else the username, else the contact address, else its id.
    pub login: String,
    pub display_name: String,
    /// Its addresses, the primary first.
    pub addresses: Vec<String>,
    /// The groups it is a member of.
    pub groups: Vec<Uuid>,
}

/// A group in the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub addresses: Vec<String>,
    /// Its members that are people of the directory.
    pub members: Vec<Uuid>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    pub people: Vec<Person>,
    pub groups: Vec<Group>,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// The directory of an active tenant; empty for one that is not.
    pub async fn directory(&self, tenant: Uuid) -> Result<Directory> {
        let active = sqlx::query_scalar!("SELECT active FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?;
        if active != Some(true) {
            return Ok(Directory::default());
        }
        let accounts = sqlx::query!(
            "SELECT id, display_name, primary_address, username, email FROM accounts
             WHERE tenant_id = $1 AND active AND kind = 'person' ORDER BY id",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let addresses = sqlx::query!(
            "SELECT address, account_id, group_id FROM addresses WHERE tenant_id = $1 ORDER BY is_primary DESC, address",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let groups = sqlx::query!("SELECT id, name FROM groups WHERE tenant_id = $1 ORDER BY name", tenant)
            .fetch_all(self.pool())
            .await
            .map_err(store_error)?;
        let members = sqlx::query!(
            "SELECT m.group_id, m.account_id FROM group_members m JOIN groups g ON g.id = m.group_id
             WHERE g.tenant_id = $1 ORDER BY m.account_id",
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;

        let mut people: BTreeMap<Uuid, Person> = accounts
            .into_iter()
            .map(|row| {
                let login = row.primary_address.or(row.username).or(row.email).unwrap_or_else(|| row.id.to_string());
                let person = Person {
                    id: row.id,
                    login,
                    display_name: row.display_name,
                    addresses: Vec::new(),
                    groups: Vec::new(),
                };
                (row.id, person)
            })
            .collect();
        let mut groups: BTreeMap<Uuid, Group> = groups
            .into_iter()
            .map(|row| (row.id, Group { id: row.id, name: row.name, addresses: Vec::new(), members: Vec::new() }))
            .collect();
        for row in addresses {
            if let Some(person) = row.account_id.and_then(|account| people.get_mut(&account)) {
                person.addresses.push(row.address);
            } else if let Some(group) = row.group_id.and_then(|group| groups.get_mut(&group)) {
                group.addresses.push(row.address);
            }
        }
        for row in members {
            if let (Some(person), Some(group)) = (people.get_mut(&row.account_id), groups.get_mut(&row.group_id)) {
                person.groups.push(row.group_id);
                group.members.push(row.account_id);
            }
        }
        Ok(Directory { people: people.into_values().collect(), groups: groups.into_values().collect() })
    }
}
