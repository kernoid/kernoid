// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who may use whose calendars and address books (RFC 0004, 9): the grants in `collection_access` – administration,
//! written by `kernoid-identity` – resolved into a user's level on another account's collections.

use std::collections::HashMap;

use serde::Serialize;
use uuid::Uuid;

use crate::{Groupware, Result};

/// A level of access; each includes the ones before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// See when the owner is busy (calendars only).
    Freebusy,
    Read,
    /// Also answer invitations the owner is invited to (calendars only).
    Rsvp,
    Write,
    /// Also share, rename or delete the collection.
    Admin,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Freebusy => "freebusy",
            Self::Read => "read",
            Self::Rsvp => "rsvp",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "freebusy" => Self::Freebusy,
            "read" => Self::Read,
            "rsvp" => Self::Rsvp,
            "write" => Self::Write,
            "admin" => Self::Admin,
            _ => return None,
        })
    }

    /// Whether the level exists for this kind of collection.
    pub fn applies_to(self, collection: CollectionType) -> bool {
        collection == CollectionType::Calendar || matches!(self, Self::Read | Self::Write | Self::Admin)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectionType {
    Calendar,
    #[serde(rename = "addressbook")]
    AddressBook,
}

impl CollectionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calendar => "calendar",
            Self::AddressBook => "addressbook",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "calendar" => Some(Self::Calendar),
            "addressbook" => Some(Self::AddressBook),
            _ => None,
        }
    }
}

/// A user's access to one account's calendars and address books.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionAccess {
    pub user: Uuid,
    pub owner: Uuid,
    /// The user's own: `admin` on everything.
    pub owned: bool,
    /// The level on each collection shared with the user.
    pub collections: HashMap<Uuid, Level>,
}

impl CollectionAccess {
    pub fn own(account: Uuid) -> Self {
        Self { user: account, owner: account, owned: true, collections: HashMap::new() }
    }

    /// The user's level on a collection of the owner, if any.
    pub fn level(&self, collection: Uuid) -> Option<Level> {
        if self.owned { Some(Level::Admin) } else { self.collections.get(&collection).copied() }
    }

    /// Whether the user has at least `level` on the collection.
    pub fn allows(&self, collection: Uuid, level: Level) -> bool {
        self.level(collection).is_some_and(|have| have >= level)
    }

    pub fn any(&self) -> bool {
        self.owned || !self.collections.is_empty()
    }
}

/// A calendar or address book shared with a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SharedCollection {
    pub owner: Uuid,
    pub owner_name: String,
    pub owner_address: Option<String>,
    pub collection_type: CollectionType,
    pub collection: Uuid,
    pub level: Level,
}

impl Groupware {
    /// What `user` may do with `owner`'s calendars and address books: everything if they are its own; otherwise the
    /// highest level of the grants to it and its groups, per collection, while the owner is active and has mail.
    pub async fn access(&self, user: Uuid, owner: Uuid) -> Result<CollectionAccess> {
        if user == owner {
            return Ok(CollectionAccess::own(user));
        }
        let rows = sqlx::query!(
            "SELECT c.collection_id, c.level
             FROM collection_access c JOIN accounts a ON a.id = c.owner_id
             WHERE c.owner_id = $2 AND a.active
               AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')
               AND (c.grantee_account = $1
                    OR c.grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))",
            user,
            owner,
        )
        .fetch_all(self.pool())
        .await?;
        let mut access = CollectionAccess { user, owner, owned: false, collections: HashMap::new() };
        for row in rows {
            let Some(level) = Level::parse(&row.level) else { continue };
            let entry = access.collections.entry(row.collection_id).or_insert(level);
            *entry = (*entry).max(level);
        }
        Ok(access)
    }

    /// The calendars and address books shared with `user` that still exist, with its level on each.
    pub async fn shared_with(&self, user: Uuid) -> Result<Vec<SharedCollection>> {
        let rows = sqlx::query!(
            r#"SELECT c.owner_id, a.display_name, a.primary_address, c.collection_type, c.collection_id, c.level
               FROM collection_access c JOIN accounts a ON a.id = c.owner_id
               WHERE a.active AND a.id <> $1
                 AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')
                 AND (c.grantee_account = $1
                      OR c.grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))
                 AND (EXISTS (SELECT 1 FROM calendars k WHERE k.id = c.collection_id AND k.account_id = c.owner_id)
                      OR EXISTS (SELECT 1 FROM addressbooks b WHERE b.id = c.collection_id AND b.account_id = c.owner_id))
               ORDER BY a.display_name, c.collection_id"#,
            user,
        )
        .fetch_all(self.pool())
        .await?;
        let mut best: Vec<SharedCollection> = Vec::new();
        for row in rows {
            let (Some(level), Some(collection_type)) =
                (Level::parse(&row.level), CollectionType::parse(&row.collection_type))
            else {
                continue;
            };
            match best.iter_mut().find(|shared| shared.collection == row.collection_id) {
                Some(shared) => shared.level = shared.level.max(level),
                None => best.push(SharedCollection {
                    owner: row.owner_id,
                    owner_name: row.display_name,
                    owner_address: row.primary_address,
                    collection_type,
                    collection: row.collection_id,
                    level,
                }),
            }
        }
        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_include_the_lower_ones() {
        let owner = Uuid::from_u128(1);
        let calendar = Uuid::from_u128(2);
        let mut access =
            CollectionAccess { user: Uuid::from_u128(3), owner, owned: false, collections: HashMap::new() };
        assert!(!access.allows(calendar, Level::Freebusy));
        access.collections.insert(calendar, Level::Rsvp);
        assert!(access.allows(calendar, Level::Read));
        assert!(!access.allows(calendar, Level::Write));
        assert!(CollectionAccess::own(owner).allows(calendar, Level::Admin));
        assert!(!Level::Rsvp.applies_to(CollectionType::AddressBook));
        assert!(Level::Write.applies_to(CollectionType::AddressBook));
        assert_eq!(Level::parse("admin"), Some(Level::Admin));
    }
}
