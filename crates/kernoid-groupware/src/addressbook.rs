// SPDX-License-Identifier: AGPL-3.0-or-later
//! Address books (RFC 0004, 5): collections of contacts, one of them the account's default.

use kernoid_mail::StoreChange;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    Groupware, GroupwareError, Result,
    changes::{self, Change, Entry, ObjectType},
    check_collection_name,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressBookInfo {
    pub id: Uuid,
    pub account: Uuid,
    /// Its name in the account's home (DAV).
    pub resource_name: String,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: i64,
    pub is_default: bool,
    pub is_subscribed: bool,
    /// Properties clients set that kernoid does not know (WebDAV dead properties), as JSON.
    pub dead_properties: serde_json::Value,
    /// The modification sequence of the last change of one of its contacts or of itself (`getctag`).
    pub modseq: i64,
    /// Encrypted (RFC 0006, 7): the collection's public key; its entries are the members' apps' (`sealed`).
    pub collection_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct NewAddressBook {
    /// Its name in the account's home; the id if none.
    pub resource_name: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: i64,
    pub is_default: bool,
}

/// What changes; `None` keeps a value, `Some(None)` clears an optional one.
#[derive(Debug, Clone, Default)]
pub struct AddressBookUpdate {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub sort_order: Option<i64>,
    pub is_default: Option<bool>,
    pub is_subscribed: Option<bool>,
}

fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(GroupwareError::Invalid("a name has 1 to 255 characters, none of them control characters".into()));
    }
    Ok(())
}

/// Creates the default address book in a change that has just made the account's groupware.
pub(crate) async fn create_default(change: &mut StoreChange, name: &str) -> Result<()> {
    let new = NewAddressBook { name: name.into(), is_default: true, ..NewAddressBook::default() };
    insert(change, Uuid::now_v7(), &new).await
}

async fn insert(change: &mut StoreChange, id: Uuid, new: &NewAddressBook) -> Result<()> {
    let modseq = change.next_modseq().await?;
    let account = change.account();
    let resource_name = new.resource_name.clone().unwrap_or_else(|| id.to_string());
    if new.is_default {
        sqlx::query!("UPDATE addressbooks SET is_default = false WHERE account_id = $1 AND is_default", account)
            .execute(change.connection())
            .await?;
    }
    sqlx::query!(
        "INSERT INTO addressbooks (id, account_id, resource_name, name, description, sort_order, is_default)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        id,
        account,
        resource_name,
        new.name,
        new.description,
        new.sort_order,
        new.is_default,
    )
    .execute(change.connection())
    .await?;
    let entry = Entry {
        object_type: ObjectType::AddressBook,
        id,
        collection: None,
        resource_name: None,
        change: Change::Created,
    };
    changes::record(change.connection(), account, modseq, entry).await
}

impl Groupware {
    /// The account's address books, by sort order and name.
    pub async fn addressbooks(&self, account: Uuid) -> Result<Vec<AddressBookInfo>> {
        let mut read = self.read(account).await?;
        let rows = sqlx::query!(
            r#"SELECT b.id, b.resource_name, b.dead_properties, b.name, b.description, b.sort_order, b.is_default, b.is_subscribed,
                      b.collection_key,
                      greatest((SELECT max(modseq) FROM groupware_changes g
                                WHERE g.account_id = b.account_id AND (g.object_id = b.id OR g.collection_id = b.id)), 0)
                          AS "modseq!"
               FROM addressbooks b WHERE b.account_id = $1 ORDER BY b.sort_order, b.name, b.id"#,
            account,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows
            .into_iter()
            .map(|row| AddressBookInfo {
                id: row.id,
                account,
                resource_name: row.resource_name,
                dead_properties: row.dead_properties,
                name: row.name,
                description: row.description,
                sort_order: row.sort_order,
                is_default: row.is_default,
                is_subscribed: row.is_subscribed,
                modseq: row.modseq,
                collection_key: row.collection_key,
            })
            .collect())
    }

    pub async fn addressbook(&self, account: Uuid, id: Uuid) -> Result<AddressBookInfo> {
        self.addressbooks(account)
            .await?
            .into_iter()
            .find(|book| book.id == id)
            .ok_or(GroupwareError::NotFound("the address book"))
    }

    /// The address book with this name in the account's home (CardDAV).
    pub async fn addressbook_by_name(&self, account: Uuid, name: &str) -> Result<Option<AddressBookInfo>> {
        Ok(self.addressbooks(account).await?.into_iter().find(|book| book.resource_name == name))
    }

    /// Creates an address book; CardDAV's extended `MKCOL` names it with `new.resource_name`.
    pub async fn create_addressbook(&self, account: Uuid, new: NewAddressBook) -> Result<Uuid> {
        check_name(&new.name)?;
        if let Some(name) = &new.resource_name {
            check_collection_name(name)?;
        }
        let id = Uuid::now_v7();
        let mut change = self.change(account).await?;
        let taken = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM addressbooks WHERE account_id = $1 AND resource_name = $2",
            account,
            new.resource_name.clone().unwrap_or_else(|| id.to_string()),
        )
        .fetch_optional(change.connection())
        .await?;
        if taken.is_some() {
            return Err(GroupwareError::PreconditionFailed);
        }
        insert(&mut change, id, &new).await?;
        change.commit().await?;
        Ok(id)
    }

    pub async fn update_addressbook(&self, account: Uuid, id: Uuid, update: AddressBookUpdate) -> Result<()> {
        if let Some(name) = &update.name {
            check_name(name)?;
        }
        let mut change = self.change(account).await?;
        let current = sqlx::query!(
            "SELECT is_default FROM addressbooks WHERE id = $1 AND account_id = $2 FOR UPDATE",
            id,
            account
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the address book"))?;
        if update.is_default == Some(false) && current.is_default {
            return Err(GroupwareError::IsDefault);
        }
        let modseq = change.next_modseq().await?;
        if update.is_default == Some(true) && !current.is_default {
            sqlx::query!("UPDATE addressbooks SET is_default = false WHERE account_id = $1 AND is_default", account)
                .execute(change.connection())
                .await?;
        }
        sqlx::query!(
            "UPDATE addressbooks SET
                 name = coalesce($3, name),
                 description = CASE WHEN $4 THEN $5 ELSE description END,
                 sort_order = coalesce($6, sort_order),
                 is_default = coalesce($7, is_default),
                 is_subscribed = coalesce($8, is_subscribed)
             WHERE id = $1 AND account_id = $2",
            id,
            account,
            update.name,
            update.description.is_some(),
            update.description.flatten(),
            update.sort_order,
            update.is_default,
            update.is_subscribed,
        )
        .execute(change.connection())
        .await?;
        let entry = Entry {
            object_type: ObjectType::AddressBook,
            id,
            collection: None,
            resource_name: None,
            change: Change::Updated,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.commit().await?;
        Ok(())
    }

    /// Replaces the properties clients set that kernoid does not know (WebDAV `PROPPATCH`).
    pub async fn set_addressbook_dead_properties(
        &self,
        account: Uuid,
        id: Uuid,
        properties: serde_json::Value,
    ) -> Result<()> {
        let mut change = self.change(account).await?;
        let modseq = change.next_modseq().await?;
        let updated = sqlx::query!(
            "UPDATE addressbooks SET dead_properties = $3 WHERE id = $1 AND account_id = $2",
            id,
            account,
            properties
        )
        .execute(change.connection())
        .await?;
        if updated.rows_affected() == 0 {
            return Err(GroupwareError::NotFound("the address book"));
        }
        let entry = Entry {
            object_type: ObjectType::AddressBook,
            id,
            collection: None,
            resource_name: None,
            change: Change::Updated,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.commit().await?;
        Ok(())
    }

    /// Destroys an address book; with contacts in it only if `remove_contacts` (JMAP `onDestroyRemoveContents`, DAV
    /// `DELETE`). The default address book cannot be destroyed.
    pub async fn destroy_addressbook(&self, account: Uuid, id: Uuid, remove_contacts: bool) -> Result<()> {
        let mut change = self.change(account).await?;
        let current = sqlx::query!(
            "SELECT is_default FROM addressbooks WHERE id = $1 AND account_id = $2 FOR UPDATE",
            id,
            account
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the address book"))?;
        if current.is_default {
            return Err(GroupwareError::IsDefault);
        }
        let contacts = sqlx::query!(
            "SELECT id, resource_name, size FROM contacts WHERE addressbook_id = $1 AND account_id = $2",
            id,
            account
        )
        .fetch_all(change.connection())
        .await?;
        let sealed = crate::sealed::sizes(change.connection(), id).await?;
        if (!contacts.is_empty() || !sealed.is_empty()) && !remove_contacts {
            return Err(GroupwareError::NotEmpty);
        }
        let sealed_freed: i64 = sealed.iter().sum();
        crate::sealed::remove_collection(change.connection(), id).await?;
        let modseq = change.next_modseq().await?;
        let mut freed = sealed_freed;
        for contact in &contacts {
            freed += contact.size;
            let entry = Entry {
                object_type: ObjectType::Contact,
                id: contact.id,
                collection: Some(id),
                resource_name: Some(&contact.resource_name),
                change: Change::Destroyed,
            };
            changes::record(change.connection(), account, modseq, entry).await?;
        }
        sqlx::query!("DELETE FROM contacts WHERE addressbook_id = $1 AND account_id = $2", id, account)
            .execute(change.connection())
            .await?;
        sqlx::query!("DELETE FROM addressbooks WHERE id = $1 AND account_id = $2", id, account)
            .execute(change.connection())
            .await?;
        let entry = Entry {
            object_type: ObjectType::AddressBook,
            id,
            collection: None,
            resource_name: None,
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.charge(-freed).await?;
        change.commit().await?;
        Ok(())
    }
}
