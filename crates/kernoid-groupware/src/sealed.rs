// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encrypted calendars and address books (RFC 0006, 7): a collection made with a key of its own. Its entries are
//! OpenPGP messages the members' apps write – an event or a contact as the apps describe it –, which kernoid keeps,
//! counts against the quota and tells of (the store's modseq moves), but cannot read: no CalDAV or CardDAV, no
//! free/busy, no invitations by the server. The collection's secret key is wrapped for each member, as a vault's is.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Groupware, GroupwareError, Result};

/// The largest entry taken (the table's limit).
const MAX_ITEM: usize = 1_048_576;
/// The largest public or wrapped key taken.
const MAX_KEY: usize = 65_536;

/// One entry of an encrypted collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedItem {
    pub id: Uuid,
    pub data: Vec<u8>,
    pub updated: DateTime<Utc>,
}

/// Whether a collection of the account is encrypted, and whether it is one at all.
async fn sealed_collection(connection: &mut PgConnection, account: Uuid, collection: Uuid) -> Result<bool> {
    let row = sqlx::query_scalar!(
        r#"SELECT collection_key IS NOT NULL AS "sealed!" FROM calendars WHERE id = $1 AND account_id = $2
           UNION ALL
           SELECT collection_key IS NOT NULL AS "sealed!" FROM addressbooks WHERE id = $1 AND account_id = $2"#,
        collection,
        account,
    )
    .fetch_optional(connection)
    .await?;
    row.ok_or(GroupwareError::NotFound("the collection"))
}

/// Plain iCalendar or vCard never goes into an encrypted collection – CalDAV, CardDAV, JMAP, invitations, imports.
pub(crate) async fn refuse_plain(connection: &mut PgConnection, collection: Uuid) -> Result<()> {
    let sealed = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM calendars WHERE id = $1 AND collection_key IS NOT NULL)
               OR EXISTS (SELECT 1 FROM addressbooks WHERE id = $1 AND collection_key IS NOT NULL) AS "sealed!""#,
        collection,
    )
    .fetch_one(connection)
    .await?;
    if sealed { Err(GroupwareError::Invalid("the collection is end-to-end encrypted".into())) } else { Ok(()) }
}

/// The sizes of a collection's encrypted entries – what destroying it frees.
pub(crate) async fn sizes(connection: &mut PgConnection, collection: Uuid) -> Result<Vec<i64>> {
    Ok(sqlx::query_scalar!(
        r#"SELECT length(data)::bigint AS "size!" FROM sealed_items WHERE collection_id = $1"#,
        collection
    )
    .fetch_all(connection)
    .await?)
}

/// Removes a collection's encrypted entries and wrapped keys, as the collection goes.
pub(crate) async fn remove_collection(connection: &mut PgConnection, collection: Uuid) -> Result<()> {
    sqlx::query!("DELETE FROM sealed_items WHERE collection_id = $1", collection).execute(&mut *connection).await?;
    sqlx::query!("DELETE FROM collection_keys WHERE collection_id = $1", collection).execute(&mut *connection).await?;
    Ok(())
}

impl Groupware {
    /// Makes a new, empty calendar or address book encrypted: its public key, and its secret key wrapped for `member`
    /// (the creator). A collection with entries, or the default one, stays as it is.
    pub async fn seal_collection(
        &self,
        account: Uuid,
        collection: Uuid,
        public_key: &[u8],
        member: Uuid,
        sealed: &[u8],
    ) -> Result<()> {
        if public_key.is_empty() || public_key.len() > MAX_KEY || sealed.is_empty() || sealed.len() > MAX_KEY {
            return Err(GroupwareError::Invalid("a key has 1 to 65536 bytes".into()));
        }
        let mut change = self.change(account).await?;
        let calendar = sqlx::query!(
            r#"UPDATE calendars c SET collection_key = $3 WHERE c.id = $1 AND c.account_id = $2 AND NOT c.is_default
                 AND c.collection_key IS NULL AND NOT EXISTS (SELECT 1 FROM calendar_events e WHERE e.calendar_id = c.id)"#,
            collection,
            account,
            public_key,
        )
        .execute(change.connection())
        .await?
        .rows_affected();
        let addressbook = sqlx::query!(
            r#"UPDATE addressbooks b SET collection_key = $3 WHERE b.id = $1 AND b.account_id = $2 AND NOT b.is_default
                 AND b.collection_key IS NULL AND NOT EXISTS (SELECT 1 FROM contacts c WHERE c.addressbook_id = b.id)"#,
            collection,
            account,
            public_key,
        )
        .execute(change.connection())
        .await?
        .rows_affected();
        if calendar + addressbook == 0 {
            return Err(GroupwareError::Invalid(
                "only a new, empty collection that is not the default is encrypted".into(),
            ));
        }
        sqlx::query!(
            "INSERT INTO collection_keys (collection_id, account_id, sealed) VALUES ($1, $2, $3)",
            collection,
            member,
            sealed,
        )
        .execute(change.connection())
        .await?;
        change.next_modseq().await?;
        change.commit().await?;
        Ok(())
    }

    /// The entries of an encrypted collection of `account`, oldest first.
    pub async fn sealed_items(&self, account: Uuid, collection: Uuid) -> Result<Vec<SealedItem>> {
        let mut read = self.read(account).await?;
        if !sealed_collection(read.connection(), account, collection).await? {
            return Err(GroupwareError::Invalid("the collection is not encrypted".into()));
        }
        let rows = sqlx::query!(
            "SELECT id, data, updated_at FROM sealed_items WHERE account_id = $1 AND collection_id = $2 ORDER BY id",
            account,
            collection,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows.into_iter().map(|row| SealedItem { id: row.id, data: row.data, updated: row.updated_at }).collect())
    }

    /// Stores an entry – new, or replacing `id` – and counts it against the quota; returns its id.
    pub async fn put_sealed_item(
        &self,
        account: Uuid,
        collection: Uuid,
        id: Option<Uuid>,
        data: &[u8],
    ) -> Result<Uuid> {
        if data.is_empty() || data.len() > MAX_ITEM {
            return Err(GroupwareError::TooLarge { limit: MAX_ITEM as u64 });
        }
        let mut change = self.change(account).await?;
        if !sealed_collection(change.connection(), account, collection).await? {
            return Err(GroupwareError::Invalid("the collection is not encrypted".into()));
        }
        let old = match id {
            Some(id) => Some(
                sqlx::query_scalar!(
                    r#"SELECT length(data)::bigint AS "size!" FROM sealed_items
                       WHERE id = $1 AND account_id = $2 AND collection_id = $3 FOR UPDATE"#,
                    id,
                    account,
                    collection,
                )
                .fetch_optional(change.connection())
                .await?
                .ok_or(GroupwareError::NotFound("the entry"))?,
            ),
            None => None,
        };
        change.charge(data.len() as i64 - old.unwrap_or(0)).await?;
        let id = id.unwrap_or_else(Uuid::now_v7);
        sqlx::query!(
            "INSERT INTO sealed_items (id, account_id, collection_id, data) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET data = $4, updated_at = now()",
            id,
            account,
            collection,
            data,
        )
        .execute(change.connection())
        .await?;
        change.next_modseq().await?;
        change.commit().await?;
        Ok(id)
    }

    pub async fn destroy_sealed_item(&self, account: Uuid, collection: Uuid, id: Uuid) -> Result<()> {
        let mut change = self.change(account).await?;
        let size = sqlx::query_scalar!(
            r#"DELETE FROM sealed_items WHERE id = $1 AND account_id = $2 AND collection_id = $3
               RETURNING length(data)::bigint AS "size!""#,
            id,
            account,
            collection,
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the entry"))?;
        change.charge(-size).await?;
        change.next_modseq().await?;
        change.commit().await?;
        Ok(())
    }

    /// The collection's secret key wrapped for `member`, if a member gave it to them.
    pub async fn collection_key(&self, collection: Uuid, member: Uuid) -> Result<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar!(
            "SELECT sealed FROM collection_keys WHERE collection_id = $1 AND account_id = $2",
            collection,
            member,
        )
        .fetch_optional(self.pool())
        .await?)
    }

    /// The accounts that have the collection's key.
    pub async fn collection_members(&self, collection: Uuid) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar!(
            "SELECT account_id FROM collection_keys WHERE collection_id = $1 ORDER BY account_id",
            collection,
        )
        .fetch_all(self.pool())
        .await?)
    }

    /// Gives a member the collection's key (or replaces it); `None` takes it away. Who may do it is checked by the
    /// caller (the collection's owner or who shares it).
    pub async fn set_collection_key(&self, collection: Uuid, member: Uuid, sealed: Option<&[u8]>) -> Result<()> {
        match sealed {
            Some(sealed) if sealed.is_empty() || sealed.len() > MAX_KEY => {
                Err(GroupwareError::Invalid("a wrapped key has 1 to 65536 bytes".into()))
            }
            Some(sealed) => {
                sqlx::query!(
                    "INSERT INTO collection_keys (collection_id, account_id, sealed) VALUES ($1, $2, $3)
                     ON CONFLICT (collection_id, account_id) DO UPDATE SET sealed = $3, created_at = now()",
                    collection,
                    member,
                    sealed,
                )
                .execute(self.pool())
                .await?;
                Ok(())
            }
            None => {
                sqlx::query!(
                    "DELETE FROM collection_keys WHERE collection_id = $1 AND account_id = $2",
                    collection,
                    member
                )
                .execute(self.pool())
                .await?;
                Ok(())
            }
        }
    }
}
