// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who may use whose calendars and address books (RFC 0004, 9). The calendars and contacts themselves are data in
//! `kernoid-groupware`; grants on them are events here.

use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::AccountEvent,
    role::{Admin, Principal},
};

/// The levels of RFC 0004, 9, lowest first; each includes the ones before.
pub const LEVELS: [&str; 5] = ["freebusy", "read", "rsvp", "write", "admin"];

/// A grant on a calendar or address book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionGrant {
    pub owner: Uuid,
    /// `calendar` or `addressbook`.
    pub collection_type: String,
    pub collection: Uuid,
    pub grantee: Principal,
    /// The grantee's primary address, or `$` and a group's name.
    pub grantee_name: String,
    pub level: String,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn rank(level: &str) -> Option<usize> {
    LEVELS.iter().position(|known| *known == level)
}

impl Identity {
    /// The kind of `owner`'s collection – `calendar` or `addressbook` – if it exists.
    async fn collection_type(&self, owner: Uuid, collection: Uuid) -> Result<&'static str> {
        let row = sqlx::query!(
            r#"SELECT EXISTS (SELECT 1 FROM calendars WHERE id = $1 AND account_id = $2) AS "calendar!",
                      EXISTS (SELECT 1 FROM addressbooks WHERE id = $1 AND account_id = $2) AS "addressbook!""#,
            collection,
            owner,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        match (row.calendar, row.addressbook) {
            (true, _) => Ok("calendar"),
            (_, true) => Ok("addressbook"),
            _ => Err(IdentityError::NotFound("the calendar or address book")),
        }
    }

    /// Grants `grantee` `level` on one of `owner`'s calendars or address books, replacing an earlier grant there.
    /// Unchecked: the callers decide who may.
    pub async fn set_collection_access(
        &self,
        owner: Uuid,
        collection: Uuid,
        grantee: Principal,
        level: &str,
        creator: &str,
    ) -> Result<()> {
        if rank(level).is_none() {
            return Err(IdentityError::Refused(format!("{level:?} is not a level; levels are {}", LEVELS.join(", "))));
        }
        if grantee == Principal::Account(owner) {
            return Err(IdentityError::Refused("an owner has every right on its own collections".into()));
        }
        let collection_type = self.collection_type(owner, collection).await?;
        if collection_type == "addressbook" && !matches!(level, "read" | "write" | "admin") {
            return Err(IdentityError::Refused("address books are shared at read, write or admin".into()));
        }
        let (instance, tenant) = self.account_owner(owner).await?;
        self.check_grantee(tenant, grantee).await?;
        let level = level.to_owned();
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            Ok(vec![AccountEvent::CollectionAccessSet {
                grantee,
                collection_type: collection_type.into(),
                collection,
                level: level.clone(),
            }])
        })
        .await
    }

    pub async fn remove_collection_access(
        &self,
        owner: Uuid,
        collection: Uuid,
        grantee: Principal,
        creator: &str,
    ) -> Result<()> {
        let (instance, tenant) = self.account_owner(owner).await?;
        self.account_command(instance, tenant, owner, creator, None, |state| {
            if !state.collection_access.contains_key(&(grantee, collection)) {
                return Err(IdentityError::NotFound("the grant"));
            }
            Ok(vec![AccountEvent::CollectionAccessRemoved { grantee, collection }])
        })
        .await
    }

    /// The grants on an account's calendars and address books, or on one of them.
    pub async fn collection_access(&self, owner: Uuid, collection: Option<Uuid>) -> Result<Vec<CollectionGrant>> {
        let rows = sqlx::query!(
            r#"SELECT c.collection_type, c.collection_id, c.grantee_account, c.grantee_group, c.level,
                      coalesce(a.primary_address, a.display_name, '$' || g.name) AS "name!"
               FROM collection_access c
               LEFT JOIN accounts a ON a.id = c.grantee_account
               LEFT JOIN groups g ON g.id = c.grantee_group
               WHERE c.owner_id = $1 AND ($2::uuid IS NULL OR c.collection_id = $2)
               ORDER BY c.collection_id, 6"#,
            owner,
            collection,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let grantee = match (row.grantee_account, row.grantee_group) {
                    (Some(account), _) => Principal::Account(account),
                    (_, Some(group)) => Principal::Group(group),
                    _ => return None,
                };
                Some(CollectionGrant {
                    owner,
                    collection_type: row.collection_type,
                    collection: row.collection_id,
                    grantee,
                    grantee_name: row.name,
                    level: row.level,
                })
            })
            .collect())
    }

    /// Whether `user` may share `owner`'s collection: the owner, or a grantee with `admin` on it (directly or through
    /// a group).
    async fn may_share(&self, user: Uuid, owner: Uuid, collection: Uuid) -> Result<bool> {
        if user == owner {
            return Ok(true);
        }
        sqlx::query_scalar!(
            r#"SELECT EXISTS (
                   SELECT 1 FROM collection_access
                   WHERE owner_id = $2 AND collection_id = $3 AND level = 'admin'
                     AND (grantee_account = $1
                          OR grantee_group IN (SELECT group_id FROM group_members WHERE account_id = $1))) AS "may!""#,
            user,
            owner,
            collection,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)
    }

    // Administration (RFC 0004, 9)

    pub async fn admin_collection_access(&self, admin: &Admin, owner: Uuid) -> Result<Vec<CollectionGrant>> {
        self.managed_account(admin, owner).await?;
        self.collection_access(owner, None).await
    }

    pub async fn admin_set_collection_access(
        &self,
        admin: &Admin,
        owner: Uuid,
        collection: Uuid,
        grantee: Principal,
        level: &str,
    ) -> Result<()> {
        self.managed_account(admin, owner).await?;
        self.set_collection_access(owner, collection, grantee, level, &admin.creator()).await
    }

    pub async fn admin_remove_collection_access(
        &self,
        admin: &Admin,
        owner: Uuid,
        collection: Uuid,
        grantee: Principal,
    ) -> Result<()> {
        self.managed_account(admin, owner).await?;
        self.remove_collection_access(owner, collection, grantee, &admin.creator()).await
    }

    // Users sharing what is theirs, or what they administer

    /// The grants on a collection, for its owner or a grantee with `admin` on it.
    pub async fn user_collection_access(
        &self,
        user: Uuid,
        owner: Uuid,
        collection: Uuid,
    ) -> Result<Vec<CollectionGrant>> {
        if !self.may_share(user, owner, collection).await? {
            return Err(IdentityError::NotFound("the calendar or address book"));
        }
        self.collection_access(owner, Some(collection)).await
    }

    pub async fn share_collection(
        &self,
        user: Uuid,
        owner: Uuid,
        collection: Uuid,
        grantee: Principal,
        level: &str,
    ) -> Result<()> {
        if !self.may_share(user, owner, collection).await? {
            return Err(IdentityError::NotFound("the calendar or address book"));
        }
        self.set_collection_access(owner, collection, grantee, level, &format!("account:{user}")).await
    }

    pub async fn unshare_collection(
        &self,
        user: Uuid,
        owner: Uuid,
        collection: Uuid,
        grantee: Principal,
    ) -> Result<()> {
        if !self.may_share(user, owner, collection).await? {
            return Err(IdentityError::NotFound("the calendar or address book"));
        }
        self.remove_collection_access(owner, collection, grantee, &format!("account:{user}")).await
    }
}
