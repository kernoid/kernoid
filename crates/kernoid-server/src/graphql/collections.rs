// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendars and address books in GraphQL (RFC 0004, 9) – the same operations and checks as the REST routes in
//! `crate::admin::collections`, both through `crate::groupware_admin`.

use async_graphql::{Context, ErrorExtensions, Object, SimpleObject};
use kernoid_groupware::GroupwareError;
use kernoid_identity::{Identity, collection_access::CollectionGrant};
use uuid::Uuid;

use super::{
    admin::{admin, principal, uuid},
    error, instance, token,
};
use crate::{
    AppState,
    groupware_admin::{self, CollectionSummary, GroupwareAdminError},
};

fn groupware_error(failure: GroupwareAdminError) -> async_graphql::Error {
    let code = match &failure {
        GroupwareAdminError::Identity(_) => {
            let GroupwareAdminError::Identity(identity) = failure else { unreachable!() };
            return error(identity);
        }
        GroupwareAdminError::NoGroupware => "BAD_REQUEST",
        GroupwareAdminError::Groupware(GroupwareError::NotFound(_)) => "NOT_FOUND",
        GroupwareAdminError::Groupware(GroupwareError::PreconditionFailed) => "CONFLICT",
        GroupwareAdminError::Groupware(
            GroupwareError::Invalid(_)
            | GroupwareError::TooLarge { .. }
            | GroupwareError::OverQuota
            | GroupwareError::UidConflict(_)
            | GroupwareError::IsDefault
            | GroupwareError::NotEmpty
            | GroupwareError::CannotCalculateChanges,
        ) => "BAD_REQUEST",
        GroupwareAdminError::Groupware(store) => {
            tracing::error!(error = %store, "calendars and contacts");
            return async_graphql::Error::new("unavailable").extend_with(|_, e| e.set("code", "UNAVAILABLE"));
        }
    };
    async_graphql::Error::new(failure.to_string()).extend_with(|_, extensions| extensions.set("code", code))
}

fn state<'a>(context: &'a Context<'_>) -> async_graphql::Result<&'a AppState> {
    context.data::<AppState>()
}

/// The account and tenant of the session.
async fn own(context: &Context<'_>) -> async_graphql::Result<(Uuid, Uuid)> {
    let identity = context.data::<Identity>()?;
    let session = identity.data_session(instance(context)?.id, token(context)?).await.map_err(error)?;
    Ok((session.account.id, session.account.tenant))
}

#[derive(Debug, SimpleObject)]
pub struct CollectionObject {
    owner: String,
    owner_name: String,
    /// `calendar` or `addressbook`.
    kind: String,
    id: String,
    name: String,
    color: Option<String>,
    is_default: bool,
    /// The caller's level: `freebusy`, `read`, `rsvp`, `write` or `admin` (an owner's).
    level: String,
}

impl From<CollectionSummary> for CollectionObject {
    fn from(summary: CollectionSummary) -> Self {
        Self {
            owner: summary.owner.to_string(),
            owner_name: summary.owner_name,
            kind: summary.collection_type.as_str().into(),
            id: summary.id.to_string(),
            name: summary.name,
            color: summary.color,
            is_default: summary.is_default,
            level: summary.level.as_str().into(),
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct CollectionGrantObject {
    kind: String,
    collection: String,
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    grantee_name: String,
    level: String,
}

impl From<CollectionGrant> for CollectionGrantObject {
    fn from(grant: CollectionGrant) -> Self {
        Self {
            kind: grant.collection_type,
            collection: grant.collection.to_string(),
            grantee_kind: grant.grantee.kind().into(),
            grantee_id: grant.grantee.id().to_string(),
            grantee_name: grant.grantee_name,
            level: grant.level,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct CollectionImportResult {
    stored: u64,
    /// UIDs of the objects not stored.
    refused: Vec<String>,
}

#[derive(Debug, Default)]
pub struct CollectionsQuery;

#[Object]
impl CollectionsQuery {
    /// An account's calendars and address books (needs `accounts.manage`).
    async fn collections(
        &self,
        context: &Context<'_>,
        account: String,
    ) -> async_graphql::Result<Vec<CollectionObject>> {
        let (_, admin) = admin(context).await?;
        let list = groupware_admin::collections(state(context)?, &admin, uuid(&account, "the account")?)
            .await
            .map_err(groupware_error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// Who may use an account's calendars and address books (needs `accounts.manage`).
    async fn collection_access(
        &self,
        context: &Context<'_>,
        account: String,
    ) -> async_graphql::Result<Vec<CollectionGrantObject>> {
        let (_, admin) = admin(context).await?;
        let grants = groupware_admin::access(state(context)?, &admin, uuid(&account, "the account")?)
            .await
            .map_err(groupware_error)?;
        Ok(grants.into_iter().map(Into::into).collect())
    }

    /// A calendar as iCalendar or an address book as vCard (needs `accounts.manage`).
    async fn export_collection(
        &self,
        context: &Context<'_>,
        account: String,
        collection: String,
    ) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        let (_, text) =
            groupware_admin::export(state(context)?, &admin, owner, collection).await.map_err(groupware_error)?;
        Ok(text)
    }

    /// The session's calendars and address books, and those shared with it.
    async fn my_collections(&self, context: &Context<'_>) -> async_graphql::Result<Vec<CollectionObject>> {
        let (account, _) = own(context).await?;
        let list = groupware_admin::own_collections(state(context)?, account).await.map_err(groupware_error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// Who may use a calendar or address book the session owns or administers.
    async fn my_collection_access(
        &self,
        context: &Context<'_>,
        owner: String,
        collection: String,
    ) -> async_graphql::Result<Vec<CollectionGrantObject>> {
        let (account, _) = own(context).await?;
        let owner = uuid(&owner, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        let grants =
            groupware_admin::own_access(state(context)?, account, owner, collection).await.map_err(groupware_error)?;
        Ok(grants.into_iter().map(Into::into).collect())
    }
}

#[derive(Debug, Default)]
pub struct CollectionsMutation;

#[Object]
impl CollectionsMutation {
    /// Grants an account or a group a level on a calendar or address book (needs `accounts.manage`).
    async fn set_collection_access(
        &self,
        context: &Context<'_>,
        account: String,
        collection: String,
        grantee_kind: String,
        grantee_id: String,
        level: String,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        let grantee = principal(&grantee_kind, &grantee_id)?;
        groupware_admin::set_access(state(context)?, &admin, owner, collection, grantee, &level)
            .await
            .map_err(groupware_error)?;
        Ok(true)
    }

    /// Removes a grant on a calendar or address book (needs `accounts.manage`).
    async fn remove_collection_access(
        &self,
        context: &Context<'_>,
        account: String,
        collection: String,
        grantee_kind: String,
        grantee_id: String,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        let grantee = principal(&grantee_kind, &grantee_id)?;
        groupware_admin::remove_access(state(context)?, &admin, owner, collection, grantee)
            .await
            .map_err(groupware_error)?;
        Ok(true)
    }

    /// Stores the events of an iCalendar file or the contacts of a vCard file (needs `accounts.manage`).
    async fn import_collection(
        &self,
        context: &Context<'_>,
        account: String,
        collection: String,
        content: String,
    ) -> async_graphql::Result<CollectionImportResult> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        let imported = groupware_admin::import(state(context)?, &admin, owner, collection, &content)
            .await
            .map_err(groupware_error)?;
        Ok(CollectionImportResult {
            stored: imported.stored as u64,
            refused: imported.refused.into_iter().map(|(uid, _)| uid).collect(),
        })
    }

    /// Shares a calendar or address book the session owns or administers with an address or `$group`.
    async fn share_collection(
        &self,
        context: &Context<'_>,
        owner: String,
        collection: String,
        grantee: String,
        level: String,
    ) -> async_graphql::Result<bool> {
        let (account, tenant) = own(context).await?;
        let owner = uuid(&owner, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        groupware_admin::share(state(context)?, account, tenant, owner, collection, &grantee, &level)
            .await
            .map_err(groupware_error)?;
        Ok(true)
    }

    /// Stops sharing a calendar or address book with someone.
    async fn unshare_collection(
        &self,
        context: &Context<'_>,
        owner: String,
        collection: String,
        grantee: String,
    ) -> async_graphql::Result<bool> {
        let (account, tenant) = own(context).await?;
        let owner = uuid(&owner, "the account")?;
        let collection = uuid(&collection, "the calendar or address book")?;
        groupware_admin::unshare(state(context)?, account, tenant, owner, collection, &grantee)
            .await
            .map_err(groupware_error)?;
        Ok(true)
    }
}
