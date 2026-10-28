// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendars and address books administered and shared (RFC 0004, 9), for REST and GraphQL alike: grants are events
//! through `kernoid_identity::collection_access`, which checks its permissions; what is data (listing, import, export)
//! is checked here, once, before `kernoid_groupware` is asked.

use kernoid_groupware::{CollectionType, Groupware, GroupwareError, Imported, Level};
use kernoid_identity::{
    IdentityError,
    collection_access::CollectionGrant,
    role::{Admin, Principal},
};
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum GroupwareAdminError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Groupware(#[from] GroupwareError),
    #[error("this installation does not handle calendars and contacts")]
    NoGroupware,
}

pub(crate) type Result<T> = std::result::Result<T, GroupwareAdminError>;

/// A calendar or address book as listed.
#[derive(Debug, Clone)]
pub(crate) struct CollectionSummary {
    pub owner: Uuid,
    pub owner_name: String,
    pub collection_type: CollectionType,
    pub id: Uuid,
    pub name: String,
    pub color: Option<String>,
    pub is_default: bool,
    /// The caller's level: `admin` on its own.
    pub level: Level,
}

fn groupware(state: &AppState) -> Result<&Groupware> {
    state.dav.as_ref().map(|dav| dav.groupware()).ok_or(GroupwareAdminError::NoGroupware)
}

/// The calendars and address books of one account, as its own.
async fn owned(groupware: &Groupware, account: Uuid, owner_name: &str) -> Result<Vec<CollectionSummary>> {
    let mut list = Vec::new();
    for calendar in groupware.calendars(account).await? {
        list.push(CollectionSummary {
            owner: account,
            owner_name: owner_name.to_owned(),
            collection_type: CollectionType::Calendar,
            id: calendar.id,
            name: calendar.name,
            color: calendar.color,
            is_default: calendar.is_default,
            level: Level::Admin,
        });
    }
    for book in groupware.addressbooks(account).await? {
        list.push(CollectionSummary {
            owner: account,
            owner_name: owner_name.to_owned(),
            collection_type: CollectionType::AddressBook,
            id: book.id,
            name: book.name,
            color: None,
            is_default: book.is_default,
            level: Level::Admin,
        });
    }
    Ok(list)
}

// Administration (needs `accounts.manage`)

pub(crate) async fn collections(state: &AppState, admin: &Admin, account: Uuid) -> Result<Vec<CollectionSummary>> {
    let info = state.identity.managed_account(admin, account).await?;
    owned(groupware(state)?, account, &info.display_name).await
}

pub(crate) async fn access(state: &AppState, admin: &Admin, owner: Uuid) -> Result<Vec<CollectionGrant>> {
    Ok(state.identity.admin_collection_access(admin, owner).await?)
}

pub(crate) async fn set_access(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    collection: Uuid,
    grantee: Principal,
    level: &str,
) -> Result<()> {
    Ok(state.identity.admin_set_collection_access(admin, owner, collection, grantee, level).await?)
}

pub(crate) async fn remove_access(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    collection: Uuid,
    grantee: Principal,
) -> Result<()> {
    Ok(state.identity.admin_remove_collection_access(admin, owner, collection, grantee).await?)
}

/// A calendar as `.ics` or an address book as `.vcf`, with its media type.
pub(crate) async fn export(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    collection: Uuid,
) -> Result<(&'static str, String)> {
    state.identity.managed_account(admin, owner).await?;
    export_collection(groupware(state)?, owner, collection).await
}

pub(crate) async fn import(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    collection: Uuid,
    text: &str,
) -> Result<Imported> {
    state.identity.managed_account(admin, owner).await?;
    import_collection(groupware(state)?, owner, collection, text).await
}

async fn export_collection(groupware: &Groupware, owner: Uuid, collection: Uuid) -> Result<(&'static str, String)> {
    if groupware.calendar(owner, collection).await.is_ok() {
        return Ok(("text/calendar; charset=utf-8", groupware.export_calendar(owner, collection).await?));
    }
    Ok(("text/vcard; charset=utf-8", groupware.export_addressbook(owner, collection).await?))
}

async fn import_collection(groupware: &Groupware, owner: Uuid, collection: Uuid, text: &str) -> Result<Imported> {
    if groupware.calendar(owner, collection).await.is_ok() {
        return Ok(groupware.import_calendar(owner, collection, text).await?);
    }
    Ok(groupware.import_addressbook(owner, collection, text).await?)
}

// One's own: what one has and what is shared with one, and sharing it

pub(crate) async fn own_collections(state: &AppState, account: Uuid) -> Result<Vec<CollectionSummary>> {
    let groupware = groupware(state)?;
    let me = groupware.principal(account).await?;
    let mut list = owned(groupware, account, &me.display_name).await?;
    for shared in groupware.shared_with(account).await? {
        let (name, color, is_default) = match shared.collection_type {
            CollectionType::Calendar => match groupware.calendar(shared.owner, shared.collection).await {
                Ok(calendar) => (calendar.name, calendar.color, false),
                Err(_) => continue,
            },
            CollectionType::AddressBook => match groupware.addressbook(shared.owner, shared.collection).await {
                Ok(book) => (book.name, None, false),
                Err(_) => continue,
            },
        };
        list.push(CollectionSummary {
            owner: shared.owner,
            owner_name: shared.owner_name,
            collection_type: shared.collection_type,
            id: shared.collection,
            name,
            color,
            is_default,
            level: shared.level,
        });
    }
    Ok(list)
}

pub(crate) async fn own_access(
    state: &AppState,
    account: Uuid,
    owner: Uuid,
    collection: Uuid,
) -> Result<Vec<CollectionGrant>> {
    Ok(state.identity.user_collection_access(account, owner, collection).await?)
}

/// Shares a collection one owns or administers with an account (by address) or a group (`$name`) of one's tenant.
pub(crate) async fn share(
    state: &AppState,
    account: Uuid,
    tenant: Uuid,
    owner: Uuid,
    collection: Uuid,
    grantee: &str,
    level: &str,
) -> Result<()> {
    let grantee = state.identity.mail_grantee(tenant, grantee).await?;
    Ok(state.identity.share_collection(account, owner, collection, grantee, level).await?)
}

pub(crate) async fn unshare(
    state: &AppState,
    account: Uuid,
    tenant: Uuid,
    owner: Uuid,
    collection: Uuid,
    grantee: &str,
) -> Result<()> {
    let grantee = state.identity.mail_grantee(tenant, grantee).await?;
    Ok(state.identity.unshare_collection(account, owner, collection, grantee).await?)
}

/// A failure as problem details.
pub(crate) fn problem(error: GroupwareAdminError) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    match error {
        GroupwareAdminError::Identity(error) => crate::sessions::problem(error),
        GroupwareAdminError::NoGroupware => crate::Problem::new(StatusCode::BAD_REQUEST)
            .detail(GroupwareAdminError::NoGroupware.to_string())
            .into_response(),
        GroupwareAdminError::Groupware(error) => {
            let status = match &error {
                GroupwareError::NotFound(_) => StatusCode::NOT_FOUND,
                GroupwareError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                GroupwareError::Invalid(_)
                | GroupwareError::OverQuota
                | GroupwareError::UidConflict(_)
                | GroupwareError::IsDefault
                | GroupwareError::NotEmpty
                | GroupwareError::CannotCalculateChanges => StatusCode::BAD_REQUEST,
                GroupwareError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
                _ => {
                    tracing::error!(%error, "calendars and contacts");
                    return crate::Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
                }
            };
            crate::Problem::new(status).detail(error.to_string()).into_response()
        }
    }
}
