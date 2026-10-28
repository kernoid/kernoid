// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendars and address books administered (RFC 0004, 9): an account's collections, who may use them, and import
//! and export – and one's own: what one has and what is shared with one, and sharing it.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
};
use kernoid_identity::collection_access::CollectionGrant;
use serde::{Deserialize, Serialize};

use super::{AdminSession, id, no_content, principal, tenant::TenantHeader};
use crate::{
    AppState, CurrentInstance, Problem,
    groupware_admin::{self, CollectionSummary, GroupwareAdminError, problem},
    sessions,
};

fn respond<T>(result: Result<T, GroupwareAdminError>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct CollectionView {
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

impl From<CollectionSummary> for CollectionView {
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

fn collections(list: Vec<CollectionSummary>) -> Response {
    Json(list.into_iter().map(CollectionView::from).collect::<Vec<_>>()).into_response()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct CollectionGrantView {
    /// `calendar` or `addressbook`.
    kind: String,
    collection: String,
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// The account's address, or `$` and the group's name.
    grantee_name: String,
    level: String,
}

impl From<CollectionGrant> for CollectionGrantView {
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

fn grants(list: Vec<CollectionGrant>) -> Response {
    Json(list.into_iter().map(CollectionGrantView::from).collect::<Vec<_>>()).into_response()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct CollectionGrantChange {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// `freebusy`, `read`, `rsvp`, `write` or `admin`; address books: `read`, `write` or `admin`.
    level: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct CollectionGrantQuery {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ImportedView {
    stored: usize,
    /// Objects not stored: their UID and why.
    refused: Vec<(String, String)>,
}

/// An account's calendars and address books (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/collections", tag = "calendars", params(TenantHeader),
    responses((status = 200, body = [CollectionView]), (status = 404, body = Problem)))]
pub(crate) async fn list(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { groupware_admin::collections(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, collections)
}

/// Who may use an account's calendars and address books (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/collections/access", tag = "calendars", params(TenantHeader),
    responses((status = 200, body = [CollectionGrantView]), (status = 404, body = Problem)))]
pub(crate) async fn access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { groupware_admin::access(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, grants)
}

/// Grants an account or a group of the tenant a level on a calendar or address book of an account, replacing an
/// earlier grant (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/collections/{collection}/access", tag = "calendars",
    params(TenantHeader), request_body = CollectionGrantChange,
    responses((status = 204), (status = 400, body = Problem), (status = 404, body = Problem)))]
pub(crate) async fn set_access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, collection)): Path<(String, String)>,
    Json(body): Json<CollectionGrantChange>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        let grantee = principal(&body.grantee_kind, &body.grantee_id)?;
        groupware_admin::set_access(&state, &admin, owner, collection, grantee, &body.level).await
    }
    .await;
    respond(result, no_content)
}

/// Removes a grant on a calendar or address book (needs `accounts.manage`).
#[utoipa::path(delete, path = "/v1/accounts/{id}/collections/{collection}/access", tag = "calendars",
    params(TenantHeader, CollectionGrantQuery), responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn remove_access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, collection)): Path<(String, String)>,
    Query(query): Query<CollectionGrantQuery>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        let grantee = principal(&query.grantee_kind, &query.grantee_id)?;
        groupware_admin::remove_access(&state, &admin, owner, collection, grantee).await
    }
    .await;
    respond(result, no_content)
}

/// A calendar as iCalendar or an address book as vCard, everything in one file (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/collections/{collection}/export", tag = "calendars",
    params(TenantHeader), responses(
        (status = 200, content_type = "text/calendar", body = String),
        (status = 404, body = Problem),
    ))]
pub(crate) async fn export(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, collection)): Path<(String, String)>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        groupware_admin::export(&state, &admin, owner, collection).await
    }
    .await;
    respond(result, |(content_type, text)| ([(header::CONTENT_TYPE, content_type)], text).into_response())
}

/// Stores the events of an iCalendar file in a calendar, or the contacts of a vCard file in an address book (the
/// request body, up to 2 MiB); one with a UID that is there already is replaced (needs `accounts.manage`).
#[utoipa::path(post, path = "/v1/accounts/{id}/collections/{collection}/import", tag = "calendars",
    params(TenantHeader), request_body(content = String, content_type = "text/calendar"),
    responses((status = 200, body = ImportedView), (status = 400, body = Problem), (status = 404, body = Problem)))]
pub(crate) async fn import(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, collection)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        let text = std::str::from_utf8(&body)
            .map_err(|_| kernoid_groupware::GroupwareError::Invalid("the file is not UTF-8".into()))?;
        groupware_admin::import(&state, &admin, owner, collection, text).await
    }
    .await;
    respond(result, |imported| {
        Json(ImportedView { stored: imported.stored, refused: imported.refused }).into_response()
    })
}

async fn own(
    state: &AppState,
    instance: uuid::Uuid,
    token: &str,
) -> Result<(uuid::Uuid, uuid::Uuid), GroupwareAdminError> {
    let session = state.identity.session(instance, token).await?;
    Ok((session.account.id, session.account.tenant))
}

/// One's own calendars and address books, and those shared with one, with one's level on each.
#[utoipa::path(get, path = "/v1/account/collections", tag = "account", responses(
    (status = 200, body = [CollectionView]),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn own_list(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
) -> Response {
    let result = async {
        let (account, _) = own(&state, instance.id, &token).await?;
        groupware_admin::own_collections(&state, account).await
    }
    .await;
    respond(result, collections)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct OwnCollectionGrantChange {
    /// An address of an account of the tenant, or `$` and a group's name.
    grantee: String,
    /// `freebusy`, `read`, `rsvp`, `write` or `admin`; address books: `read`, `write` or `admin`.
    level: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct OwnCollectionGrantQuery {
    /// An address of an account of the tenant, or `$` and a group's name.
    grantee: String,
}

/// Who may use a calendar or address book one owns or administers (`admin`).
#[utoipa::path(get, path = "/v1/account/collections/{owner}/{collection}/access", tag = "account", responses(
    (status = 200, body = [CollectionGrantView]),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, body = Problem),
))]
pub(crate) async fn own_access(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Path((owner, collection)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (account, _) = own(&state, instance.id, &token).await?;
        let owner = id(&owner, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        groupware_admin::own_access(&state, account, owner, collection).await
    }
    .await;
    respond(result, grants)
}

/// Shares a calendar or address book one owns or administers with an account or a group of one's tenant.
#[utoipa::path(put, path = "/v1/account/collections/{owner}/{collection}/access", tag = "account",
    request_body = OwnCollectionGrantChange, responses(
        (status = 204),
        (status = 400, body = Problem),
        (status = 401, description = "no valid session", body = Problem),
        (status = 404, body = Problem),
    ))]
pub(crate) async fn share(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Path((owner, collection)): Path<(String, String)>,
    Json(body): Json<OwnCollectionGrantChange>,
) -> Response {
    let result = async {
        let (account, tenant) = own(&state, instance.id, &token).await?;
        let owner = id(&owner, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        groupware_admin::share(&state, account, tenant, owner, collection, &body.grantee, &body.level).await
    }
    .await;
    respond(result, no_content)
}

/// Stops sharing a calendar or address book with someone.
#[utoipa::path(delete, path = "/v1/account/collections/{owner}/{collection}/access", tag = "account",
    params(OwnCollectionGrantQuery), responses(
        (status = 204),
        (status = 401, description = "no valid session", body = Problem),
        (status = 404, body = Problem),
    ))]
pub(crate) async fn unshare(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Path((owner, collection)): Path<(String, String)>,
    Query(query): Query<OwnCollectionGrantQuery>,
) -> Response {
    let result = async {
        let (account, tenant) = own(&state, instance.id, &token).await?;
        let owner = id(&owner, "the account")?;
        let collection = id(&collection, "the calendar or address book")?;
        groupware_admin::unshare(&state, account, tenant, owner, collection, &query.grantee).await
    }
    .await;
    respond(result, no_content)
}
