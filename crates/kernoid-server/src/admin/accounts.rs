// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts of the tenant administered: create, change, aliases, passwords, second factors, sessions. Setting a
//! password, resetting second factors, deactivating and ending sessions need every permission the account holds.

use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_identity::{Address, IdentityError, account::AccountInfo, session::SessionSummary};
use serde::{Deserialize, Serialize};

use super::{AdminSession, created, id, no_content, respond, tenant::TenantHeader};
use crate::{AppState, Problem};

pub(crate) fn address(value: &str) -> Result<Address, IdentityError> {
    Address::parse(value).map_err(|error| IdentityError::Refused(error.to_string()))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AccountDetails {
    id: String,
    tenant: String,
    /// The login name: the primary address, else the username, else the contact address.
    address: String,
    display_name: String,
    active: bool,
    /// A shared mailbox (RFC 0002, 12.1): nobody logs in as it.
    shared: bool,
    /// Has an address of the tenant (RFC 0003, 1); only such an account can have mail.
    native: bool,
    /// A drive (RFC 0005, 12): a file store of the tenant; nobody logs in as it.
    drive: bool,
}

impl From<AccountInfo> for AccountDetails {
    fn from(account: AccountInfo) -> Self {
        Self {
            id: account.id.to_string(),
            tenant: account.tenant.to_string(),
            address: account.address,
            display_name: account.display_name,
            active: account.active,
            shared: account.shared,
            drive: account.drive,
            native: account.native,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewAccount {
    /// The login name; on a verified domain of the tenant.
    address: String,
    display_name: String,
    /// An initial password; without one, the account cannot log in with a password yet.
    password: Option<String>,
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct AccountChange {
    display_name: Option<String>,
    /// An alias of the account that becomes its login name; the former one stays as an alias.
    primary_address: Option<String>,
    /// `false` deactivates the account and ends its sessions.
    active: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewPassword {
    password: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SessionSummaryView {
    id: String,
    checks: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    client_address: Option<String>,
    user_agent: Option<String>,
}

impl From<SessionSummary> for SessionSummaryView {
    fn from(session: SessionSummary) -> Self {
        Self {
            id: session.id.to_string(),
            checks: session.checks,
            created_at: session.created_at,
            expires_at: session.expires_at,
            client_address: session.client_address,
            user_agent: session.user_agent,
        }
    }
}

/// The tenant's accounts (needs `directory.read`).
#[utoipa::path(get, path = "/v1/accounts", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = [AccountDetails])))]
pub(crate) async fn list(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(state.identity.admin_accounts(&admin).await, |list| {
        Json(list.into_iter().map(AccountDetails::from).collect::<Vec<_>>()).into_response()
    })
}

/// Creates an account (needs `accounts.manage`).
#[utoipa::path(post, path = "/v1/accounts", tag = "accounts", params(TenantHeader), request_body = NewAccount,
    responses((status = 201, body = super::Created), (status = 409, description = "the address is taken", body = Problem)))]
pub(crate) async fn add(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewAccount>,
) -> Response {
    let result = async {
        let account = state.identity.admin_add_account(&admin, &address(&body.address)?, &body.display_name).await?;
        if let Some(password) = &body.password {
            state.identity.admin_set_password(&admin, account, password).await?;
        }
        Ok(account)
    }
    .await;
    respond(result, created)
}

/// One account (needs `directory.read`).
#[utoipa::path(get, path = "/v1/accounts/{id}", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = AccountDetails), (status = 404, body = Problem)))]
pub(crate) async fn get(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.identity.admin_account(&admin, id(&account, "the account")?).await }.await;
    respond(result, |account| Json(AccountDetails::from(account)).into_response())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AddressView {
    address: String,
    /// The primary address – the login name; the others are aliases.
    primary: bool,
}

/// An account's addresses: the primary one first, then its aliases (needs `directory.read`).
#[utoipa::path(get, path = "/v1/accounts/{id}/addresses", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = [AddressView]), (status = 404, body = Problem)))]
pub(crate) async fn addresses(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.identity.admin_account_addresses(&admin, id(&account, "the account")?).await }.await;
    respond(result, |list| {
        Json(list.into_iter().map(|(address, primary)| AddressView { address, primary }).collect::<Vec<_>>())
            .into_response()
    })
}

/// Changes an account's display name, login name or active state (needs `accounts.manage`).
#[utoipa::path(patch, path = "/v1/accounts/{id}", tag = "accounts", params(TenantHeader), request_body = AccountChange,
    responses((status = 204), (status = 403, body = Problem)))]
pub(crate) async fn change(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<AccountChange>,
) -> Response {
    let result = async {
        let account = id(&account, "the account")?;
        if let Some(name) = &body.display_name {
            state.identity.admin_rename_account(&admin, account, name).await?;
        }
        if let Some(primary) = &body.primary_address {
            state.identity.admin_set_primary_address(&admin, account, &address(primary)?).await?;
        }
        if let Some(active) = body.active {
            state.identity.admin_set_account_active(&admin, account, active).await?;
        }
        Ok(())
    }
    .await;
    respond(result, no_content)
}

/// Adds an alias on a verified domain of the tenant (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/aliases/{address}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 409, description = "the address is taken", body = Problem)))]
pub(crate) async fn add_alias(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, alias)): Path<(String, String)>,
) -> Response {
    let result =
        async { state.identity.admin_add_alias(&admin, id(&account, "the account")?, &address(&alias)?).await }.await;
    respond(result, no_content)
}

/// Removes an alias; the login name cannot be removed (needs `accounts.manage`).
#[utoipa::path(delete, path = "/v1/accounts/{id}/aliases/{address}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn remove_alias(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, alias)): Path<(String, String)>,
) -> Response {
    let result =
        async { state.identity.admin_remove_alias(&admin, id(&account, "the account")?, &address(&alias)?).await }
            .await;
    respond(result, no_content)
}

/// Sets an account's password and ends its sessions (needs `accounts.manage` and every permission the account
/// holds).
#[utoipa::path(put, path = "/v1/accounts/{id}/password", tag = "accounts", params(TenantHeader),
    request_body = NewPassword, responses((status = 204), (status = 403, body = Problem)))]
pub(crate) async fn set_password(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<NewPassword>,
) -> Response {
    let result =
        async { state.identity.admin_set_password(&admin, id(&account, "the account")?, &body.password).await }.await;
    respond(result, no_content)
}

/// Removes all TOTP, passkeys and recovery codes of an account (needs `accounts.manage` and every permission the
/// account holds).
#[utoipa::path(delete, path = "/v1/accounts/{id}/second-factors", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 403, body = Problem)))]
pub(crate) async fn reset_second_factors(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.identity.admin_reset_second_factors(&admin, id(&account, "the account")?).await }.await;
    respond(result, no_content)
}

/// The account's valid sessions (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/sessions", tag = "accounts", params(TenantHeader),
    responses((status = 200, body = [SessionSummaryView])))]
pub(crate) async fn sessions(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { state.identity.admin_account_sessions(&admin, id(&account, "the account")?).await }.await;
    respond(result, |list| Json(list.into_iter().map(SessionSummaryView::from).collect::<Vec<_>>()).into_response())
}

/// Ends one session of the account (needs `accounts.manage` and every permission the account holds).
#[utoipa::path(delete, path = "/v1/accounts/{id}/sessions/{session}", tag = "accounts", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn terminate_session(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, session)): Path<(String, String)>,
) -> Response {
    let result = async {
        let (account, session) = (id(&account, "the account")?, id(&session, "the session")?);
        state.identity.admin_terminate_session(&admin, account, session).await
    }
    .await;
    respond(result, no_content)
}
