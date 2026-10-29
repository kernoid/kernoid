// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mail of the tenant administered (RFC 0002, 12.3 and 13): shared mailboxes, quotas, retention, access, Sieve
//! scripts, importing messages, mailboxes as mbox, and the queue – and one's own: the stores shared with one, and
//! sharing one's own.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use kernoid_identity::mail_access::MailGrant;
use kernoid_mail::{Access, MailboxInfo, QueuedRecipient, SharedStore, SieveScript};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{AdminSession, accounts::address, created, id, no_content, principal, tenant::TenantHeader};
use crate::{
    AppState, CurrentInstance, Problem,
    mail_admin::{self, MailAdminError, problem},
    sessions,
};

fn respond<T>(result: Result<T, MailAdminError>, ok: impl FnOnce(T) -> Response) -> Response {
    match result {
        Ok(value) => ok(value),
        Err(error) => problem(error),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewSharedMailbox {
    /// On a verified domain of the tenant.
    address: String,
    display_name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct MailboxView {
    id: String,
    parent_id: Option<String>,
    name: String,
    role: Option<String>,
    total_emails: u64,
    unread_emails: u64,
}

impl From<MailboxInfo> for MailboxView {
    fn from(mailbox: MailboxInfo) -> Self {
        Self {
            id: mailbox.id.to_string(),
            parent_id: mailbox.parent_id.map(|id| id.to_string()),
            name: mailbox.name,
            role: mailbox.role.map(|role| role.as_str().to_owned()),
            total_emails: mailbox.total_emails,
            unread_emails: mailbox.unread_emails,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct MailOverviewView {
    /// A shared mailbox, which nobody logs in as.
    shared: bool,
    used_bytes: u64,
    /// The account's own quota; null when the tenant's default holds.
    quota: Option<u64>,
    /// What holds: the account's own quota or the tenant's default; null for no limit.
    effective_quota: Option<u64>,
    mailboxes: Vec<MailboxView>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct Quota {
    /// Bytes; null for none (the tenant's default, or no limit).
    bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct Retention {
    /// Days emails stay in the accounts' Trash; null keeps them.
    trash_days: Option<u32>,
    /// Days emails stay in the accounts' Junk; null keeps them.
    junk_days: Option<u32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct MboxImportView {
    imported: u64,
    /// Messages refused: not a message, too large, over the quota.
    failed: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = MailGrantView)]
pub(crate) struct GrantView {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// The account's address, or `$` and the group's name.
    grantee_name: String,
    /// Null: the whole store.
    mailbox: Option<String>,
    /// IMAP ACL rights (RFC 4314), e.g. `lrs`.
    rights: String,
    send_as: bool,
}

impl From<MailGrant> for GrantView {
    fn from(grant: MailGrant) -> Self {
        Self {
            grantee_kind: grant.grantee.kind().into(),
            grantee_id: grant.grantee.id().to_string(),
            grantee_name: grant.grantee_name,
            mailbox: grant.mailbox.map(|id| id.to_string()),
            rights: grant.rights,
            send_as: grant.send_as,
        }
    }
}

fn grants(list: Vec<MailGrant>) -> Response {
    Json(list.into_iter().map(GrantView::from).collect::<Vec<_>>()).into_response()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct GrantChange {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// A mailbox of the account; leave out for the whole store.
    mailbox: Option<String>,
    /// IMAP ACL rights (RFC 4314): letters of `lrswipkxtea`.
    rights: String,
    /// May send from the account's addresses; for the whole store only.
    #[serde(default)]
    send_as: bool,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct GrantQuery {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    /// The mailbox of the grant; leave out for the grant on the whole store.
    mailbox: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SieveScriptView {
    name: String,
    content: String,
    active: bool,
}

impl From<SieveScript> for SieveScriptView {
    fn from(script: SieveScript) -> Self {
        Self { name: script.name, content: script.content, active: script.active }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct NewSieveScript {
    content: String,
    /// Make it the script that runs.
    #[serde(default)]
    activate: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ActiveScript {
    /// The script that runs; null for none.
    name: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct ImportQuery {
    /// A mailbox id or a role (`inbox`, `archive`, …); the inbox if left out.
    mailbox: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct QueueQuery {
    /// At most this many recipients (1–1000, default 100).
    limit: Option<i64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct QueuedView {
    message: String,
    address: String,
    status: String,
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    last_error: Option<String>,
}

impl From<QueuedRecipient> for QueuedView {
    fn from(recipient: QueuedRecipient) -> Self {
        Self {
            message: recipient.message.to_string(),
            address: recipient.address,
            status: recipient.status,
            attempts: recipient.attempts,
            next_attempt_at: recipient.next_attempt_at,
            last_error: recipient.last_error,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct SharedStoreView {
    /// The owner's account id – the JMAP account id.
    account: String,
    address: String,
    display_name: String,
    /// Rights on the whole store (RFC 4314); further rights may hold on single mailboxes.
    rights: String,
    send_as: bool,
}

impl From<(SharedStore, Access)> for SharedStoreView {
    fn from((store, access): (SharedStore, Access)) -> Self {
        Self {
            account: store.owner.to_string(),
            address: store.address,
            display_name: store.display_name,
            rights: access.store.letters(),
            send_as: access.send_as,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct OwnGrantChange {
    /// An address of an account of the tenant, or `$` and a group's name.
    grantee: String,
    /// A mailbox of one's own; leave out for the whole store.
    mailbox: Option<String>,
    /// IMAP ACL rights (RFC 4314): letters of `lrswipkxtea`.
    rights: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct OwnGrantQuery {
    /// An address of an account of the tenant, or `$` and a group's name.
    grantee: String,
    /// The mailbox of the grant; leave out for the grant on the whole store.
    mailbox: Option<String>,
}

fn mailbox_id(value: Option<&str>) -> Result<Option<Uuid>, MailAdminError> {
    value.map(|value| id(value, "the mailbox")).transpose().map_err(MailAdminError::from)
}

/// Creates a shared mailbox: an account nobody logs in as, used through granted access (needs `accounts.manage`).
#[utoipa::path(post, path = "/v1/shared-mailboxes", tag = "mail", params(TenantHeader), request_body = NewSharedMailbox,
    responses((status = 201, body = super::Created), (status = 409, description = "the address is taken", body = Problem)))]
pub(crate) async fn add_shared_mailbox(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<NewSharedMailbox>,
) -> Response {
    let result = async {
        let address = address(&body.address)?;
        mail_admin::add_shared_mailbox(&state, &admin, &address, &body.display_name).await
    }
    .await;
    respond(result, created)
}

/// An account's mail: usage, quota and mailboxes (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/mail", tag = "mail", params(TenantHeader),
    responses((status = 200, body = MailOverviewView), (status = 404, body = Problem)))]
pub(crate) async fn overview(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { mail_admin::overview(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, |overview| {
        Json(MailOverviewView {
            shared: overview.shared,
            used_bytes: overview.used_bytes,
            quota: overview.quota,
            effective_quota: overview.effective_quota,
            mailboxes: overview.mailboxes.into_iter().map(MailboxView::from).collect(),
        })
        .into_response()
    })
}

/// Sets an account's mail quota; null for the tenant's default (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/mail/quota", tag = "mail", params(TenantHeader), request_body = Quota,
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn set_quota(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<Quota>,
) -> Response {
    let result = async { mail_admin::set_quota(&state, &admin, id(&account, "the account")?, body.bytes).await }.await;
    respond(result, no_content)
}

/// The tenant's default mail quota (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/mail-quota", tag = "mail", params(TenantHeader),
    responses((status = 200, body = Quota)))]
pub(crate) async fn default_quota(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(mail_admin::default_quota(&state, &admin).await, |bytes| Json(Quota { bytes }).into_response())
}

/// Sets the tenant's default mail quota, for every account without its own; null for no limit (needs
/// `tenant.manage`).
#[utoipa::path(put, path = "/v1/tenant/mail-quota", tag = "mail", params(TenantHeader), request_body = Quota,
    responses((status = 204)))]
pub(crate) async fn set_default_quota(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<Quota>,
) -> Response {
    respond(mail_admin::set_default_quota(&state, &admin, body.bytes).await, no_content)
}

/// Who may use an account's mail (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/mail/access", tag = "mail", params(TenantHeader),
    responses((status = 200, body = [GrantView]), (status = 404, body = Problem)))]
pub(crate) async fn access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { mail_admin::access(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, grants)
}

/// Grants an account or a group of the tenant access to an account's mail, replacing an earlier grant there (needs
/// `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/mail/access", tag = "mail", params(TenantHeader),
    request_body = GrantChange, responses((status = 204), (status = 400, body = Problem), (status = 404, body = Problem)))]
pub(crate) async fn set_access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<GrantChange>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let grantee = principal(&body.grantee_kind, &body.grantee_id)?;
        let mailbox = mailbox_id(body.mailbox.as_deref())?;
        mail_admin::set_access(&state, &admin, owner, grantee, mailbox, &body.rights, body.send_as).await
    }
    .await;
    respond(result, no_content)
}

/// Removes a grant on an account's mail (needs `accounts.manage`).
#[utoipa::path(delete, path = "/v1/accounts/{id}/mail/access", tag = "mail", params(TenantHeader, GrantQuery),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn remove_access(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Query(query): Query<GrantQuery>,
) -> Response {
    let result = async {
        let owner = id(&account, "the account")?;
        let grantee = principal(&query.grantee_kind, &query.grantee_id)?;
        let mailbox = mailbox_id(query.mailbox.as_deref())?;
        mail_admin::remove_access(&state, &admin, owner, grantee, mailbox).await
    }
    .await;
    respond(result, no_content)
}

/// An account's Sieve scripts (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/mail/sieve", tag = "mail", params(TenantHeader),
    responses((status = 200, body = [SieveScriptView]), (status = 404, body = Problem)))]
pub(crate) async fn sieve_scripts(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
) -> Response {
    let result = async { mail_admin::sieve_scripts(&state, &admin, id(&account, "the account")?).await }.await;
    respond(result, |list| Json(list.into_iter().map(SieveScriptView::from).collect::<Vec<_>>()).into_response())
}

/// Saves a Sieve script, checked first (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/mail/sieve/{name}", tag = "mail", params(TenantHeader),
    request_body = NewSieveScript, responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn put_sieve_script(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, name)): Path<(String, String)>,
    Json(body): Json<NewSieveScript>,
) -> Response {
    let result = async {
        let account = id(&account, "the account")?;
        mail_admin::put_sieve_script(&state, &admin, account, &name, &body.content, body.activate).await
    }
    .await;
    respond(result, no_content)
}

/// Removes a Sieve script (needs `accounts.manage`).
#[utoipa::path(delete, path = "/v1/accounts/{id}/mail/sieve/{name}", tag = "mail", params(TenantHeader),
    responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn remove_sieve_script(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, name)): Path<(String, String)>,
) -> Response {
    let result =
        async { mail_admin::remove_sieve_script(&state, &admin, id(&account, "the account")?, &name).await }.await;
    respond(result, no_content)
}

/// Chooses the Sieve script that runs; null for none (needs `accounts.manage`).
#[utoipa::path(put, path = "/v1/accounts/{id}/mail/sieve-active", tag = "mail", params(TenantHeader),
    request_body = ActiveScript, responses((status = 204), (status = 404, body = Problem)))]
pub(crate) async fn activate_sieve_script(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Json(body): Json<ActiveScript>,
) -> Response {
    let result = async {
        let account = id(&account, "the account")?;
        mail_admin::activate_sieve_script(&state, &admin, account, body.name.as_deref()).await
    }
    .await;
    respond(result, no_content)
}

/// Stores a message (RFC 5322, the request body) in a mailbox of an account (needs `accounts.manage`).
#[utoipa::path(post, path = "/v1/accounts/{id}/mail/import", tag = "mail", params(TenantHeader, ImportQuery),
    request_body(content = String, content_type = "message/rfc822"),
    responses((status = 201, body = super::Created), (status = 400, body = Problem)))]
pub(crate) async fn import(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path(account): Path<String>,
    Query(query): Query<ImportQuery>,
    body: Bytes,
) -> Response {
    let result = async {
        mail_admin::import(&state, &admin, id(&account, "the account")?, query.mailbox.as_deref(), body).await
    }
    .await;
    respond(result, created)
}

/// The queue of outgoing mail of the instance's tenants, newest first (needs `instance.read`).
#[utoipa::path(get, path = "/v1/instance/mail-queue", tag = "mail", params(QueueQuery),
    responses((status = 200, body = [QueuedView])))]
pub(crate) async fn queue(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Query(query): Query<QueueQuery>,
) -> Response {
    respond(mail_admin::queue(&state, &admin, query.limit.unwrap_or(100)).await, |list| {
        Json(list.into_iter().map(QueuedView::from).collect::<Vec<_>>()).into_response()
    })
}

/// The account and tenant of a session.
async fn own(state: &AppState, instance: Uuid, token: &str) -> Result<(Uuid, Uuid), MailAdminError> {
    let session = state.identity.session(instance, token).await?;
    Ok((session.account.id, session.account.tenant))
}

/// The mail shared with one's own account: other accounts' stores one may use.
#[utoipa::path(get, path = "/v1/account/mail/shared", tag = "account", responses(
    (status = 200, body = [SharedStoreView]),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn own_shared(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
) -> Response {
    let result = async {
        let (account, _) = own(&state, instance.id, &token).await?;
        mail_admin::shared_with(&state, account).await
    }
    .await;
    respond(result, |list| Json(list.into_iter().map(SharedStoreView::from).collect::<Vec<_>>()).into_response())
}

/// Who may use one's own mail.
#[utoipa::path(get, path = "/v1/account/mail/access", tag = "account", responses(
    (status = 200, body = [GrantView]),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn own_access(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
) -> Response {
    let result = async {
        let (account, _) = own(&state, instance.id, &token).await?;
        mail_admin::own_access(&state, account).await
    }
    .await;
    respond(result, grants)
}

/// Shares one's own mail – the whole store or one mailbox – with an account or a group of one's tenant.
#[utoipa::path(put, path = "/v1/account/mail/access", tag = "account", request_body = OwnGrantChange, responses(
    (status = 204),
    (status = 400, body = Problem),
    (status = 401, description = "no valid session", body = Problem),
))]
pub(crate) async fn share_own(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Json(body): Json<OwnGrantChange>,
) -> Response {
    let result = async {
        let (account, tenant) = own(&state, instance.id, &token).await?;
        let mailbox = mailbox_id(body.mailbox.as_deref())?;
        mail_admin::share_own(&state, account, tenant, &body.grantee, mailbox, &body.rights).await
    }
    .await;
    respond(result, no_content)
}

/// Stops sharing one's own mail with someone.
#[utoipa::path(delete, path = "/v1/account/mail/access", tag = "account", params(OwnGrantQuery), responses(
    (status = 204),
    (status = 401, description = "no valid session", body = Problem),
    (status = 404, body = Problem),
))]
pub(crate) async fn unshare_own(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    sessions::SessionToken(token): sessions::SessionToken,
    Query(query): Query<OwnGrantQuery>,
) -> Response {
    let result = async {
        let (account, tenant) = own(&state, instance.id, &token).await?;
        let mailbox = mailbox_id(query.mailbox.as_deref())?;
        mail_admin::unshare_own(&state, account, tenant, &query.grantee, mailbox).await
    }
    .await;
    respond(result, no_content)
}

/// The tenant's mail retention (needs `directory.read`).
#[utoipa::path(get, path = "/v1/tenant/mail-retention", tag = "mail", params(TenantHeader),
    responses((status = 200, body = Retention)))]
pub(crate) async fn retention(State(state): State<AppState>, AdminSession(admin): AdminSession) -> Response {
    respond(mail_admin::retention(&state, &admin).await, |(trash_days, junk_days)| {
        Json(Retention { trash_days, junk_days }).into_response()
    })
}

/// Sets how many days emails stay in the accounts' Trash and Junk; null keeps them (needs `tenant.manage`).
#[utoipa::path(put, path = "/v1/tenant/mail-retention", tag = "mail", params(TenantHeader), request_body = Retention,
    responses((status = 204), (status = 400, body = Problem)))]
pub(crate) async fn set_retention(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Json(body): Json<Retention>,
) -> Response {
    respond(mail_admin::set_retention(&state, &admin, body.trash_days, body.junk_days).await, no_content)
}

/// A mailbox of an account (by id or role) as mbox, with its keywords (needs `accounts.manage`).
#[utoipa::path(get, path = "/v1/accounts/{id}/mail/mailboxes/{mailbox}/mbox", tag = "mail", params(TenantHeader),
    responses((status = 200, content_type = "application/mbox", body = String), (status = 404, body = Problem)))]
pub(crate) async fn export(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, mailbox)): Path<(String, String)>,
) -> Response {
    // The first email is read before the response starts: if it cannot be read (its object missing in storage), the
    // answer is a problem with a status, not a connection that breaks off empty.
    let result = async {
        let account = id(&account, "the account")?;
        let (mail, entries) = mail_admin::export(&state, &admin, account, &mailbox).await?;
        let mut entries = entries.into_iter();
        let first = match entries.next() {
            Some(entry) => Some(mail.mbox_entry(account, &entry).await?),
            None => None,
        };
        Ok::<_, MailAdminError>((account, mail, first, entries))
    }
    .await;
    respond(result, |(account, mail, first, entries)| {
        // One email after the other, so that a large mailbox is not held in memory.
        let rest = futures_util::stream::unfold((mail, entries), move |(mail, mut entries)| async move {
            let entry = entries.next()?;
            let chunk = mail.mbox_entry(account, &entry).await.map(Bytes::from).map_err(|error| {
                tracing::error!(%error, email = %entry.email, "an export broke off at an email that could not be read");
                std::io::Error::other(error)
            });
            Some((chunk, (mail, entries)))
        });
        let first = futures_util::stream::iter(first.map(|first| Ok(Bytes::from(first))));
        ([(axum::http::header::CONTENT_TYPE, "application/mbox")], axum::body::Body::from_stream(first.chain(rest)))
            .into_response()
    })
}

/// Stores the messages of an mbox (the request body, up to 2 MiB; larger ones with the CLI) in a mailbox of an account
/// (by id or role), with their keywords (needs `accounts.manage`).
#[utoipa::path(post, path = "/v1/accounts/{id}/mail/mailboxes/{mailbox}/mbox", tag = "mail", params(TenantHeader),
    request_body(content = String, content_type = "application/mbox"),
    responses((status = 200, body = MboxImportView), (status = 404, body = Problem)))]
pub(crate) async fn import_mbox(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Path((account, mailbox)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let result =
        async { mail_admin::import_mbox(&state, &admin, id(&account, "the account")?, &mailbox, &body).await }.await;
    respond(result, |done| Json(MboxImportView { imported: done.imported, failed: done.failed }).into_response())
}
