// SPDX-License-Identifier: AGPL-3.0-or-later
//! Administration of mail (RFC 0002, 12.3), for REST and GraphQL alike: what is an event goes through
//! `kernoid_identity::mail_access`, which checks its permissions; what is mail data (mailboxes, Sieve scripts,
//! importing, the queue) is checked here, once, before `kernoid_mail` is asked.

use axum::body::Bytes;
use kernoid_identity::{
    IdentityError,
    mail_access::MailGrant,
    role::{Admin, Permission, Principal},
};
use kernoid_mail::{
    Access, Mail, MailError, MailboxEntry, MailboxInfo, MboxImport, NewEmail, QueuedRecipient, Role, SharedStore,
    SieveScript,
};
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum MailAdminError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Mail(#[from] MailError),
    #[error("this installation does not handle mail")]
    NoMail,
}

pub(crate) type Result<T> = std::result::Result<T, MailAdminError>;

/// An account's mail as its administrators see it.
#[derive(Debug, Clone)]
pub(crate) struct MailOverview {
    pub shared: bool,
    pub used_bytes: u64,
    /// The account's own quota; `None` when the tenant's default holds.
    pub quota: Option<u64>,
    /// What holds: the account's own quota, or else the tenant's default.
    pub effective_quota: Option<u64>,
    pub mailboxes: Vec<MailboxInfo>,
}

fn mail(state: &AppState) -> Result<&Mail> {
    state.jmap.as_ref().map(kernoid_jmap::Jmap::mail).ok_or(MailAdminError::NoMail)
}

/// The account, if the administrator may manage it (`accounts.manage`, same tenant).
async fn managed(state: &AppState, admin: &Admin, account: Uuid) -> Result<kernoid_identity::account::AccountInfo> {
    Ok(state.identity.managed_account(admin, account).await?)
}

pub(crate) async fn add_shared_mailbox(
    state: &AppState,
    admin: &Admin,
    address: &kernoid_identity::Address,
    display_name: &str,
) -> Result<Uuid> {
    Ok(state.identity.admin_add_shared_mailbox(admin, address, display_name).await?)
}

pub(crate) async fn overview(state: &AppState, admin: &Admin, account: Uuid) -> Result<MailOverview> {
    let info = managed(state, admin, account).await?;
    let mail = mail(state)?;
    let (used_bytes, effective_quota) = mail.quota(account).await?;
    Ok(MailOverview {
        shared: info.shared,
        used_bytes,
        quota: state.identity.mail_quota(account).await?,
        effective_quota,
        mailboxes: mail.mailboxes(account).await?,
    })
}

pub(crate) async fn set_quota(state: &AppState, admin: &Admin, account: Uuid, bytes: Option<u64>) -> Result<()> {
    Ok(state.identity.admin_set_mail_quota(admin, account, bytes).await?)
}

pub(crate) async fn default_quota(state: &AppState, admin: &Admin) -> Result<Option<u64>> {
    Ok(state.identity.admin_default_mail_quota(admin).await?)
}

pub(crate) async fn set_default_quota(state: &AppState, admin: &Admin, bytes: Option<u64>) -> Result<()> {
    Ok(state.identity.admin_set_default_mail_quota(admin, bytes).await?)
}

pub(crate) async fn access(state: &AppState, admin: &Admin, owner: Uuid) -> Result<Vec<MailGrant>> {
    Ok(state.identity.admin_mail_access(admin, owner).await?)
}

pub(crate) async fn set_access(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    grantee: Principal,
    mailbox: Option<Uuid>,
    rights: &str,
    send_as: bool,
) -> Result<()> {
    Ok(state.identity.admin_set_mail_access(admin, owner, grantee, mailbox, rights, send_as).await?)
}

pub(crate) async fn remove_access(
    state: &AppState,
    admin: &Admin,
    owner: Uuid,
    grantee: Principal,
    mailbox: Option<Uuid>,
) -> Result<()> {
    Ok(state.identity.admin_remove_mail_access(admin, owner, grantee, mailbox).await?)
}

pub(crate) async fn sieve_scripts(state: &AppState, admin: &Admin, account: Uuid) -> Result<Vec<SieveScript>> {
    managed(state, admin, account).await?;
    Ok(mail(state)?.sieve_scripts(account).await?)
}

pub(crate) async fn put_sieve_script(
    state: &AppState,
    admin: &Admin,
    account: Uuid,
    name: &str,
    content: &str,
    activate: bool,
) -> Result<()> {
    managed(state, admin, account).await?;
    mail(state)?.put_sieve_script(account, name, content, activate).await?;
    Ok(())
}

pub(crate) async fn remove_sieve_script(state: &AppState, admin: &Admin, account: Uuid, name: &str) -> Result<()> {
    managed(state, admin, account).await?;
    Ok(mail(state)?.remove_sieve_script(account, name).await?)
}

/// Makes `name` the script that runs; `None` runs none.
pub(crate) async fn activate_sieve_script(
    state: &AppState,
    admin: &Admin,
    account: Uuid,
    name: Option<&str>,
) -> Result<()> {
    managed(state, admin, account).await?;
    Ok(mail(state)?.activate_sieve_script(account, name).await?)
}

/// Days in Trash and in Junk.
pub(crate) async fn retention(state: &AppState, admin: &Admin) -> Result<(Option<u32>, Option<u32>)> {
    Ok(state.identity.admin_mail_retention(admin).await?)
}

pub(crate) async fn set_retention(
    state: &AppState,
    admin: &Admin,
    trash_days: Option<u32>,
    junk_days: Option<u32>,
) -> Result<()> {
    Ok(state.identity.admin_set_mail_retention(admin, trash_days, junk_days).await?)
}

/// A mailbox of the account by its id or role.
async fn mailbox_of(mail: &Mail, account: Uuid, value: &str) -> Result<Uuid> {
    Ok(match Role::parse(value) {
        Some(role) => mail.mailbox_with_role(account, role).await?,
        None => {
            let id = Uuid::parse_str(value).map_err(|_| MailError::NotFound("the mailbox"))?;
            if !mail.mailboxes(account).await?.iter().any(|mailbox| mailbox.id == id) {
                return Err(MailError::NotFound("the mailbox").into());
            }
            id
        }
    })
}

/// The emails of a mailbox to export as mbox, and the store to read them from.
pub(crate) async fn export(
    state: &AppState,
    admin: &Admin,
    account: Uuid,
    mailbox: &str,
) -> Result<(Mail, Vec<MailboxEntry>)> {
    managed(state, admin, account).await?;
    let mail = mail(state)?;
    let mailbox = mailbox_of(mail, account, mailbox).await?;
    Ok((mail.clone(), mail.mailbox_entries(account, mailbox).await?))
}

/// A whole mailbox as mbox, in memory (GraphQL).
pub(crate) async fn export_text(state: &AppState, admin: &Admin, account: Uuid, mailbox: &str) -> Result<Vec<u8>> {
    let (mail, entries) = export(state, admin, account, mailbox).await?;
    let mut out = Vec::new();
    for entry in &entries {
        out.extend(mail.mbox_entry(account, entry).await?);
    }
    Ok(out)
}

/// Stores the messages of an mbox in a mailbox of the account (by id or role).
pub(crate) async fn import_mbox(
    state: &AppState,
    admin: &Admin,
    account: Uuid,
    mailbox: &str,
    data: &[u8],
) -> Result<MboxImport> {
    managed(state, admin, account).await?;
    let mail = mail(state)?;
    let mailbox = mailbox_of(mail, account, mailbox).await?;
    Ok(mail.import_mbox(account, mailbox, data).await?)
}

/// Stores a message in a mailbox of the account – named by its id or role, the inbox if none.
pub(crate) async fn import(
    state: &AppState,
    admin: &Admin,
    account: Uuid,
    mailbox: Option<&str>,
    raw: Bytes,
) -> Result<Uuid> {
    managed(state, admin, account).await?;
    let mail = mail(state)?;
    let target = match mailbox {
        None => mail.mailbox_with_role(account, Role::Inbox).await?,
        Some(value) => match Role::parse(value) {
            Some(role) => mail.mailbox_with_role(account, role).await?,
            None => Uuid::parse_str(value).map_err(|_| MailError::NotFound("the mailbox"))?,
        },
    };
    let new = NewEmail { mailbox_ids: vec![target], ..NewEmail::default() };
    Ok(mail.import_email(account, raw, new).await?.id)
}

/// The queue of the instance's tenants (`instance.read`).
pub(crate) async fn queue(state: &AppState, admin: &Admin, limit: i64) -> Result<Vec<QueuedRecipient>> {
    admin.require(Permission::InstanceRead)?;
    Ok(mail(state)?.instance_queue(admin.instance(), limit.clamp(1, 1000)).await?)
}

// One's own (a session's account)

/// The stores shared with the account, with what it may do there.
pub(crate) async fn shared_with(state: &AppState, account: Uuid) -> Result<Vec<(SharedStore, Access)>> {
    let mail = mail(state)?;
    let mut stores = Vec::new();
    for store in mail.shared_with(account).await? {
        let access = mail.access(account, store.owner).await?;
        if access.any() {
            stores.push((store, access));
        }
    }
    Ok(stores)
}

pub(crate) async fn own_access(state: &AppState, account: Uuid) -> Result<Vec<MailGrant>> {
    Ok(state.identity.mail_access(account).await?)
}

/// Shares the account's own mail with an account (by address) or a group (`$name`) of its tenant.
pub(crate) async fn share_own(
    state: &AppState,
    account: Uuid,
    tenant: Uuid,
    grantee: &str,
    mailbox: Option<Uuid>,
    rights: &str,
) -> Result<()> {
    let grantee = state.identity.mail_grantee(tenant, grantee).await?;
    Ok(state.identity.share_own_mail(account, grantee, mailbox, rights).await?)
}

pub(crate) async fn unshare_own(
    state: &AppState,
    account: Uuid,
    tenant: Uuid,
    grantee: &str,
    mailbox: Option<Uuid>,
) -> Result<()> {
    let grantee = state.identity.mail_grantee(tenant, grantee).await?;
    Ok(state.identity.unshare_own_mail(account, grantee, mailbox).await?)
}

/// A failure as problem details.
pub(crate) fn problem(error: MailAdminError) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    match error {
        MailAdminError::Identity(error) => crate::sessions::problem(error),
        MailAdminError::NoMail => {
            crate::Problem::new(StatusCode::BAD_REQUEST).detail(MailAdminError::NoMail.to_string()).into_response()
        }
        MailAdminError::Mail(error) => {
            let status = match &error {
                MailError::NotFound(_) => StatusCode::NOT_FOUND,
                MailError::Exists(_) => StatusCode::CONFLICT,
                MailError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                MailError::Invalid(_)
                | MailError::OverQuota
                | MailError::MailboxHasChild
                | MailError::MailboxHasEmail
                | MailError::Unparsable
                | MailError::CannotCalculateChanges => StatusCode::BAD_REQUEST,
                MailError::Blob(_) => {
                    tracing::error!(%error, "mail store");
                    return crate::Problem::new(StatusCode::SERVICE_UNAVAILABLE)
                        .detail("stored content could not be read")
                        .into_response();
                }
                _ => {
                    tracing::error!(%error, "mail store");
                    return crate::Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
                }
            };
            crate::Problem::new(status).detail(error.to_string()).into_response()
        }
    }
}
