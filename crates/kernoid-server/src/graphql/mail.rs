// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mail in GraphQL (RFC 0002, 12.3) – the same operations and checks as the REST routes in `crate::admin::mail`,
//! both through `crate::mail_admin`.

use async_graphql::{Context, ErrorExtensions, Object, SimpleObject};
use axum::body::Bytes;
use chrono::{DateTime, Utc};
use kernoid_identity::{Identity, mail_access::MailGrant};
use kernoid_mail::MailError;
use uuid::Uuid;

use super::{
    admin::{admin, principal, uuid},
    error, instance, token,
};
use crate::{
    AppState,
    mail_admin::{self, MailAdminError},
};

/// A mail administration error as a GraphQL error with a code.
fn mail_error(failure: MailAdminError) -> async_graphql::Error {
    let code = match &failure {
        MailAdminError::Identity(_) => {
            let MailAdminError::Identity(identity) = failure else { unreachable!() };
            return error(identity);
        }
        MailAdminError::NoMail => "BAD_REQUEST",
        MailAdminError::Mail(MailError::NotFound(_)) => "NOT_FOUND",
        MailAdminError::Mail(MailError::Exists(_)) => "CONFLICT",
        MailAdminError::Mail(
            MailError::Invalid(_)
            | MailError::TooLarge { .. }
            | MailError::OverQuota
            | MailError::MailboxHasChild
            | MailError::MailboxHasEmail
            | MailError::Unparsable
            | MailError::CannotCalculateChanges,
        ) => "BAD_REQUEST",
        MailAdminError::Mail(store) => {
            tracing::error!(error = %store, "mail store");
            return async_graphql::Error::new("unavailable").extend_with(|_, e| e.set("code", "UNAVAILABLE"));
        }
    };
    async_graphql::Error::new(failure.to_string()).extend_with(|_, extensions| extensions.set("code", code))
}

fn state<'a>(context: &'a Context<'_>) -> async_graphql::Result<&'a AppState> {
    context.data::<AppState>()
}

fn mailbox(value: Option<&str>) -> async_graphql::Result<Option<Uuid>> {
    value.map(|value| uuid(value, "the mailbox")).transpose()
}

/// The account and tenant of the session.
async fn own(context: &Context<'_>) -> async_graphql::Result<(Uuid, Uuid)> {
    let identity = context.data::<Identity>()?;
    let session = identity.session(instance(context)?.id, token(context)?).await.map_err(error)?;
    Ok((session.account.id, session.account.tenant))
}

#[derive(Debug, SimpleObject)]
pub struct MailboxObject {
    id: String,
    parent_id: Option<String>,
    name: String,
    role: Option<String>,
    total_emails: u64,
    unread_emails: u64,
}

#[derive(Debug, SimpleObject)]
pub struct MailOverview {
    /// A shared mailbox: nobody logs in as it.
    shared: bool,
    used_bytes: u64,
    /// The account's own quota; null when the tenant's default holds.
    quota: Option<u64>,
    /// What holds; null for no limit.
    effective_quota: Option<u64>,
    mailboxes: Vec<MailboxObject>,
}

#[derive(Debug, SimpleObject)]
pub struct MailGrantObject {
    /// `account` or `group`.
    grantee_kind: String,
    grantee_id: String,
    grantee_name: String,
    /// Null: the whole store.
    mailbox: Option<String>,
    /// IMAP ACL rights (RFC 4314).
    rights: String,
    send_as: bool,
}

impl From<MailGrant> for MailGrantObject {
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

#[derive(Debug, SimpleObject)]
pub struct SieveScriptObject {
    name: String,
    content: String,
    active: bool,
}

#[derive(Debug, SimpleObject)]
pub struct QueuedRecipientObject {
    message: String,
    address: String,
    status: String,
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    last_error: Option<String>,
}

#[derive(Debug, SimpleObject)]
pub struct SharedStoreObject {
    /// The owner's account id – the JMAP account id.
    account: String,
    address: String,
    display_name: String,
    /// Rights on the whole store.
    rights: String,
    send_as: bool,
}

#[derive(Debug, SimpleObject)]
pub struct MailRetention {
    /// Days emails stay in the accounts' Trash; null keeps them.
    trash_days: Option<u32>,
    /// Days emails stay in the accounts' Junk; null keeps them.
    junk_days: Option<u32>,
}

#[derive(Debug, SimpleObject)]
pub struct MboxImportResult {
    imported: u64,
    /// Messages refused: not a message, too large, over the quota.
    failed: u64,
}

#[derive(Debug, Default)]
pub struct MailQuery;

#[Object]
impl MailQuery {
    /// An account's mail: usage, quota and mailboxes (needs `accounts.manage`).
    async fn account_mail(&self, context: &Context<'_>, account: String) -> async_graphql::Result<MailOverview> {
        let (_, admin) = admin(context).await?;
        let overview =
            mail_admin::overview(state(context)?, &admin, uuid(&account, "the account")?).await.map_err(mail_error)?;
        Ok(MailOverview {
            shared: overview.shared,
            used_bytes: overview.used_bytes,
            quota: overview.quota,
            effective_quota: overview.effective_quota,
            mailboxes: overview
                .mailboxes
                .into_iter()
                .map(|mailbox| MailboxObject {
                    id: mailbox.id.to_string(),
                    parent_id: mailbox.parent_id.map(|id| id.to_string()),
                    name: mailbox.name,
                    role: mailbox.role.map(|role| role.as_str().to_owned()),
                    total_emails: mailbox.total_emails,
                    unread_emails: mailbox.unread_emails,
                })
                .collect(),
        })
    }

    /// The tenant's default mail quota (needs `directory.read`).
    async fn tenant_mail_quota(&self, context: &Context<'_>) -> async_graphql::Result<Option<u64>> {
        let (_, admin) = admin(context).await?;
        mail_admin::default_quota(state(context)?, &admin).await.map_err(mail_error)
    }

    /// The tenant's mail retention (needs `directory.read`).
    async fn mail_retention(&self, context: &Context<'_>) -> async_graphql::Result<MailRetention> {
        let (_, admin) = admin(context).await?;
        let (trash_days, junk_days) = mail_admin::retention(state(context)?, &admin).await.map_err(mail_error)?;
        Ok(MailRetention { trash_days, junk_days })
    }

    /// A mailbox of an account (by id or role) as mbox (needs `accounts.manage`); for large mailboxes use the REST
    /// route, which streams.
    async fn export_mailbox(
        &self,
        context: &Context<'_>,
        account: String,
        mailbox: String,
    ) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        let mbox = mail_admin::export_text(state(context)?, &admin, account, &mailbox).await.map_err(mail_error)?;
        Ok(String::from_utf8_lossy(&mbox).into_owned())
    }

    /// Who may use an account's mail (needs `accounts.manage`).
    async fn mail_access(&self, context: &Context<'_>, account: String) -> async_graphql::Result<Vec<MailGrantObject>> {
        let (_, admin) = admin(context).await?;
        let grants =
            mail_admin::access(state(context)?, &admin, uuid(&account, "the account")?).await.map_err(mail_error)?;
        Ok(grants.into_iter().map(Into::into).collect())
    }

    /// An account's Sieve scripts (needs `accounts.manage`).
    async fn sieve_scripts(
        &self,
        context: &Context<'_>,
        account: String,
    ) -> async_graphql::Result<Vec<SieveScriptObject>> {
        let (_, admin) = admin(context).await?;
        let scripts = mail_admin::sieve_scripts(state(context)?, &admin, uuid(&account, "the account")?)
            .await
            .map_err(mail_error)?;
        Ok(scripts
            .into_iter()
            .map(|script| SieveScriptObject { name: script.name, content: script.content, active: script.active })
            .collect())
    }

    /// The queue of outgoing mail of the instance's tenants (needs `instance.read`).
    async fn mail_queue(
        &self,
        context: &Context<'_>,
        #[graphql(default = 100)] limit: i64,
    ) -> async_graphql::Result<Vec<QueuedRecipientObject>> {
        let (_, admin) = admin(context).await?;
        let queue = mail_admin::queue(state(context)?, &admin, limit).await.map_err(mail_error)?;
        Ok(queue
            .into_iter()
            .map(|recipient| QueuedRecipientObject {
                message: recipient.message.to_string(),
                address: recipient.address,
                status: recipient.status,
                attempts: recipient.attempts,
                next_attempt_at: recipient.next_attempt_at,
                last_error: recipient.last_error,
            })
            .collect())
    }

    /// The mail shared with the session's account.
    async fn shared_mail(&self, context: &Context<'_>) -> async_graphql::Result<Vec<SharedStoreObject>> {
        let (account, _) = own(context).await?;
        let stores = mail_admin::shared_with(state(context)?, account).await.map_err(mail_error)?;
        Ok(stores
            .into_iter()
            .map(|(store, access)| SharedStoreObject {
                account: store.owner.to_string(),
                address: store.address,
                display_name: store.display_name,
                rights: access.store.letters(),
                send_as: access.send_as,
            })
            .collect())
    }

    /// Who may use the session's account's mail.
    async fn my_mail_access(&self, context: &Context<'_>) -> async_graphql::Result<Vec<MailGrantObject>> {
        let (account, _) = own(context).await?;
        let grants = mail_admin::own_access(state(context)?, account).await.map_err(mail_error)?;
        Ok(grants.into_iter().map(Into::into).collect())
    }
}

#[derive(Debug, Default)]
pub struct MailMutation;

#[Object]
impl MailMutation {
    /// Creates a shared mailbox (needs `accounts.manage`); returns its id.
    async fn add_shared_mailbox(
        &self,
        context: &Context<'_>,
        address: String,
        display_name: String,
    ) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let address = super::admin::address(&address)?;
        let id = mail_admin::add_shared_mailbox(state(context)?, &admin, &address, &display_name)
            .await
            .map_err(mail_error)?;
        Ok(id.to_string())
    }

    /// Sets an account's mail quota; null for the tenant's default (needs `accounts.manage`).
    async fn set_mail_quota(
        &self,
        context: &Context<'_>,
        account: String,
        bytes: Option<u64>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        mail_admin::set_quota(state(context)?, &admin, uuid(&account, "the account")?, bytes)
            .await
            .map_err(mail_error)?;
        Ok(true)
    }

    /// Sets the tenant's default mail quota; null for no limit (needs `tenant.manage`).
    async fn set_tenant_mail_quota(&self, context: &Context<'_>, bytes: Option<u64>) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        mail_admin::set_default_quota(state(context)?, &admin, bytes).await.map_err(mail_error)?;
        Ok(true)
    }

    /// Sets how many days emails stay in the accounts' Trash and Junk; null keeps them (needs `tenant.manage`).
    async fn set_mail_retention(
        &self,
        context: &Context<'_>,
        trash_days: Option<u32>,
        junk_days: Option<u32>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        mail_admin::set_retention(state(context)?, &admin, trash_days, junk_days).await.map_err(mail_error)?;
        Ok(true)
    }

    /// Stores the messages of an mbox in a mailbox of an account (by id or role), with their keywords (needs
    /// `accounts.manage`).
    async fn import_mbox(
        &self,
        context: &Context<'_>,
        account: String,
        mailbox: String,
        mbox: String,
    ) -> async_graphql::Result<MboxImportResult> {
        let (_, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        let done = mail_admin::import_mbox(state(context)?, &admin, account, &mailbox, mbox.as_bytes())
            .await
            .map_err(mail_error)?;
        Ok(MboxImportResult { imported: done.imported, failed: done.failed })
    }

    /// Grants an account or a group access to an account's mail (needs `accounts.manage`).
    #[allow(clippy::too_many_arguments, reason = "the arguments of the GraphQL field")]
    async fn set_mail_access(
        &self,
        context: &Context<'_>,
        account: String,
        grantee_kind: String,
        grantee_id: String,
        mailbox: Option<String>,
        rights: String,
        #[graphql(default)] send_as: bool,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let grantee = principal(&grantee_kind, &grantee_id)?;
        let mailbox = self::mailbox(mailbox.as_deref())?;
        mail_admin::set_access(state(context)?, &admin, owner, grantee, mailbox, &rights, send_as)
            .await
            .map_err(mail_error)?;
        Ok(true)
    }

    /// Removes a grant on an account's mail (needs `accounts.manage`).
    async fn remove_mail_access(
        &self,
        context: &Context<'_>,
        account: String,
        grantee_kind: String,
        grantee_id: String,
        mailbox: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let owner = uuid(&account, "the account")?;
        let grantee = principal(&grantee_kind, &grantee_id)?;
        let mailbox = self::mailbox(mailbox.as_deref())?;
        mail_admin::remove_access(state(context)?, &admin, owner, grantee, mailbox).await.map_err(mail_error)?;
        Ok(true)
    }

    /// Saves a Sieve script, checked first (needs `accounts.manage`).
    async fn put_sieve_script(
        &self,
        context: &Context<'_>,
        account: String,
        name: String,
        content: String,
        #[graphql(default)] activate: bool,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        mail_admin::put_sieve_script(state(context)?, &admin, account, &name, &content, activate)
            .await
            .map_err(mail_error)?;
        Ok(true)
    }

    /// Removes a Sieve script (needs `accounts.manage`).
    async fn remove_sieve_script(
        &self,
        context: &Context<'_>,
        account: String,
        name: String,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        mail_admin::remove_sieve_script(state(context)?, &admin, account, &name).await.map_err(mail_error)?;
        Ok(true)
    }

    /// Chooses the Sieve script that runs; null for none (needs `accounts.manage`).
    async fn activate_sieve_script(
        &self,
        context: &Context<'_>,
        account: String,
        name: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (_, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        mail_admin::activate_sieve_script(state(context)?, &admin, account, name.as_deref())
            .await
            .map_err(mail_error)?;
        Ok(true)
    }

    /// Stores a message (RFC 5322 as text) in a mailbox of an account – by id or role, the inbox if none (needs
    /// `accounts.manage`); returns the email's id.
    async fn import_mail(
        &self,
        context: &Context<'_>,
        account: String,
        message: String,
        mailbox: Option<String>,
    ) -> async_graphql::Result<String> {
        let (_, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        let id = mail_admin::import(state(context)?, &admin, account, mailbox.as_deref(), Bytes::from(message))
            .await
            .map_err(mail_error)?;
        Ok(id.to_string())
    }

    /// Shares the session's account's mail with an account (by address) or a group (`$name`) of its tenant.
    async fn share_my_mail(
        &self,
        context: &Context<'_>,
        grantee: String,
        mailbox: Option<String>,
        rights: String,
    ) -> async_graphql::Result<bool> {
        let (account, tenant) = own(context).await?;
        let mailbox = self::mailbox(mailbox.as_deref())?;
        mail_admin::share_own(state(context)?, account, tenant, &grantee, mailbox, &rights)
            .await
            .map_err(mail_error)?;
        Ok(true)
    }

    /// Stops sharing the session's account's mail with someone.
    async fn unshare_my_mail(
        &self,
        context: &Context<'_>,
        grantee: String,
        mailbox: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (account, tenant) = own(context).await?;
        let mailbox = self::mailbox(mailbox.as_deref())?;
        mail_admin::unshare_own(state(context)?, account, tenant, &grantee, mailbox).await.map_err(mail_error)?;
        Ok(true)
    }
}
