// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts linked to identities at external identity providers (RFC 0001, 7.7): who logs in with the provider's
//! subject `sub` logs in as the linked account. The link is an event of the account (`account.link_added`,
//! `account.link_removed`); one external identity is linked to at most one account.

use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::{AccountEvent, AccountInfo},
    role::{Admin, Permission},
    session::{CHECK_IDP, CHECK_IDP_MFA, ClientMeta, NewSession},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub idp: Uuid,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Links an external identity to an account; an identity linked to another account is refused.
    pub async fn link_account(&self, account: Uuid, idp: Uuid, subject: &str, creator: &str) -> Result<()> {
        if subject.is_empty() || subject.len() > 255 {
            return Err(IdentityError::Refused("a subject has 1 to 255 bytes".into()));
        }
        if let Some(other) = self.account_by_link(idp, subject).await? {
            return if other.id == account { Ok(()) } else { Err(IdentityError::Exists("a link of this identity")) };
        }
        let (instance, tenant) = self.account_owner(account).await?;
        let subject = subject.to_owned();
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            crate::account::with_login(state)?;
            Ok(vec![AccountEvent::LinkAdded { idp, subject: subject.clone() }])
        })
        .await
    }

    pub async fn unlink_account(&self, account: Uuid, idp: Uuid, subject: &str, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        let subject = subject.to_owned();
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.links.contains(&(idp, subject.clone())) {
                return Err(IdentityError::NotFound("the link"));
            }
            Ok(vec![AccountEvent::LinkRemoved { idp, subject: subject.clone() }])
        })
        .await
    }

    /// The account an external identity is linked to.
    pub async fn account_by_link(&self, idp: Uuid, subject: &str) -> Result<Option<AccountInfo>> {
        let account = sqlx::query_scalar!(
            "SELECT account_id FROM account_links WHERE idp_id = $1 AND subject = $2",
            idp,
            subject,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        match account {
            Some(id) => Ok(Some(self.account(id).await?)),
            None => Ok(None),
        }
    }

    pub async fn account_links(&self, account: Uuid) -> Result<Vec<LinkInfo>> {
        let rows = sqlx::query!(
            "SELECT idp_id, subject, created_at FROM account_links WHERE account_id = $1 ORDER BY created_at",
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| LinkInfo { idp: row.idp_id, subject: row.subject, created_at: row.created_at })
            .collect())
    }

    /// A session for an account that logged in at an external identity provider – with a second factor if the
    /// provider said so. Only for accounts that are active in an active tenant.
    pub async fn create_external_session(
        &self,
        instance: Uuid,
        account: Uuid,
        multi_factor: bool,
        lifetime: Option<Duration>,
        client: &ClientMeta,
    ) -> Result<NewSession> {
        let info = self.account(account).await?;
        let tenant_active =
            self.tenants(instance).await?.iter().any(|tenant| tenant.id == info.tenant && tenant.active);
        if info.instance != instance || !info.active || !tenant_active {
            return Err(IdentityError::AccountDeactivated);
        }
        let mut checks = vec![CHECK_IDP.to_owned()];
        if multi_factor {
            checks.push(CHECK_IDP_MFA.to_owned());
        }
        let lifetime = lifetime.unwrap_or(crate::session::DEFAULT_LIFETIME).min(crate::session::MAX_LIFETIME);
        self.open_session(instance, info, checks, lifetime, client).await
    }

    pub async fn admin_account_links(&self, admin: &Admin, account: Uuid) -> Result<Vec<LinkInfo>> {
        self.admin_account(admin, account).await?;
        self.account_links(account).await
    }

    pub async fn admin_unlink_account(&self, admin: &Admin, account: Uuid, idp: Uuid, subject: &str) -> Result<()> {
        admin.require(Permission::AccountsManage)?;
        self.admin_account(admin, account).await?;
        self.unlink_account(account, idp, subject, &admin.creator()).await
    }
}
