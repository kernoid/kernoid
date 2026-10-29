// SPDX-License-Identifier: AGPL-3.0-or-later
//! The language of the emails kernoid writes itself – invitations, notices of files added through links: an account's
//! own choice (`account.language_set`), else its tenant's (`tenant.language_set`), else English. The apps choose
//! their language from the browser; this is only for what kernoid sends.

use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    account::AccountEvent,
    role::{Admin, Permission},
    tenant::TenantEvent,
};

/// The languages kernoid writes in, by their codes (BCP 47 primary tags).
pub const LANGUAGES: &[&str] = &["en", "de"];

/// English, when nothing else is chosen.
pub const DEFAULT: &str = "en";

fn checked(language: Option<&str>) -> Result<Option<String>> {
    match language {
        None => Ok(None),
        Some(code) => {
            let code = code.trim().to_ascii_lowercase();
            if LANGUAGES.contains(&code.as_str()) {
                Ok(Some(code))
            } else {
                Err(IdentityError::Refused(format!("the language is one of {}", LANGUAGES.join(", "))))
            }
        }
    }
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Sets the language of the emails kernoid writes to `account`; `None` for its tenant's.
    pub async fn set_account_language(&self, account: Uuid, language: Option<&str>, creator: &str) -> Result<()> {
        let language = checked(language)?;
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            if state.language == language {
                return Ok(Vec::new());
            }
            Ok(vec![AccountEvent::LanguageSet { language: language.clone() }])
        })
        .await
    }

    /// The same for the token's own account.
    pub async fn set_own_language(&self, instance: Uuid, token: &str, language: Option<&str>) -> Result<()> {
        let session = self.session(instance, token).await?;
        self.set_account_language(session.account.id, language, &format!("account:{}", session.account.id)).await
    }

    /// The account's own choice, and the language its emails are written in.
    pub async fn account_language(&self, account: Uuid) -> Result<(Option<String>, String)> {
        let row = sqlx::query!(
            "SELECT a.language AS own, t.language AS tenant FROM accounts a JOIN tenants t ON t.id = a.tenant_id
             WHERE a.id = $1",
            account,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the account"))?;
        let used = row.own.clone().or(row.tenant).unwrap_or_else(|| DEFAULT.to_owned());
        Ok((row.own, used))
    }

    /// The language of the token's own account: its choice, and what is used.
    pub async fn own_language(&self, instance: Uuid, token: &str) -> Result<(Option<String>, String)> {
        let session = self.session(instance, token).await?;
        self.account_language(session.account.id).await
    }

    /// Sets the language of the emails kernoid writes to the tenant's accounts that chose none; `None` for English.
    pub async fn set_tenant_language(&self, tenant: Uuid, language: Option<&str>, creator: &str) -> Result<()> {
        let language = checked(language)?;
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if state.language == language {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::LanguageSet { language: language.clone() }])
        })
        .await
    }

    pub async fn tenant_language(&self, tenant: Uuid) -> Result<Option<String>> {
        sqlx::query_scalar!("SELECT language FROM tenants WHERE id = $1", tenant)
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?
            .ok_or(IdentityError::NotFound("the tenant"))
    }

    pub async fn admin_tenant_language(&self, admin: &Admin) -> Result<Option<String>> {
        admin.require(Permission::DirectoryRead)?;
        self.tenant_language(admin.tenant()).await
    }

    pub async fn admin_set_tenant_language(&self, admin: &Admin, language: Option<&str>) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.set_tenant_language(admin.tenant(), language, &admin.creator()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_are_checked() {
        assert_eq!(checked(Some(" DE ")).unwrap(), Some("de".to_owned()));
        assert_eq!(checked(None).unwrap(), None);
        assert!(checked(Some("fr")).is_err());
    }
}
