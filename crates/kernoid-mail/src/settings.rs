// SPDX-License-Identifier: AGPL-3.0-or-later
//! Settings of an account's mail store, chosen by its owner: how long its Trash keeps emails (none: the tenant's
//! days; RFC 0002, 13.2) and the address it sends from unless it picks another – one of its own, or of a group it
//! may send as (9.2).

use uuid::Uuid;

use crate::{Mail, MailError, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailSettings {
    /// Days the account's Trash keeps an email; none follows the tenant.
    pub trash_retention_days: Option<i32>,
    /// The tenant's days, for showing what "none" means; none keeps for good.
    pub tenant_trash_retention_days: Option<i32>,
    /// The address new emails come from; none means the account's primary address.
    pub default_from: Option<String>,
}

impl Mail {
    pub async fn settings(&self, account: Uuid) -> Result<MailSettings> {
        let row = sqlx::query!(
            "SELECT ma.trash_retention_days, ma.default_from, t.trash_retention_days AS tenant_days
             FROM mail_accounts ma JOIN tenants t ON t.id = ma.tenant_id
             WHERE ma.account_id = $1",
            account,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MailError::NotFound("the mail store"))?;
        Ok(MailSettings {
            trash_retention_days: row.trash_retention_days,
            tenant_trash_retention_days: row.tenant_days,
            default_from: row.default_from,
        })
    }

    /// Sets both settings; `default_from` must be an address the account may send from.
    pub async fn set_settings(
        &self,
        account: Uuid,
        trash_retention_days: Option<i32>,
        default_from: Option<&str>,
    ) -> Result<()> {
        if let Some(days) = trash_retention_days
            && !(1..=3650).contains(&days)
        {
            return Err(MailError::Invalid("the Trash keeps emails for 1 to 3650 days".into()));
        }
        let default_from = match default_from.map(str::trim).filter(|address| !address.is_empty()) {
            None => None,
            Some(address) => {
                let address = address.to_lowercase();
                let (_, own) = self.account_addresses(account).await?;
                let groups = self.group_sender_addresses(account).await?;
                let allowed = own
                    .iter()
                    .chain(groups.iter().map(|(_, address)| address))
                    .any(|known| known.eq_ignore_ascii_case(&address));
                if !allowed {
                    return Err(MailError::Invalid(format!("{address} is not an address this account may send from")));
                }
                Some(address)
            }
        };
        let updated = sqlx::query!(
            "UPDATE mail_accounts SET trash_retention_days = $2, default_from = $3 WHERE account_id = $1",
            account,
            trash_retention_days,
            default_from,
        )
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(MailError::NotFound("the mail store"));
        }
        Ok(())
    }
}
