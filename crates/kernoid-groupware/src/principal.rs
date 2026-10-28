// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts as calendar users (RFC 0004, 8.1): name and addresses for DAV principals and scheduling, read from the
//! identity read models.

use uuid::Uuid;

use crate::{Groupware, GroupwareError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalInfo {
    pub id: Uuid,
    pub tenant: Uuid,
    pub display_name: String,
    /// The account's addresses, the primary one first, lower case.
    pub addresses: Vec<String>,
}

impl Groupware {
    /// An active account with mail as a calendar user.
    pub async fn principal(&self, account: Uuid) -> Result<PrincipalInfo> {
        let row = sqlx::query!(
            r#"SELECT a.tenant_id, a.display_name,
                      coalesce(array_agg(lower(d.address) ORDER BY d.is_primary DESC, d.address)
                               FILTER (WHERE d.address IS NOT NULL), '{}') AS "addresses!"
               FROM accounts a LEFT JOIN addresses d ON d.account_id = a.id
               WHERE a.id = $1 AND a.active
               GROUP BY a.id"#,
            account,
        )
        .fetch_optional(self.pool())
        .await?
        .ok_or(GroupwareError::NotFound("the account"))?;
        Ok(PrincipalInfo {
            id: account,
            tenant: row.tenant_id,
            display_name: row.display_name,
            addresses: row.addresses,
        })
    }

    /// The active accounts with mail of a tenant whose name or address contains `text` (DAV
    /// `principal-property-search`), at most `limit`.
    pub async fn search_principals(&self, tenant: Uuid, text: &str, limit: i64) -> Result<Vec<PrincipalInfo>> {
        let pattern = format!("%{}%", text.to_lowercase().replace(['%', '_', '\\'], ""));
        let ids = sqlx::query_scalar!(
            r#"SELECT a.id FROM accounts a
               WHERE a.tenant_id = $1 AND a.active
                 AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')
                 AND (lower(a.display_name) LIKE $2
                      OR EXISTS (SELECT 1 FROM addresses d WHERE d.account_id = a.id AND lower(d.address) LIKE $2))
               ORDER BY a.display_name, a.id LIMIT $3"#,
            tenant,
            pattern,
            limit,
        )
        .fetch_all(self.pool())
        .await?;
        let mut principals = Vec::with_capacity(ids.len());
        for id in ids {
            principals.push(self.principal(id).await?);
        }
        Ok(principals)
    }

    /// The active account with mail in `tenant` that has `address`.
    pub async fn account_by_address(&self, tenant: Uuid, address: &str) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar!(
            "SELECT a.id FROM addresses d JOIN accounts a ON a.id = d.account_id
             WHERE lower(d.address) = $1 AND a.tenant_id = $2 AND a.active
               AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')",
            address.to_lowercase(),
            tenant,
        )
        .fetch_optional(self.pool())
        .await?)
    }
}
