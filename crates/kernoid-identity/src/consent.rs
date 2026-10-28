// SPDX-License-Identifier: AGPL-3.0-or-later
//! What an account agreed applications may have (RFC 0001, 7.2): asked for by applications that require it, and for
//! `offline_access`. A consent is an event of the account (`account.consent_granted`, `account.consent_revoked`);
//! withdrawing it, and the tokens issued on it, is up to the account and its administrators.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Identity, IdentityError, Result, account::AccountEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentInfo {
    pub application: Uuid,
    pub application_name: String,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Records that the account agreed to `scopes` for an application, in addition to what it agreed to before.
    pub async fn grant_consent(
        &self,
        account: Uuid,
        application: Uuid,
        scopes: &[String],
        creator: &str,
    ) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        let scopes = scopes.to_vec();
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            let mut all = state.consents.get(&application).cloned().unwrap_or_default();
            let before = all.len();
            for scope in &scopes {
                if !all.contains(scope) {
                    all.push(scope.clone());
                }
            }
            Ok(if all.len() == before && state.consents.contains_key(&application) {
                Vec::new()
            } else {
                vec![AccountEvent::ConsentGranted { application, scopes: all }]
            })
        })
        .await
    }

    pub async fn revoke_consent(&self, account: Uuid, application: Uuid, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.consents.contains_key(&application) {
                return Err(IdentityError::NotFound("the consent"));
            }
            Ok(vec![AccountEvent::ConsentRevoked { application }])
        })
        .await
    }

    /// The scopes the account agreed to for an application; `None` without a consent.
    pub async fn consent(&self, account: Uuid, application: Uuid) -> Result<Option<Vec<String>>> {
        sqlx::query_scalar!(
            "SELECT scopes FROM consents WHERE account_id = $1 AND application_id = $2",
            account,
            application,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)
    }

    pub async fn consents(&self, account: Uuid) -> Result<Vec<ConsentInfo>> {
        let rows = sqlx::query!(
            "SELECT c.application_id, a.name, c.scopes, c.granted_at FROM consents c
             JOIN applications a ON a.id = c.application_id
             WHERE c.account_id = $1 ORDER BY c.granted_at",
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| ConsentInfo {
                application: row.application_id,
                application_name: row.name,
                scopes: row.scopes,
                granted_at: row.granted_at,
            })
            .collect())
    }
}
