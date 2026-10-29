// SPDX-License-Identifier: AGPL-3.0-or-later
//! App passwords (RFC 0002, 10.1): for mail programs, which cannot ask for a second factor. Made per device, shown
//! once, random – so a SHA-256 hash is enough, as for tokens. A mail login takes an app password, or the account's own
//! password only if the account needs no second factor: a password alone must not get around the second factor a
//! login in the browser asks for.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use kernoid_events::{InlineFuture, aggregate::CommandError, inline};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    Address, Identity, IdentityError, Result,
    account::{Account, AccountEvent, AccountInfo, project},
    services::Service,
    session::{FAILURES_PER_ADDRESS, FAILURES_PER_NAME, address_key, name_key},
};

/// App passwords one account may have.
const MAX_APP_PASSWORDS: usize = 25;
/// Letters of an app password: 24 from the base32 alphabet, 120 random bits.
const LENGTH: usize = 24;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPasswordInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// The hash of an app password, as typed: dashes and spaces do not count, nor does case.
fn hash(secret: &str) -> Vec<u8> {
    let normalized: String =
        secret.chars().filter(|c| !matches!(c, '-' | ' ')).map(|c| c.to_ascii_lowercase()).collect();
    Sha256::digest(normalized.as_bytes()).to_vec()
}

/// A new app password, in groups of four: `abcd-efgh-…`.
fn generate() -> Result<String> {
    let mut random = [0u8; LENGTH];
    getrandom::fill(&mut random).map_err(|_| IdentityError::Refused("no randomness available".into()))?;
    let letters: Vec<char> = random.iter().map(|byte| ALPHABET[usize::from(byte % 32)] as char).collect();
    Ok(letters.chunks(4).map(|group| group.iter().collect::<String>()).collect::<Vec<_>>().join("-"))
}

fn command_error(error: CommandError<IdentityError>) -> IdentityError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

impl Identity {
    /// Makes an app password named `name` for `account`; returns its id and the password – shown this once.
    pub async fn add_app_password(&self, account: Uuid, name: &str, creator: &str) -> Result<(Uuid, String)> {
        let name = crate::valid_name(name)?;
        let (instance, tenant) = self.account_owner(account).await?;
        let secret = generate()?;
        let (id, hashed, stored_name) = (Uuid::now_v7(), hash(&secret), name.clone());
        let store = inline(move |connection, events| {
            let (hashed, name) = (hashed.clone(), stored_name.clone());
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO account_app_passwords (id, account_id, name, hash) VALUES ($1, $2, $3, $4)",
                    id,
                    account,
                    name,
                    hashed,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                |state: &Account| {
                    if !state.exists {
                        return Err(IdentityError::NotFound("the account"));
                    }
                    crate::account::with_login(state)?;
                    if state.app_passwords.len() >= MAX_APP_PASSWORDS {
                        return Err(IdentityError::Refused(format!(
                            "an account has at most {MAX_APP_PASSWORDS} app passwords"
                        )));
                    }
                    Ok(vec![AccountEvent::AppPasswordAdded { id, name: name.clone() }])
                },
                store,
            )
            .await
            .map_err(command_error)?;
        Ok((id, secret))
    }

    pub async fn remove_app_password(&self, account: Uuid, id: Uuid, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.app_passwords.contains(&id) {
                return Err(IdentityError::NotFound("the app password"));
            }
            Ok(vec![AccountEvent::AppPasswordRemoved { id }])
        })
        .await
    }

    pub async fn app_passwords(&self, account: Uuid) -> Result<Vec<AppPasswordInfo>> {
        sqlx::query_as!(
            AppPasswordInfo,
            "SELECT id, name, created_at, last_used_at FROM account_app_passwords WHERE account_id = $1 ORDER BY created_at",
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)
    }

    /// An app password for the session's own account (needs a recent login).
    pub async fn add_own_app_password(&self, instance: Uuid, token: &str, name: &str) -> Result<(Uuid, String)> {
        let session = self.recent_session(instance, token).await?;
        let account = session.account.id;
        self.add_app_password(account, name, &format!("account:{account}")).await
    }

    pub async fn own_app_passwords(&self, instance: Uuid, token: &str) -> Result<Vec<AppPasswordInfo>> {
        let session = self.session(instance, token).await?;
        self.app_passwords(session.account.id).await
    }

    pub async fn remove_own_app_password(&self, instance: Uuid, token: &str, id: Uuid) -> Result<()> {
        let session = self.session(instance, token).await?;
        let account = session.account.id;
        self.remove_app_password(account, id, &format!("account:{account}")).await
    }

    /// A login of a mail program (submission, IMAP, POP3, CalDAV, CardDAV): a native address of an account with the
    /// service `mail` (RFC 0003, 4) and an app password – or the account's own password, if it needs no second
    /// factor. Failed attempts count like failed logins; every failure is the same `InvalidCredentials`.
    pub async fn mail_login(&self, login: &str, secret: &str, client: Option<IpAddr>) -> Result<AccountInfo> {
        self.program_login(login, secret, client, &[Service::Mail], None).await
    }

    /// A login of a program like [`Identity::mail_login`], for an account with any of `services` – JMAP takes
    /// accounts with mail or files (RFC 0005, 8). With the `instance` a request reached (HTTP: JMAP, WebDAV, DAV),
    /// the login name is found as at the login page – an address, or a username or contact address where the tenant
    /// allows them (RFC 0003, 2); without one (IMAP, POP3, SMTP), only an address finds the account: usernames and
    /// contact addresses are unique per instance only.
    pub async fn program_login(
        &self,
        login: &str,
        secret: &str,
        client: Option<IpAddr>,
        services: &[Service],
        instance: Option<Uuid>,
    ) -> Result<AccountInfo> {
        let services: Vec<String> = services.iter().map(|service| service.as_str().to_owned()).collect();
        let account = match instance {
            Some(instance) => self.find_login(instance, login).await?,
            None => match Address::parse(login) {
                Ok(address) => sqlx::query_scalar!(
                    r#"SELECT account_id AS "account_id!" FROM addresses WHERE address = $1"#,
                    address.as_str()
                )
                .fetch_optional(self.pool())
                .await
                .map_err(store_error)?,
                Err(_) => None,
            },
        };
        let row = match account {
            Some(account) => sqlx::query!(
                r#"SELECT t.instance_id, a.id, a.tenant_id
                   FROM accounts a JOIN tenants t ON t.id = a.tenant_id
                   WHERE a.id = $1
                     AND EXISTS (SELECT 1 FROM account_services s
                                 WHERE s.account_id = a.id AND s.service = ANY($2) AND s.state = 'on')"#,
                account,
                &services,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?,
            None => None,
        };
        let Some(row) = row else {
            // As long as a check of a real account: an unknown address must not show.
            let _ = self.authenticate(Uuid::nil(), login, secret).await;
            return Err(IdentityError::InvalidCredentials);
        };
        let instance = row.instance_id;
        let mut keys = vec![(name_key(login), FAILURES_PER_NAME)];
        if let Some(address) = client {
            keys.push((address_key(address), FAILURES_PER_ADDRESS));
        }
        for (key, limit) in &keys {
            self.refuse_if_throttled(instance, key, *limit).await?;
        }
        let app_password = sqlx::query_scalar!(
            "UPDATE account_app_passwords SET last_used_at = now() WHERE account_id = $1 AND hash = $2 RETURNING id",
            row.id,
            hash(secret),
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        let result = if app_password.is_some() {
            self.account_info(row.id).await
        } else if self.password_suffices(row.id).await? {
            self.authenticate(instance, login, secret).await
        } else {
            Err(IdentityError::InvalidCredentials)
        };
        match result {
            Err(IdentityError::InvalidCredentials) => {
                for (key, _) in &keys {
                    self.count_failure(instance, key).await?;
                }
                Err(IdentityError::InvalidCredentials)
            }
            Err(error) => Err(error),
            Ok(account) => {
                sqlx::query!("DELETE FROM login_failures WHERE instance_id = $1 AND key = $2", instance, keys[0].0)
                    .execute(self.pool())
                    .await
                    .map_err(store_error)?;
                if !account.active || !self.tenant_active(account.tenant).await? {
                    return Err(IdentityError::AccountDeactivated);
                }
                Ok(account)
            }
        }
    }

    /// Whether the account's own password may log a mail program in: it has no second factor and needs none.
    async fn password_suffices(&self, account: Uuid) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT t.mfa_required,
                      (EXISTS (SELECT 1 FROM account_totp WHERE account_id = a.id AND confirmed_at IS NOT NULL)
                       OR EXISTS (SELECT 1 FROM account_passkeys WHERE account_id = a.id)) AS "has_factor!"
               FROM accounts a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1"#,
            account,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        Ok(!row.mfa_required && !row.has_factor)
    }

    async fn account_info(&self, account: Uuid) -> Result<AccountInfo> {
        let row = sqlx::query!(
            r#"SELECT t.instance_id, a.tenant_id, a.id, a.display_name, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!", a.primary_address IS NOT NULL AS "native!", a.active, a.kind
             FROM accounts a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1"#,
            account,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)?;
        Ok(AccountInfo {
            instance: row.instance_id,
            tenant: row.tenant_id,
            id: row.id,
            display_name: row.display_name,
            address: row.primary_address,
            native: row.native,
            active: row.active,
            shared: row.kind == "shared",
            drive: row.kind == "drive",
        })
    }

    async fn tenant_active(&self, tenant: Uuid) -> Result<bool> {
        sqlx::query_scalar!("SELECT active FROM tenants WHERE id = $1", tenant)
            .fetch_one(self.pool())
            .await
            .map_err(store_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_passwords_are_random_and_typed_loosely() {
        let secret = generate().unwrap();
        assert_eq!(secret.len(), LENGTH + LENGTH / 4 - 1);
        assert_ne!(secret, generate().unwrap());
        assert_eq!(hash(&secret), hash(&secret.to_uppercase().replace('-', " ")));
    }
}
