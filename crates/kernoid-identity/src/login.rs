// SPDX-License-Identifier: AGPL-3.0-or-later
//! Logins (RFC 0003, 2): an account is found by a native address, a username or its verified contact address – each
//! unique in the instance – in that order. Usernames and logging in with the contact address are the tenant's
//! choice (`tenant.login_policy_set`).

use uuid::Uuid;

use crate::{
    Address, Identity, IdentityError, Result,
    account::{Account, AccountEvent},
    role::{Admin, Permission},
    tenant::TenantEvent,
};

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

/// A username: 3–64 letters, digits, `.`, `-` and `_`, kept lower case; never an address.
pub fn valid_username(username: &str) -> Result<String> {
    let username = username.trim().to_lowercase();
    let length = username.chars().count();
    let allowed = |c: char| c.is_alphanumeric() || matches!(c, '.' | '-' | '_');
    if !(3..=64).contains(&length) || !username.chars().all(allowed) {
        return Err(IdentityError::Refused(
            "a username has 3 to 64 letters, digits, '.', '-' and '_' – and no '@'".into(),
        ));
    }
    Ok(username)
}

impl Identity {
    /// The account a login name finds at `instance` (RFC 0003, 2): a native address, a username, a verified contact
    /// address – in that order, each as the tenant allows.
    pub async fn find_login(&self, instance: Uuid, login: &str) -> Result<Option<Uuid>> {
        let login = login.trim();
        if let Ok(address) = Address::parse(login) {
            let native = sqlx::query_scalar!(
                "SELECT a.id FROM addresses ad JOIN accounts a ON a.id = ad.account_id
                 JOIN tenants t ON t.id = a.tenant_id WHERE ad.address = $1 AND t.instance_id = $2",
                address.as_str(),
                instance,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?;
            if native.is_some() {
                return Ok(native);
            }
            return sqlx::query_scalar!(
                "SELECT e.account_id FROM account_emails e JOIN accounts a ON a.id = e.account_id
                 JOIN tenants t ON t.id = a.tenant_id
                 WHERE e.instance_id = $1 AND e.email = $2 AND t.email_login",
                instance,
                address.as_str(),
            )
            .fetch_optional(self.pool())
            .await
            .map_err(store_error);
        }
        sqlx::query_scalar!(
            "SELECT u.account_id FROM account_usernames u JOIN accounts a ON a.id = u.account_id
             JOIN tenants t ON t.id = a.tenant_id
             WHERE u.instance_id = $1 AND u.username = $2 AND t.usernames",
            instance,
            login.to_lowercase(),
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)
    }

    /// Whether a login name is taken at `instance`, whatever the tenants allow – for registering.
    pub async fn login_taken(&self, instance: Uuid, login: &str) -> Result<bool> {
        let login = login.trim().to_lowercase();
        sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM addresses ad JOIN tenants t ON t.id = ad.tenant_id
                              WHERE ad.address = $2)
                   OR EXISTS (SELECT 1 FROM account_emails WHERE instance_id = $1 AND email = $2)
                   OR EXISTS (SELECT 1 FROM account_usernames WHERE instance_id = $1 AND username = $2) AS "taken!""#,
            instance,
            login,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)
    }

    /// Gives an account a username (the tenant must allow usernames), or takes it away.
    pub async fn set_username(&self, account: Uuid, username: Option<&str>, creator: &str) -> Result<()> {
        let username = username.map(valid_username).transpose()?;
        let (instance, tenant) = self.account_owner(account).await?;
        if let Some(username) = &username {
            if !self.tenant(instance, tenant).await?.state.login_policy.usernames {
                return Err(IdentityError::Refused("the tenant does not use usernames".into()));
            }
            let holder = sqlx::query_scalar!(
                "SELECT account_id FROM account_usernames WHERE instance_id = $1 AND username = $2",
                instance,
                username,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?;
            if holder.is_some_and(|holder| holder != account) || self.login_taken_by_address(username).await? {
                return Err(IdentityError::Exists("the username"));
            }
        }
        self.account_command(instance, tenant, account, creator, None, |state: &Account| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            crate::account::with_login(state)?;
            if state.username == username {
                return Ok(Vec::new());
            }
            Ok(vec![AccountEvent::UsernameSet { username: username.clone() }])
        })
        .await
    }

    async fn login_taken_by_address(&self, login: &str) -> Result<bool> {
        sqlx::query_scalar!(r#"SELECT EXISTS (SELECT 1 FROM addresses WHERE address = $1) AS "taken!""#, login)
            .fetch_one(self.pool())
            .await
            .map_err(store_error)
    }

    /// Sets the contact address – any domain. A verified one is a login and must not be another account's contact
    /// address or native address in the instance.
    pub async fn set_contact_email(
        &self,
        account: Uuid,
        email: Option<&str>,
        verified: bool,
        creator: &str,
    ) -> Result<()> {
        let email = email
            .map(|email| Address::parse(email).map_err(|error| IdentityError::Refused(error.to_string())))
            .transpose()?
            .map(|email| email.as_str().to_owned());
        let (instance, tenant) = self.account_owner(account).await?;
        if let Some(email) = email.as_deref().filter(|_| verified)
            && let Some(holder) = self.contact_holder(instance, email).await?
            && holder != account
        {
            return Err(IdentityError::Exists("an account with this address"));
        }
        self.account_command(instance, tenant, account, creator, None, |state: &Account| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            if state.email == email.clone().map(|email| (email, verified)) {
                return Ok(Vec::new());
            }
            Ok(vec![AccountEvent::EmailSet { email: email.clone(), verified }])
        })
        .await
    }

    /// The account an address belongs to in the instance: as a native address or a verified contact address.
    pub async fn contact_holder(&self, instance: Uuid, email: &str) -> Result<Option<Uuid>> {
        let email = email.trim().to_lowercase();
        sqlx::query_scalar!(
            r#"SELECT ad.account_id AS "id!" FROM addresses ad JOIN tenants t ON t.id = ad.tenant_id
               WHERE ad.address = $2 AND t.instance_id = $1
               UNION ALL
               SELECT account_id FROM account_emails WHERE instance_id = $1 AND email = $2
               LIMIT 1"#,
            instance,
            email,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)
    }

    /// Sets how a tenant's accounts log in.
    pub async fn set_login_policy(
        &self,
        tenant: Uuid,
        usernames: bool,
        email_login: bool,
        creator: &str,
    ) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            let policy = state.login_policy;
            if policy.usernames == usernames && policy.email_login == email_login {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::LoginPolicySet { usernames, email_login }])
        })
        .await
    }

    /// Creates an account without a native address (RFC 0003, 1) in `tenant`: for logins with a provider, a username
    /// or a verified contact address – and files, if the tenant's rules give them. Returns its id.
    pub async fn add_external_account(
        &self,
        tenant: Uuid,
        display_name: &str,
        email: Option<(&str, bool)>,
        creator: &str,
    ) -> Result<Uuid> {
        let display_name = crate::valid_name(display_name)?;
        let instance = self.tenant_instance(tenant).await?;
        let tenant_state = self.tenant(instance, tenant).await?.state;
        if !tenant_state.active {
            return Err(IdentityError::Refused("the tenant is deactivated".into()));
        }
        let email = email
            .map(|(email, verified)| {
                Address::parse(email)
                    .map(|email| (email.as_str().to_owned(), verified))
                    .map_err(|error| IdentityError::Refused(error.to_string()))
            })
            .transpose()?;
        if let Some((email, true)) = &email
            && self.contact_holder(instance, email).await?.is_some()
        {
            return Err(IdentityError::Exists("an account with this address"));
        }
        let (on, requested) = crate::services::initial(&tenant_state.service_policies, false);
        let id = Uuid::now_v7();
        self.account_command(instance, tenant, id, creator, None, |state: &Account| {
            if state.exists {
                return Err(IdentityError::Exists("the account"));
            }
            let mut events =
                vec![AccountEvent::ExternalAdded { display_name: display_name.clone(), services: on.clone() }];
            events.extend(requested.iter().map(|service| AccountEvent::ServiceRequested { service: *service }));
            if let Some((email, verified)) = &email {
                events.push(AccountEvent::EmailSet { email: Some(email.clone()), verified: *verified });
            }
            Ok(events)
        })
        .await?;
        Ok(id)
    }

    // Administration

    pub async fn admin_add_external_account(
        &self,
        admin: &Admin,
        display_name: &str,
        email: Option<&str>,
        username: Option<&str>,
    ) -> Result<Uuid> {
        admin.require(Permission::AccountsManage)?;
        // An administrator's word does not verify an address of another domain; the person confirms it later.
        let account = self
            .add_external_account(admin.tenant(), display_name, email.map(|e| (e, false)), &admin.creator())
            .await?;
        if let Some(username) = username {
            self.set_username(account, Some(username), &admin.creator()).await?;
        }
        Ok(account)
    }

    pub async fn admin_set_username(&self, admin: &Admin, account: Uuid, username: Option<&str>) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.set_username(account, username, &admin.creator()).await
    }

    pub async fn admin_set_contact_email(
        &self,
        admin: &Admin,
        account: Uuid,
        email: Option<&str>,
        verified: bool,
    ) -> Result<()> {
        self.managed_account(admin, account).await?;
        self.set_contact_email(account, email, verified, &admin.creator()).await
    }

    pub async fn admin_login_policy(&self, admin: &Admin) -> Result<crate::tenant::LoginPolicy> {
        admin.require(Permission::DirectoryRead)?;
        Ok(self.tenant(admin.instance(), admin.tenant()).await?.state.login_policy)
    }

    pub async fn admin_set_login_policy(&self, admin: &Admin, usernames: bool, email_login: bool) -> Result<()> {
        admin.require(Permission::PoliciesManage)?;
        self.set_login_policy(admin.tenant(), usernames, email_login, &admin.creator()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert_eq!(valid_username(" Max.Muster_67 ").unwrap(), "max.muster_67");
        assert!(valid_username("ma").is_err());
        assert!(valid_username("max@firma.de").is_err());
        assert!(valid_username("max muster").is_err());
    }
}
