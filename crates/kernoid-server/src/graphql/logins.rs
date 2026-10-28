// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts, logins and services in GraphQL (RFC 0003) – the same operations and checks as the REST routes in
//! `crate::registration`, `crate::federation` and `crate::admin::logins`.

use std::time::Duration;

use async_graphql::{Context, Object, SimpleObject};
use kernoid_identity::{
    DomainName, Identity, IdentityError,
    registration::NewRegistration,
    services::{Assign, Service, ServicePolicy},
    session::ClientMeta,
};
use kernoid_oidc::Oidc;

use super::{
    ExchangedIdpLogin, IdentityProviderSummary,
    admin::{admin, uuid},
    error, instance, oidc_error, token,
};
use crate::{AppState, Client};

#[derive(Debug, SimpleObject)]
pub struct RegistrationOptions {
    /// People without an address of their own may register.
    open: bool,
    /// Domains on which new accounts may take an address – a mailbox.
    domains: Vec<String>,
    usernames: bool,
    /// kernoid can send the code; without it, registering works only with providers.
    by_email: bool,
}

#[derive(Debug, SimpleObject)]
pub struct LinkProposal {
    email: String,
    provider: String,
    may_register: bool,
}

#[derive(Debug, SimpleObject)]
pub struct AccountService {
    service: String,
    /// `on` or `requested`.
    state: String,
}

#[derive(Debug, SimpleObject)]
pub struct LoginPolicy {
    usernames: bool,
    email_login: bool,
}

#[derive(Debug, SimpleObject)]
pub struct TenantRegistration {
    allowed: bool,
    domains: Vec<String>,
}

#[derive(Debug, SimpleObject)]
pub struct ServicePolicyObject {
    service: String,
    /// `none`, `native` or `all`.
    assign: String,
    approval: bool,
}

#[derive(Debug, Default)]
pub struct LoginsQuery;

#[Object]
impl LoginsQuery {
    /// What registering offers at this instance.
    async fn registration_options(&self, context: &Context<'_>) -> async_graphql::Result<RegistrationOptions> {
        let state = context.data::<AppState>()?;
        let options = state.identity.registration_options(instance(context)?.id).await.map_err(error)?;
        Ok(RegistrationOptions {
            open: options.open,
            domains: options.domains,
            usernames: options.usernames,
            by_email: state.notification_from.is_some() && state.jmap.is_some(),
        })
    }

    /// The providers offered to everyone on the login page.
    async fn login_providers(&self, context: &Context<'_>) -> async_graphql::Result<Vec<IdentityProviderSummary>> {
        let oidc = context.data::<Oidc>()?;
        let list = oidc.open_providers(instance(context)?.id).await.map_err(oidc_error)?;
        Ok(list.into_iter().map(|idp| IdentityProviderSummary { id: idp.id.to_string(), name: idp.name }).collect())
    }

    /// What a provider login that found an account with its verified address proposes; does not use the code up.
    async fn link_proposal(&self, context: &Context<'_>, login: String) -> async_graphql::Result<LinkProposal> {
        let oidc = context.data::<Oidc>()?;
        let proposal = oidc.link_proposal(instance(context)?.id, &login).await.map_err(oidc_error)?;
        Ok(LinkProposal { email: proposal.email, provider: proposal.provider, may_register: proposal.may_register })
    }

    /// The services of an account (needs `directory.read`).
    async fn account_services(
        &self,
        context: &Context<'_>,
        account: String,
    ) -> async_graphql::Result<Vec<AccountService>> {
        let (identity, admin) = admin(context).await?;
        let list = identity.admin_services(&admin, uuid(&account, "the account")?).await.map_err(error)?;
        Ok(list
            .into_iter()
            .map(|(service, state)| AccountService { service: service.as_str().into(), state: state.as_str().into() })
            .collect())
    }

    /// How the tenant's accounts log in (needs `directory.read`).
    async fn login_policy(&self, context: &Context<'_>) -> async_graphql::Result<LoginPolicy> {
        let (identity, admin) = admin(context).await?;
        let policy = identity.admin_login_policy(&admin).await.map_err(error)?;
        Ok(LoginPolicy { usernames: policy.usernames, email_login: policy.email_login })
    }

    /// Whether people may register with the tenant, and on which domains (needs `directory.read`).
    async fn tenant_registration(&self, context: &Context<'_>) -> async_graphql::Result<TenantRegistration> {
        let (identity, admin) = admin(context).await?;
        let (allowed, domains) = identity.admin_registration(&admin).await.map_err(error)?;
        Ok(TenantRegistration { allowed, domains })
    }

    /// The tenant's rules for each service (needs `directory.read`).
    async fn service_policies(&self, context: &Context<'_>) -> async_graphql::Result<Vec<ServicePolicyObject>> {
        let (identity, admin) = admin(context).await?;
        let list = identity.admin_service_policies(&admin).await.map_err(error)?;
        Ok(list
            .into_iter()
            .map(|(service, rule)| ServicePolicyObject {
                service: service.as_str().into(),
                assign: rule.assign.as_str().into(),
                approval: rule.approval,
            })
            .collect())
    }
}

#[derive(Debug, Default)]
pub struct LoginsMutation;

#[Object]
impl LoginsMutation {
    /// Starts a registration and sends a code to the email address; returns the registration's id.
    async fn register(
        &self,
        context: &Context<'_>,
        email: String,
        password: String,
        display_name: String,
        native_address: Option<String>,
        username: Option<String>,
    ) -> async_graphql::Result<String> {
        let state = context.data::<AppState>()?;
        let client = context.data_opt::<Client>().map(|client| client.address);
        let new = NewRegistration {
            email: &email,
            password: &password,
            display_name: &display_name,
            native_address: native_address.as_deref(),
            username: username.as_deref(),
        };
        let id = crate::registration::begin(state, instance(context)?.id, new, client).await.map_err(error)?;
        Ok(id.to_string())
    }

    /// Finishes a registration with the code; returns the new account's id.
    async fn confirm_registration(
        &self,
        context: &Context<'_>,
        id: String,
        code: String,
    ) -> async_graphql::Result<String> {
        let identity = context.data::<Identity>()?;
        let id = uuid(&id, "the registration").map_err(|_| error(IdentityError::InvalidCode))?;
        let account = identity.finish_registration(instance(context)?.id, id, &code).await.map_err(error)?;
        Ok(account.to_string())
    }

    /// Links the provider login of a proposal to the bearer token's account.
    async fn confirm_idp_link(&self, context: &Context<'_>, login: String) -> async_graphql::Result<bool> {
        let oidc = context.data::<Oidc>()?;
        oidc.confirm_link(instance(context)?.id, &login, token(context)?).await.map_err(oidc_error)?;
        Ok(true)
    }

    /// Creates a separate account for the provider login of a proposal, where registration is open, and logs it in.
    async fn register_instead(
        &self,
        context: &Context<'_>,
        login: String,
        lifetime_seconds: Option<u64>,
    ) -> async_graphql::Result<ExchangedIdpLogin> {
        let oidc = context.data::<Oidc>()?;
        let meta = context.data::<ClientMeta>()?;
        let lifetime = lifetime_seconds.map(Duration::from_secs);
        let result = oidc.register_instead(instance(context)?.id, &login, lifetime, meta).await.map_err(oidc_error)?;
        Ok(ExchangedIdpLogin { session: result.session.into(), auth_request: result.auth_request })
    }

    /// Starts linking a provider to the bearer token's account; returns where to send the browser.
    async fn start_idp_link(&self, context: &Context<'_>, identity_provider: String) -> async_graphql::Result<String> {
        let oidc = context.data::<Oidc>()?;
        let idp = uuid(&identity_provider, "the identity provider")?;
        oidc.start_idp_link(&instance(context)?, token(context)?, idp).await.map_err(oidc_error)
    }

    /// Creates an account without an address of the tenant (needs `accounts.manage`); returns its id.
    async fn add_external_account(
        &self,
        context: &Context<'_>,
        display_name: String,
        email: Option<String>,
        username: Option<String>,
    ) -> async_graphql::Result<String> {
        let (identity, admin) = admin(context).await?;
        let id = identity
            .admin_add_external_account(&admin, &display_name, email.as_deref(), username.as_deref())
            .await
            .map_err(error)?;
        Ok(id.to_string())
    }

    /// Grants a service – `mail` or `files` (needs `accounts.manage`).
    async fn grant_service(
        &self,
        context: &Context<'_>,
        account: String,
        service: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let service = Service::parse(&service).map_err(error)?;
        identity.admin_grant_service(&admin, uuid(&account, "the account")?, service).await.map_err(error)?;
        Ok(true)
    }

    /// Takes a service away (needs `accounts.manage`).
    async fn revoke_service(
        &self,
        context: &Context<'_>,
        account: String,
        service: String,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let service = Service::parse(&service).map_err(error)?;
        identity.admin_revoke_service(&admin, uuid(&account, "the account")?, service).await.map_err(error)?;
        Ok(true)
    }

    /// Gives an account a username, or takes it away with null (needs `accounts.manage`).
    async fn set_username(
        &self,
        context: &Context<'_>,
        account: String,
        username: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity
            .admin_set_username(&admin, uuid(&account, "the account")?, username.as_deref())
            .await
            .map_err(error)?;
        Ok(true)
    }

    /// Sets an account's contact address (needs `accounts.manage`).
    async fn set_contact_email(
        &self,
        context: &Context<'_>,
        account: String,
        email: Option<String>,
        #[graphql(default)] verified: bool,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let account = uuid(&account, "the account")?;
        identity.admin_set_contact_email(&admin, account, email.as_deref(), verified).await.map_err(error)?;
        Ok(true)
    }

    /// Sets how the tenant's accounts log in (needs `policies.manage`).
    async fn set_login_policy(
        &self,
        context: &Context<'_>,
        usernames: bool,
        email_login: bool,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        identity.admin_set_login_policy(&admin, usernames, email_login).await.map_err(error)?;
        Ok(true)
    }

    /// Opens or closes registration and names its domains (needs `policies.manage`).
    async fn set_tenant_registration(
        &self,
        context: &Context<'_>,
        allowed: bool,
        #[graphql(default)] domains: Vec<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let domains = domains
            .iter()
            .map(|domain| DomainName::parse(domain).map_err(|e| error(IdentityError::Refused(e.to_string()))))
            .collect::<async_graphql::Result<Vec<_>>>()?;
        identity.admin_set_registration(&admin, allowed, &domains).await.map_err(error)?;
        Ok(true)
    }

    /// Sets who gets a service when an account is created, and whether it needs approval (needs `policies.manage`).
    async fn set_service_policy(
        &self,
        context: &Context<'_>,
        service: String,
        assign: String,
        approval: bool,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let service = Service::parse(&service).map_err(error)?;
        let rule = ServicePolicy { assign: Assign::parse(&assign).map_err(error)?, approval };
        identity.admin_set_service_policy(&admin, service, rule).await.map_err(error)?;
        Ok(true)
    }

    /// Names the tenant where people without an address of a tenant register (needs `instance.manage`).
    async fn set_registration_tenant(
        &self,
        context: &Context<'_>,
        tenant: Option<String>,
    ) -> async_graphql::Result<bool> {
        let (identity, admin) = admin(context).await?;
        let tenant = tenant.as_deref().map(|tenant| uuid(tenant, "the tenant")).transpose()?;
        identity.admin_set_registration_tenant(&admin, tenant).await.map_err(error)?;
        Ok(true)
    }
}
