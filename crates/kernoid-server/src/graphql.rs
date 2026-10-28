// SPDX-License-Identifier: AGPL-3.0-or-later
//! The GraphQL API at `/graphql`, next to the REST API: the same operations, for clients that prefer to ask for
//! exactly the fields they need. Depth and complexity of queries are limited, so that one query cannot occupy the
//! server. Errors carry a code in `extensions.code` (e.g. `UNAUTHENTICATED`, `TOO_MANY_ATTEMPTS` with `retryAfter`).

use std::time::Duration;

use async_graphql::{Context, EmptySubscription, ErrorExtensions, Object, Schema, SimpleObject};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{Extension, extract::State, http::HeaderMap, response::IntoResponse};
use chrono::{DateTime, Utc};
use kernoid_identity::{
    Identity, IdentityError, InstanceInfo,
    account::AccountInfo,
    session::{ClientMeta, SessionInfo},
};

use kernoid_oidc::{Oidc, OidcError};
use uuid::Uuid;

use crate::{AppState, Client, sessions};

mod admin;
mod collections;
mod files;
mod logins;
mod mail;

pub type ApiSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

/// Every query: sessions and login, and administration.
#[derive(async_graphql::MergedObject, Default)]
pub struct QueryRoot(
    Query,
    admin::AdminQuery,
    mail::MailQuery,
    logins::LoginsQuery,
    collections::CollectionsQuery,
    files::FilesQuery,
);

#[derive(async_graphql::MergedObject, Default)]
pub struct MutationRoot(
    Mutation,
    admin::AdminMutation,
    mail::MailMutation,
    logins::LoginsMutation,
    collections::CollectionsMutation,
    files::FilesMutation,
);

pub fn schema() -> ApiSchema {
    Schema::build(QueryRoot::default(), MutationRoot::default(), EmptySubscription)
        .limit_depth(16)
        .limit_complexity(1_000)
        .finish()
}

/// The bearer token of the request, if any.
struct BearerToken(String);

/// An identity error as a GraphQL error with a code; internal errors are logged, never shown.
fn error(error: IdentityError) -> async_graphql::Error {
    let code = match &error {
        IdentityError::InvalidCredentials
        | IdentityError::InvalidSession
        | IdentityError::InvalidCode
        | IdentityError::PasskeyRejected => "UNAUTHENTICATED",
        IdentityError::AccountDeactivated | IdentityError::Forbidden(_) => "FORBIDDEN",
        IdentityError::RecentLoginRequired => "LOGIN_REQUIRED",
        IdentityError::MfaRequired => "MFA_REQUIRED",
        IdentityError::TooManyAttempts { .. } => "TOO_MANY_ATTEMPTS",
        IdentityError::NotFound(_) => "NOT_FOUND",
        IdentityError::Exists(_) | IdentityError::DomainTaken(_) | IdentityError::AddressTaken(_) => "CONFLICT",
        IdentityError::Refused(_) | IdentityError::Verification(_) => "BAD_REQUEST",
        IdentityError::Store(store) => {
            tracing::error!(error = %store, "identity store");
            return async_graphql::Error::new("unavailable").extend_with(|_, e| e.set("code", "UNAVAILABLE"));
        }
    };
    let retry_after = match &error {
        IdentityError::TooManyAttempts { retry_after } => Some(retry_after.as_secs()),
        _ => None,
    };
    async_graphql::Error::new(error.to_string()).extend_with(|_, extensions| {
        extensions.set("code", code);
        if let Some(seconds) = retry_after {
            extensions.set("retryAfter", seconds);
        }
    })
}

fn instance(context: &Context<'_>) -> async_graphql::Result<InstanceInfo> {
    context.data_opt::<InstanceInfo>().cloned().ok_or_else(|| {
        async_graphql::Error::new("no instance is reached under this host")
            .extend_with(|_, e| e.set("code", "NOT_FOUND"))
    })
}

fn token<'a>(context: &'a Context<'_>) -> async_graphql::Result<&'a str> {
    context.data_opt::<BearerToken>().map(|token| token.0.as_str()).ok_or_else(|| error(IdentityError::InvalidSession))
}

#[derive(Debug, Default)]
pub struct Query;

#[derive(Debug, Default)]
pub struct Mutation;

#[derive(Debug, SimpleObject)]
pub struct Version {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, SimpleObject)]
pub struct Instance {
    id: String,
    name: String,
    primary_domain: String,
}

#[derive(Debug, SimpleObject)]
pub struct Account {
    id: String,
    tenant: String,
    address: String,
    display_name: String,
}

impl From<AccountInfo> for Account {
    fn from(account: AccountInfo) -> Self {
        Self {
            id: account.id.to_string(),
            tenant: account.tenant.to_string(),
            address: account.address,
            display_name: account.display_name,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct Session {
    id: String,
    account: Account,
    /// The checks the session passed, e.g. `password`.
    checks: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<SessionInfo> for Session {
    fn from(session: SessionInfo) -> Self {
        Self {
            id: session.id.to_string(),
            account: session.account.into(),
            checks: session.checks,
            created_at: session.created_at,
            expires_at: session.expires_at,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct AuthRequest {
    id: String,
    /// The name of the application asking.
    application: String,
    scopes: Vec<String>,
    /// `none`, `login`, `consent`, `select_account` – what the login UI must respect.
    prompt: Vec<String>,
    /// The session may be at most this many seconds old.
    max_age: Option<i32>,
    expires_at: DateTime<Utc>,
}

/// An OpenID Connect error as a GraphQL error with a code.
fn oidc_error(error: OidcError) -> async_graphql::Error {
    let code = match error {
        OidcError::Identity(identity) => return self::error(identity),
        OidcError::AuthRequestNotFound => "NOT_FOUND",
        OidcError::AccessDenied(_) => "FORBIDDEN",
        OidcError::LoginRequired => "LOGIN_REQUIRED",
        OidcError::MfaRequired => "MFA_REQUIRED",
        OidcError::ConsentRequired => "CONSENT_REQUIRED",
        OidcError::Internal(ref message) => {
            tracing::error!(%message, "oidc");
            return async_graphql::Error::new("unavailable").extend_with(|_, e| e.set("code", "UNAVAILABLE"));
        }
        _ => "BAD_REQUEST",
    };
    async_graphql::Error::new(error.to_string()).extend_with(|_, e| e.set("code", code))
}

/// A WebAuthn challenge: `options` for the browser, `id` to send back with its answer.
#[derive(Debug, SimpleObject)]
pub struct PasskeyChallenge {
    id: String,
    options: async_graphql::Json<serde_json::Value>,
}

impl From<kernoid_identity::passkey::Challenge> for PasskeyChallenge {
    fn from(challenge: kernoid_identity::passkey::Challenge) -> Self {
        Self { id: challenge.id, options: async_graphql::Json(challenge.options) }
    }
}

#[derive(Debug, SimpleObject)]
pub struct TotpSetup {
    /// The secret in base32.
    secret: String,
    /// `otpauth://` URI for a QR code.
    uri: String,
    /// The URI as a QR code: an SVG image as a `data:` URL.
    qr_code: String,
}

/// The second factors of an account.
#[derive(Debug, SimpleObject)]
pub struct SecondFactors {
    totp: bool,
    passkeys: i64,
    recovery_codes_left: i64,
    /// The tenant requires a second factor.
    required: bool,
    /// The account has none yet and may log in without one until then.
    setup_due: Option<DateTime<Utc>>,
}

#[derive(Debug, SimpleObject)]
pub struct Passkey {
    id: String,
    name: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

fn relying_party(context: &Context<'_>) -> async_graphql::Result<kernoid_identity::passkey::RelyingParty> {
    Ok(crate::mfa::passkey_relying_party(context.data::<Oidc>()?, &instance(context)?))
}

impl From<kernoid_identity::session::NewSession> for CreatedSession {
    fn from(session: kernoid_identity::session::NewSession) -> Self {
        Self {
            id: session.id.to_string(),
            token: session.token,
            expires_at: session.expires_at,
            account: session.account.into(),
            device_token: session.device_token,
        }
    }
}

#[derive(Debug, SimpleObject)]
pub struct IdentityProviderSummary {
    id: String,
    name: String,
}

#[derive(Debug, SimpleObject)]
pub struct ExchangedIdpLogin {
    session: CreatedSession,
    /// The auth request the login was for – finish it next.
    auth_request: Option<String>,
}

#[derive(Debug, SimpleObject)]
pub struct CreatedSession {
    id: String,
    /// The session token: shown this once, sent as `Authorization: Bearer <token>`.
    token: String,
    expires_at: DateTime<Utc>,
    account: Account,
    /// After a password login: keep it for this address and send it with the next login (`deviceToken`).
    device_token: Option<String>,
}

#[Object]
impl Query {
    /// The instance reached under the host of this request; null if there is none.
    async fn instance(&self, context: &Context<'_>) -> Option<Instance> {
        context.data_opt::<InstanceInfo>().map(|info| Instance {
            id: info.id.to_string(),
            name: info.name.clone(),
            primary_domain: info.primary_domain.clone(),
        })
    }

    /// The name and version of this kernoid.
    async fn version(&self) -> Version {
        Version { name: "kernoid", version: env!("CARGO_PKG_VERSION") }
    }

    /// A pending OpenID Connect auth request – for the login UI to show who is asking.
    async fn auth_request(&self, context: &Context<'_>, id: String) -> async_graphql::Result<AuthRequest> {
        let oidc = context.data::<Oidc>()?;
        let info = oidc.auth_request(&instance(context)?, &id).await.map_err(oidc_error)?;
        Ok(AuthRequest {
            id: info.id,
            application: info.application,
            scopes: info.scopes,
            prompt: info.prompt,
            max_age: info.max_age,
            expires_at: info.expires_at,
        })
    }

    /// The second factors of the session's account.
    async fn second_factors(&self, context: &Context<'_>) -> async_graphql::Result<SecondFactors> {
        let identity = context.data::<Identity>()?;
        let factors = identity.second_factors(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(SecondFactors {
            totp: factors.totp,
            passkeys: factors.passkeys,
            recovery_codes_left: factors.recovery_codes_left,
            required: factors.required,
            setup_due: factors.setup_due,
        })
    }

    /// The passkeys of the session's account.
    async fn passkeys(&self, context: &Context<'_>) -> async_graphql::Result<Vec<Passkey>> {
        let identity = context.data::<Identity>()?;
        let list = identity.passkeys(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(list
            .into_iter()
            .map(|p| Passkey {
                id: p.id.to_string(),
                name: p.name,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            })
            .collect())
    }

    /// The session of the bearer token.
    async fn session(&self, context: &Context<'_>) -> async_graphql::Result<Session> {
        let identity = context.data::<Identity>()?;
        let session = identity.session(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(session.into())
    }

    /// Where an address logs in: the identity provider its domain is routed to, if any.
    async fn login_options(
        &self,
        context: &Context<'_>,
        address: String,
    ) -> async_graphql::Result<Option<IdentityProviderSummary>> {
        let oidc = context.data::<Oidc>()?;
        let found = oidc.login_options(instance(context)?.id, &address).await.map_err(oidc_error)?;
        Ok(found.map(|idp| IdentityProviderSummary { id: idp.id.to_string(), name: idp.name }))
    }

    /// The applications the bearer token's account agreed to.
    async fn my_consents(&self, context: &Context<'_>) -> async_graphql::Result<Vec<admin::Consent>> {
        let identity = context.data::<Identity>()?;
        let session = identity.session(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(identity.consents(session.account.id).await.map_err(error)?.into_iter().map(Into::into).collect())
    }

    /// The valid sessions of the bearer token's account, newest first.
    async fn my_sessions(&self, context: &Context<'_>) -> async_graphql::Result<Vec<admin::SessionSummaryObject>> {
        let identity = context.data::<Identity>()?;
        let list = identity.own_sessions(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(list.into_iter().map(Into::into).collect())
    }
}

#[Object]
impl Mutation {
    /// Logs in: checks address and password at the instance of this host and creates a session.
    async fn create_session(
        &self,
        context: &Context<'_>,
        address: String,
        password: String,
        lifetime_seconds: Option<u64>,
        device_token: Option<String>,
    ) -> async_graphql::Result<CreatedSession> {
        let identity = context.data::<Identity>()?;
        let client = context.data::<ClientMeta>()?;
        let lifetime = lifetime_seconds.map(Duration::from_secs);
        let instance = instance(context)?.id;
        let device = device_token.as_deref();
        let session = identity
            .create_session_on_device(instance, &address, &password, lifetime, client, device)
            .await
            .map_err(error)?;
        Ok(session.into())
    }

    /// Finishes an auth request with the session of the bearer token; returns the URL to send the browser to. With
    /// `CONSENT_REQUIRED`, show what the application asks for and finish again with `consent: true`.
    async fn finish_auth_request(
        &self,
        context: &Context<'_>,
        id: String,
        consent: Option<bool>,
    ) -> async_graphql::Result<String> {
        let oidc = context.data::<Oidc>()?;
        oidc.finish(&instance(context)?, &id, token(context)?, consent.unwrap_or(false)).await.map_err(oidc_error)
    }

    /// Withdraws one's own consent to an application, and the application's tokens – offline access included.
    async fn revoke_my_consent(&self, context: &Context<'_>, application: String) -> async_graphql::Result<bool> {
        let oidc = context.data::<Oidc>()?;
        let application = Uuid::parse_str(&application).map_err(|_| error(IdentityError::NotFound("the consent")))?;
        oidc.revoke_own_consent(instance(context)?.id, token(context)?, application).await.map_err(oidc_error)?;
        Ok(true)
    }

    /// Ends an auth request without a login (`login_required`, `consent_required`, `interaction_required`,
    /// `account_selection_required`, `access_denied`); returns the URL that tells the application.
    async fn decline_auth_request(
        &self,
        context: &Context<'_>,
        id: String,
        error: String,
    ) -> async_graphql::Result<String> {
        let oidc = context.data::<Oidc>()?;
        oidc.fail(&instance(context)?, &id, &error).await.map_err(oidc_error)
    }

    /// Starts a login with a passkey – no address, no password.
    async fn start_passkey_login(&self, context: &Context<'_>) -> async_graphql::Result<PasskeyChallenge> {
        let identity = context.data::<Identity>()?;
        let challenge = identity
            .start_passkey_login(&relying_party(context)?, instance(context)?.id, context.data::<ClientMeta>()?)
            .await
            .map_err(error)?;
        Ok(challenge.into())
    }

    /// Finishes a passkey login and creates a session.
    async fn finish_passkey_login(
        &self,
        context: &Context<'_>,
        challenge_id: String,
        credential: async_graphql::Json<serde_json::Value>,
        lifetime_seconds: Option<u64>,
    ) -> async_graphql::Result<CreatedSession> {
        let identity = context.data::<Identity>()?;
        let session = identity
            .finish_passkey_login(
                &relying_party(context)?,
                instance(context)?.id,
                &challenge_id,
                &credential.0,
                lifetime_seconds.map(Duration::from_secs),
                context.data::<ClientMeta>()?,
            )
            .await
            .map_err(error)?;
        Ok(session.into())
    }

    /// Checks a TOTP code as a further check of the current session.
    async fn check_totp(&self, context: &Context<'_>, code: String) -> async_graphql::Result<Session> {
        let identity = context.data::<Identity>()?;
        Ok(identity.check_totp(instance(context)?.id, token(context)?, &code).await.map_err(error)?.into())
    }

    /// Starts a passkey check of the current session.
    async fn start_passkey_check(&self, context: &Context<'_>) -> async_graphql::Result<PasskeyChallenge> {
        let identity = context.data::<Identity>()?;
        let challenge = identity
            .start_passkey_check(&relying_party(context)?, instance(context)?.id, token(context)?)
            .await
            .map_err(error)?;
        Ok(challenge.into())
    }

    /// Finishes a passkey check of the current session.
    async fn finish_passkey_check(
        &self,
        context: &Context<'_>,
        challenge_id: String,
        credential: async_graphql::Json<serde_json::Value>,
    ) -> async_graphql::Result<Session> {
        let identity = context.data::<Identity>()?;
        let session = identity
            .finish_passkey_check(
                &relying_party(context)?,
                instance(context)?.id,
                token(context)?,
                &challenge_id,
                &credential.0,
            )
            .await
            .map_err(error)?;
        Ok(session.into())
    }

    /// Proposes a TOTP secret for the session's account (needs a recent session).
    async fn start_totp(&self, context: &Context<'_>) -> async_graphql::Result<TotpSetup> {
        let identity = context.data::<Identity>()?;
        let instance = instance(context)?;
        let setup = identity.start_totp(instance.id, token(context)?, &instance.name).await.map_err(error)?;
        Ok(TotpSetup { secret: setup.secret, uri: setup.uri, qr_code: setup.qr_code })
    }

    /// Confirms the proposed TOTP secret with a first code.
    async fn confirm_totp(&self, context: &Context<'_>, code: String) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        identity.confirm_totp(instance(context)?.id, token(context)?, &code).await.map_err(error)?;
        Ok(true)
    }

    /// Generates new recovery codes (needs a recent session); earlier ones stop working. Shown this once.
    async fn generate_recovery_codes(&self, context: &Context<'_>) -> async_graphql::Result<Vec<String>> {
        let identity = context.data::<Identity>()?;
        identity.generate_recovery_codes(instance(context)?.id, token(context)?).await.map_err(error)
    }

    /// Uses a recovery code as a further check of the current session.
    async fn check_recovery_code(&self, context: &Context<'_>, code: String) -> async_graphql::Result<Session> {
        let identity = context.data::<Identity>()?;
        Ok(identity.check_recovery_code(instance(context)?.id, token(context)?, &code).await.map_err(error)?.into())
    }

    /// Removes TOTP from the session's account.
    async fn remove_totp(&self, context: &Context<'_>) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        identity.remove_totp(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(true)
    }

    /// Starts registering a passkey for the session's account (needs a recent session).
    async fn start_passkey_registration(&self, context: &Context<'_>) -> async_graphql::Result<PasskeyChallenge> {
        let identity = context.data::<Identity>()?;
        let challenge = identity
            .start_passkey_registration(&relying_party(context)?, instance(context)?.id, token(context)?)
            .await
            .map_err(error)?;
        Ok(challenge.into())
    }

    /// Finishes registering a passkey; returns its id.
    async fn finish_passkey_registration(
        &self,
        context: &Context<'_>,
        challenge_id: String,
        name: String,
        credential: async_graphql::Json<serde_json::Value>,
    ) -> async_graphql::Result<String> {
        let identity = context.data::<Identity>()?;
        let id = identity
            .finish_passkey_registration(
                &relying_party(context)?,
                instance(context)?.id,
                token(context)?,
                &challenge_id,
                &name,
                &credential.0,
            )
            .await
            .map_err(error)?;
        Ok(id.to_string())
    }

    /// Removes a passkey of the session's account.
    async fn remove_passkey(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        let id = uuid::Uuid::parse_str(&id)?;
        identity.remove_passkey(instance(context)?.id, token(context)?, id).await.map_err(error)?;
        Ok(true)
    }

    /// Logs out: ends the session of the bearer token.
    async fn terminate_session(&self, context: &Context<'_>) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        identity.terminate_session(instance(context)?.id, token(context)?).await.map_err(error)?;
        Ok(true)
    }

    /// Logs out like `terminateSession`; if the session came from a SAML provider with single logout, returns where
    /// to send the browser next, to log out there too.
    async fn logout(&self, context: &Context<'_>) -> async_graphql::Result<Option<String>> {
        let oidc = context.data::<Oidc>()?;
        oidc.logout(&instance(context)?, token(context)?).await.map_err(oidc_error)
    }

    /// Starts a login at an identity provider; returns where to send the browser.
    async fn start_idp_login(
        &self,
        context: &Context<'_>,
        identity_provider: String,
        auth_request: Option<String>,
        login_hint: Option<String>,
    ) -> async_graphql::Result<String> {
        let oidc = context.data::<Oidc>()?;
        let idp =
            Uuid::parse_str(&identity_provider).map_err(|_| error(IdentityError::NotFound("the identity provider")))?;
        oidc.start_idp_login(&instance(context)?, idp, auth_request.as_deref(), login_hint.as_deref())
            .await
            .map_err(oidc_error)
    }

    /// Exchanges the result of a login at an identity provider (`<login id>.<code>`) for a session – once.
    async fn exchange_idp_login(
        &self,
        context: &Context<'_>,
        login: String,
        lifetime_seconds: Option<u64>,
    ) -> async_graphql::Result<ExchangedIdpLogin> {
        let oidc = context.data::<Oidc>()?;
        let meta = context.data::<ClientMeta>()?;
        let lifetime = lifetime_seconds.map(Duration::from_secs);
        let result =
            oidc.exchange_idp_login(instance(context)?.id, &login, lifetime, meta).await.map_err(oidc_error)?;
        Ok(ExchangedIdpLogin { session: result.session.into(), auth_request: result.auth_request })
    }

    /// Ends a session of the bearer token's own account.
    async fn terminate_my_session(&self, context: &Context<'_>, id: String) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        let id = Uuid::parse_str(&id).map_err(|_| error(IdentityError::NotFound("the session")))?;
        identity.terminate_own_session(instance(context)?.id, token(context)?, id).await.map_err(error)?;
        Ok(true)
    }

    /// Changes the own password: needs a recent session and the current password; other sessions end.
    async fn change_password(
        &self,
        context: &Context<'_>,
        current_password: String,
        new_password: String,
    ) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        let (instance, token) = (instance(context)?.id, token(context)?);
        identity.change_own_password(instance, token, &current_password, &new_password).await.map_err(error)?;
        Ok(true)
    }

    /// Changes the own display name.
    async fn update_profile(&self, context: &Context<'_>, display_name: String) -> async_graphql::Result<bool> {
        let identity = context.data::<Identity>()?;
        identity.rename_own_account(instance(context)?.id, token(context)?, &display_name).await.map_err(error)?;
        Ok(true)
    }
}

/// Runs a GraphQL request with what it is about as context data: the instance of the host, the bearer token, where
/// it comes from.
pub async fn handler(
    State((state, schema)): State<(AppState, ApiSchema)>,
    client: Option<Extension<Client>>,
    headers: HeaderMap,
    request: GraphQLRequest,
) -> axum::response::Response {
    let client = client.map(|c| c.0);
    let mut request = request
        .into_inner()
        .data(state.identity.clone())
        .data(state.oidc.clone())
        .data(admin::TargetTenant(crate::admin::target_tenant(&headers)))
        .data(state.clone())
        .data(sessions::client_meta(client.as_ref(), &headers));
    let instance = match crate::instance::of_request(&state.identity, client.as_ref()).await {
        Ok(instance) => instance,
        Err(problem) => return problem.into_response(),
    };
    // A GraphQL request is a POST: with the session cookie, the CSRF check applies.
    match crate::cookie::session_token(&state, &axum::http::Method::POST, &headers, instance.as_ref()) {
        Ok(token) => request = request.data(BearerToken(token)),
        Err(refused) if crate::cookie::present(&headers) && sessions::bearer(&headers).is_none() => return refused,
        Err(_) => {}
    }
    if let Some(instance) = instance {
        request = request.data(instance);
    }
    if let Some(client) = client {
        request = request.data(client);
    }
    GraphQLResponse::from(schema.execute(request).await).into_response()
}
