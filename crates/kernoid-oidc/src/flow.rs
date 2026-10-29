// SPDX-License-Identifier: AGPL-3.0-or-later
//! The authorization code flow with PKCE and refresh tokens (OpenID Connect Core 1.0, OAuth 2.1 draft, RFC 7636,
//! RFC 9207, RFC 9700), consent and offline access, JWT access tokens (RFC 9068), token introspection (RFC 7662) and
//! revocation (RFC 7009), RP-initiated and front-channel logout (OpenID Connect RP-Initiated Logout 1.0,
//! Front-Channel Logout 1.0).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use kernoid_identity::InstanceInfo;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    Oidc, OidcError, Result,
    application::{ApplicationInfo, Kind, TokenFormat},
    constant_time_eq, internal, jwt, lifetime, random_secret, sha256,
};

/// Scopes kernoid knows; others are ignored, as OpenID Connect allows.
pub const SCOPES: &[&str] =
    &["openid", "profile", "email", OFFLINE_SCOPE, ROLES_SCOPE, kernoid_identity::app_password::MAIL_SCOPE];
/// Refresh tokens that outlive the session (OpenID Connect Core, 11) – for applications that may ask for it, with the
/// person's consent.
pub const OFFLINE_SCOPE: &str = "offline_access";
/// Asks for the account's roles in the application's project, also when the project does not assert them anyway.
pub const ROLES_SCOPE: &str = "urn:kernoid:project:roles";
/// The claim with the project roles: `{"<role key>": {"<tenant id>": "<tenant name>"}}`, shaped like ZITADEL's
/// `urn:zitadel:iam:org:project:roles`.
pub const ROLES_CLAIM: &str = "urn:kernoid:project:roles";
/// Restricts a login to one tenant: `urn:kernoid:tenant:id:<tenant id>`.
pub const TENANT_SCOPE: &str = "urn:kernoid:tenant:id:";
const MAX_PARAMETER: usize = 512;
/// `prompt` values kernoid knows (OpenID Connect Core, 3.1.2.1).
pub const PROMPTS: &[&str] = &["none", "login", "consent", "select_account"];
/// Errors the login UI may end an auth request with.
pub const UI_ERRORS: &[&str] =
    &["login_required", "consent_required", "interaction_required", "account_selection_required", "access_denied"];

/// The query of an authorization request, as sent.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
}

/// Where `authorize` sends the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorized {
    /// To the login UI, which finishes the auth request with a session.
    Login { auth_request: String, url: String },
    /// Back to the (checked) redirect URI with an error.
    Error { url: String },
}

/// An auth request, as the login UI may show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthRequestInfo {
    pub id: String,
    pub application: String,
    pub scopes: Vec<String>,
    /// What the login UI must respect: `none` (no interaction – end with `login_required` if there is no session),
    /// `login` (log in again), `consent`, `select_account`.
    pub prompt: Vec<String>,
    /// The session may be at most this many seconds old.
    pub max_age: Option<i32>,
    pub expires_at: DateTime<Utc>,
}

/// The form of a token request, with the client as authenticated by the caller (Basic header or form).
#[derive(Debug, Clone, Default)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    /// For a refresh: fewer scopes than granted, if wanted.
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// The query of a logout request (OpenID Connect RP-Initiated Logout 1.0, 2).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct EndSessionRequest {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// What an RP-initiated logout leads to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndSession {
    /// The registered `post_logout_redirect_uri`, with `state`.
    pub redirect: Option<String>,
    /// Front-channel logout URIs of the applications the session logged in to, with `iss` and `sid`: the page that
    /// confirms the logout loads each in a frame.
    pub frontchannel: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub id_token: String,
    /// The next refresh token; the one used for this response is used up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// What one login granted, for issuing tokens.
struct Grant {
    account: Uuid,
    /// The session the login was in; for offline grants it may be gone.
    session: Option<Uuid>,
    /// `offline_access`: the tokens outlive the session.
    offline: bool,
    /// The auth request: every token of one login belongs to it.
    family: String,
    scopes: Vec<String>,
    nonce: Option<String>,
    auth_time: DateTime<Utc>,
    checks: Vec<String>,
    session_expires: DateTime<Utc>,
}

pub type Claims = Map<String, Value>;

/// What [`Oidc::clean_up`] removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cleaned {
    pub auth_requests: u64,
    pub codes: u64,
    pub access_tokens: u64,
    pub refresh_tokens: u64,
    pub idp_logins: u64,
    pub logout_notifications: u64,
}

fn scopes(scope: &str) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for scope in scope.split_ascii_whitespace().take(50) {
        if scope.len() <= 200 && !list.iter().any(|known| known == scope) {
            list.push(scope.to_owned());
        }
    }
    list
}

/// A PKCE code verifier or challenge: 43 to 128 unreserved characters (RFC 7636, 4.1).
fn pkce_value(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// `uri` with `pairs` added to its query.
fn with_query(uri: &str, pairs: &[(&str, &str)]) -> Result<String> {
    if pairs.is_empty() {
        return Ok(uri.to_owned());
    }
    let mut url = url::Url::parse(uri).map_err(internal)?;
    url.query_pairs_mut().extend_pairs(pairs);
    Ok(url.into())
}

fn store(error: sqlx::Error) -> OidcError {
    internal(error)
}

/// The PKCE challenge of a verifier (RFC 7636, S256).
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The discovery document of an instance (OpenID Connect Discovery 1.0).
pub fn discovery(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/v2/authorize"),
        "token_endpoint": format!("{issuer}/oauth/v2/token"),
        "userinfo_endpoint": format!("{issuer}/oidc/v1/userinfo"),
        "end_session_endpoint": format!("{issuer}/oidc/v1/end_session"),
        "revocation_endpoint": format!("{issuer}/oauth/v2/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth/v2/introspect"),
        "jwks_uri": format!("{issuer}/oauth/v2/keys"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "prompt_values_supported": PROMPTS,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [crate::keys::ALGORITHM],
        "scopes_supported": SCOPES,
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "amr", "azp",
                             "name", "preferred_username", "email", "email_verified", ROLES_CLAIM],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
    })
}

impl Oidc {
    /// Checks an authorization request and parks it for the login UI. Errors about the client or its redirect URI
    /// are returned (to be shown); everything else goes back to the redirect URI.
    pub async fn authorize(&self, instance: &InstanceInfo, request: &AuthorizeRequest) -> Result<Authorized> {
        let issuer = self.issuer(&instance.primary_domain);
        let client_id = request.client_id.as_deref().ok_or(OidcError::InvalidClient)?;
        let application = self.application(Uuid::parse_str(client_id).map_err(|_| OidcError::InvalidClient)?).await?;
        if application.instance != instance.id || !application.active {
            return Err(OidcError::InvalidClient);
        }
        let redirect_uri = request.redirect_uri.as_deref().ok_or(OidcError::InvalidRedirectUri)?;
        if !application.redirect_uris.iter().any(|registered| registered == redirect_uri) {
            return Err(OidcError::InvalidRedirectUri);
        }

        // From here on, errors are told to the client.
        let state = request.state.as_deref();
        let error = |code: &str, description: &str| -> Result<Authorized> {
            let mut pairs = vec![("error", code), ("error_description", description), ("iss", issuer.as_str())];
            if let Some(state) = state {
                pairs.push(("state", state));
            }
            Ok(Authorized::Error { url: with_query(redirect_uri, &pairs)? })
        };
        if request.response_type.as_deref() != Some("code") {
            return error("unsupported_response_type", "only the authorization code flow is supported");
        }
        let mut scopes = scopes(request.scope.as_deref().unwrap_or(""));
        if !application.options.offline_access {
            // Ignored, as OpenID Connect Core (11) has it for an application that may not ask for it.
            scopes.retain(|scope| scope != OFFLINE_SCOPE);
        }
        if !scopes.iter().any(|scope| scope == "openid") {
            return error("invalid_scope", "the scope openid is required");
        }
        let challenge = request.code_challenge.as_deref().unwrap_or("");
        if request.code_challenge_method.as_deref() != Some("S256") || !pkce_value(challenge) {
            return error("invalid_request", "PKCE with code_challenge_method S256 is required");
        }
        if state.is_some_and(|s| s.len() > MAX_PARAMETER)
            || request.nonce.as_ref().is_some_and(|n| n.len() > MAX_PARAMETER)
        {
            return error("invalid_request", "state and nonce have at most 512 characters");
        }
        let prompt = self::scopes(request.prompt.as_deref().unwrap_or(""));
        if prompt.iter().any(|value| !PROMPTS.contains(&value.as_str())) {
            return error("invalid_request", "unknown prompt value");
        }
        if prompt.len() > 1 && prompt.iter().any(|value| value == "none") {
            return error("invalid_request", "prompt=none cannot be combined");
        }
        let max_age = match request.max_age.as_deref() {
            None => None,
            Some(value) => match value.parse::<i32>() {
                Ok(seconds) if seconds >= 0 => Some(seconds),
                _ => return error("invalid_request", "max_age is a number of seconds"),
            },
        };

        let id = random_secret("ar1.")?;
        sqlx::query!(
            "INSERT INTO auth_requests
                 (id, instance_id, application_id, redirect_uri, scopes, state, nonce, code_challenge, prompt, max_age,
                  expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $10, $11, now() + make_interval(secs => $9))",
            id,
            instance.id,
            application.id,
            redirect_uri,
            &scopes,
            state,
            request.nonce,
            challenge,
            lifetime::AUTH_REQUEST.as_secs() as f64,
            &prompt,
            max_age,
        )
        .execute(self.pool())
        .await
        .map_err(store)?;
        let url = with_query(&self.login_url(instance), &[("authRequest", id.as_str())])?;
        Ok(Authorized::Login { auth_request: id, url })
    }

    /// A pending auth request, for the login UI to show what is being asked for.
    pub async fn auth_request(&self, instance: &InstanceInfo, id: &str) -> Result<AuthRequestInfo> {
        let row = sqlx::query!(
            "SELECT r.id, a.name, r.scopes, r.prompt, r.max_age, r.expires_at
             FROM auth_requests r JOIN applications a ON a.id = r.application_id
             WHERE r.id = $1 AND r.instance_id = $2 AND r.session_id IS NULL AND r.expires_at > now()",
            id,
            instance.id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store)?
        .ok_or(OidcError::AuthRequestNotFound)?;
        Ok(AuthRequestInfo {
            id: row.id,
            application: row.name,
            scopes: row.scopes,
            prompt: row.prompt,
            max_age: row.max_age,
            expires_at: row.expires_at,
        })
    }

    /// Finishes an auth request with the session of `session_token`: issues a one-time code and returns the URL the
    /// browser goes back to. `consent` says the person agreed to what the application asks for, after the login UI
    /// showed it (on [`OidcError::ConsentRequired`]).
    pub async fn finish(
        &self,
        instance: &InstanceInfo,
        id: &str,
        session_token: &str,
        consent: bool,
    ) -> Result<String> {
        let session = self.identity.session(instance.id, session_token).await?;
        let request = sqlx::query!(
            "SELECT application_id, redirect_uri, scopes, state, prompt, max_age, created_at FROM auth_requests
             WHERE id = $1 AND instance_id = $2 AND session_id IS NULL AND expires_at > now()",
            id,
            instance.id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store)?
        .ok_or(OidcError::AuthRequestNotFound)?;
        let application = self.application(request.application_id).await?;
        if !application.active || !self.may_use(&application, session.account.id, session.account.tenant).await? {
            return Err(OidcError::AccessDenied("this account may not use this application".into()));
        }
        let tenant = session.account.tenant.to_string();
        if request.scopes.iter().filter_map(|scope| scope.strip_prefix(TENANT_SCOPE)).any(|wanted| wanted != tenant) {
            return Err(OidcError::AccessDenied("the application asks for another tenant".into()));
        }
        // prompt=login: a login after the request; max_age: a login at most that long ago.
        let session_age = Utc::now() - session.created_at;
        if request.prompt.iter().any(|value| value == "login") && session.created_at < request.created_at
            || request.max_age.is_some_and(|max| session_age > chrono::Duration::seconds(max.into()))
        {
            return Err(OidcError::LoginRequired);
        }
        if !kernoid_identity::session::is_multi_factor(&session.checks)
            && (application.mfa_required || self.identity.mfa_required_now(session.account.id).await?)
        {
            return Err(OidcError::MfaRequired);
        }
        let asks_consent = request.prompt.iter().any(|value| value == "consent");
        if asks_consent
            || application.options.consent_required
            || request.scopes.iter().any(|scope| scope == OFFLINE_SCOPE)
        {
            let given = self.identity.consent(session.account.id, application.id).await?.unwrap_or_default();
            let covered = request.scopes.iter().all(|scope| given.contains(scope));
            if !consent && (asks_consent || !covered) {
                return Err(OidcError::ConsentRequired);
            }
            if consent {
                let creator = format!("account:{}", session.account.id);
                self.identity.grant_consent(session.account.id, application.id, &request.scopes, &creator).await?;
            }
        }

        let code = random_secret("kac1.")?;
        let mut tx = self.pool().begin().await.map_err(store)?;
        let taken = sqlx::query!(
            "UPDATE auth_requests SET session_id = $2 WHERE id = $1 AND session_id IS NULL",
            id,
            session.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(store)?
        .rows_affected();
        if taken != 1 {
            return Err(OidcError::AuthRequestNotFound);
        }
        sqlx::query!(
            "INSERT INTO session_applications (session_id, application_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            session.id,
            application.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(store)?;
        sqlx::query!(
            "INSERT INTO authorization_codes (code_hash, auth_request_id, session_id, account_id, expires_at)
             VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
            &sha256(&code)[..],
            id,
            session.id,
            session.account.id,
            lifetime::CODE.as_secs() as f64,
        )
        .execute(&mut *tx)
        .await
        .map_err(store)?;
        tx.commit().await.map_err(store)?;

        let issuer = self.issuer(&instance.primary_domain);
        let mut pairs = vec![("code", code.as_str()), ("iss", issuer.as_str())];
        if let Some(state) = request.state.as_deref() {
            pairs.push(("state", state));
        }
        with_query(&request.redirect_uri, &pairs)
    }

    /// Whether an account of `tenant` may log in to an application: one of the application's own tenant, or of a
    /// tenant the application's project is granted to; and, if the project checks roles, only with a role in it.
    async fn may_use(&self, application: &ApplicationInfo, account: Uuid, tenant: Uuid) -> Result<bool> {
        let Some(project) = application.project else { return Ok(application.tenant == tenant) };
        if application.tenant != tenant && self.identity.project_access(tenant, project).await.is_err() {
            return Ok(false);
        }
        let info = self.identity.project(project).await?;
        Ok(!info.role_check || !self.identity.account_project_roles(project, account).await?.is_empty())
    }

    /// The project roles for tokens and userinfo – if the project asserts them or the scope asks for them.
    async fn role_claim(&self, application: Uuid, account: Uuid, scopes: &[String]) -> Result<Option<Value>> {
        let application = self.application(application).await?;
        let Some(project) = application.project else { return Ok(None) };
        let info = self.identity.project(project).await?;
        if !info.role_assertion && !scopes.iter().any(|scope| scope == ROLES_SCOPE) {
            return Ok(None);
        }
        // The tenant the account belongs to – the project's own, or one it is granted to.
        let tenant = sqlx::query!(
            "SELECT t.id, t.name FROM accounts a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1",
            account,
        )
        .fetch_one(self.pool())
        .await
        .map_err(store)?;
        let roles = self.identity.account_project_roles(project, account).await?;
        let mut claim = Map::new();
        for role in roles {
            claim.insert(role, json!({ tenant.id.to_string(): tenant.name }));
        }
        Ok(Some(Value::Object(claim)))
    }

    /// Ends an auth request without a login – the login UI found no session for `prompt=none`, or the person
    /// declined; returns the URL that tells the application, with one of [`UI_ERRORS`].
    pub async fn fail(&self, instance: &InstanceInfo, id: &str, error: &str) -> Result<String> {
        if !UI_ERRORS.contains(&error) {
            return Err(OidcError::InvalidRequest(format!("unknown error {error:?}")));
        }
        let request = sqlx::query!(
            "UPDATE auth_requests SET expires_at = now()
             WHERE id = $1 AND instance_id = $2 AND session_id IS NULL AND expires_at > now()
             RETURNING redirect_uri, state",
            id,
            instance.id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store)?
        .ok_or(OidcError::AuthRequestNotFound)?;
        let issuer = self.issuer(&instance.primary_domain);
        let mut pairs = vec![("error", error), ("iss", issuer.as_str())];
        if let Some(state) = request.state.as_deref() {
            pairs.push(("state", state));
        }
        with_query(&request.redirect_uri, &pairs)
    }

    /// The token endpoint: a code or a refresh token for new tokens.
    pub async fn token(&self, instance: &InstanceInfo, request: &TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_deref() {
            Some("authorization_code") => self.exchange_code(instance, request).await,
            Some("refresh_token") => self.refresh(instance, request).await,
            _ => Err(OidcError::UnsupportedGrantType),
        }
    }

    /// Exchanges a code for an ID token, an access token and a refresh token.
    async fn exchange_code(&self, instance: &InstanceInfo, request: &TokenRequest) -> Result<TokenResponse> {
        let client_id = request.client_id.as_deref().ok_or(OidcError::InvalidClient)?;
        let client = self.authenticate_client(instance.id, client_id, request.client_secret.as_deref()).await?;
        let code = request.code.as_deref().ok_or_else(|| OidcError::InvalidRequest("code is missing".into()))?;
        let verifier = request.code_verifier.as_deref().unwrap_or("");
        if !pkce_value(verifier) {
            return Err(OidcError::InvalidRequest("a code_verifier of 43 to 128 characters is required".into()));
        }

        let mut tx = self.pool().begin().await.map_err(store)?;
        let found = sqlx::query!(
            r#"SELECT c.used_at, c.expires_at > now() AS "fresh!", c.session_id, c.account_id,
                      r.id AS auth_request, r.instance_id, r.application_id, r.redirect_uri, r.scopes, r.nonce,
                      r.code_challenge
               FROM authorization_codes c JOIN auth_requests r ON r.id = c.auth_request_id
               WHERE c.code_hash = $1
               FOR UPDATE OF c"#,
            &sha256(code)[..],
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(store)?
        .ok_or_else(|| OidcError::InvalidGrant("the code is not valid".into()))?;
        if found.used_at.is_some() {
            // A code used twice may have been stolen: what was issued for it is withdrawn (RFC 6749, 4.1.2).
            revoke_family(&mut tx, &found.auth_request).await?;
            tx.commit().await.map_err(store)?;
            tracing::warn!(application = %client.id, "authorization code presented a second time; tokens revoked");
            return Err(OidcError::InvalidGrant("the code is not valid".into()));
        }
        let challenge = pkce_challenge(verifier);
        let valid = found.fresh
            && found.instance_id == instance.id
            && found.application_id == client.id
            && request.redirect_uri.as_deref() == Some(found.redirect_uri.as_str())
            && constant_time_eq(challenge.as_bytes(), found.code_challenge.as_bytes());
        if !valid {
            return Err(OidcError::InvalidGrant("the code is not valid".into()));
        }
        sqlx::query!("UPDATE authorization_codes SET used_at = now() WHERE code_hash = $1", &sha256(code)[..])
            .execute(&mut *tx)
            .await
            .map_err(store)?;
        let session = sqlx::query!(
            "SELECT s.created_at, s.checks, s.expires_at FROM sessions s
             JOIN accounts a ON a.id = s.account_id JOIN tenants t ON t.id = s.tenant_id
             WHERE s.id = $1 AND s.terminated_at IS NULL AND s.expires_at > now() AND a.active AND t.active",
            found.session_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(store)?
        .ok_or_else(|| OidcError::InvalidGrant("the session has ended".into()))?;
        let grant = Grant {
            account: found.account_id,
            session: Some(found.session_id),
            offline: found.scopes.iter().any(|scope| scope == OFFLINE_SCOPE),
            family: found.auth_request,
            scopes: found.scopes,
            nonce: found.nonce,
            auth_time: session.created_at,
            checks: session.checks,
            session_expires: session.expires_at,
        };
        let (access_token, refresh_token) = self.issue(&mut tx, instance, &client, &grant).await?;
        tx.commit().await.map_err(store)?;
        self.respond(instance, client.id, &grant, access_token, refresh_token).await
    }

    /// Exchanges a refresh token for new tokens and the next refresh token. A refresh token is used once: one that
    /// comes back after it was used has been copied, and every token of its login is revoked (RFC 9700, 4.14.2).
    /// An offline one (`offline_access`) does not need its session, but the consent it was given on.
    async fn refresh(&self, instance: &InstanceInfo, request: &TokenRequest) -> Result<TokenResponse> {
        let client_id = request.client_id.as_deref().ok_or(OidcError::InvalidClient)?;
        let client = self.authenticate_client(instance.id, client_id, request.client_secret.as_deref()).await?;
        let token = request
            .refresh_token
            .as_deref()
            .ok_or_else(|| OidcError::InvalidRequest("refresh_token is missing".into()))?;
        let mut tx = self.pool().begin().await.map_err(store)?;
        let found = sqlx::query!(
            r#"SELECT r.used_at, r.expires_at > now() AS "fresh!", r.family, r.instance_id, r.application_id,
                      r.account_id, r.session_id, r.scopes, r.offline, r.auth_time, r.checks,
                      s.expires_at AS "session_expires?",
                      (a.active AND t.active AND (r.offline OR (s.terminated_at IS NULL AND s.expires_at > now())))
                          IS TRUE AS "alive!",
                      a.tenant_id
               FROM refresh_tokens r
               LEFT JOIN sessions s ON s.id = r.session_id
               JOIN accounts a ON a.id = r.account_id
               JOIN tenants t ON t.id = a.tenant_id
               WHERE r.token_hash = $1
               FOR UPDATE OF r"#,
            &sha256(token)[..],
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(store)?
        .ok_or_else(|| OidcError::InvalidGrant("the refresh token is not valid".into()))?;
        if found.instance_id != instance.id || found.application_id != client.id {
            return Err(OidcError::InvalidGrant("the refresh token is not valid".into()));
        }
        if found.used_at.is_some() {
            revoke_family(&mut tx, &found.family).await?;
            tx.commit().await.map_err(store)?;
            tracing::warn!(application = %client.id, "refresh token presented a second time; tokens revoked");
            return Err(OidcError::InvalidGrant("the refresh token is not valid".into()));
        }
        if !found.fresh || !found.alive {
            return Err(OidcError::InvalidGrant("the refresh token has expired or its session ended".into()));
        }
        // Offline access ends when the application may no longer ask for it, or the consent is withdrawn.
        if found.offline {
            let given = self.identity.consent(found.account_id, client.id).await?.unwrap_or_default();
            if !client.options.offline_access || !given.iter().any(|scope| scope == OFFLINE_SCOPE) {
                return Err(OidcError::InvalidGrant("offline access is no longer granted".into()));
            }
        }
        // A requirement switched on after the login applies to refreshing, too.
        if !kernoid_identity::session::is_multi_factor(&found.checks)
            && (client.mfa_required || self.identity.mfa_required_now(found.account_id).await?)
        {
            return Err(OidcError::InvalidGrant("a login with a second factor is required".into()));
        }
        // So does a project role taken away after the login.
        if !self.may_use(&client, found.account_id, found.tenant_id).await? {
            return Err(OidcError::InvalidGrant("the account has no role in the application's project".into()));
        }
        let scopes = match request.scope.as_deref() {
            None => found.scopes,
            Some(asked) => {
                let asked = scopes(asked);
                if asked.iter().any(|scope| !found.scopes.contains(scope)) {
                    return Err(OidcError::InvalidScope);
                }
                asked
            }
        };
        sqlx::query!("UPDATE refresh_tokens SET used_at = now() WHERE token_hash = $1", &sha256(token)[..])
            .execute(&mut *tx)
            .await
            .map_err(store)?;
        let grant = Grant {
            account: found.account_id,
            session: found.session_id,
            offline: found.offline,
            family: found.family,
            scopes,
            nonce: None,
            auth_time: found.auth_time,
            checks: found.checks,
            session_expires: found.session_expires.unwrap_or_else(Utc::now),
        };
        let (access_token, refresh_token) = self.issue(&mut tx, instance, &client, &grant).await?;
        tx.commit().await.map_err(store)?;
        self.respond(instance, client.id, &grant, access_token, refresh_token).await
    }

    /// Stores a new access token and refresh token for `grant`. The refresh token lives as long as the session; an
    /// offline one [`lifetime::OFFLINE_REFRESH`] from now, and the tokens of an offline grant are not bound to the
    /// session. The access token is opaque or, if the application wants it, a JWT (RFC 9068) – stored by its hash
    /// either way, so that revocation, introspection and userinfo work alike.
    async fn issue(
        &self,
        connection: &mut sqlx::PgConnection,
        instance: &InstanceInfo,
        client: &ApplicationInfo,
        grant: &Grant,
    ) -> Result<(String, String)> {
        let bound = grant.session.filter(|_| !grant.offline);
        let access_token = match client.options.access_token_format {
            TokenFormat::Opaque => random_secret("kat1.")?,
            TokenFormat::Jwt => self.jwt_access_token(instance, client, grant).await?,
        };
        sqlx::query!(
            "INSERT INTO access_tokens
                 (token_hash, instance_id, application_id, account_id, session_id, auth_request_id, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
            &sha256(&access_token)[..],
            instance.id,
            client.id,
            grant.account,
            bound,
            grant.family,
            &grant.scopes,
            lifetime::ACCESS_TOKEN.as_secs() as f64,
        )
        .execute(&mut *connection)
        .await
        .map_err(store)?;
        let refresh_token = random_secret("krt1.")?;
        let expires = if grant.offline { Utc::now() + lifetime::OFFLINE_REFRESH } else { grant.session_expires };
        sqlx::query!(
            "INSERT INTO refresh_tokens
                 (token_hash, family, instance_id, application_id, account_id, session_id, scopes, expires_at, offline,
                  auth_time, checks)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &sha256(&refresh_token)[..],
            grant.family,
            instance.id,
            client.id,
            grant.account,
            grant.session,
            &grant.scopes,
            expires,
            grant.offline,
            grant.auth_time,
            &grant.checks,
        )
        .execute(&mut *connection)
        .await
        .map_err(store)?;
        Ok((access_token, refresh_token))
    }

    /// An access token as a JWT (RFC 9068): for resource servers that check tokens without asking kernoid. Its
    /// audience is the application; it carries the scopes and, as ID tokens do, the project roles.
    async fn jwt_access_token(
        &self,
        instance: &InstanceInfo,
        client: &ApplicationInfo,
        grant: &Grant,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer(&instance.primary_domain),
            "sub": grant.account.to_string(),
            "aud": client.id.to_string(),
            "client_id": client.id.to_string(),
            "iat": now,
            "exp": now + lifetime::ACCESS_TOKEN.as_secs() as i64,
            "jti": random_secret("")?,
            "scope": grant.scopes.join(" "),
            "auth_time": grant.auth_time.timestamp(),
        });
        if let Some(session) = grant.session.filter(|_| !grant.offline) {
            claims["sid"] = Value::String(session.to_string());
        }
        if let Some(roles) = self.role_claim(client.id, grant.account, &grant.scopes).await? {
            claims[ROLES_CLAIM] = roles;
        }
        let (kid, key) = self.signer(instance.id).await?;
        jwt::sign_typed(&key, &kid, "at+jwt", &claims)
    }

    /// The token response, with an ID token signed by the instance's active key.
    async fn respond(
        &self,
        instance: &InstanceInfo,
        client: Uuid,
        grant: &Grant,
        access_token: String,
        refresh_token: String,
    ) -> Result<TokenResponse> {
        let now = Utc::now().timestamp();
        let amr = amr(&grant.checks);
        let mut claims = json!({
            "iss": self.issuer(&instance.primary_domain),
            "sub": grant.account.to_string(),
            "aud": client.to_string(),
            "azp": client.to_string(),
            "iat": now,
            "exp": now + lifetime::ID_TOKEN.as_secs() as i64,
            "auth_time": grant.auth_time.timestamp(),
            "amr": amr,
        });
        if let Some(session) = grant.session {
            claims["sid"] = Value::String(session.to_string());
        }
        if let Some(nonce) = &grant.nonce {
            claims["nonce"] = Value::String(nonce.clone());
        }
        if let Some(roles) = self.role_claim(client, grant.account, &grant.scopes).await? {
            claims[ROLES_CLAIM] = roles;
        }
        let (kid, key) = self.signer(instance.id).await?;
        let id_token = jwt::sign(&key, &kid, &claims)?;
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: lifetime::ACCESS_TOKEN.as_secs(),
            id_token,
            refresh_token: Some(refresh_token),
            scope: grant.scopes.join(" "),
        })
    }

    /// Revokes a token of the client (RFC 7009): a refresh token together with every token of its login, an access
    /// token alone. Unknown tokens and tokens of other clients are not an error – the answer tells nothing.
    pub async fn revoke(
        &self,
        instance: &InstanceInfo,
        client_id: &str,
        client_secret: Option<&str>,
        token: &str,
    ) -> Result<()> {
        let client = self.authenticate_client(instance.id, client_id, client_secret).await?;
        let mut tx = self.pool().begin().await.map_err(store)?;
        let family = sqlx::query_scalar!(
            "SELECT family FROM refresh_tokens WHERE token_hash = $1 AND instance_id = $2 AND application_id = $3",
            &sha256(token)[..],
            instance.id,
            client.id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(store)?;
        match family {
            Some(family) => revoke_family(&mut tx, &family).await?,
            None => {
                sqlx::query!(
                    "DELETE FROM access_tokens WHERE token_hash = $1 AND instance_id = $2 AND application_id = $3",
                    &sha256(token)[..],
                    instance.id,
                    client.id,
                )
                .execute(&mut *tx)
                .await
                .map_err(store)?;
            }
        }
        tx.commit().await.map_err(store)
    }

    /// Introspection (RFC 7662) for resource servers: whether a token is active, and for whom. The caller is a
    /// confidential client; it learns about tokens of its own and of applications of the same project – any other
    /// token is reported inactive, like an unknown one.
    pub async fn introspect(
        &self,
        instance: &InstanceInfo,
        client_id: &str,
        client_secret: Option<&str>,
        token: &str,
    ) -> Result<Value> {
        let caller = self.authenticate_client(instance.id, client_id, client_secret).await?;
        if caller.kind == Kind::Public {
            return Err(OidcError::InvalidClient);
        }
        let inactive = || Ok(json!({ "active": false }));
        let access = sqlx::query!(
            r#"SELECT k.application_id, k.account_id, k.scopes, k.expires_at, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!"
               FROM access_tokens k
               JOIN accounts a ON a.id = k.account_id
               JOIN tenants t ON t.id = a.tenant_id
               LEFT JOIN sessions s ON s.id = k.session_id
               WHERE k.token_hash = $1 AND k.instance_id = $2 AND k.expires_at > now() AND a.active AND t.active
                 AND (k.session_id IS NULL OR (s.terminated_at IS NULL AND s.expires_at > now()))"#,
            &sha256(token)[..],
            instance.id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store)?;
        let (application, account, scopes, expires, kind, address) = match access {
            Some(row) => {
                (row.application_id, row.account_id, row.scopes, row.expires_at, "Bearer", row.primary_address)
            }
            None => {
                let refresh = sqlx::query!(
                    r#"SELECT r.application_id, r.account_id, r.scopes, r.expires_at, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!"
                       FROM refresh_tokens r
                       JOIN accounts a ON a.id = r.account_id
                       JOIN tenants t ON t.id = a.tenant_id
                       LEFT JOIN sessions s ON s.id = r.session_id
                       WHERE r.token_hash = $1 AND r.instance_id = $2 AND r.used_at IS NULL AND r.expires_at > now()
                         AND a.active AND t.active
                         AND (r.offline OR (s.terminated_at IS NULL AND s.expires_at > now()))"#,
                    &sha256(token)[..],
                    instance.id,
                )
                .fetch_optional(self.pool())
                .await
                .map_err(store)?;
                let Some(row) = refresh else { return inactive() };
                (row.application_id, row.account_id, row.scopes, row.expires_at, "refresh_token", row.primary_address)
            }
        };
        let owner = self.application(application).await?;
        let related = owner.id == caller.id || owner.project.is_some() && owner.project == caller.project;
        if !related || !owner.active {
            return inactive();
        }
        let mut answer = json!({
            "active": true,
            "scope": scopes.join(" "),
            "client_id": owner.id.to_string(),
            "sub": account.to_string(),
            "aud": owner.id.to_string(),
            "iss": self.issuer(&instance.primary_domain),
            "exp": expires.timestamp(),
            "token_type": kind,
        });
        if scopes.iter().any(|scope| scope == "profile" || scope == "email") {
            answer["username"] = Value::String(address);
        }
        if let Some(roles) = self.role_claim(owner.id, account, &scopes).await? {
            answer[ROLES_CLAIM] = roles;
        }
        Ok(answer)
    }

    /// Logs out at the request of an application. The session is the one named in `id_token_hint` (an ID token this
    /// instance signed – expired is fine); it ends, and with it every token issued from it. The browser goes back
    /// only to a `post_logout_redirect_uri` registered for the client; without one, `None`. Applications the session
    /// logged in to learn of it by front-channel (the returned URIs, for frames) and back-channel logout (by the
    /// worker, [`Oidc::deliver_logout_notifications`]). Offline grants stay.
    pub async fn end_session(&self, instance: &InstanceInfo, request: &EndSessionRequest) -> Result<EndSession> {
        let mut client = match request.client_id.as_deref() {
            Some(id) => Some(Uuid::parse_str(id).map_err(|_| OidcError::InvalidClient)?),
            None => None,
        };
        let mut session = None;
        if let Some(hint) = request.id_token_hint.as_deref() {
            let claims = self.verify_own_id_token(instance, hint).await?;
            let audience = claims["aud"].as_str().and_then(|aud| Uuid::parse_str(aud).ok());
            if client.is_some() && client != audience {
                return Err(OidcError::InvalidRequest("client_id does not match the ID token".into()));
            }
            client = client.or(audience);
            session = claims["sid"].as_str().and_then(|sid| Uuid::parse_str(sid).ok());
        }
        let redirect = match request.post_logout_redirect_uri.as_deref() {
            None => None,
            Some(uri) => {
                let client = client.ok_or_else(|| {
                    OidcError::InvalidRequest("post_logout_redirect_uri needs id_token_hint or client_id".into())
                })?;
                let application = self.application(client).await?;
                if application.instance != instance.id
                    || !application.post_logout_redirect_uris.iter().any(|registered| registered == uri)
                {
                    return Err(OidcError::InvalidRequest("post_logout_redirect_uri is not registered".into()));
                }
                let mut pairs = Vec::new();
                if let Some(state) = request.state.as_deref() {
                    pairs.push(("state", state));
                }
                Some(with_query(uri, &pairs)?)
            }
        };
        let mut frontchannel = Vec::new();
        if let Some(session) = session {
            let issuer = self.issuer(&instance.primary_domain);
            let uris = sqlx::query_scalar!(
                r#"SELECT a.frontchannel_logout_uri AS "uri!" FROM session_applications sa
                   JOIN applications a ON a.id = sa.application_id
                   JOIN sessions s ON s.id = sa.session_id
                   WHERE sa.session_id = $1 AND s.instance_id = $2 AND s.terminated_at IS NULL
                     AND a.frontchannel_logout_uri IS NOT NULL"#,
                session,
                instance.id,
            )
            .fetch_all(self.pool())
            .await
            .map_err(store)?;
            for uri in uris {
                frontchannel.push(with_query(&uri, &[("iss", issuer.as_str()), ("sid", &session.to_string())])?);
            }
            let creator = client.map_or_else(|| "application".to_owned(), |client| format!("application:{client}"));
            self.identity.terminate_session_by_id(instance.id, session, &creator).await?;
            sqlx::query!("DELETE FROM refresh_tokens WHERE session_id = $1 AND NOT offline", session)
                .execute(self.pool())
                .await
                .map_err(store)?;
        }
        Ok(EndSession { redirect, frontchannel })
    }

    /// The claims of an ID token this instance signed, if its signature and issuer are right; expiry is not checked.
    async fn verify_own_id_token(&self, instance: &InstanceInfo, token: &str) -> Result<Value> {
        let invalid = || OidcError::InvalidRequest("id_token_hint is not valid".into());
        let kid = jwt::key_id(token).ok_or_else(invalid)?;
        let jwk = sqlx::query_scalar!(
            "SELECT public_jwk FROM signing_keys WHERE instance_id = $1 AND kid = $2",
            instance.id,
            kid,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store)?
        .ok_or_else(invalid)?;
        let claims = jwt::verify(&jwk, token).ok_or_else(invalid)?;
        if claims["iss"].as_str() != Some(self.issuer(&instance.primary_domain).as_str()) {
            return Err(invalid());
        }
        Ok(claims)
    }

    /// The claims an access token may see: `sub` always; `name` and `preferred_username` (the login name) with
    /// `profile`; `email` and `email_verified` with `email` – the contact address, else the primary address.
    pub async fn userinfo(&self, instance: &InstanceInfo, access_token: &str) -> Result<Claims> {
        let row = sqlx::query!(
            r#"SELECT a.id, a.display_name, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!",
                      coalesce(a.email, a.primary_address) AS email,
                      CASE WHEN a.email IS NOT NULL THEN a.email_verified ELSE a.primary_address IS NOT NULL END AS "email_verified!",
                      k.scopes, k.application_id
               FROM access_tokens k
               JOIN accounts a ON a.id = k.account_id
               JOIN tenants t ON t.id = a.tenant_id
               LEFT JOIN sessions s ON s.id = k.session_id
               WHERE k.token_hash = $1 AND k.instance_id = $2 AND k.expires_at > now() AND a.active AND t.active
                 AND (k.session_id IS NULL OR (s.terminated_at IS NULL AND s.expires_at > now()))"#,
            &sha256(access_token)[..],
            instance.id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store)?
        .ok_or(OidcError::InvalidToken)?;
        let mut claims = Claims::new();
        claims.insert("sub".into(), Value::String(row.id.to_string()));
        if row.scopes.iter().any(|scope| scope == "profile") {
            claims.insert("name".into(), Value::String(row.display_name));
            claims.insert("preferred_username".into(), Value::String(row.primary_address.clone()));
        }
        // The contact address if there is one, else the primary address (RFC 0003, 1).
        if row.scopes.iter().any(|scope| scope == "email")
            && let Some(email) = row.email
        {
            claims.insert("email".into(), Value::String(email));
            claims.insert("email_verified".into(), Value::Bool(row.email_verified));
        }
        if let Some(roles) = self.role_claim(row.application_id, row.id, &row.scopes).await? {
            claims.insert(ROLES_CLAIM.into(), roles);
        }
        Ok(claims)
    }

    /// Withdraws an account's consent to an application, and every token the application holds for the account.
    pub async fn revoke_consent(&self, account: Uuid, application: Uuid, creator: &str) -> Result<()> {
        self.identity.revoke_consent(account, application, creator).await?;
        let mut tx = self.pool().begin().await.map_err(store)?;
        sqlx::query!("DELETE FROM refresh_tokens WHERE account_id = $1 AND application_id = $2", account, application)
            .execute(&mut *tx)
            .await
            .map_err(store)?;
        sqlx::query!("DELETE FROM access_tokens WHERE account_id = $1 AND application_id = $2", account, application)
            .execute(&mut *tx)
            .await
            .map_err(store)?;
        tx.commit().await.map_err(store)
    }

    /// Withdraws a consent of the session token's own account.
    pub async fn revoke_own_consent(&self, instance: Uuid, token: &str, application: Uuid) -> Result<()> {
        let session = self.identity.session(instance, token).await?;
        self.revoke_consent(session.account.id, application, &format!("account:{}", session.account.id)).await
    }

    /// Removes expired tokens, codes and auth requests. Auth requests are kept while tokens issued for them may live,
    /// codes an hour beyond their end, so that a code presented again is still recognised.
    pub async fn clean_up(&self) -> Result<Cleaned> {
        let access_tokens = sqlx::query!("DELETE FROM access_tokens WHERE expires_at < now()")
            .execute(self.pool())
            .await
            .map_err(store)?
            .rows_affected();
        let codes = sqlx::query!("DELETE FROM authorization_codes WHERE expires_at < now() - interval '1 hour'")
            .execute(self.pool())
            .await
            .map_err(store)?
            .rows_affected();
        let refresh_tokens = sqlx::query!("DELETE FROM refresh_tokens WHERE expires_at < now()")
            .execute(self.pool())
            .await
            .map_err(store)?
            .rows_affected();
        // A login's refresh tokens keep its auth request (their family) alive.
        let keep = (lifetime::ACCESS_TOKEN + lifetime::AUTH_REQUEST).as_secs() as f64 + 3600.0;
        let auth_requests = sqlx::query!(
            "DELETE FROM auth_requests r WHERE r.expires_at < now() - make_interval(secs => $1)
             AND NOT EXISTS (SELECT 1 FROM refresh_tokens t WHERE t.family = r.id)",
            keep,
        )
        .execute(self.pool())
        .await
        .map_err(store)?
        .rows_affected();
        let idp_logins = sqlx::query!("DELETE FROM idp_logins WHERE expires_at < now() - interval '1 hour'")
            .execute(self.pool())
            .await
            .map_err(store)?
            .rows_affected();
        sqlx::query!("DELETE FROM saml_logouts WHERE expires_at < now()").execute(self.pool()).await.map_err(store)?;
        let logout_notifications =
            sqlx::query!("DELETE FROM logout_notifications WHERE created_at < now() - interval '7 days'")
                .execute(self.pool())
                .await
                .map_err(store)?
                .rows_affected();
        Ok(Cleaned { auth_requests, codes, access_tokens, refresh_tokens, idp_logins, logout_notifications })
    }
}

/// The `amr` claim (RFC 8176) for the checks a session passed: `pwd` for a password, `otp` for TOTP or a recovery
/// code, `pop` for a
/// passkey (proof of possession of a key, with user verification); `mfa` when more than one factor was used – a
/// passkey with user verification counts as two.
fn amr(checks: &[String]) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = checks
        .iter()
        .filter_map(|check| match check.as_str() {
            "password" => Some("pwd"),
            // A recovery code is a one-time password, too.
            "totp" | "recovery" => Some("otp"),
            "passkey" => Some("pop"),
            _ => None,
        })
        .collect();
    if methods.len() > 1 || methods.contains(&"pop") {
        methods.push("mfa");
    }
    methods
}

/// Revokes every token of one login.
async fn revoke_family(connection: &mut sqlx::PgConnection, family: &str) -> Result<()> {
    sqlx::query!("DELETE FROM refresh_tokens WHERE family = $1", family)
        .execute(&mut *connection)
        .await
        .map_err(store)?;
    sqlx::query!("DELETE FROM access_tokens WHERE auth_request_id = $1", family)
        .execute(&mut *connection)
        .await
        .map_err(store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_methods() {
        let checks = |list: &[&str]| list.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>();
        assert_eq!(amr(&checks(&["password"])), ["pwd"]);
        assert_eq!(amr(&checks(&["password", "totp"])), ["pwd", "otp", "mfa"]);
        assert_eq!(amr(&checks(&["passkey"])), ["pop", "mfa"]);
        assert_eq!(amr(&checks(&["password", "passkey"])), ["pwd", "pop", "mfa"]);
    }

    #[test]
    fn scope_lists() {
        assert_eq!(scopes(" openid  email openid profile "), ["openid", "email", "profile"]);
        assert_eq!(scopes(&"x ".repeat(100)).len(), 1);
    }

    #[test]
    fn pkce_values() {
        assert!(pkce_value(&"a".repeat(43)));
        assert!(pkce_value("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert!(!pkce_value(&"a".repeat(42)));
        assert!(!pkce_value(&"a".repeat(129)));
        assert!(!pkce_value(&format!("{}+", "a".repeat(43))));
        // The example of RFC 7636, appendix B.
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn queries_are_added_and_encoded() {
        assert_eq!(
            with_query("https://app.example/cb?x=1", &[("code", "a b"), ("state", "s&t")]).unwrap(),
            "https://app.example/cb?x=1&code=a+b&state=s%26t"
        );
    }
}
