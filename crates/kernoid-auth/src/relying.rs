// SPDX-License-Identifier: AGPL-3.0-or-later
//! A program's server as the relying party of an OpenID provider (RFC 0009, 2): the login with the authorization code
//! flow and PKCE, access tokens and logout tokens checked against the provider's keys, and who logged in as a
//! [`Principal`]. Written against the standard – any provider will do; kernoid's tenant and project roles are read
//! where they are.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

use crate::{
    outbound,
    provider::{self, ExternalError, ProviderMetadata},
};

/// kernoid's claim with the account's roles in the application's project: `{"<role>": {"<tenant id>": "<name>"}}`.
pub const KERNOID_ROLES_CLAIM: &str = "urn:kernoid:project:roles";
/// kernoid's claim with the account's tenant.
pub const KERNOID_TENANT_CLAIM: &str = "urn:kernoid:tenant";
/// kernoid's scope that asks for the project roles.
pub const KERNOID_ROLES_SCOPE: &str = "urn:kernoid:project:roles";
/// The event of a logout token (OpenID Connect Back-Channel Logout 1.0, 2.4).
const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// How long the provider's discovery document and keys are kept before they are fetched again.
const PROVIDER_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// Seconds of clock difference accepted.
const LEEWAY: i64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Provider(#[from] ExternalError),
    /// The callback does not belong to the login this browser started.
    #[error("the login's state does not match")]
    State,
    #[error("the provider ended the login: {0}")]
    Denied(String),
    #[error("the token is not valid: {0}")]
    Token(String),
    #[error("the settings are not valid: {0}")]
    Settings(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

/// How the program logs in with its provider.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The provider: its issuer, e.g. `https://id.example.org` for a kernoid.
    pub issuer: String,
    /// The program's application at the provider.
    pub client_id: String,
    /// The application's secret; leave out for a public client.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Where the provider sends the browser back, e.g. `https://music.example.org/auth/callback`.
    pub redirect_uri: String,
    /// Scopes asked for besides `openid`; by default `profile`, `email` and kernoid's project roles.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// The claim with the roles, for a provider other than kernoid; kernoid's by default.
    #[serde(default)]
    pub roles_claim: Option<String>,
    /// Let the provider be reached over plain HTTP and at private addresses – only for a provider in the program's
    /// own network, or for development.
    #[serde(default)]
    pub allow_private: bool,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "***"))
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("roles_claim", &self.roles_claim)
            .field("allow_private", &self.allow_private)
            .finish()
    }
}

fn default_scopes() -> Vec<String> {
    ["profile", "email", KERNOID_ROLES_SCOPE].map(str::to_owned).to_vec()
}

/// Who logged in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The provider's identity of the person – with kernoid, the account's id.
    pub subject: String,
    /// The person's tenant (kernoid: its id), if the provider says.
    pub tenant: Option<String>,
    /// The person's roles in the program – kernoid's project roles.
    pub roles: BTreeSet<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    /// The provider's login session, for logging out (`sid`).
    pub session: Option<String>,
}

impl Principal {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// From the claims of an ID token, an access token or userinfo.
    fn from_claims(claims: &Value, roles_claim: &str) -> Option<Self> {
        let subject = claims["sub"].as_str().filter(|sub| !sub.is_empty())?.to_owned();
        let roles = match &claims[roles_claim] {
            // kernoid's (and ZITADEL's) shape: roles as keys.
            Value::Object(map) => map.keys().cloned().collect(),
            Value::Array(list) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            Value::String(spaced) => spaced.split_whitespace().map(str::to_owned).collect(),
            _ => BTreeSet::new(),
        };
        let text = |name: &str| claims[name].as_str().map(str::to_owned);
        Some(Self {
            subject,
            tenant: text(KERNOID_TENANT_CLAIM),
            roles,
            name: text("name"),
            email: text("email").filter(|_| claims["email_verified"].as_bool() != Some(false)),
            session: text("sid"),
        })
    }
}

/// A login this browser started: kept by the program until the provider sends the browser back (in a cookie).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    /// Where to go after the login – a path of the program.
    pub next: String,
}

impl Pending {
    /// As a cookie's value.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("a pending login serialises"))
    }

    pub fn decode(value: &str) -> Option<Self> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).ok()?).ok()
    }
}

/// A login that began: send the browser to `url`, keep `pending`.
#[derive(Debug, Clone)]
pub struct Start {
    pub url: String,
    pub pending: Pending,
}

/// A finished login.
#[derive(Debug, Clone)]
pub struct Login {
    pub principal: Principal,
    /// For logging out at the provider (`id_token_hint`).
    pub id_token: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Whom a logout token ends: every session of `subject`, or the one login `session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logout {
    pub subject: Option<String>,
    pub session: Option<String>,
}

/// What the provider says about itself, fetched once in a while.
#[derive(Debug, Clone)]
struct Known {
    metadata: ProviderMetadata,
    keys: Vec<Value>,
    fetched: Instant,
}

/// The program as the relying party of its provider. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    settings: Arc<Settings>,
    client: reqwest::Client,
    known: Arc<RwLock<Option<Known>>>,
}

impl RelyingParty {
    pub fn new(settings: Settings) -> Result<Self> {
        let redirect =
            Url::parse(&settings.redirect_uri).map_err(|e| AuthError::Settings(format!("redirect_uri: {e}")))?;
        if redirect.scheme() != "https" && !settings.allow_private {
            return Err(AuthError::Settings("redirect_uri must be HTTPS".into()));
        }
        let client = outbound::client(settings.allow_private);
        Ok(Self { settings: Arc::new(settings), client, known: Arc::new(RwLock::new(None)) })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    fn roles_claim(&self) -> &str {
        self.settings.roles_claim.as_deref().unwrap_or(KERNOID_ROLES_CLAIM)
    }

    /// The provider's metadata and keys – fetched again when they are old, or when `refresh` (an unknown key).
    async fn known(&self, refresh: bool) -> Result<Known> {
        if !refresh
            && let Some(known) = self.known.read().await.as_ref()
            && known.fetched.elapsed() < PROVIDER_LIFETIME
        {
            return Ok(known.clone());
        }
        let allow = self.settings.allow_private;
        let metadata = provider::discover(&self.client, &self.settings.issuer, allow).await?;
        let keys = provider::keys(&self.client, &metadata, allow).await?;
        let known = Known { metadata, keys, fetched: Instant::now() };
        *self.known.write().await = Some(known.clone());
        Ok(known)
    }

    /// Begins a login; afterwards the browser comes back to `redirect_uri`, and then goes on to `next` (a path of the
    /// program – anything else becomes `/`).
    pub async fn start(&self, next: &str) -> Result<Start> {
        let known = self.known(false).await?;
        let pending = Pending {
            state: random()?,
            nonce: random()?,
            verifier: random()?,
            next: if next.starts_with('/') && !next.starts_with("//") { next.to_owned() } else { "/".into() },
        };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
        let mut scopes = vec!["openid".to_owned()];
        scopes.extend(self.settings.scopes.iter().filter(|scope| *scope != "openid").cloned());
        let mut url = Url::parse(&known.metadata.authorization_endpoint)
            .map_err(|e| AuthError::Provider(ExternalError::Invalid(e.to_string())))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.settings.client_id)
            .append_pair("redirect_uri", &self.settings.redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &pending.state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(Start { url: url.into(), pending })
    }

    /// Finishes the login the browser came back with: `state` must be the pending one's; the code is exchanged and
    /// the ID token checked.
    pub async fn finish(&self, pending: &Pending, code: &str, state: &str) -> Result<Login> {
        if !same(state, &pending.state) {
            return Err(AuthError::State);
        }
        let known = self.known(false).await?;
        let tokens = provider::exchange_code(
            &self.client,
            &known.metadata,
            code,
            &self.settings.redirect_uri,
            &pending.verifier,
            &self.settings.client_id,
            self.settings.client_secret.as_deref(),
            self.settings.allow_private,
        )
        .await?;
        let mut keys = known.keys;
        if provider::names_unknown_key(&tokens.id_token, &keys) {
            keys = self.known(true).await?.keys;
        }
        let expected = provider::Expected {
            issuer: &self.settings.issuer,
            client_id: &self.settings.client_id,
            nonce: &pending.nonce,
            now: jiff::Timestamp::now().as_second(),
        };
        let claims = provider::verify_id_token(&tokens.id_token, &keys, expected)?;
        let principal = Principal::from_claims(&claims, self.roles_claim())
            .ok_or_else(|| AuthError::Token("the ID token has no subject".into()))?;
        Ok(Login {
            principal,
            id_token: tokens.id_token,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        })
    }

    /// Checks a signed token of the provider – its signature, issuer and time – and gives its claims.
    async fn verify(&self, token: &str) -> Result<(Value, Value)> {
        let mut keys = self.known(false).await?.keys;
        if provider::names_unknown_key(token, &keys) {
            keys = self.known(true).await?.keys;
        }
        let (header, claims) = provider::verify_signature(token, &keys).map_err(AuthError::Token)?;
        if claims["iss"].as_str().map(|iss| iss.trim_end_matches('/'))
            != Some(self.settings.issuer.trim_end_matches('/'))
        {
            return Err(AuthError::Token("it comes from another issuer".into()));
        }
        let now = jiff::Timestamp::now().as_second();
        if claims["iat"].as_i64().is_some_and(|iat| iat - LEEWAY > now) {
            return Err(AuthError::Token("it was issued in the future".into()));
        }
        Ok((header, claims))
    }

    fn audience_is_mine(&self, claims: &Value) -> bool {
        match &claims["aud"] {
            Value::String(one) => one == &self.settings.client_id,
            Value::Array(many) => many.iter().any(|aud| aud.as_str() == Some(self.settings.client_id.as_str())),
            _ => false,
        }
    }

    /// Checks an access token the program's apps send as `Authorization: Bearer` – a JWT (RFC 9068, as kernoid issues
    /// for applications that ask for it) for this application, not expired.
    pub async fn verify_access_token(&self, token: &str) -> Result<Principal> {
        let (header, claims) = self.verify(token).await?;
        let kind = header["typ"].as_str().unwrap_or_default().to_ascii_lowercase();
        if kind != "at+jwt" && kind != "application/at+jwt" {
            return Err(AuthError::Token("it is not an access token".into()));
        }
        if !self.audience_is_mine(&claims) {
            return Err(AuthError::Token("it is for another application".into()));
        }
        if claims["exp"].as_i64().is_none_or(|exp| exp + LEEWAY < jiff::Timestamp::now().as_second()) {
            return Err(AuthError::Token("it has expired".into()));
        }
        Principal::from_claims(&claims, self.roles_claim()).ok_or_else(|| AuthError::Token("it has no subject".into()))
    }

    /// Checks a logout token of back-channel logout (OpenID Connect Back-Channel Logout 1.0, 2.6).
    pub async fn verify_logout_token(&self, token: &str) -> Result<Logout> {
        let (_, claims) = self.verify(token).await?;
        if !self.audience_is_mine(&claims) {
            return Err(AuthError::Token("it is for another application".into()));
        }
        if !claims["events"].as_object().is_some_and(|events| events.contains_key(LOGOUT_EVENT)) {
            return Err(AuthError::Token("it is not a logout token".into()));
        }
        if claims.get("nonce").is_some() {
            return Err(AuthError::Token("a logout token has no nonce".into()));
        }
        let text = |name: &str| claims[name].as_str().filter(|value| !value.is_empty()).map(str::to_owned);
        let logout = Logout { subject: text("sub"), session: text("sid") };
        if logout.subject.is_none() && logout.session.is_none() {
            return Err(AuthError::Token("it names no one".into()));
        }
        Ok(logout)
    }

    /// Where to send the browser to log out at the provider too, if it has an end session endpoint.
    pub async fn logout_url(&self, id_token: Option<&str>, after: Option<&str>) -> Result<Option<String>> {
        let known = self.known(false).await?;
        let Some(endpoint) = known.metadata.end_session_endpoint else { return Ok(None) };
        let mut url = Url::parse(&endpoint).map_err(|e| AuthError::Provider(ExternalError::Invalid(e.to_string())))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &self.settings.client_id);
            if let Some(hint) = id_token {
                query.append_pair("id_token_hint", hint);
            }
            if let Some(after) = after {
                query.append_pair("post_logout_redirect_uri", after);
            }
        }
        Ok(Some(url.into()))
    }
}

/// 32 random bytes, base64url.
pub(crate) fn random() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| AuthError::Settings(format!("no randomness: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Compares secrets in time that does not depend on where they differ.
pub(crate) fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn principals_from_kernoid_and_other_providers() {
        let kernoid = json!({ "sub": "0193…", "urn:kernoid:tenant": "t1", "name": "Ada", "email": "ada@example.org",
            "email_verified": true, "sid": "s1", "urn:kernoid:project:roles": { "librarian": { "t1": "School" } } });
        let principal = Principal::from_claims(&kernoid, KERNOID_ROLES_CLAIM).unwrap();
        assert_eq!(principal.tenant.as_deref(), Some("t1"));
        assert!(principal.has_role("librarian") && !principal.has_role("admin"));
        assert_eq!(principal.session.as_deref(), Some("s1"));
        let other = json!({ "sub": "x", "groups": ["a", "b"], "email": "x@example.org", "email_verified": false });
        let principal = Principal::from_claims(&other, "groups").unwrap();
        assert_eq!(principal.roles.len(), 2);
        assert_eq!(principal.email, None);
        assert!(Principal::from_claims(&json!({ "sub": "" }), "roles").is_none());
    }

    #[test]
    fn pending_logins_survive_a_cookie() {
        let pending = Pending { state: "s".into(), nonce: "n".into(), verifier: "v".into(), next: "/x".into() };
        assert_eq!(Pending::decode(&pending.encode()), Some(pending));
        assert_eq!(Pending::decode("not base64 json"), None);
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "ab"));
    }
}
