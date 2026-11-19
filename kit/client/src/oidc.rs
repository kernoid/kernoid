// SPDX-License-Identifier: MIT
//! Logging in with OpenID Connect, as kernoid's own apps do (RFC 0001, 7.2; RFC 8252): the authorization code flow
//! with PKCE in the system's browser – where kernoid's login page asks for the passkey, the password or a second
//! factor –, kernoid's built-in client of the apps (`kernoid_apps_client_id` in the discovery document), and the
//! scope `urn:kernoid:data`, with which the access token reaches JMAP, CalDAV, CardDAV and WebDAV. `offline_access`
//! gives a refresh token, so that the app stays logged in.
//!
//! [`begin`] gives the URL to open and what to keep; the app opens it (`ASWebAuthenticationSession`, Custom Tabs, the
//! default browser with a loopback listener) and hands the URL it is sent back to [`finish`].

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Options, Result, is_local, split_origin};

/// What kernoid's apps ask for.
pub const SCOPES: &str = "openid profile email offline_access urn:kernoid:data";

/// The URI kernoid's apps are sent back to on Apple's systems and Android (their private scheme, RFC 8252, 7.1); on
/// desktops a loopback address with a port of the app's choosing (7.3): `http://127.0.0.1:<port>/oauth`.
pub const APP_REDIRECT_URI: &str = "dev.kernoid.kernoid:/oauth";

/// A login begun: the URL for the browser, and what [`finish`] needs. Keep it until the browser comes back.
#[derive(Debug, Clone)]
pub struct Login {
    pub url: String,
    issuer: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    client_id: String,
    redirect_uri: String,
    verifier: String,
    state: String,
}

/// The tokens of a login. `refresh_token` renews them ([`refresh`]); `expires_at` is the access token's end, in
/// seconds since 1970.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
    /// For the token endpoint and client id that renew them.
    pub token_endpoint: String,
    pub client_id: String,
    /// Where [`revoke`] ends the login (RFC 7009), if the server has one.
    pub revocation_endpoint: Option<String>,
}

/// What an app keeps of a login to resume it after a restart – in the system's key store, as it is a credential:
/// the refresh token and where it is used, never the access token. kernoid rotates refresh tokens, so it is kept
/// again after every [`refresh`]; presenting one used before ends the login (OAuth 2.0 Security BCP, 4.14).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Saved {
    pub refresh_token: String,
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

impl Tokens {
    /// What to keep of these tokens; none without a refresh token.
    pub fn saved(&self) -> Option<Saved> {
        Some(Saved {
            refresh_token: self.refresh_token.clone()?,
            token_endpoint: self.token_endpoint.clone(),
            client_id: self.client_id.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
        })
    }
}

impl Saved {
    /// Tokens to renew: the access token is empty until [`refresh`] gives one.
    pub fn tokens(&self) -> Tokens {
        Tokens {
            access_token: String::new(),
            refresh_token: Some(self.refresh_token.clone()),
            expires_at: 0,
            token_endpoint: self.token_endpoint.clone(),
            client_id: self.client_id.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
        }
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    kernoid_apps_client_id: Option<String>,
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

fn random(bytes: usize) -> Result<String> {
    let mut buffer = vec![0; bytes];
    getrandom::fill(&mut buffer).map_err(|error| Error::Transport(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn http(origin: &str, options: &Options) -> Result<reqwest::Client> {
    if !origin.starts_with("https://") && !(options.allow_http && origin.starts_with("http://")) && !is_local(origin) {
        return Err(Error::Protocol(format!("{origin} is not HTTPS")));
    }
    crate::http(origin, &options.user_agent, Some(std::time::Duration::from_secs(60)))
}

/// The origin of a server as the user gives it: `https://host`, a URL of it, or the host alone.
fn origin_of(server: &str) -> Result<String> {
    let server = server.trim().trim_end_matches('/');
    let server = if server.contains("://") { server.to_owned() } else { format!("https://{server}") };
    split_origin(&server)
        .map(|(origin, _)| origin.to_owned())
        .ok_or_else(|| Error::Protocol(format!("not a URL: {server}")))
}

/// Begins a login at `server` for kernoid's own apps, to come back to `redirect_uri` ([`APP_REDIRECT_URI`] or a
/// loopback address); `login_hint` fills in the address on the login page.
pub async fn begin(server: &str, redirect_uri: &str, login_hint: Option<&str>, options: &Options) -> Result<Login> {
    let origin = origin_of(server)?;
    let response = http(&origin, options)?
        .get(format!("{origin}/.well-known/openid-configuration"))
        .header("accept", "application/json")
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(Error::Status(response.status().as_u16(), None));
    }
    let discovery: Discovery = response.json().await.map_err(|error| Error::Protocol(error.to_string()))?;
    let client_id = discovery
        .kernoid_apps_client_id
        .ok_or_else(|| Error::Protocol("this server has no client for kernoid's apps".into()))?;
    // The issuer is the server asked – its host; the endpoints are used on the origin asked, as the JMAP client keeps
    // to it, so nothing goes elsewhere (and a server behind a proxy that names no port still works).
    let host = |url: &str| split_origin(url).map(|(origin, _)| crate::host(origin).to_ascii_lowercase());
    if host(&discovery.issuer) != host(&origin) {
        return Err(Error::Protocol("the server names another issuer".into()));
    }
    let here = |endpoint: &str| -> Result<String> {
        if host(endpoint) != host(&origin) {
            return Err(Error::Protocol("the server's endpoints are on another host".into()));
        }
        Ok(format!("{origin}{}", split_origin(endpoint).map_or("/", |(_, path)| path)))
    };
    let (authorization_endpoint, token_endpoint) =
        (here(&discovery.authorization_endpoint)?, here(&discovery.token_endpoint)?);
    let revocation_endpoint = discovery.revocation_endpoint.as_deref().map(here).transpose()?;
    let verifier = random(32)?;
    let state = random(16)?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url = url::Url::parse(&authorization_endpoint).map_err(|error| Error::Protocol(error.to_string()))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(hint) = login_hint.map(str::trim).filter(|hint| !hint.is_empty()) {
            query.append_pair("login_hint", hint);
        }
    }
    Ok(Login {
        url: url.into(),
        issuer: discovery.issuer,
        token_endpoint,
        revocation_endpoint,
        client_id,
        redirect_uri: redirect_uri.to_owned(),
        verifier,
        state,
    })
}

/// Finishes a login with the URL the browser was sent back to: checks `state` and `iss` (RFC 9207), and exchanges
/// the code for tokens.
pub async fn finish(login: &Login, callback: &str, options: &Options) -> Result<Tokens> {
    let url = url::Url::parse(callback).map_err(|_| Error::Protocol("not the URL of a login".into()))?;
    let params: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    if params.get("state") != Some(&login.state) {
        return Err(Error::Protocol("the login came back for another request".into()));
    }
    if let Some(iss) = params.get("iss")
        && iss != &login.issuer
    {
        return Err(Error::Protocol("the login came back from another server".into()));
    }
    if let Some(error) = params.get("error") {
        let description = params.get("error_description").cloned();
        return Err(Error::Method { kind: error.clone(), description });
    }
    let code = params.get("code").ok_or_else(|| Error::Protocol("the login came back without a code".into()))?;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", login.redirect_uri.as_str()),
        ("code_verifier", login.verifier.as_str()),
        ("client_id", login.client_id.as_str()),
    ];
    tokens(&login.token_endpoint, &login.client_id, login.revocation_endpoint.as_deref(), &form, options).await
}

/// New tokens for a refresh token; the one used is used up (kernoid rotates them).
pub async fn refresh(tokens: &Tokens, options: &Options) -> Result<Tokens> {
    let refresh_token =
        tokens.refresh_token.as_deref().ok_or_else(|| Error::Protocol("the login has no refresh token".into()))?;
    let form =
        [("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("client_id", tokens.client_id.as_str())];
    let mut new =
        self::tokens(&tokens.token_endpoint, &tokens.client_id, tokens.revocation_endpoint.as_deref(), &form, options)
            .await?;
    // A server may keep the refresh token as it is.
    if new.refresh_token.is_none() {
        new.refresh_token = tokens.refresh_token.clone();
    }
    Ok(new)
}

async fn tokens(
    endpoint: &str,
    client_id: &str,
    revocation_endpoint: Option<&str>,
    form: &[(&str, &str)],
    options: &Options,
) -> Result<Tokens> {
    let (origin, _) = split_origin(endpoint).ok_or_else(|| Error::Protocol(format!("not a URL: {endpoint}")))?;
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
    let response = http(origin, options)?
        .post(endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    let status = response.status().as_u16();
    let body: Value = response.json().await.map_err(|error| Error::Protocol(error.to_string()))?;
    if status != 200 {
        let kind = body.get("error").and_then(Value::as_str).unwrap_or("invalid_grant").to_owned();
        if kind == "invalid_grant" {
            return Err(Error::Unauthorized);
        }
        let description = body.get("error_description").and_then(Value::as_str).map(str::to_owned);
        return Err(Error::Method { kind, description });
    }
    let answer: TokenAnswer = serde_json::from_value(body).map_err(|error| Error::Protocol(error.to_string()))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
    Ok(Tokens {
        access_token: answer.access_token,
        refresh_token: answer.refresh_token,
        expires_at: now + answer.expires_in,
        token_endpoint: endpoint.to_owned(),
        client_id: client_id.to_owned(),
        revocation_endpoint: revocation_endpoint.map(str::to_owned),
    })
}

/// Ends a login: revokes the refresh token – and with it its access tokens – at the server (RFC 7009). A login the
/// server no longer knows counts as ended.
pub async fn revoke(tokens: &Tokens, options: &Options) -> Result<()> {
    let (Some(endpoint), Some(refresh_token)) = (&tokens.revocation_endpoint, &tokens.refresh_token) else {
        return Ok(());
    };
    let (origin, _) = split_origin(endpoint).ok_or_else(|| Error::Protocol(format!("not a URL: {endpoint}")))?;
    let form =
        [("token", refresh_token.as_str()), ("token_type_hint", "refresh_token"), ("client_id", &tokens.client_id)];
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
    let response = http(origin, options)?
        .post(endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    match response.status().as_u16() {
        200 => Ok(()),
        status => Err(Error::Status(status, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_as_people_type_them() {
        assert_eq!(origin_of("login.example").unwrap(), "https://login.example");
        assert_eq!(origin_of("http://apps.localhost:18382/").unwrap(), "http://apps.localhost:18382");
        assert_eq!(origin_of("https://a.example/jmap/session").unwrap(), "https://a.example");
    }

    #[test]
    fn verifiers_are_long_and_fresh() {
        let (a, b) = (random(32).unwrap(), random(32).unwrap());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }
}
