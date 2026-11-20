// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's ACME client (RFC 8555), as much of it as ordering certificates with HTTP-01 takes: the directory (7.1.1),
//! nonces (7.2), requests signed as JWS with ES256 (6.2, RFC 7515), accounts (7.3), orders and their authorizations
//! (7.4, 7.5), challenges (7.5.1, 8.1, 8.3), finalizing with a certificate request and downloading the chain (7.4.2),
//! and the CA's error documents (6.7, RFC 7807) – `badNonce` is tried again with a fresh nonce, `Retry-After` is
//! followed while polling.

use std::{path::Path, sync::Mutex, time::Duration};

use aws_lc_rs::{
    digest,
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, KeyPair as _},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Longest any one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a `badNonce` is tried again with a fresh nonce.
const NONCE_ATTEMPTS: usize = 3;
/// The pause between polls when the CA names none.
const POLL_PAUSE: Duration = Duration::from_secs(2);
/// The longest pause between polls kernoid follows.
const MOST_PAUSE: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    /// An error document of the CA (RFC 8555, 6.7).
    #[error("{0}")]
    Problem(Problem),
    #[error("{0}")]
    Protocol(String),
}

fn protocol(what: impl Into<String>) -> Error {
    Error::Protocol(what.into())
}

/// The CA's description of an error: its type (`urn:ietf:params:acme:error:…`), what it says, and what it says about
/// each identifier.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Problem {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub subproblems: Vec<Problem>,
    /// `Retry-After` of the answer, in seconds – with `rateLimited`.
    #[serde(skip)]
    pub retry_after: Option<u64>,
}

impl Problem {
    fn is(&self, kind: &str) -> bool {
        self.kind == format!("urn:ietf:params:acme:error:{kind}")
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = self.kind.strip_prefix("urn:ietf:params:acme:error:").unwrap_or(&self.kind);
        write!(f, "{kind}: {}", self.detail)?;
        for sub in &self.subproblems {
            write!(f, "; {sub}")?;
        }
        if let Some(seconds) = self.retry_after {
            write!(f, " (again after {seconds} s)")?;
        }
        Ok(())
    }
}

/// The CA's directory (RFC 8555, 7.1.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// A CA: its directory, and the nonces it handed out.
#[derive(Debug)]
pub struct Ca {
    http: reqwest::Client,
    url: String,
    directory: Directory,
    nonces: Mutex<Vec<String>>,
}

impl Ca {
    /// Reads the directory at `url`; `extra_root` (PEM) is trusted besides the system's roots – for a test CA.
    pub async fn connect(url: &str, extra_root: Option<&Path>) -> Result<Self, Error> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("kernoid/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = extra_root {
            let pem = std::fs::read(path).map_err(|e| protocol(format!("cannot read {}: {e}", path.display())))?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)?;
            builder = builder.tls_certs_merge(certificates);
        }
        let http = builder.build()?;
        let response = http.get(url).send().await?;
        let directory = json_of(response).await?;
        Ok(Self { http, url: url.to_owned(), directory, nonces: Mutex::new(Vec::new()) })
    }

    async fn nonce(&self) -> Result<String, Error> {
        if let Some(nonce) = self.nonces.lock().expect("not poisoned").pop() {
            return Ok(nonce);
        }
        let response = self.http.head(&self.directory.new_nonce).send().await?;
        self.keep_nonce(&response);
        self.nonces.lock().expect("not poisoned").pop().ok_or_else(|| protocol("the CA gave no nonce"))
    }

    fn keep_nonce(&self, response: &reqwest::Response) {
        if let Some(nonce) = response.headers().get("replay-nonce").and_then(|value| value.to_str().ok()) {
            let mut nonces = self.nonces.lock().expect("not poisoned");
            nonces.push(nonce.to_owned());
            // Only the newest few: a CA forgets old ones.
            let excess = nonces.len().saturating_sub(8);
            nonces.drain(..excess);
        }
    }

    /// A request signed by `key` (with `kid`, or with the public key itself for a new account); `payload` `None` is
    /// a POST-as-GET (RFC 8555, 6.3). A `badNonce` is tried again.
    async fn post(
        &self,
        url: &str,
        key: &AccountKey,
        kid: Option<&str>,
        payload: Option<&Value>,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, Error> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let nonce = self.nonce().await?;
            let body = key.jws(url, &nonce, kid, payload)?;
            let mut request = self.http.post(url).header(header::CONTENT_TYPE, "application/jose+json").body(body);
            if let Some(accept) = accept {
                request = request.header(header::ACCEPT, accept);
            }
            let response = request.send().await?;
            self.keep_nonce(&response);
            if response.status().is_success() {
                return Ok(response);
            }
            let problem = problem_of(response).await;
            if problem.is("badNonce") && attempt < NONCE_ATTEMPTS {
                continue;
            }
            return Err(Error::Problem(problem));
        }
    }
}

async fn problem_of(response: reqwest::Response) -> Problem {
    let status = response.status();
    let retry_after = retry_after(&response);
    let text = response.text().await.unwrap_or_default();
    let mut problem = serde_json::from_str::<Problem>(&text).unwrap_or_else(|_| Problem {
        kind: format!("HTTP {status}"),
        detail: text.chars().take(200).collect(),
        ..Problem::default()
    });
    problem.retry_after = retry_after;
    problem
}

async fn json_of<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    if !response.status().is_success() {
        return Err(Error::Problem(problem_of(response).await));
    }
    let text = response.text().await?;
    serde_json::from_str(&text).map_err(|e| protocol(format!("an answer of the CA is not understood: {e}")))
}

/// `Retry-After` in seconds (RFC 9110, 10.2.3); an HTTP date counts as a minute.
fn retry_after(response: &reqwest::Response) -> Option<u64> {
    let value = response.headers().get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    Some(value.parse().unwrap_or(60))
}

/// An account's key: ECDSA P-256, signing with ES256 (RFC 7518, 3.4).
struct AccountKey {
    pair: EcdsaKeyPair,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl AccountKey {
    fn generate() -> Result<Self, Error> {
        let document = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map_err(|_| protocol("cannot make an account key"))?;
        Self::from_pkcs8(document.as_ref())
    }

    fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|e| protocol(format!("the account key is not usable: {e}")))?;
        Ok(Self { pair, pkcs8: Zeroizing::new(der.to_vec()) })
    }

    /// The public key as a JWK (RFC 7518, 6.2.1): `x` and `y` of the uncompressed point.
    fn jwk(&self) -> Value {
        let point = self.pair.public_key().as_ref();
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        })
    }

    /// The JWK thumbprint (RFC 7638) of the key.
    fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        thumbprint(jwk["x"].as_str().unwrap_or_default(), jwk["y"].as_str().unwrap_or_default())
    }

    /// A request in the flattened JSON serialization of JWS (RFC 8555, 6.2).
    fn jws(&self, url: &str, nonce: &str, kid: Option<&str>, payload: Option<&Value>) -> Result<String, Error> {
        let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
        match kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.jwk(),
        }
        let protected = URL_SAFE_NO_PAD.encode(protected.to_string());
        let payload = payload.map_or_else(String::new, |payload| URL_SAFE_NO_PAD.encode(payload.to_string()));
        let signature = self
            .pair
            .sign(&SystemRandom::new(), format!("{protected}.{payload}").as_bytes())
            .map_err(|_| protocol("cannot sign a request"))?;
        Ok(json!({
            "protected": protected,
            "payload": payload,
            "signature": URL_SAFE_NO_PAD.encode(signature.as_ref()),
        })
        .to_string())
    }
}

/// The JWK thumbprint of a P-256 key (RFC 7638, 3): SHA-256 of the required members in lexicographic order, without
/// whitespace, in base64url.
fn thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, canonical.as_bytes()))
}

/// What kernoid keeps of an account (sealed in `acme_accounts`): its URL, its key as PKCS #8 in base64url, and the
/// directory – the shape stored since kernoid 0.1, read as it was written.
#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub id: String,
    pub key_pkcs8: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").field("id", &self.id).finish_non_exhaustive()
    }
}

/// An account at a CA.
pub struct Account<'a> {
    ca: &'a Ca,
    key: AccountKey,
    url: String,
}

impl std::fmt::Debug for Account<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").field("url", &self.url).finish_non_exhaustive()
    }
}

/// An order (RFC 8555, 7.1.3), with its URL.
#[derive(Debug, Clone, Deserialize)]
pub struct Order {
    #[serde(skip)]
    pub url: String,
    pub status: Status,
    #[serde(default)]
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
    pub error: Option<Problem>,
}

/// An authorization (7.1.4).
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    pub status: Status,
    pub identifier: Identifier,
    #[serde(default)]
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

/// A challenge (7.1.5, 8).
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub token: String,
    pub status: Status,
}

/// The states of orders, authorizations and challenges (7.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl<'a> Account<'a> {
    /// A new account with a new key – or, should the CA know the key, its existing one (RFC 8555, 7.3.1).
    pub async fn create(ca: &'a Ca, contact: &[String]) -> Result<(Self, Credentials), Error> {
        let key = AccountKey::generate()?;
        let payload = json!({ "contact": contact, "termsOfServiceAgreed": true });
        let response = ca.post(&ca.directory.new_account, &key, None, Some(&payload), None).await?;
        let url = location(&response)?;
        let credentials = Credentials {
            id: url.clone(),
            key_pkcs8: URL_SAFE_NO_PAD.encode(key.pkcs8.as_slice()),
            directory: Some(ca.url.clone()),
        };
        Ok((Self { ca, key, url }, credentials))
    }

    /// The account the credentials name, asked of the CA (`onlyReturnExisting`, 7.3.1) so that an account the CA no
    /// longer has is noticed before it is used.
    pub async fn find(ca: &'a Ca, credentials: &Credentials) -> Result<Self, Error> {
        let der = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(credentials.key_pkcs8.trim_end_matches('='))
                .map_err(|_| protocol("the stored account key is not base64url"))?,
        );
        let key = AccountKey::from_pkcs8(&der)?;
        let payload = json!({ "onlyReturnExisting": true });
        let response = ca.post(&ca.directory.new_account, &key, None, Some(&payload), None).await?;
        let url = location(&response)?;
        if url != credentials.id {
            tracing::warn!(stored = %credentials.id, now = %url, "the CA names the ACME account differently");
        }
        Ok(Self { ca, key, url })
    }

    /// `token.thumbprint` – what the HTTP-01 challenge answers (8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.key.thumbprint())
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<(T, Option<u64>, Option<String>), Error> {
        let response = self.ca.post(url, &self.key, Some(&self.url), payload, None).await?;
        let pause = retry_after(&response);
        let location =
            response.headers().get(header::LOCATION).and_then(|value| value.to_str().ok()).map(str::to_owned);
        Ok((json_of(response).await?, pause, location))
    }

    /// A new order for these DNS names (7.4).
    pub async fn new_order(&self, names: &[String]) -> Result<Order, Error> {
        let identifiers: Vec<Value> = names.iter().map(|name| json!({ "type": "dns", "value": name })).collect();
        let payload = json!({ "identifiers": identifiers });
        let (mut order, _, location): (Order, _, _) =
            self.post_json(&self.ca.directory.new_order, Some(&payload)).await?;
        order.url = location.ok_or_else(|| protocol("the CA named no order URL"))?;
        Ok(order)
    }

    pub async fn authorization(&self, url: &str) -> Result<Authorization, Error> {
        Ok(self.post_json(url, None).await?.0)
    }

    /// Tells the CA that a challenge can be checked now (7.5.1).
    pub async fn ready(&self, challenge: &Challenge) -> Result<(), Error> {
        let _: (Value, _, _) = self.post_json(&challenge.url, Some(&json!({}))).await?;
        Ok(())
    }

    async fn order(&self, url: &str) -> Result<(Order, Option<u64>), Error> {
        let (mut order, pause, _): (Order, _, _) = self.post_json(url, None).await?;
        order.url = url.to_owned();
        Ok((order, pause))
    }

    /// Polls the order until it is no longer `pending` or `processing`, or `patience` is over, pausing as the CA's
    /// `Retry-After` says.
    pub async fn settle(&self, url: &str, patience: Duration) -> Result<Order, Error> {
        let until = tokio::time::Instant::now() + patience;
        loop {
            let (order, pause) = self.order(url).await?;
            if !matches!(order.status, Status::Pending | Status::Processing) {
                return Ok(order);
            }
            let pause = pause.map_or(POLL_PAUSE, Duration::from_secs).min(MOST_PAUSE);
            if tokio::time::Instant::now() + pause > until {
                return Err(protocol(format!("the order is still {:?}", order.status)));
            }
            tokio::time::sleep(pause).await;
        }
    }

    /// Sends the certificate request (DER) of a `ready` order (7.4).
    pub async fn finalize(&self, order: &Order, csr: &[u8]) -> Result<(), Error> {
        let payload = json!({ "csr": URL_SAFE_NO_PAD.encode(csr) });
        let _: (Value, _, _) = self.post_json(&order.finalize, Some(&payload)).await?;
        Ok(())
    }

    /// The issued chain, leaf first, as PEM (7.4.2).
    pub async fn certificate(&self, url: &str) -> Result<String, Error> {
        let response =
            self.ca.post(url, &self.key, Some(&self.url), None, Some("application/pem-certificate-chain")).await?;
        let chain = response.text().await?;
        if !chain.contains("-----BEGIN CERTIFICATE-----") {
            return Err(protocol("the CA sent no certificate chain"));
        }
        Ok(chain)
    }
}

fn location(response: &reqwest::Response) -> Result<String, Error> {
    if !matches!(response.status(), StatusCode::OK | StatusCode::CREATED) {
        return Err(protocol(format!("the CA answered {}", response.status())));
    }
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| protocol("the CA named no account URL"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_signed_jws_with_the_key_or_its_account() {
        let key = AccountKey::generate().unwrap();
        let body: Value =
            serde_json::from_str(&key.jws("https://ca.example/new-acct", "n1", None, Some(&json!({"a": 1}))).unwrap())
                .unwrap();
        let decode = |field: &str| URL_SAFE_NO_PAD.decode(body[field].as_str().unwrap()).unwrap();
        let protected: Value = serde_json::from_slice(&decode("protected")).unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "n1");
        assert_eq!(protected["url"], "https://ca.example/new-acct");
        assert_eq!(protected["jwk"]["kty"], "EC");
        assert!(protected.get("kid").is_none());
        assert_eq!(serde_json::from_slice::<Value>(&decode("payload")).unwrap(), json!({"a": 1}));
        // ES256: r and s of 32 bytes each, over `protected.payload`.
        let signature = decode("signature");
        assert_eq!(signature.len(), 64);
        let signed = format!("{}.{}", body["protected"].as_str().unwrap(), body["payload"].as_str().unwrap());
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key.pair.public_key().as_ref())
            .verify(signed.as_bytes(), &signature)
            .unwrap();

        let as_get: Value = serde_json::from_str(
            &key.jws("https://ca.example/order/1", "n2", Some("https://ca.example/acct/7"), None).unwrap(),
        )
        .unwrap();
        assert_eq!(as_get["payload"], "", "POST-as-GET");
        let protected: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(as_get["protected"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(protected["kid"], "https://ca.example/acct/7");
        assert!(protected.get("jwk").is_none());
    }

    #[test]
    fn the_thumbprint_hashes_the_canonical_jwk() {
        // The EC key of RFC 7515, appendix A.3; its canonical JWK (RFC 7638, 3.2) hashed with SHA-256.
        let (x, y) = ("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        let canonical = r#"{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        assert_eq!(thumbprint(x, y), URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, canonical.as_bytes())));
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        assert_eq!(key.thumbprint(), thumbprint(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap()));
        assert_eq!(key.thumbprint().len(), 43, "32 bytes in base64url");
    }

    #[test]
    fn stored_credentials_are_read_as_written_before() {
        // The shape kernoid stored up to 0.5 (an account at Pebble).
        let stored = r#"{"id":"https://localhost:14000/my-account/2053a2418a50d0cd","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSgJTgmSq2slxniTDgvFs4fKoPWNOIoaXyFkv-bcRHiShRANCAATy-mmNnHjB-gkcxXSB-rv_NPI8CjhCwSsD8l_SHlDfxwZKaai1Be3HIc7ttQSkhwVoUFhqs8dcDHc22Jdm2rFn","directory":"https://localhost:14000/dir"}"#;
        let credentials: Credentials = serde_json::from_str(stored).unwrap();
        let der = URL_SAFE_NO_PAD.decode(&credentials.key_pkcs8).unwrap();
        AccountKey::from_pkcs8(&der).unwrap();
        assert_eq!(serde_json::to_string(&credentials).unwrap(), stored);
    }

    #[test]
    fn problems_are_shown_with_their_subproblems() {
        let problem: Problem = serde_json::from_str(
            r#"{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"no","subproblems":[{"type":"urn:ietf:params:acme:error:caa","detail":"CAA forbids"}]}"#,
        )
        .unwrap();
        assert!(problem.is("rejectedIdentifier"));
        assert_eq!(problem.to_string(), "rejectedIdentifier: no; caa: CAA forbids");
    }
}
