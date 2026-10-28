// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid as the client of another OpenID provider (OpenID Connect Core 1.0, Discovery 1.0): what logging in with an
//! external identity provider needs – its discovery document, the code exchange with PKCE, and the ID token verified
//! against its published keys. Signatures are checked by aws-lc-rs; kernoid parses JWKs and compares claims, nothing
//! more.

use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RSA_PSS_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::outbound::{MAX_BODY, check_url};

/// Seconds of clock difference accepted when checking `exp` and `iat`.
const LEEWAY: i64 = 120;

#[derive(Debug, thiserror::Error)]
pub enum ExternalError {
    #[error("the identity provider cannot be reached: {0}")]
    Unreachable(String),
    #[error("the identity provider answered something unexpected: {0}")]
    Invalid(String),
    #[error("the identity provider refused: {0}")]
    Refused(String),
}

type Result<T> = std::result::Result<T, ExternalError>;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Reads an answer of at most `MAX_BODY` bytes as JSON.
async fn json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<(reqwest::StatusCode, T)> {
    let status = response.status();
    if response.content_length().is_some_and(|length| length > MAX_BODY as u64) {
        return Err(ExternalError::Invalid("the answer is too large".into()));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(|e| ExternalError::Unreachable(e.to_string()))? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BODY {
            return Err(ExternalError::Invalid("the answer is too large".into()));
        }
    }
    let value =
        serde_json::from_slice(&body).map_err(|e| ExternalError::Invalid(format!("not the expected JSON: {e}")))?;
    Ok((status, value))
}

fn endpoint(value: &str, allow_private: bool) -> Result<Url> {
    let url = Url::parse(value).map_err(|e| ExternalError::Invalid(format!("{value}: {e}")))?;
    check_url(&url, allow_private).map_err(ExternalError::Invalid)?;
    Ok(url)
}

/// The provider's discovery document; its `issuer` must be the one asked for (OpenID Connect Discovery 1.0, 4.3).
pub async fn discover(client: &Client, issuer: &str, allow_private: bool) -> Result<ProviderMetadata> {
    let url = endpoint(&format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/')), allow_private)?;
    let response = client.get(url).send().await.map_err(|e| ExternalError::Unreachable(e.to_string()))?;
    let (status, metadata): (_, ProviderMetadata) = json(response).await?;
    if !status.is_success() {
        return Err(ExternalError::Invalid(format!("discovery answered {status}")));
    }
    if metadata.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(ExternalError::Invalid(format!("the provider calls itself {}", metadata.issuer)));
    }
    for url in [&metadata.authorization_endpoint, &metadata.token_endpoint, &metadata.jwks_uri] {
        endpoint(url, allow_private)?;
    }
    Ok(metadata)
}

/// The provider's signing keys.
pub async fn keys(client: &Client, metadata: &ProviderMetadata, allow_private: bool) -> Result<Vec<Value>> {
    let response = client
        .get(endpoint(&metadata.jwks_uri, allow_private)?)
        .send()
        .await
        .map_err(|e| ExternalError::Unreachable(e.to_string()))?;
    let (status, jwks): (_, Value) = json(response).await?;
    if !status.is_success() {
        return Err(ExternalError::Invalid(format!("the keys answered {status}")));
    }
    jwks["keys"].as_array().cloned().ok_or_else(|| ExternalError::Invalid("no keys".into()))
}

/// What the code exchange gives.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenSet {
    pub id_token: String,
    #[serde(default)]
    pub access_token: Option<String>,
}

/// Exchanges an authorization code (with the PKCE verifier) at the provider's token endpoint; kernoid authenticates
/// with `client_secret_post`.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    client: &Client,
    metadata: &ProviderMetadata,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
    client_id: &str,
    client_secret: Option<&str>,
    allow_private: bool,
) -> Result<TokenSet> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let response = client
        .post(endpoint(&metadata.token_endpoint, allow_private)?)
        .form(&form)
        .send()
        .await
        .map_err(|e| ExternalError::Unreachable(e.to_string()))?;
    let (status, body): (_, Value) = json(response).await?;
    if !status.is_success() {
        let error = body["error"].as_str().unwrap_or("unknown error");
        return Err(ExternalError::Refused(format!("{error} ({status})")));
    }
    serde_json::from_value(body).map_err(|e| ExternalError::Invalid(format!("no ID token: {e}")))
}

/// What kernoid expects of an ID token.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Seconds since the epoch.
    pub now: i64,
}

/// Verifies an ID token: the signature with one of `keys` (by `kid`, or any fitting key without one), then issuer,
/// audience, authorized party, expiry, issue time and nonce. Returns its claims.
pub fn verify_id_token(token: &str, keys: &[Value], expected: Expected<'_>) -> Result<Value> {
    let invalid = |why: &str| ExternalError::Invalid(format!("the ID token {why}"));
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else { return Err(invalid("is not a JWS")) };
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| invalid("is not base64url"));
    let head: Value = serde_json::from_slice(&decode(header)?).map_err(|_| invalid("has no JSON header"))?;
    let algorithm = head["alg"].as_str().unwrap_or_default();
    let kid = head["kid"].as_str();
    let signature = decode(signature)?;
    let message = format!("{header}.{payload}");
    let verified = keys
        .iter()
        .filter(|key| kid.is_none() || key["kid"].as_str() == kid)
        .filter(|key| key["use"].as_str().is_none_or(|usage| usage == "sig"))
        .any(|key| verify_with(key, algorithm, message.as_bytes(), &signature));
    if !verified {
        return Err(invalid(&format!("has no valid signature ({algorithm})")));
    }
    let claims: Value = serde_json::from_slice(&decode(payload)?).map_err(|_| invalid("has no JSON claims"))?;
    if claims["iss"].as_str().map(|iss| iss.trim_end_matches('/')) != Some(expected.issuer.trim_end_matches('/')) {
        return Err(invalid("comes from another issuer"));
    }
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(one) => vec![one.as_str()],
        Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expected.client_id) {
        return Err(invalid("is for another client"));
    }
    if audiences.len() > 1 && claims["azp"].as_str() != Some(expected.client_id) {
        return Err(invalid("is for several clients, and kernoid is not the authorized party"));
    }
    if claims["exp"].as_i64().is_none_or(|exp| exp + LEEWAY < expected.now) {
        return Err(invalid("has expired"));
    }
    if claims["iat"].as_i64().is_some_and(|iat| iat - LEEWAY > expected.now) {
        return Err(invalid("was issued in the future"));
    }
    if claims["nonce"].as_str() != Some(expected.nonce) {
        return Err(invalid("has another nonce"));
    }
    if claims["sub"].as_str().is_none_or(str::is_empty) {
        return Err(invalid("has no subject"));
    }
    Ok(claims)
}

/// Checks a signature with a JWK – RSA (RS256/384/512, PS256) or EC (ES256 on P-256, ES384 on P-384).
fn verify_with(jwk: &Value, algorithm: &str, message: &[u8], signature: &[u8]) -> bool {
    let field = |name: &str| jwk[name].as_str().and_then(|value| URL_SAFE_NO_PAD.decode(value).ok());
    if jwk["alg"].as_str().is_some_and(|alg| alg != algorithm) {
        return false;
    }
    match (jwk["kty"].as_str(), algorithm) {
        (Some("RSA"), "RS256" | "RS384" | "RS512" | "PS256") => {
            let (Some(n), Some(e)) = (field("n"), field("e")) else { return false };
            let parameters: &signature::RsaParameters = match algorithm {
                "RS256" => &RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &RSA_PKCS1_2048_8192_SHA512,
                _ => &RSA_PSS_2048_8192_SHA256,
            };
            RsaPublicKeyComponents { n, e }.verify(parameters, message, signature).is_ok()
        }
        (Some("EC"), "ES256" | "ES384") => {
            let curve = jwk["crv"].as_str();
            let (Some(x), Some(y)) = (field("x"), field("y")) else { return false };
            let (verification, size): (&'static dyn signature::VerificationAlgorithm, usize) = match (algorithm, curve)
            {
                ("ES256", Some("P-256")) => (&ECDSA_P256_SHA256_FIXED, 32),
                ("ES384", Some("P-384")) => (&ECDSA_P384_SHA384_FIXED, 48),
                _ => return false,
            };
            if x.len() != size || y.len() != size {
                return false;
            }
            let point = [&[0x04][..], &x, &y].concat();
            UnparsedPublicKey::new(verification, point).verify(message, signature).is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::{KeyPair as RsaKeyPair, KeySize},
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256},
    };
    use serde_json::json;

    use super::*;

    fn token(header: &Value, claims: &Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        let signature = sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn claims(now: i64) -> Value {
        json!({ "iss": "https://idp.example", "aud": "kernoid", "sub": "user-1", "exp": now + 300, "iat": now, "nonce": "n1" })
    }

    fn expected(now: i64) -> Expected<'static> {
        Expected { issuer: "https://idp.example/", client_id: "kernoid", nonce: "n1", now }
    }

    #[test]
    fn rs256_and_es256_tokens_verify() {
        let now = 1_800_000_000;
        let rsa = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public = rsa.public_key();
        let rsa_jwk = json!({ "kty": "RSA", "kid": "r1",
            "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
            "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()) });
        let signed = token(&json!({ "alg": "RS256", "kid": "r1" }), &claims(now), |input| {
            let mut signature = vec![0; rsa.public_modulus_len()];
            rsa.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input, &mut signature).unwrap();
            signature
        });
        assert_eq!(verify_id_token(&signed, std::slice::from_ref(&rsa_jwk), expected(now)).unwrap()["sub"], "user-1");

        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new()).unwrap();
        let ec = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = ec.public_key().as_ref();
        let ec_jwk = json!({ "kty": "EC", "crv": "P-256", "kid": "e1",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65]) });
        let signed = token(&json!({ "alg": "ES256", "kid": "e1" }), &claims(now), |input| {
            ec.sign(&SystemRandom::new(), input).unwrap().as_ref().to_vec()
        });
        assert!(verify_id_token(&signed, &[rsa_jwk.clone(), ec_jwk], expected(now)).is_ok());

        // Wrong key, other audience, expired, other nonce, alg none.
        let wrong = json!({ "kty": "RSA", "kid": "e1", "n": "AQAB", "e": "AQAB" });
        assert!(verify_id_token(&signed, &[wrong], expected(now)).is_err());
        assert!(verify_id_token(&signed, std::slice::from_ref(&rsa_jwk), expected(now)).is_err());
        let rs = |claims: &Value| {
            token(&json!({ "alg": "RS256", "kid": "r1" }), claims, |input| {
                let mut signature = vec![0; rsa.public_modulus_len()];
                rsa.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input, &mut signature).unwrap();
                signature
            })
        };
        for (field, value) in
            [("aud", json!("other")), ("exp", json!(now - 600)), ("nonce", json!("n2")), ("iss", json!("https://evil"))]
        {
            let mut changed = claims(now);
            changed[field] = value;
            assert!(verify_id_token(&rs(&changed), std::slice::from_ref(&rsa_jwk), expected(now)).is_err(), "{field}");
        }
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(now)).unwrap())
        );
        assert!(verify_id_token(&unsigned, &[rsa_jwk], expected(now)).is_err());
    }
}
