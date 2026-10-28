// SPDX-License-Identifier: AGPL-3.0-or-later
//! JSON Web Tokens signed with RS256 (RFC 7515/7519), the algorithm every OpenID provider must offer.

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::KeyPair,
    signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaPublicKeyComponents},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use crate::{Result, internal};

/// `header.payload.signature`, each part base64url without padding.
pub(crate) fn sign(key: &KeyPair, kid: &str, claims: &Value) -> Result<String> {
    sign_typed(key, kid, "JWT", claims)
}

/// A JWT with its own type (`typ`): `at+jwt` for access tokens (RFC 9068), `logout+jwt` for logout tokens.
pub(crate) fn sign_typed(key: &KeyPair, kid: &str, typ: &str, claims: &Value) -> Result<String> {
    let header = json!({ "alg": "RS256", "typ": typ, "kid": kid });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(internal)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(internal)?)
    );
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut signature).map_err(internal)?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// The `kid` in the header of a JWT, without checking anything else.
pub(crate) fn key_id(token: &str) -> Option<String> {
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').next()?).ok()?).ok()?;
    header["kid"].as_str().map(str::to_owned)
}

/// The claims of an RS256 JWT whose signature verifies with `jwk` (an RSA public key as published in the JWKS).
pub(crate) fn verify(jwk: &Value, token: &str) -> Option<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header, claims, signature] = parts.as_slice() else { return None };
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header["alg"] != "RS256" {
        return None;
    }
    let decode = |field: &str| URL_SAFE_NO_PAD.decode(jwk[field].as_str()?).ok();
    let public = RsaPublicKeyComponents { n: decode("n")?, e: decode("e")? };
    let message = format!("{}.{}", parts[0], parts[1]);
    public.verify(&RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &URL_SAFE_NO_PAD.decode(signature).ok()?).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rsa::KeySize,
        signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey},
    };

    use super::*;

    #[test]
    fn signed_and_verifiable() {
        let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let token = sign(&key, "kid-1", &json!({ "sub": "alice" })).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-1" }));
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref());
        let message = format!("{}.{}", parts[0], parts[1]);
        public.verify(message.as_bytes(), &URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        assert!(public.verify(b"something else", &URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).is_err());

        let jwk = json!({
            "n": URL_SAFE_NO_PAD.encode(key.public_key().modulus().big_endian_without_leading_zero()),
            "e": URL_SAFE_NO_PAD.encode(key.public_key().exponent().big_endian_without_leading_zero()),
        });
        assert_eq!(key_id(&token).as_deref(), Some("kid-1"));
        assert_eq!(verify(&jwk, &token), Some(json!({ "sub": "alice" })));
        let other = KeyPair::generate(KeySize::Rsa2048).unwrap();
        assert_eq!(verify(&jwk, &sign(&other, "kid-1", &json!({ "sub": "alice" })).unwrap()), None);
        let mut tampered = token.clone();
        tampered.replace_range(parts[0].len() + 1..parts[0].len() + 2, "X");
        assert_eq!(verify(&jwk, &tampered), None);
    }
}
