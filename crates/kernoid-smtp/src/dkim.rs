// SPDX-License-Identifier: AGPL-3.0-or-later
//! DKIM keys of the tenants' domains (RFC 0002, 10.3): RSA with 2048 bits, made by the worker for every verified
//! domain, sealed with the main key. Signing is mail-auth's.

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rsa::{KeyPair, KeySize},
    signature::KeyPair as _,
};
use base64::Engine;
use kernoid_store::{MainKeys, PgPool};
use mail_auth::{
    common::crypto::{RsaKey, Sha256},
    dkim::DkimSigner,
};

/// The selector of the keys: `kernoid1._domainkey.<domain>`.
pub const SELECTOR: &str = "kernoid1";

/// The headers signed, where present (RFC 6376, 5.4.1).
const SIGNED_HEADERS: [&str; 12] = [
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "Reply-To",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("DKIM key: {0}")]
    Key(String),
}

fn context(domain: &str) -> Vec<u8> {
    format!("kernoid/dkim-key/v1/{domain}").into_bytes()
}

/// Makes a key for every verified domain of an active tenant that has none; returns how many.
pub async fn ensure_keys(pool: &PgPool, main: &MainKeys) -> Result<usize, DkimError> {
    let missing = sqlx::query!(
        "SELECT d.domain, d.tenant_id FROM tenant_domains d
         WHERE d.verified AND NOT EXISTS (SELECT 1 FROM dkim_keys k WHERE k.domain = d.domain)",
    )
    .fetch_all(pool)
    .await?;
    let mut made = 0;
    for row in missing {
        type Generated = (zeroize::Zeroizing<Vec<u8>>, Vec<u8>);
        let (private, public) = tokio::task::spawn_blocking(|| -> Result<Generated, DkimError> {
            let key = KeyPair::generate(KeySize::Rsa2048).map_err(|e| DkimError::Key(e.to_string()))?;
            let private: Pkcs8V1Der<'static> = key.as_der().map_err(|e| DkimError::Key(e.to_string()))?;
            let public: PublicKeyX509Der<'static> =
                key.public_key().as_der().map_err(|e| DkimError::Key(e.to_string()))?;
            Ok((zeroize::Zeroizing::new(private.as_ref().to_vec()), public.as_ref().to_vec()))
        })
        .await
        .map_err(|e| DkimError::Key(e.to_string()))??;
        let sealed = main.seal_secret(&context(&row.domain), &private).map_err(|e| DkimError::Key(e.to_string()))?;
        // Another worker may make one at the same time; the first stays.
        let inserted = sqlx::query!(
            "INSERT INTO dkim_keys (domain, tenant_id, selector, private_sealed, public_key) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (domain) DO NOTHING",
            row.domain,
            row.tenant_id,
            SELECTOR,
            sealed,
            public,
        )
        .execute(pool)
        .await?;
        made += inserted.rows_affected() as usize;
    }
    Ok(made)
}

/// The TXT record to publish at `<selector>._domainkey.<domain>`, if the domain has a key.
pub async fn public_record(pool: &PgPool, domain: &str) -> Result<Option<(String, String)>, DkimError> {
    let row = sqlx::query!("SELECT selector, public_key FROM dkim_keys WHERE domain = $1", domain)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| {
        let key = base64::engine::general_purpose::STANDARD.encode(row.public_key);
        (row.selector, format!("v=DKIM1; k=rsa; p={key}"))
    }))
}

/// The `DKIM-Signature` header for `raw`, signed with the key of `domain`; `None` if the domain has no key.
pub async fn sign(pool: &PgPool, main: &MainKeys, domain: &str, raw: &[u8]) -> Result<Option<String>, DkimError> {
    let row = sqlx::query!("SELECT selector, private_sealed FROM dkim_keys WHERE domain = $1", domain)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let (private, _) =
        main.open_secret(&context(domain), &row.private_sealed).map_err(|e| DkimError::Key(e.to_string()))?;
    let key = RsaKey::<Sha256>::from_key_der(rustls::pki_types::PrivateKeyDer::Pkcs8(private.as_slice().into()))
        .map_err(|e| DkimError::Key(e.to_string()))?;
    let signature = DkimSigner::from_key(key)
        .domain(domain)
        .selector(row.selector)
        .headers(SIGNED_HEADERS)
        .sign(raw)
        .map_err(|e| DkimError::Key(e.to_string()))?;
    use mail_auth::common::headers::HeaderWriter;
    Ok(Some(signature.to_header()))
}
