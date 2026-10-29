// SPDX-License-Identifier: AGPL-3.0-or-later
//! DKIM keys of the tenants' domains (RFC 0002, 10.3), sealed with the main key: RSA with 2048 bits and Ed25519
//! (RFC 8463), each under a selector of its own, made by the worker for every verified domain. A domain's first RSA
//! key signs at once; any later key – the first Ed25519 key, or one made by `rotate` – is `next` until DNS shows its
//! record (`activate_published`), then it signs and the key it replaces is `retired`. Mail is signed with every
//! active key. Signing is mail-auth's.

use std::future::Future;

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rsa::{KeyPair, KeySize},
    signature::{Ed25519KeyPair, KeyPair as _},
};
use base64::Engine;
use kernoid_store::{MainKeys, PgPool};
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::DkimSigner,
};

/// The algorithms of DKIM keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Rsa,
    Ed25519,
}

impl Algorithm {
    pub const ALL: [Self; 2] = [Self::Rsa, Self::Ed25519];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|algorithm| algorithm.as_str() == value)
    }

    /// Selectors are `kernoid<n>` for RSA – `kernoid1` was the only one before keys changed – and `kernoid-ed<n>`.
    fn selector(self, number: usize) -> String {
        match self {
            Self::Rsa => format!("kernoid{number}"),
            Self::Ed25519 => format!("kernoid-ed{number}"),
        }
    }
}

/// A key of a domain as DNS should show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub selector: String,
    pub algorithm: Algorithm,
    /// `next` or `active`.
    pub state: String,
    /// The TXT record for `<selector>._domainkey.<domain>`.
    pub record: String,
}

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

type Generated = (zeroize::Zeroizing<Vec<u8>>, Vec<u8>);

/// A new key: PKCS#8 private key and the public key as the record's `p=` needs it (SubjectPublicKeyInfo for RSA,
/// the raw 32 bytes for Ed25519).
async fn generate(algorithm: Algorithm) -> Result<Generated, DkimError> {
    tokio::task::spawn_blocking(move || -> Result<Generated, DkimError> {
        let error = |e: aws_lc_rs::error::Unspecified| DkimError::Key(e.to_string());
        match algorithm {
            Algorithm::Rsa => {
                let key = KeyPair::generate(KeySize::Rsa2048).map_err(|e| DkimError::Key(e.to_string()))?;
                let private: Pkcs8V1Der<'static> = key.as_der().map_err(error)?;
                let public: PublicKeyX509Der<'static> = key.public_key().as_der().map_err(error)?;
                Ok((zeroize::Zeroizing::new(private.as_ref().to_vec()), public.as_ref().to_vec()))
            }
            Algorithm::Ed25519 => {
                let key = Ed25519KeyPair::generate().map_err(error)?;
                let private = key.to_pkcs8().map_err(error)?;
                Ok((zeroize::Zeroizing::new(private.as_ref().to_vec()), key.public_key().as_ref().to_vec()))
            }
        }
    })
    .await
    .map_err(|e| DkimError::Key(e.to_string()))?
}

/// Adds a key of `algorithm` to `domain` in `state`, under the next selector; false if another worker was quicker
/// (one `next` and one `active` per algorithm).
async fn add_key(
    pool: &PgPool,
    main: &MainKeys,
    domain: &str,
    tenant: uuid::Uuid,
    algorithm: Algorithm,
    state: &str,
) -> Result<bool, DkimError> {
    let (private, public) = generate(algorithm).await?;
    let sealed = main.seal_secret(&context(domain), &private).map_err(|e| DkimError::Key(e.to_string()))?;
    let made = sqlx::query_scalar!(
        "SELECT count(*) AS \"count!\" FROM dkim_keys WHERE domain = $1 AND algorithm = $2",
        domain,
        algorithm.as_str(),
    )
    .fetch_one(pool)
    .await?;
    let selector = algorithm.selector(made as usize + 1);
    let inserted = sqlx::query!(
        "INSERT INTO dkim_keys (domain, tenant_id, selector, algorithm, state, private_sealed, public_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        domain,
        tenant,
        selector,
        algorithm.as_str(),
        state,
        sealed,
        public,
    )
    .execute(pool)
    .await?;
    Ok(inserted.rows_affected() == 1)
}

/// Makes the keys every verified domain of a tenant needs: an RSA key that signs at once, and an Ed25519 key that
/// signs once its record is published. Returns how many it made.
pub async fn ensure_keys(pool: &PgPool, main: &MainKeys) -> Result<usize, DkimError> {
    let missing = sqlx::query!(
        "SELECT d.domain, d.tenant_id, a.algorithm AS \"algorithm!\" FROM tenant_domains d
         CROSS JOIN unnest(ARRAY['rsa', 'ed25519']) AS a(algorithm)
         WHERE d.verified
           AND NOT EXISTS (SELECT 1 FROM dkim_keys k WHERE k.domain = d.domain AND k.algorithm = a.algorithm)",
    )
    .fetch_all(pool)
    .await?;
    let mut made = 0;
    for row in missing {
        let Some(algorithm) = Algorithm::parse(&row.algorithm) else { continue };
        let state = if algorithm == Algorithm::Rsa { "active" } else { "next" };
        // Another worker may make one at the same time; the first stays.
        if add_key(pool, main, &row.domain, row.tenant_id, algorithm, state).await? {
            made += 1;
        }
    }
    Ok(made)
}

/// Starts a change of `domain`'s key of `algorithm`: a new key, `next` until its record is published. Returns its
/// selector; if one is waiting already, that one's.
pub async fn rotate(pool: &PgPool, main: &MainKeys, domain: &str, algorithm: Algorithm) -> Result<String, DkimError> {
    loop {
        let waiting = sqlx::query_scalar!(
            "SELECT selector FROM dkim_keys WHERE domain = $1 AND algorithm = $2 AND state = 'next'",
            domain,
            algorithm.as_str(),
        )
        .fetch_optional(pool)
        .await?;
        if let Some(selector) = waiting {
            return Ok(selector);
        }
        let tenant = sqlx::query_scalar!("SELECT tenant_id FROM tenant_domains WHERE domain = $1 AND verified", domain)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| DkimError::Key(format!("{domain} is not a verified domain")))?;
        add_key(pool, main, domain, tenant, algorithm, "next").await?;
    }
}

/// Lets every `next` key whose record DNS shows sign, retiring the key of its algorithm that signed so far. `lookup`
/// returns the TXT records of a name. Returns how many keys became active.
pub async fn activate<F, Fut>(pool: &PgPool, lookup: F) -> Result<usize, DkimError>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Vec<String>>,
{
    let waiting = sqlx::query!(
        "SELECT domain, selector, algorithm, public_key FROM dkim_keys WHERE state = 'next' ORDER BY domain, selector"
    )
    .fetch_all(pool)
    .await?;
    let mut activated = 0;
    for key in waiting {
        let expected = encode(&key.public_key);
        let found = lookup(format!("{}._domainkey.{}", key.selector, key.domain)).await;
        if !found.iter().any(|record| crate::dns_check::dkim_key(record).as_deref() == Some(expected.as_str())) {
            continue;
        }
        let mut transaction = pool.begin().await?;
        sqlx::query!(
            "UPDATE dkim_keys SET state = 'retired', state_since = now()
             WHERE domain = $1 AND algorithm = $2 AND state = 'active'",
            key.domain,
            key.algorithm,
        )
        .execute(&mut *transaction)
        .await?;
        let updated = sqlx::query!(
            "UPDATE dkim_keys SET state = 'active', state_since = now()
             WHERE domain = $1 AND selector = $2 AND state = 'next'",
            key.domain,
            key.selector,
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        activated += updated.rows_affected() as usize;
    }
    Ok(activated)
}

/// `activate` with the TXT records of `dns`.
pub async fn activate_published(pool: &PgPool, dns: &crate::Dns) -> Result<usize, DkimError> {
    activate(pool, |name| async move { crate::dns_check::txt(dns, &name).await }).await
}

fn encode(public: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(public)
}

/// The records DNS should show for `domain`: its active and next keys.
pub async fn public_records(pool: &PgPool, domain: &str) -> Result<Vec<PublicKey>, DkimError> {
    let rows = sqlx::query!(
        "SELECT selector, algorithm, state, public_key FROM dkim_keys
         WHERE domain = $1 AND state <> 'retired' ORDER BY algorithm DESC, state, selector",
        domain,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let algorithm = Algorithm::parse(&row.algorithm)?;
            let record = format!("v=DKIM1; k={}; p={}", algorithm.as_str(), encode(&row.public_key));
            Some(PublicKey { selector: row.selector, algorithm, state: row.state, record })
        })
        .collect())
}

/// The `DKIM-Signature` headers for `raw`, one per active key of `domain`; none if the domain has no key.
pub async fn sign(pool: &PgPool, main: &MainKeys, domain: &str, raw: &[u8]) -> Result<Vec<String>, DkimError> {
    use mail_auth::common::headers::HeaderWriter;
    let rows = sqlx::query!(
        "SELECT selector, algorithm, private_sealed FROM dkim_keys
         WHERE domain = $1 AND state = 'active' ORDER BY algorithm DESC",
        domain,
    )
    .fetch_all(pool)
    .await?;
    let mut headers = Vec::new();
    for row in rows {
        let (private, _) =
            main.open_secret(&context(domain), &row.private_sealed).map_err(|e| DkimError::Key(e.to_string()))?;
        let signature = match Algorithm::parse(&row.algorithm) {
            Some(Algorithm::Rsa) => {
                let key =
                    RsaKey::<Sha256>::from_key_der(rustls::pki_types::PrivateKeyDer::Pkcs8(private.as_slice().into()))
                        .map_err(|e| DkimError::Key(e.to_string()))?;
                DkimSigner::from_key(key).domain(domain).selector(row.selector).headers(SIGNED_HEADERS).sign(raw)
            }
            Some(Algorithm::Ed25519) => {
                let key = Ed25519Key::from_pkcs8_der(&private).map_err(|e| DkimError::Key(e.to_string()))?;
                DkimSigner::from_key(key).domain(domain).selector(row.selector).headers(SIGNED_HEADERS).sign(raw)
            }
            None => continue,
        }
        .map_err(|e| DkimError::Key(e.to_string()))?;
        headers.push(signature.to_header());
    }
    Ok(headers)
}
