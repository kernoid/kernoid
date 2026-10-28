// SPDX-License-Identifier: AGPL-3.0-or-later
//! Certificates from an ACME CA (RFC 8555) for every instance domain (RFC 0001, 9).
//!
//! - **Ordering** is the worker's: for each domain without a certificate, or with one ending within
//!   `http.acme.renew_days`, it orders one with the HTTP-01 challenge – at most [`ORDERS_PER_ROUND`] per round, with
//!   growing pauses after failures (the CA's rate limits), and only in the process that holds the `acme` lock.
//! - **Everything is kept in PostgreSQL** – the account key and the certificate keys sealed with the main key – so that
//!   every `api` process serves the certificates ([`Certificates`], by SNI, refreshed every minute) and answers the
//!   CA's challenges (`/.well-known/acme-challenge/<token>` on `http.acme.http_listen`), whichever of them the CA
//!   reaches. Nothing beyond PostgreSQL is needed.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use kernoid_config::Acme;
use kernoid_identity::Identity;
use kernoid_store::{MainKeys, PgPool, lock::Lock};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// Most certificates ordered in one round.
pub const ORDERS_PER_ROUND: i64 = 10;
/// How long a challenge answer is kept.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("{0}")]
    Config(String),
    #[error("ACME: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error(transparent)]
    Store(#[from] sqlx::Error),
    #[error("{0}")]
    Certificate(String),
}

fn tls_key_context(domain: &str) -> Vec<u8> {
    format!("kernoid/tls-key/v1/{domain}").into_bytes()
}

fn account_context(directory: &str) -> Vec<u8> {
    format!("kernoid/acme-account/v1/{directory}").into_bytes()
}

/// A chain and key as rustls serves them.
fn certified_key(chain_pem: &str, key_der: &[u8]) -> Result<CertifiedKey, AcmeError> {
    let bad = |e: &dyn std::fmt::Display| AcmeError::Certificate(e.to_string());
    let chain =
        CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>().map_err(|e| bad(&e))?;
    let key = PrivateKeyDer::try_from(key_der.to_vec()).map_err(|e| bad(&e))?;
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|e| bad(&e))?;
    Ok(CertifiedKey::new(chain, signer))
}

/// When the first certificate of a PEM chain ends.
fn not_after(chain_pem: &str) -> Result<DateTime<Utc>, AcmeError> {
    use x509_cert::der::Decode;
    let bad = |e: &dyn std::fmt::Display| AcmeError::Certificate(e.to_string());
    let first = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .ok_or_else(|| AcmeError::Certificate("the chain is empty".into()))?
        .map_err(|e| bad(&e))?;
    let certificate = x509_cert::Certificate::from_der(&first).map_err(|e| bad(&e))?;
    let end = certificate.tbs_certificate.validity.not_after.to_unix_duration();
    DateTime::from_timestamp(end.as_secs() as i64, 0).ok_or_else(|| AcmeError::Certificate("no end date".into()))
}

/// Whether a CA can issue for a domain at all – names for local use cannot get public certificates.
fn orderable(domain: &str) -> bool {
    const LOCAL: [&str; 7] = [".localhost", ".test", ".local", ".internal", ".example", ".invalid", ".home.arpa"];
    domain.contains('.') && domain != "localhost" && !LOCAL.iter().any(|suffix| domain.ends_with(suffix))
}

/// The pause after `attempts` failed orders: an hour, doubling, at most a day.
fn backoff(attempts: i32) -> Duration {
    Duration::from_secs((3600u64 << attempts.clamp(0, 5) as u32).min(24 * 3600))
}

/// The configured certificate (`http.tls`) as the one served for names without an ACME certificate.
pub fn static_certificate(certificate: &std::path::Path, key: &std::path::Path) -> Result<CertifiedKey, AcmeError> {
    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|e| AcmeError::Config(format!("cannot read {}: {e}", path.display())))
    };
    let chain = String::from_utf8(read(certificate)?).map_err(|e| AcmeError::Certificate(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(&read(key)?).map_err(|e| AcmeError::Certificate(e.to_string()))?;
    certified_key(&chain, key.secret_der())
}

/// The certificates an `api` process serves: by SNI from PostgreSQL, else the configured one.
#[derive(Debug)]
pub struct Certificates {
    pool: PgPool,
    main: MainKeys,
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    seen: RwLock<Option<DateTime<Utc>>>,
    fallback: Option<Arc<CertifiedKey>>,
}

impl Certificates {
    pub fn new(pool: PgPool, main: MainKeys, fallback: Option<Arc<CertifiedKey>>) -> Self {
        Self { pool, main, cache: RwLock::default(), seen: RwLock::default(), fallback }
    }

    /// Loads certificates stored or renewed since the last time; returns how many.
    pub async fn refresh(&self) -> Result<usize, AcmeError> {
        let since = *self.seen.read().expect("not poisoned");
        let rows = sqlx::query!(
            "SELECT domain, chain_pem, key_sealed, updated_at FROM tls_certificates
             WHERE $1::timestamptz IS NULL OR updated_at > $1 ORDER BY updated_at",
            since,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut loaded = 0;
        for row in rows {
            let opened = self.main.open_secret(&tls_key_context(&row.domain), &row.key_sealed);
            let key = match opened {
                Ok((key, _)) => certified_key(&row.chain_pem, &key),
                Err(error) => Err(AcmeError::Certificate(error.to_string())),
            };
            match key {
                Ok(key) => {
                    self.cache.write().expect("not poisoned").insert(row.domain, Arc::new(key));
                    loaded += 1;
                }
                Err(error) => tracing::error!(domain = %row.domain, %error, "a stored certificate is not usable"),
            }
            *self.seen.write().expect("not poisoned") = Some(row.updated_at);
        }
        Ok(loaded)
    }

    /// Refreshes every minute until shutdown.
    pub async fn keep_fresh(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            if let Err(error) = self.refresh().await {
                tracing::warn!(%error, "loading certificates failed; trying again");
            }
            tokio::select! {
                () = &mut shutdown => return,
                () = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
        }
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().map(str::to_ascii_lowercase);
        name.and_then(|name| self.cache.read().expect("not poisoned").get(&name).cloned())
            .or_else(|| self.fallback.clone())
    }
}

#[derive(Clone)]
struct Challenges {
    pool: PgPool,
    identity: Identity,
}

/// The CA's HTTP-01 request: the key authorization of a token being answered.
async fn challenge(State(challenges): State<Challenges>, Path(token): Path<String>) -> Response {
    let answer = sqlx::query_scalar!(
        "SELECT key_authorization FROM acme_challenges WHERE token = $1 AND expires_at > now()",
        token,
    )
    .fetch_optional(&challenges.pool)
    .await;
    match answer {
        Ok(Some(answer)) => ([(header::CONTENT_TYPE, "text/plain")], answer).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "reading an ACME challenge");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Everything else on the HTTP port goes to HTTPS – for the instances' domains only, so it redirects nowhere else.
async fn to_https(State(challenges): State<Challenges>, headers: HeaderMap, uri: Uri) -> Response {
    let host = headers.get(header::HOST).and_then(|host| host.to_str().ok()).unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(name, port)| if port.parse::<u16>().is_ok() { name } else { host });
    match challenges.identity.instance_by_host(host).await {
        Ok(Some(_)) => {
            let path = uri.path_and_query().map_or("/", |path| path.as_str());
            Redirect::permanent(&format!("https://{host}{path}")).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The router of `http.acme.http_listen`.
pub fn http_router(pool: PgPool, identity: Identity) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(challenge))
        .fallback(to_https)
        .with_state(Challenges { pool, identity })
}

/// What one round of [`Orderer::renew`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Renewed {
    pub issued: usize,
    pub failed: usize,
}

/// Orders and renews certificates – the worker's part.
#[derive(Debug, Clone)]
pub struct Orderer {
    pool: PgPool,
    main: MainKeys,
    config: Acme,
}

impl Orderer {
    pub fn new(pool: PgPool, main: MainKeys, config: Acme) -> Result<Self, AcmeError> {
        // instant-acme's HTTP client takes the process's rustls provider; make it the one kernoid uses everywhere
        // (AWS-LC). Elsewhere kernoid names its provider explicitly, so this changes nothing there.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        if !config.terms_agreed {
            return Err(AcmeError::Config(
                "http.acme.terms_agreed must be true: read the CA's terms of service first".into(),
            ));
        }
        Ok(Self { pool, main, config })
    }

    /// The installation's account at the CA – made at first use.
    async fn account(&self) -> Result<Account, AcmeError> {
        let builder = || match &self.config.ca_root {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        };
        let context = account_context(&self.config.directory);
        let stored = sqlx::query_scalar!(
            "SELECT credentials_sealed FROM acme_accounts WHERE directory = $1",
            self.config.directory,
        )
        .fetch_optional(&self.pool)
        .await?;
        if let Some(sealed) = stored {
            let (json, _) =
                self.main.open_secret(&context, &sealed).map_err(|e| AcmeError::Certificate(e.to_string()))?;
            let credentials: AccountCredentials =
                serde_json::from_slice(&json).map_err(|e| AcmeError::Certificate(e.to_string()))?;
            return Ok(builder()?.from_credentials(credentials).await?);
        }
        let contact: Vec<&str> = self.config.contact.iter().map(String::as_str).collect();
        let new = NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false };
        let (account, credentials) = builder()?.create(&new, self.config.directory.clone(), None).await?;
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(&credentials).map_err(|e| AcmeError::Certificate(e.to_string()))?,
        );
        let sealed = self.main.seal_secret(&context, &json).map_err(|e| AcmeError::Certificate(e.to_string()))?;
        sqlx::query!(
            "INSERT INTO acme_accounts (directory, credentials_sealed) VALUES ($1, $2)
             ON CONFLICT (directory) DO NOTHING",
            self.config.directory,
            sealed,
        )
        .execute(&self.pool)
        .await?;
        tracing::info!(directory = %self.config.directory, "ACME account created");
        Ok(account)
    }

    /// Orders certificates for the domains that need one, in the one process that holds the lock.
    pub async fn renew(&self) -> Result<Renewed, AcmeError> {
        let Some(lock) = Lock::try_take(&self.pool, "acme").await? else { return Ok(Renewed::default()) };
        let result = self.renew_locked().await;
        lock.release().await?;
        result
    }

    async fn renew_locked(&self) -> Result<Renewed, AcmeError> {
        sqlx::query!("DELETE FROM acme_challenges WHERE expires_at < now()").execute(&self.pool).await?;
        let due = sqlx::query_scalar!(
            "SELECT d.domain FROM instance_domains d
             LEFT JOIN tls_certificates c ON c.domain = d.domain
             LEFT JOIN acme_orders o ON o.domain = d.domain
             WHERE (c.domain IS NULL OR c.not_after < now() + make_interval(days => $1))
               AND (o.domain IS NULL OR o.next_attempt_at <= now())
             ORDER BY c.not_after NULLS FIRST, d.domain LIMIT $2",
            self.config.renew_days as i32,
            ORDERS_PER_ROUND,
        )
        .fetch_all(&self.pool)
        .await?;
        let due: Vec<String> = due.into_iter().filter(|domain| orderable(domain)).collect();
        let mut done = Renewed::default();
        if due.is_empty() {
            return Ok(done);
        }
        let account = self.account().await?;
        for domain in due {
            match self.order(&account, &domain).await {
                Ok(()) => {
                    done.issued += 1;
                    sqlx::query!("DELETE FROM acme_orders WHERE domain = $1", domain).execute(&self.pool).await?;
                    tracing::info!(%domain, "certificate issued");
                }
                Err(error) => {
                    done.failed += 1;
                    tracing::warn!(%domain, %error, "ordering a certificate failed");
                    let attempts = sqlx::query_scalar!("SELECT attempts FROM acme_orders WHERE domain = $1", domain)
                        .fetch_optional(&self.pool)
                        .await?
                        .unwrap_or(0);
                    sqlx::query!(
                        "INSERT INTO acme_orders (domain, attempts, next_attempt_at, last_error)
                         VALUES ($1, $2, now() + make_interval(secs => $3), $4)
                         ON CONFLICT (domain) DO UPDATE SET attempts = $2,
                             next_attempt_at = now() + make_interval(secs => $3), last_error = $4",
                        domain,
                        attempts + 1,
                        backoff(attempts).as_secs() as f64,
                        error.to_string().chars().take(500).collect::<String>(),
                    )
                    .execute(&self.pool)
                    .await?;
                }
            }
        }
        Ok(done)
    }

    /// One order: the HTTP-01 challenge answered through PostgreSQL, a new key, the chain stored.
    async fn order(&self, account: &Account, domain: &str) -> Result<(), AcmeError> {
        let identifiers = [Identifier::Dns(domain.to_owned())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => return Err(AcmeError::Certificate(format!("the authorization is {status:?}"))),
            }
            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| AcmeError::Certificate("the CA offers no HTTP-01 challenge".into()))?;
            let answer = challenge.key_authorization();
            sqlx::query!(
                "INSERT INTO acme_challenges (token, key_authorization, expires_at)
                 VALUES ($1, $2, now() + make_interval(secs => $3))
                 ON CONFLICT (token) DO UPDATE SET key_authorization = excluded.key_authorization",
                challenge.token,
                answer.as_str(),
                CHALLENGE_LIFETIME.as_secs() as f64,
            )
            .execute(&self.pool)
            .await?;
            challenge.set_ready().await?;
        }
        let patience = RetryPolicy::new().timeout(Duration::from_secs(120));
        let status = order.poll_ready(&patience).await?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::Certificate(format!("the order is {status:?}")));
        }
        let key_pem = zeroize::Zeroizing::new(order.finalize().await?);
        let chain = order.poll_certificate(&patience).await?;
        let key =
            PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| AcmeError::Certificate(e.to_string()))?;
        certified_key(&chain, key.secret_der())?;
        let sealed = self
            .main
            .seal_secret(&tls_key_context(domain), key.secret_der())
            .map_err(|e| AcmeError::Certificate(e.to_string()))?;
        sqlx::query!(
            "INSERT INTO tls_certificates (domain, chain_pem, key_sealed, not_after, updated_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (domain) DO UPDATE SET chain_pem = $2, key_sealed = $3, not_after = $4, updated_at = now()",
            domain,
            chain,
            sealed,
            not_after(&chain)?,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// A domain's certificate state, for the operator (`kernoid acme status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateState {
    pub domain: String,
    pub not_after: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

pub async fn status(pool: &PgPool) -> Result<Vec<CertificateState>, AcmeError> {
    let rows = sqlx::query!(
        r#"SELECT d.domain, c.not_after AS "not_after?", o.attempts AS "attempts?", o.next_attempt_at AS "next?",
                  o.last_error AS "last_error?"
           FROM instance_domains d
           LEFT JOIN tls_certificates c ON c.domain = d.domain
           LEFT JOIN acme_orders o ON o.domain = d.domain
           ORDER BY d.domain"#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| CertificateState {
            domain: row.domain,
            not_after: row.not_after,
            attempts: row.attempts.unwrap_or(0),
            next_attempt_at: row.next,
            last_error: row.last_error,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_names_are_ordered() {
        assert!(orderable("login.firma.de"));
        for local in ["localhost", "login.example.localhost", "kernoid.test", "a.local", "x.internal", "y"] {
            assert!(!orderable(local), "{local}");
        }
    }

    #[test]
    fn pauses_grow_to_a_day() {
        assert_eq!(backoff(0), Duration::from_secs(3600));
        assert_eq!(backoff(2), Duration::from_secs(4 * 3600));
        assert_eq!(backoff(9), Duration::from_secs(24 * 3600));
    }
}
