// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant keys: created on a tenant's first write, kept wrapped in `tenant_keys`, held unwrapped in memory.
//!
//! **Rotation.** A tenant key is rotated by adding the next number ([`TenantKeys::rotate`]); new content is sealed
//! with it, older content stays readable through the number in its header. The main key is rotated by configuring a
//! new one, keeping the old ones as previous keys until [`rewrap`] – run as the owner of the schema, since the runtime
//! role may not change keys – has wrapped every tenant key with the new one.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto::{self, CryptoError, Key};

/// How long a process keeps using the tenant key it knows as current; after a rotation in another process, new
/// content uses the new key at the latest after this time.
const CURRENT_FOR: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("tenant key {number} of {tenant}: {source}")]
    Crypto { tenant: Uuid, number: u32, source: CryptoError },
    #[error("tenant key {number} of {tenant} does not exist")]
    Missing { tenant: Uuid, number: u32 },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// The configured main keys: the current one wraps, previous ones only unwrap until everything is rewrapped.
#[derive(Debug, Clone)]
pub struct MainKeys {
    current: Key,
    previous: Vec<Key>,
}

impl MainKeys {
    pub fn new(current: Key, previous: Vec<Key>) -> Self {
        Self { current, previous }
    }

    /// Seals a secret with the current main key (see [`crypto::seal_secret`]).
    pub fn seal_secret(&self, context: &[u8], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        crypto::seal_secret(&self.current, context, secret)
    }

    /// Opens a secret sealed with the current or a previous main key; tells whether it was a previous one (and the
    /// secret should be sealed again).
    pub fn open_secret(
        &self,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<(zeroize::Zeroizing<Vec<u8>>, bool), CryptoError> {
        if let Ok(secret) = crypto::open_secret(&self.current, context, sealed) {
            return Ok((secret, false));
        }
        self.previous
            .iter()
            .find_map(|key| crypto::open_secret(key, context, sealed).ok())
            .map(|secret| (secret, true))
            .ok_or(CryptoError::Authentication)
    }

    /// The main keys to try for a tenant key wrapped by the key with `fingerprint` (all of them if unknown).
    fn candidates(&self, fingerprint: Option<&[u8]>) -> Vec<&Key> {
        let all = std::iter::once(&self.current).chain(&self.previous);
        match fingerprint {
            Some(fingerprint) => all.filter(|key| crypto::fingerprint(key) == fingerprint).collect(),
            None => all.collect(),
        }
    }

    fn unwrap(&self, tenant: Uuid, number: u32, wrapped: &[u8], fingerprint: Option<&[u8]>) -> Result<Key, KeyError> {
        let candidates = self.candidates(fingerprint);
        let found = candidates.iter().find_map(|main| crypto::unwrap(main, tenant, number, wrapped).ok());
        found.ok_or(KeyError::Crypto { tenant, number, source: CryptoError::Authentication })
    }
}

#[derive(Debug)]
pub struct TenantKeys {
    pool: PgPool,
    main: MainKeys,
    keys: RwLock<HashMap<(Uuid, u32), Arc<Key>>>,
    current: RwLock<HashMap<Uuid, (u32, Instant)>>,
}

impl TenantKeys {
    pub fn new(pool: PgPool, main: Key) -> Self {
        Self::with_main_keys(pool, MainKeys::new(main, Vec::new()))
    }

    pub fn with_main_keys(pool: PgPool, main: MainKeys) -> Self {
        Self { pool, main, keys: RwLock::default(), current: RwLock::default() }
    }

    /// The key new content of `tenant` is sealed with; created if the tenant has none.
    pub async fn current(&self, tenant: Uuid) -> Result<(u32, Arc<Key>), KeyError> {
        let cached = self.current.read().expect("lock").get(&tenant).copied();
        let number = match cached {
            Some((number, since)) if since.elapsed() < CURRENT_FOR => number,
            _ => {
                let number = match self.newest(tenant).await? {
                    Some(number) => number,
                    None => self.add(tenant, 1).await?,
                };
                self.current.write().expect("lock").insert(tenant, (number, Instant::now()));
                number
            }
        };
        Ok((number, self.get(tenant, number).await?))
    }

    /// Adds the tenant's next key and makes it current; returns its number.
    pub async fn rotate(&self, tenant: Uuid) -> Result<u32, KeyError> {
        let next = self.newest(tenant).await?.unwrap_or(0) + 1;
        self.add(tenant, next).await?;
        // Another process may have rotated at the same time; the newest key is current either way.
        let newest = self.newest(tenant).await?.unwrap_or(next);
        self.current.write().expect("lock").insert(tenant, (newest, Instant::now()));
        Ok(newest)
    }

    /// Key `number` of `tenant`.
    pub async fn get(&self, tenant: Uuid, number: u32) -> Result<Arc<Key>, KeyError> {
        if let Some(key) = self.keys.read().expect("lock").get(&(tenant, number)) {
            return Ok(key.clone());
        }
        let row = sqlx::query!(
            "SELECT wrapped, main_key FROM tenant_keys WHERE tenant_id = $1 AND number = $2",
            tenant,
            i32::try_from(number).map_err(|_| KeyError::Missing { tenant, number })?,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(KeyError::Missing { tenant, number })?;
        let key = Arc::new(self.main.unwrap(tenant, number, &row.wrapped, row.main_key.as_deref())?);
        self.keys.write().expect("lock").insert((tenant, number), key.clone());
        Ok(key)
    }

    async fn newest(&self, tenant: Uuid) -> Result<Option<u32>, KeyError> {
        let number = sqlx::query_scalar!("SELECT max(number) FROM tenant_keys WHERE tenant_id = $1", tenant)
            .fetch_one(&self.pool)
            .await?;
        Ok(number.map(|n| n as u32))
    }

    /// Adds key `number` – unless another process was faster, whose key is then used.
    async fn add(&self, tenant: Uuid, number: u32) -> Result<u32, KeyError> {
        let crypto_error = |source| KeyError::Crypto { tenant, number, source };
        let key = Key::random().map_err(crypto_error)?;
        let wrapped = crypto::wrap(&self.main.current, tenant, number, &key).map_err(crypto_error)?;
        sqlx::query!(
            "INSERT INTO tenant_keys (tenant_id, number, wrapped, main_key) VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
            tenant,
            number as i32,
            wrapped,
            &crypto::fingerprint(&self.main.current)[..],
        )
        .execute(&self.pool)
        .await?;
        Ok(number)
    }
}

/// How many tenant keys are wrapped with which main key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WrapStatus {
    pub current: i64,
    pub previous: i64,
    /// Written before fingerprints were kept, or with a main key that is no longer configured.
    pub unknown: i64,
}

/// Counts the tenant keys by the main key that wrapped them.
pub async fn wrap_status(pool: &PgPool, main: &MainKeys) -> Result<WrapStatus, KeyError> {
    let rows = sqlx::query!(r#"SELECT main_key, count(*) AS "count!" FROM tenant_keys GROUP BY main_key"#)
        .fetch_all(pool)
        .await?;
    let current = crypto::fingerprint(&main.current);
    let previous: Vec<_> = main.previous.iter().map(crypto::fingerprint).collect();
    let mut status = WrapStatus::default();
    for row in rows {
        match row.main_key.as_deref() {
            Some(fingerprint) if fingerprint == current => status.current += row.count,
            Some(fingerprint) if previous.iter().any(|p| p == fingerprint) => status.previous += row.count,
            _ => status.unknown += row.count,
        }
    }
    Ok(status)
}

/// Wraps every tenant key that is not wrapped with the current main key again with it. Needs the owner of the schema
/// (the runtime role may not change keys). Stops at the first key no configured main key can unwrap; returns the
/// number of keys rewrapped.
pub async fn rewrap(owner: &PgPool, main: &MainKeys) -> Result<u64, KeyError> {
    let current = crypto::fingerprint(&main.current);
    let rows = sqlx::query!(
        "SELECT tenant_id, number, wrapped, main_key FROM tenant_keys
         WHERE main_key IS DISTINCT FROM $1 ORDER BY tenant_id, number",
        &current[..],
    )
    .fetch_all(owner)
    .await?;
    let mut rewrapped = 0;
    for row in rows {
        let (tenant, number) = (row.tenant_id, row.number as u32);
        let key = main.unwrap(tenant, number, &row.wrapped, row.main_key.as_deref())?;
        let wrapped = crypto::wrap(&main.current, tenant, number, &key).map_err(|source| KeyError::Crypto {
            tenant,
            number,
            source,
        })?;
        // Only if unchanged since it was read; a concurrent rewrap has done the work otherwise.
        rewrapped += sqlx::query!(
            "UPDATE tenant_keys SET wrapped = $3, main_key = $4
             WHERE tenant_id = $1 AND number = $2 AND wrapped = $5",
            tenant,
            row.number,
            wrapped,
            &current[..],
            row.wrapped,
        )
        .execute(owner)
        .await?
        .rows_affected();
    }
    Ok(rewrapped)
}
