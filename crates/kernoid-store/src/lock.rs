// SPDX-License-Identifier: AGPL-3.0-or-later
//! Work only one process of an installation should do at a time – rotating keys, ordering certificates – guarded by
//! a PostgreSQL advisory lock (session level, so that no transaction stays open while the work runs).

use sqlx::{PgPool, pool::PoolConnection, postgres::Postgres};

/// Held while the work runs; released when dropped (with its connection back in the pool) or by [`Lock::release`].
#[derive(Debug)]
pub struct Lock {
    connection: Option<PoolConnection<Postgres>>,
    key: i64,
}

/// The lock key of a name: the first eight bytes of its SHA-256, so that names do not collide by accident.
fn key(name: &str) -> i64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("kernoid lock {name}").as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("eight bytes"))
}

impl Lock {
    /// Takes the lock `name` if no other process holds it.
    pub async fn try_take(pool: &PgPool, name: &str) -> Result<Option<Self>, sqlx::Error> {
        let mut connection = pool.acquire().await?;
        let key = key(name);
        let taken = sqlx::query_scalar!(r#"SELECT pg_try_advisory_lock($1) AS "taken!""#, key)
            .fetch_one(&mut *connection)
            .await?;
        Ok(taken.then_some(Self { connection: Some(connection), key }))
    }

    pub async fn release(mut self) -> Result<(), sqlx::Error> {
        if let Some(mut connection) = self.connection.take() {
            sqlx::query_scalar!(r#"SELECT pg_advisory_unlock($1) AS "released!""#, self.key)
                .fetch_one(&mut *connection)
                .await?;
        }
        Ok(())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Not released explicitly: the connection is closed instead of returned, which ends the lock.
        if let Some(connection) = self.connection.take() {
            drop(connection.detach());
        }
    }
}
