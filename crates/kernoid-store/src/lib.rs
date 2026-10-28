// SPDX-License-Identifier: AGPL-3.0-or-later
//! The storage layer: PostgreSQL for structure, metadata and events, object storage for content.
//!
//! SQL is written only with sqlx's checked macros (`query!`, `query_as!`, `query_scalar!`): every statement is a
//! literal checked against the schema at build time, and every value is a bound parameter. The unchecked functions
//! are forbidden by `clippy.toml`.
//!
//! Two PostgreSQL roles: the **owner** of the schema runs migrations (`migrate`), the **runtime** role serves and has
//! only the rights `kernoid_grant_runtime` gives it – it can add events but not change or remove them.

mod blob;
pub mod crypto;
pub mod garbage;
mod keys;
pub mod lock;
pub mod parts;

pub use blob::{BlobError, BlobStore};
pub use keys::{KeyError, MainKeys, TenantKeys, WrapStatus, rewrap, wrap_status};
pub use sqlx::PgPool;

use std::str::FromStr;

use kernoid_config::Database;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// Schema migrations of the whole installation, in one history.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Opens the connection pool of the runtime role, with the statement and idle-transaction limits of `config`.
pub async fn connect(config: &Database) -> Result<PgPool, sqlx::Error> {
    let options = PgConnectOptions::from_str(config.url.expose())?.application_name("kernoid").options([
        ("statement_timeout", config.statement_timeout_ms.to_string()),
        ("idle_in_transaction_session_timeout", config.idle_in_transaction_timeout_ms.to_string()),
    ]);
    PgPoolOptions::new().max_connections(config.max_connections).connect_with(options).await
}

/// Brings the schema up to date as the owner (`migrate_url`, else `url`) and grants the runtime role (the user of
/// `url`) what it needs. Run once per upgrade, before the new version serves – not by every process. Returns false
/// if both URLs name the same role, so that nothing is separated.
pub async fn migrate(config: &Database) -> Result<bool, MigrateError> {
    let runtime = PgConnectOptions::from_str(config.url.expose())?;
    let owner = connect_owner(config).await?;
    MIGRATOR.run(&owner).await?;
    let owner_role = sqlx::query_scalar!(r#"SELECT current_user AS "role!""#).fetch_one(&owner).await?;
    let separated = owner_role != runtime.get_username();
    if separated {
        sqlx::query!(r#"SELECT 1 AS "granted!" FROM kernoid_grant_runtime($1)"#, runtime.get_username() as &str)
            .fetch_one(&owner)
            .await?;
    }
    owner.close().await;
    Ok(separated)
}

/// One connection as the owner of the schema (`migrate_url`, else `url`), for migrations and key maintenance.
pub async fn connect_owner(config: &Database) -> Result<PgPool, sqlx::Error> {
    let owner_url = config.migrate_url.as_ref().unwrap_or(&config.url);
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(PgConnectOptions::from_str(owner_url.expose())?.application_name("kernoid-owner"))
        .await
}

/// Checks that PostgreSQL answers.
pub async fn ping(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query_scalar!(r#"SELECT 1 AS "one!""#).fetch_one(pool).await.map(drop)
}
