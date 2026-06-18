//! State DB pool + schema migrations.
//!
//! The gateway owns this Postgres. It stores sessions, audit rows, the
//! denylist, and (since #47) the permissions store. Migrations live in
//! `migrations/` and are applied at boot via `sqlx::migrate!` — failure to
//! migrate refuses to start the process.

pub mod permissions;

use std::time::Duration;

use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::{MySqlPool, PgPool};

#[derive(Debug, thiserror::Error)]
pub enum StateDbError {
    #[error("failed to connect to state DB")]
    Connect(#[source] sqlx::Error),
    #[error("failed to run state DB migrations")]
    Migrate(#[source] sqlx::migrate::MigrateError),
}

/// Connect to the state DB and run pending migrations. Returned pool is shared
/// across the process — Postgres-only, never re-pointed at a target DB.
pub async fn connect(url: &str, pool_size: u32) -> Result<PgPool, StateDbError> {
    let pool = PgPoolOptions::new()
        .max_connections(pool_size)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await
        .map_err(StateDbError::Connect)?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(StateDbError::Migrate)?;

    Ok(pool)
}

/// Connect to a MySQL permissions store and run the mysql migrations.
/// Used only when `permissions.store.driver = mysql` (#59); the state DB
/// itself stays Postgres-only (audit_calls + sessions live there). The
/// mysql migrations live under `migrations-mysql/` and create the
/// `permissions_*` tables only — not the state-DB-only sessions / audit
/// tables.
pub async fn connect_permissions_mysql(
    url: &str,
    pool_size: u32,
) -> Result<MySqlPool, StateDbError> {
    let pool = MySqlPoolOptions::new()
        .max_connections(pool_size)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await
        .map_err(StateDbError::Connect)?;

    sqlx::migrate!("./migrations-mysql")
        .run(&pool)
        .await
        .map_err(StateDbError::Migrate)?;

    Ok(pool)
}
