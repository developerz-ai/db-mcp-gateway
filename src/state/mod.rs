//! State DB pool + schema migrations.
//!
//! The gateway owns this Postgres. It stores sessions, audit rows, and the
//! denylist. Migrations live in `migrations/` and are applied at boot via
//! `sqlx::migrate!` — failure to migrate refuses to start the process.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

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
