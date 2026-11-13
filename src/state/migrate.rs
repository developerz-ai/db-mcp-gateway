//! Boot-time schema migrations for the state DB and the MySQL permissions
//! store.
//!
//! Versions applied by a newer image are tolerated, so a one-release rollback
//! boots: a drop lands only after the release that stopped using the object
//! runs everywhere (expand/contract, plan 101 slice 03), so release N-1 runs on
//! schema N. A known migration whose checksum changed, or a failed one, still
//! refuses boot.

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{MySqlPool, PgPool};

const NEWEST_APPLIED_SQL: &str = "SELECT max(version) FROM _sqlx_migrations";

pub(super) async fn state_db(pool: &PgPool) -> Result<(), MigrateError> {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await?;
    let newest_applied = sqlx::query_scalar(NEWEST_APPLIED_SQL)
        .fetch_one(pool)
        .await
        .map_err(MigrateError::Execute)?;
    warn_if_schema_ahead("state DB", &migrator, newest_applied);
    Ok(())
}

pub(super) async fn permissions_mysql(pool: &MySqlPool) -> Result<(), MigrateError> {
    let mut migrator = sqlx::migrate!("./migrations-mysql");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await?;
    let newest_applied = sqlx::query_scalar(NEWEST_APPLIED_SQL)
        .fetch_one(pool)
        .await
        .map_err(MigrateError::Execute)?;
    warn_if_schema_ahead("permissions store", &migrator, newest_applied);
    Ok(())
}

/// Booting on a schema a newer release migrated is allowed, but loudly: an
/// operator who rolled back further than one release must see it at boot.
fn warn_if_schema_ahead(store: &'static str, migrator: &Migrator, newest_applied: Option<i64>) {
    let newest_known = migrator.iter().map(|m| m.version).max();
    if let (Some(applied), Some(known)) = (newest_applied, newest_known)
        && applied > known
    {
        tracing::warn!(
            store,
            applied,
            known,
            "schema was migrated by a newer gateway release; running on it as a rollback"
        );
    }
}
