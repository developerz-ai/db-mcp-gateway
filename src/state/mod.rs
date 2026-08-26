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
    /// State DB connect failed. The `#[source]` `sqlx::Error` can embed the DSN
    /// — and therefore the password — in its `Display` on a malformed-URL or
    /// auth failure. NEVER render this variant's source into a log, response, or
    /// process-exit message; log its *type* and emit a generic error instead
    /// (see `boot_db_error` in `main.rs`). CLAUDE.md non-negotiable #1.
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

/// Classify a connect-time [`sqlx::Error`] into a short, **credential-free**
/// token safe to log and to ship to GlitchTip.
///
/// [`StateDbError::Connect`]'s `Display`/`Debug` can embed the DSN, so the boot
/// path may never render it (CLAUDE.md non-negotiable #1). What it rendered
/// instead — `std::any::type_name_of_val(&source)` — is the constant
/// `"sqlx_core::error::Error"` for every failure, which is why a month of
/// production boot failures could not be told apart: a refused connection, an
/// expired password and a 5s pool timeout all logged the same nine words.
///
/// Only the variant discriminant escapes, plus two pieces that are enum-shaped
/// rather than free text: `io::ErrorKind` (e.g. `ConnectionRefused`) and the
/// database's five-character SQLSTATE (e.g. `28P01` = invalid password). The
/// source's *message* is never included — `Configuration` and `Tls` in
/// particular can carry the URL and the host.
pub fn connect_error_class(err: &sqlx::Error) -> String {
    match err {
        // The message is `error with configuration: <the URL>` — class only.
        sqlx::Error::Configuration(_) => "configuration".to_owned(),
        sqlx::Error::Io(io) => format!("io/{:?}", io.kind()),
        sqlx::Error::Tls(_) => "tls".to_owned(),
        sqlx::Error::Protocol(_) => "protocol".to_owned(),
        sqlx::Error::Database(db) => match db.code() {
            Some(code) => format!("database/{code}"),
            None => "database".to_owned(),
        },
        sqlx::Error::PoolTimedOut => "pool_timed_out".to_owned(),
        sqlx::Error::PoolClosed => "pool_closed".to_owned(),
        sqlx::Error::WorkerCrashed => "worker_crashed".to_owned(),
        // `sqlx::Error` is `#[non_exhaustive]` and the rest are query-time
        // shapes (decode, column lookup, …) that connect cannot produce.
        _ => "other".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    //! Pure classification — no database, no network.

    use super::connect_error_class;

    #[test]
    fn classifies_connect_failures_without_leaking_the_source_message() {
        assert_eq!(
            connect_error_class(&sqlx::Error::Io(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused
            ))),
            "io/ConnectionRefused"
        );
        assert_eq!(
            connect_error_class(&sqlx::Error::PoolTimedOut),
            "pool_timed_out"
        );
        assert_eq!(connect_error_class(&sqlx::Error::PoolClosed), "pool_closed");
        // Query-time variants collapse to one token rather than panicking or
        // rendering anything.
        assert_eq!(connect_error_class(&sqlx::Error::RowNotFound), "other");
    }

    #[test]
    fn never_renders_a_dsn_bearing_source() {
        // `Configuration` and `Tls` wrap a boxed source whose `Display` is the
        // connection string on a malformed-URL failure. The class must not
        // carry one character of it.
        let dsn = "postgres://app:hunter2@db.internal:5432/app";

        for err in [
            sqlx::Error::Configuration(Box::<dyn std::error::Error + Send + Sync>::from(
                dsn.to_owned(),
            )),
            sqlx::Error::Tls(Box::<dyn std::error::Error + Send + Sync>::from(
                dsn.to_owned(),
            )),
            sqlx::Error::Protocol(dsn.to_owned()),
        ] {
            let class = connect_error_class(&err);
            assert!(!class.contains("hunter2"), "password leaked: {class}");
            assert!(!class.contains("db.internal"), "host leaked: {class}");
            assert!(!class.contains("postgres://"), "dsn leaked: {class}");
        }
    }
}
