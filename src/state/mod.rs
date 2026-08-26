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
///
/// What the boot seam can actually produce is narrower than this `match`, and
/// the difference matters when reading a class in Loki. `sqlx`'s pool swallows
/// `Io(ConnectionRefused)` and transient `Database` errors and retries them
/// until the acquire deadline (`sqlx-core-0.8.6/src/pool/inner.rs:374`), so at
/// boot a server that is down, unroutable or not yet listening arrives as
/// **`pool_timed_out`**, never as `io/ConnectionRefused`. `io/*` is reached
/// only by the io kinds that bubble immediately, and a rejected password —
/// which is not transient — arrives promptly as `database/28P01`. So the pair
/// this classifier really separates is *cannot reach it* (`pool_timed_out`)
/// from *reached it and was refused* (`database/<sqlstate>`), which is the
/// distinction the old constant `"sqlx_core::error::Error"` destroyed.
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

    /// Minimal [`sqlx::error::DatabaseError`] so the `Database` arm — the only
    /// one that reads a value back out of a driver-supplied object — can be
    /// exercised without a server. Carries a SQLSTATE and a message; the
    /// message exists so the non-leak test can prove it is not rendered.
    #[derive(Debug)]
    struct FakeDbError {
        code: String,
        message: String,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for FakeDbError {}

    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(std::borrow::Cow::Borrowed(&self.code))
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    #[test]
    fn classifies_connect_failures_without_leaking_the_source_message() {
        // `io/<kind>` for the io errors that bubble out of the pool. Note the
        // boot seam never renders `io/ConnectionRefused`: sqlx retries that one
        // kind until the acquire deadline, so a down server surfaces as
        // `pool_timed_out` (see the note on `connect_error_class`).
        assert_eq!(
            connect_error_class(&sqlx::Error::Io(std::io::Error::from(
                std::io::ErrorKind::HostUnreachable
            ))),
            "io/HostUnreachable"
        );
        // The class a down/unroutable server actually reaches the operator as.
        assert_eq!(
            connect_error_class(&sqlx::Error::PoolTimedOut),
            "pool_timed_out"
        );
        // The class a rejected password reaches the operator as — the other
        // half of the distinction the old constant `error_type` destroyed.
        assert_eq!(
            connect_error_class(&sqlx::Error::Database(Box::new(FakeDbError {
                code: "28P01".to_owned(),
                message: "password authentication failed for user \"app\"".to_owned(),
            }))),
            "database/28P01"
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
            // The `Database` arm reads `code()` off the driver's object; its
            // `message()` must stay out of the class even when it holds a DSN.
            sqlx::Error::Database(Box::new(FakeDbError {
                code: "28P01".to_owned(),
                message: dsn.to_owned(),
            })),
        ] {
            let class = connect_error_class(&err);
            assert!(!class.contains("hunter2"), "password leaked: {class}");
            assert!(!class.contains("db.internal"), "host leaked: {class}");
            assert!(!class.contains("postgres://"), "dsn leaked: {class}");
        }
    }
}
