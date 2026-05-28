//! Execution layer: per-`(server, database)` Postgres pools and the query path
//! that enforces `statement_timeout`, row caps, and cancellation.
//!
//! Security-required (see CLAUDE.md). Two non-negotiables:
//!
//! 1. The connection password (literal, env-resolved, or backend-resolved) is
//!    NEVER embedded in `Display` for any error or in any tracing field on
//!    the request path. The DSN we build is fed to `sqlx` and dropped.
//! 2. The DB-side `statement_timeout` is set via `SET LOCAL` inside the
//!    per-query transaction, so a single misuse can't outlive its tx. We also
//!    wrap the query in `tokio::time::timeout` as belt-and-suspenders — if
//!    the DB ignores `SET LOCAL`, the future still completes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use serde::Serialize;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode};
use sqlx::{Column, Executor, PgPool, Row};
use tokio::sync::RwLock;

use crate::config::{Database, Password, Server, Tls};

const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 5;
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Extra slack on top of the DB-side `statement_timeout` so the Tokio guard
/// doesn't preempt before Postgres has a chance to surface its own cancel.
const TOKIO_TIMEOUT_SLACK_MS: u64 = 500;

/// Per-DB Postgres pool registry. One pool per `(server, database)` so a slow
/// query on DB A can never block DB B.
#[derive(Clone, Default)]
pub struct PoolRegistry {
    inner: Arc<RwLock<HashMap<(String, String), PgPool>>>,
}

impl std::fmt::Debug for PoolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PgPool's Debug exposes the connection URL with password. Never let
        // a derived/auto Debug leak that — print structural info only.
        f.debug_struct("PoolRegistry")
            .field("pools", &"<RwLock<HashMap<(server, db), PgPool>>>")
            .finish()
    }
}

impl PoolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the pool for `(server.name, database.name)`, opening it if
    /// needed. Lazy: a misconfigured DB only errors on first use, not at boot.
    pub async fn get_or_open(
        &self,
        server: &Server,
        database: &Database,
    ) -> Result<PgPool, ExecError> {
        let key = (server.name.clone(), database.name.clone());

        if let Some(pool) = self.inner.read().await.get(&key).cloned() {
            return Ok(pool);
        }

        // Re-check under the write lock — another task may have opened it
        // while we were waiting on the upgrade.
        let mut writer = self.inner.write().await;
        if let Some(pool) = writer.get(&key).cloned() {
            return Ok(pool);
        }

        let password = resolve_password(&database.password)?;
        let opts = build_connect_options(server, database, &password);
        let pool = PgPoolOptions::new()
            .max_connections(DEFAULT_POOL_MAX_CONNECTIONS)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_with(opts)
            .await
            .map_err(|_| ExecError::Connection)?;

        writer.insert(key, pool.clone());
        Ok(pool)
    }
}

fn build_connect_options(server: &Server, database: &Database, password: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&server.host)
        .port(server.port)
        .username(&database.role)
        .password(password)
        .database(&database.name)
        .ssl_mode(match server.tls {
            Tls::Required => PgSslMode::Require,
            Tls::Insecure => PgSslMode::Disable,
        })
}

fn resolve_password(password: &Password) -> Result<String, ExecError> {
    match password {
        Password::Literal(s) => Ok(s.clone()),
        Password::EnvVar(name) => std::env::var(name).map_err(|_| ExecError::PasswordUnresolved {
            kind: "env",
            reference: name.clone(),
        }),
        // vault: / aws-sm: / gcp-sm: resolution lands with #5. Until then we
        // surface a structured error rather than silently failing the connect.
        Password::SecretBackend { scheme, reference } => Err(ExecError::PasswordUnresolved {
            kind: match scheme.as_str() {
                "vault" => "vault",
                "aws-sm" => "aws-sm",
                "gcp-sm" => "gcp-sm",
                _ => "unknown",
            },
            reference: reference.clone(),
        }),
    }
}

/// Typed execution errors. `Display` carries no secrets, hostnames, or
/// connection strings; details for operators live in `tracing` events and
/// the chained `source()`.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("connection to target DB failed")]
    Connection,

    #[error("DB unavailable")]
    Unavailable,

    #[error("query exceeded the configured statement_timeout")]
    Timeout,

    #[error("SQL rejected by the DB")]
    Sql,

    #[error("password reference `{kind}:{reference}` could not be resolved")]
    PasswordUnresolved {
        kind: &'static str,
        reference: String,
    },
}

#[derive(Debug, Serialize)]
pub struct ExecResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// True if the query produced more rows than `row_limit` allowed; the
    /// remaining rows were not pulled from the DB.
    pub truncated: bool,
    pub elapsed_ms: u64,
}

/// Run `sql` against `pool` with the given statement timeout + row cap.
///
/// - Wraps the query in a transaction so `SET LOCAL statement_timeout` is
///   scoped per-query.
/// - Streams rows; stops after `row_limit` and marks `truncated = true`.
/// - Cancellation safety: dropping this future drops the transaction →
///   sqlx releases the connection → Postgres cancels the in-flight query.
///   Tested by the integration suite (#4 acceptance).
pub async fn run_query(
    pool: &PgPool,
    sql: &str,
    statement_timeout_ms: Option<u32>,
    row_limit: u32,
) -> Result<ExecResult, ExecError> {
    // Belt-and-suspenders: a Tokio-side deadline so even a misapplied
    // SET LOCAL (or a DB that ignores it) still bounds the call.
    if let Some(ms) = statement_timeout_ms {
        let budget = Duration::from_millis(u64::from(ms) + TOKIO_TIMEOUT_SLACK_MS);
        match tokio::time::timeout(
            budget,
            run_query_inner(pool, sql, statement_timeout_ms, row_limit),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    } else {
        run_query_inner(pool, sql, statement_timeout_ms, row_limit).await
    }
}

async fn run_query_inner(
    pool: &PgPool,
    sql: &str,
    statement_timeout_ms: Option<u32>,
    row_limit: u32,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let mut tx = pool.begin().await.map_err(|_| ExecError::Unavailable)?;

    if let Some(ms) = statement_timeout_ms {
        // `ms` is u32, so the SQL fragment is purely a number — no injection
        // risk from interpolation.
        let stmt = format!("SET LOCAL statement_timeout = {ms}");
        tx.execute(stmt.as_str()).await.map_err(classify)?;
    }

    let limit = row_limit as usize;
    let mut columns: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<Value>> = Vec::new();
    let mut truncated = false;

    {
        let mut stream = sqlx::query(sql).fetch(&mut *tx);
        while let Some(row_result) = stream.next().await {
            let row = row_result.map_err(classify)?;
            if columns.is_empty() {
                columns = row.columns().iter().map(|c| c.name().to_string()).collect();
            }
            if rows.len() >= limit {
                truncated = true;
                break;
            }
            rows.push(decode_row(&row));
        }
        // Stream is dropped here so the borrow on `tx` ends and we can commit.
    }

    tx.commit().await.map_err(classify)?;

    Ok(ExecResult {
        columns,
        rows,
        truncated,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

fn classify(err: sqlx::Error) -> ExecError {
    // Postgres `statement_timeout` raises SQLSTATE `57014` (`query_canceled`).
    if let sqlx::Error::Database(db) = &err
        && let Some(code) = db.code()
        && code == "57014"
    {
        return ExecError::Timeout;
    }
    if matches!(err, sqlx::Error::PoolTimedOut | sqlx::Error::Io(_)) {
        return ExecError::Unavailable;
    }
    ExecError::Sql
}

fn decode_row(row: &PgRow) -> Vec<Value> {
    (0..row.columns().len())
        .map(|i| decode_value(row, i))
        .collect()
}

/// Best-effort value decode for the common Postgres types. Real schema-aware
/// type handling (timestamps, arrays, jsonb) arrives with the schema-typed
/// tools (#6/#7) — for now anything we can't recognise serialises as `null`.
fn decode_value(row: &PgRow, idx: usize) -> Value {
    // NULL has no concrete type to probe against; let it fall through to the
    // Option-of-string check which is the most permissive null detection.
    if let Ok(None) = row.try_get::<Option<String>, _>(idx) {
        return Value::Null;
    }
    if let Ok(v) = row.try_get::<i64, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<i32, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<f64, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<bool, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<String, _>(idx) {
        return Value::from(v);
    }
    Value::Null
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_password_handles_each_form() {
        assert_eq!(
            resolve_password(&Password::Literal("hunter2".into())).unwrap(),
            "hunter2"
        );

        let env_name = "DB_MCP_EXEC_TEST_PW";
        // SAFETY: test sets and clears a unique env var; nothing else reads it.
        unsafe {
            std::env::set_var(env_name, "from-env");
        }
        assert_eq!(
            resolve_password(&Password::EnvVar(env_name.into())).unwrap(),
            "from-env"
        );
        unsafe {
            std::env::remove_var(env_name);
        }
        assert!(matches!(
            resolve_password(&Password::EnvVar(env_name.into())),
            Err(ExecError::PasswordUnresolved { kind: "env", .. })
        ));

        assert!(matches!(
            resolve_password(&Password::SecretBackend {
                scheme: "vault".into(),
                reference: "secret/path".into()
            }),
            Err(ExecError::PasswordUnresolved { kind: "vault", .. })
        ));
    }

    #[test]
    fn exec_error_display_carries_no_secrets() {
        let e = ExecError::PasswordUnresolved {
            kind: "env",
            reference: "MY_VAR".into(),
        };
        let s = format!("{e}");
        // Reference name is operationally useful and not itself a secret.
        assert!(s.contains("MY_VAR"));
        // Other variants must not leak details.
        assert_eq!(
            format!("{}", ExecError::Connection),
            "connection to target DB failed"
        );
        assert_eq!(
            format!("{}", ExecError::Timeout),
            "query exceeded the configured statement_timeout"
        );
    }
}
