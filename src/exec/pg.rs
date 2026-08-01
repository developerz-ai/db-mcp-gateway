//! Postgres adapter — `DbAdapter` impl plus the per-DB pool open path.
//!
//! Security non-negotiables (CLAUDE.md):
//!
//! 1. The connection password (literal, env-resolved, or backend-resolved) is
//!    NEVER embedded in `Display` for any error or in any tracing field on
//!    the request path. The DSN we build is fed to `sqlx` and dropped.
//! 2. The DB-side `statement_timeout` is set via `SET LOCAL` inside the
//!    per-query transaction, so a single misuse can't outlive its tx. We also
//!    wrap the query in `tokio::time::timeout` as belt-and-suspenders — if
//!    the DB ignores `SET LOCAL`, the future still completes. A timeout is
//!    ALWAYS applied: a grant that declines to cap (or asks for more than
//!    the gateway allows) is resolved by
//!    [`super::adapter::effective_timeout_ms`], so no query can pin a pool
//!    connection indefinitely and no grant can loosen past the ceiling.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt;
use metrics::gauge;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode};
use sqlx::{Column, Executor, PgPool, Row};

use crate::config::{Database, Password, Server, Tls};

use super::adapter::{
    AdapterKind, DbAdapter, ExecError, ExecQuery, ExecResult, TOKIO_TIMEOUT_SLACK_MS,
    effective_timeout_ms,
};

/// Public so integration tests (e.g. `cancellation_real_db`) can size the
/// saturation workload to match the pool exactly rather than duplicating the
/// literal — a stale copy would silently stop exercising full saturation if
/// this constant changed.
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 5;
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Dedicated pool for `pg_cancel_backend(pid)` writes. Must stay separate
/// from the main pool — if `CancelOnDrop::drop` fired through the main
/// pool, its `execute` would queue on `acquire()` behind the very
/// connections the cancels are trying to free (five hung queries + five
/// drops with `max_connections = 5` deadlocks every cancel until
/// `statement_timeout` expires). Sized to 2 so a burst of concurrent
/// disconnects gets two round-trips in parallel; cancels are single-round
/// and cheap, no need for more.
const CANCEL_POOL_MAX_CONNECTIONS: u32 = 2;

/// Per-`(server, database)` Postgres adapter. Wraps a `PgPool`; one instance
/// per logical DB so a slow query on DB A can never block DB B.
pub struct PgAdapter {
    pool: PgPool,
    /// Dedicated pool for `pg_cancel_backend(pid)`. Never shares connections
    /// with `pool` — see [`CANCEL_POOL_MAX_CONNECTIONS`] for the reason.
    cancel_pool: PgPool,
    /// Composite label for metrics tagging — bounded cardinality, supplied
    /// from YAML config rather than user input.
    db_label: String,
}

impl std::fmt::Debug for PgAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `PgPool`'s derived `Debug` exposes the connection URL with password.
        // Never let that leak — print structural info only.
        f.debug_struct("PgAdapter")
            .field("db", &self.db_label)
            .finish()
    }
}

impl PgAdapter {
    /// Open a fresh pool for `(server, database)`. Lazy: a misconfigured DB
    /// only errors here (the registry calls this on first request to that
    /// DB), not at boot.
    pub async fn open(server: &Server, database: &Database) -> Result<Self, ExecError> {
        let password = resolve_password(&database.password)?;
        let opts = build_connect_options(server, database, &password);
        // Same DSN for both pools — the cancel pool is a Postgres client like
        // any other, it just never runs anything but `pg_cancel_backend(...)`.
        let pool = PgPoolOptions::new()
            .max_connections(DEFAULT_POOL_MAX_CONNECTIONS)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_with(opts.clone())
            .await
            .map_err(|_| ExecError::Connection)?;
        let cancel_pool = PgPoolOptions::new()
            .max_connections(CANCEL_POOL_MAX_CONNECTIONS)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_with(opts)
            .await
            .map_err(|_| ExecError::Connection)?;

        let db_label = format!("{}/{}", server.name, database.name);
        // Single label `db = "<server>/<database>"` — bounded cardinality.
        // Live connection count would need a polling task; reporting the
        // configured max is the cheap first signal for "pool exists for this
        // db". A separate `pool_kind` label distinguishes the query pool from
        // the cancel pool so operator dashboards see both without stat name
        // proliferation.
        gauge!("pool_size", "db" => db_label.clone(), "pool_kind" => "query")
            .set(DEFAULT_POOL_MAX_CONNECTIONS as f64);
        gauge!("pool_size", "db" => db_label.clone(), "pool_kind" => "cancel")
            .set(CANCEL_POOL_MAX_CONNECTIONS as f64);

        Ok(Self {
            pool,
            cancel_pool,
            db_label,
        })
    }
}

#[async_trait]
impl DbAdapter for PgAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Postgres
    }

    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        // A timeout is ALWAYS applied: the grant value when present (it may be
        // tighter), else the gateway ceiling. `None` would otherwise leave the
        // query unbounded and pin a pool connection — see S4. Both the
        // DB-side `SET LOCAL` and this Tokio guard use the same effective
        // value (computed again inside `run_query_inner`).
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        // Belt-and-suspenders: a Tokio-side deadline so even a misapplied
        // SET LOCAL (or a DB that ignores it) still bounds the call.
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        match tokio::time::timeout(
            budget,
            run_query_inner(&self.pool, &self.cancel_pool, &query),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    async fn health(&self) -> Result<(), ExecError> {
        // `SELECT 1` proves the pool can hand out a working connection and
        // the DB is accepting queries. Cheaper than a no-op acquire because
        // the round-trip catches half-open connections too.
        sqlx::query("SELECT 1")
            .fetch_optional(&self.pool)
            .await
            .map(|_| ())
            .map_err(classify)
    }
}

fn build_connect_options(
    server: &Server,
    database: &Database,
    password: &SecretString,
) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&server.host)
        .port(server.port)
        .username(&database.role)
        // The sqlx boundary: the plaintext `&str` exists only for this builder
        // call, then lives inside `PgConnectOptions` (fed to the pool, dropped).
        .password(password.expose_secret())
        .database(&database.name)
        .ssl_mode(match server.tls {
            Tls::Required => PgSslMode::Require,
            Tls::Insecure => PgSslMode::Disable,
        })
}

/// Adapt `Password::resolve` into `ExecError`. The boot-time walk in
/// `ConfigFile::resolve_secrets` already failed fast on every unresolvable
/// ref — but pools are opened lazily, so a `${FILE:…}` mount that disappears
/// after boot (rotation gone wrong) still needs a structured error here.
///
/// Visible to sibling adapters (`mongo::MongoAdapter::open`) — the
/// resolution rules are identical regardless of backend, and the
/// `ExecError` mapping is the same in every call site.
pub(super) fn resolve_password(password: &Password) -> Result<SecretString, ExecError> {
    use crate::config::SecretError;
    password.resolve().map_err(|err| match err {
        SecretError::EnvNotSet(name) | SecretError::EnvNotUtf8(name) => {
            ExecError::PasswordUnresolved {
                kind: "env",
                reference: name,
            }
        }
        SecretError::FileUnreadable { path, .. } | SecretError::FileEmpty(path) => {
            ExecError::PasswordUnresolved {
                kind: "file",
                reference: path.display().to_string(),
            }
        }
        // Keep the stable `(kind, reference)` tool-facing shape: `kind` is the
        // category, the scheme goes into `reference`. Emitting `kind: "vault"`
        // would force tool callers to match on every supported backend name.
        SecretError::BackendNotImplemented(scheme) => ExecError::PasswordUnresolved {
            kind: "backend",
            reference: scheme,
        },
        // Malformed refs are caught at YAML parse time, never reach here —
        // but stay structured rather than panic if invariants drift. No
        // payload is available (and intentionally so: the raw token could
        // be a typo'd plaintext password — see `SecretError::Malformed`).
        SecretError::Malformed => ExecError::PasswordUnresolved {
            kind: "malformed",
            reference: String::new(),
        },
    })
}

/// Fires `pg_cancel_backend(pid)` from a detached task if dropped while
/// armed — the server-side half of cancellation safety (CLAUDE.md
/// *§Cancellation safety*).
///
/// Why this is necessary: when the agent disconnects, axum drops the handler
/// future and with it this query future, mid-`.await`. Dropping a sqlx
/// `Transaction` does NOT stop the query already running on the Postgres
/// backend — it only closes the client socket. The backend keeps executing
/// until it finishes or hits `statement_timeout`, pinning a pool connection
/// for up to the full timeout after the client is gone. So we capture the
/// backend PID up front and, on drop, cancel it over the **cancel pool** —
/// a pool that is deliberately separate from the query pool. Using the
/// query pool would have `execute` queue on `acquire()` behind the very
/// connections the cancels are trying to free (see
/// [`CANCEL_POOL_MAX_CONNECTIONS`]).
///
/// Disarmed on the normal path once the query has run to completion, so a
/// cleanly-returned connection is never targeted — otherwise a late cancel
/// could hit an unrelated query that reused the same backend PID.
struct CancelOnDrop {
    /// `Some` while armed: the cancel pool (never the main query pool) and
    /// the backend PID to cancel.
    armed: Option<(PgPool, i32)>,
}

impl CancelOnDrop {
    fn disarm(&mut self) {
        self.armed = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some((pool, pid)) = self.armed.take() else {
            return;
        };
        // Detached: the parent future is being dropped, so we can't await the
        // cancel inline. The spawn outlives this Drop and runs on a fresh
        // connection. No error Display in the log — this is the request path,
        // and `pid` alone tells the operator which backend failed to cancel.
        tokio::spawn(async move {
            if sqlx::query("SELECT pg_cancel_backend($1)")
                .bind(pid)
                .execute(&pool)
                .await
                .is_err()
            {
                tracing::warn!(pid, "pg_cancel_backend on drop failed");
            }
        });
    }
}

async fn run_query_inner(
    pool: &PgPool,
    cancel_pool: &PgPool,
    query: &ExecQuery<'_>,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let mut tx = pool.begin().await.map_err(|_| ExecError::Unavailable)?;

    // Capture this connection's backend PID so a drop (agent disconnect) can
    // cancel the exact backend running our query — dropping `tx` alone won't
    // stop it. Armed now and disarmed only after a clean commit below. The
    // guard holds the *cancel* pool so `pg_cancel_backend` can always
    // acquire, even when every connection in the query pool is pinned by
    // stuck backends.
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .map_err(classify)?;
    let mut cancel = CancelOnDrop {
        armed: Some((cancel_pool.clone(), pid)),
    };

    // Run the statement under the guard. By the time this block resolves — Ok
    // OR Err — the backend has stopped executing our query, so we disarm
    // before returning. The guard stays armed ONLY if this future is dropped
    // while awaiting (agent disconnect / outer `tokio::time::timeout`): the
    // one case where the backend is still running and must be cancelled.
    // Disarming on every normal return prevents a stray `pg_cancel_backend(pid)`
    // from cancelling an unrelated statement that later reuses this pooled
    // backend (same PID) — a flake where a timeout's detached cancel landed
    // mid-next-query and turned a healthy result into a spurious error.
    let result: Result<ExecResult, ExecError> = async {
        // Always set a DB-side cap — the grant value clamped to the gateway
        // ceiling, never `None` (see S4). `ms` is u32, so the SQL fragment is
        // purely a number — no injection risk from interpolation.
        let ms = effective_timeout_ms(query.statement_timeout_ms);
        let stmt = format!("SET LOCAL statement_timeout = {ms}");
        tx.execute(stmt.as_str()).await.map_err(classify)?;

        let limit = query.row_limit as usize;
        let mut columns: Vec<String> = Vec::new();
        let mut rows: Vec<Vec<Value>> = Vec::new();
        let mut truncated = false;

        {
            let mut sqlx_query = sqlx::query(query.sql);
            for bind in query.binds {
                sqlx_query = sqlx_query.bind(*bind);
            }
            let mut stream = sqlx_query.fetch(&mut *tx);
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
    .await;
    // Statement finished (success or error) — no orphaned backend to cancel.
    cancel.disarm();
    result
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
/// type handling (timestamps, arrays) arrives with the tools that need them
/// — for now anything we can't recognise serialises as `null`.
fn decode_value(row: &PgRow, idx: usize) -> Value {
    // JSON / JSONB first — these come back as opaque types that don't
    // decode as String. Without this, an `EXPLAIN (FORMAT JSON)` plan or
    // any `jsonb` column would surface to clients as `null`.
    if let Ok(json) = row.try_get::<sqlx::types::Json<Value>, _>(idx) {
        return json.0;
    }
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
            resolve_password(&Password::Literal("hunter2".into()))
                .unwrap()
                .expose_secret(),
            "hunter2"
        );

        let env_name = "DB_MCP_EXEC_TEST_PW";
        // SAFETY: test sets and clears a unique env var; nothing else reads it.
        unsafe {
            std::env::set_var(env_name, "from-env");
        }
        assert_eq!(
            resolve_password(&Password::EnvVar(env_name.into()))
                .unwrap()
                .expose_secret(),
            "from-env"
        );
        unsafe {
            std::env::remove_var(env_name);
        }
        assert!(matches!(
            resolve_password(&Password::EnvVar(env_name.into())),
            Err(ExecError::PasswordUnresolved { kind: "env", .. })
        ));

        // `kind: "backend"` keeps the tool-facing shape stable across
        // backends; the scheme rides along in `reference` so operators can
        // still tell vault from aws-sm in logs.
        match resolve_password(&Password::SecretBackend {
            scheme: "vault".into(),
            reference: "secret/path".into(),
        }) {
            Err(ExecError::PasswordUnresolved { kind, reference }) => {
                assert_eq!(kind, "backend");
                assert_eq!(reference, "vault");
            }
            other => panic!("expected PasswordUnresolved {{ kind: backend, .. }}, got {other:?}"),
        }
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
