//! Row/column decoding and sqlx-error classification.
//!
//! `classify` is intentionally narrow: any credential-quoting `sqlx::Error`
//! variant maps to a typed [`ExecError`] whose `Display` we control, and no
//! source chain from sqlx crosses the request boundary. New adapters must
//! preserve this discipline (see [`super::super::adapter`] module docs).

use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgRow;

use super::super::adapter::ExecError;

pub(super) fn classify(err: sqlx::Error) -> ExecError {
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

pub(super) fn decode_row(row: &PgRow) -> Vec<Value> {
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
