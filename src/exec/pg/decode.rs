//! Row/column decoding and sqlx-error classification.
//!
//! `classify` is intentionally narrow: any credential-quoting `sqlx::Error`
//! variant maps to a typed [`ExecError`] whose `Display` we control, and no
//! source chain from sqlx crosses the request boundary. New adapters must
//! preserve this discipline (see [`super::super::adapter`] module docs).

use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{Row, TypeInfo, ValueRef};

use super::super::adapter::ExecError;

/// Key of the marker object returned for a column this gateway can't render
/// as JSON. See [`decode_value`].
const UNSUPPORTED_TYPE_KEY: &str = "unsupported_type";

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

/// Decode one cell to JSON.
///
/// The cardinal rule is that `Value::Null` means *SQL NULL* and nothing else.
/// A type this gateway can't render decodes to
/// `{"unsupported_type": "<pg type>"}` instead — an agent acting on query
/// results must never be handed a null that was really a `uuid`, a
/// `timestamptz`, or a money `numeric` (#136).
fn decode_value(row: &PgRow, idx: usize) -> Value {
    // Type-agnostic NULL check. Probing `Option<String>` (as this used to)
    // only detects NULL in text-compatible columns: sqlx checks the column
    // OID first, so a NULL `timestamptz` failed the probe and fell through —
    // arriving at the same fabricated `null` as a *non*-NULL one.
    let Ok(raw) = row.try_get_raw(idx) else {
        // Unreachable: `idx` comes from this row's own column list.
        return unsupported(None);
    };
    if raw.is_null() {
        return Value::Null;
    }
    let type_name = raw.type_info().name().to_string();

    // JSON / JSONB first — these come back as opaque types that don't
    // decode as String. Without this, an `EXPLAIN (FORMAT JSON)` plan or
    // any `jsonb` column would surface to clients as `null`.
    if let Ok(json) = row.try_get::<sqlx::types::Json<Value>, _>(idx) {
        return json.0;
    }
    // sqlx 0.8 enforces strict type compatibility per column OID: an `INT2`
    // value won't decode as `i32`, nor `REAL` as `f64`. Each width needs its
    // own probe, or non-null smallints/reals silently surface as `null`.
    if let Ok(v) = row.try_get::<i64, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<i32, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<i16, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<f64, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<f32, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<bool, _>(idx) {
        return Value::from(v);
    }
    if let Ok(v) = row.try_get::<String, _>(idx) {
        return Value::from(v);
    }
    // `numeric` as a JSON *string*, not a float. Postgres numerics are
    // arbitrary-precision and are what money columns are made of; rendering
    // one as `f64` would swap a visible wrong answer for an invisible one.
    if let Ok(v) = row.try_get::<sqlx::types::BigDecimal, _>(idx) {
        return Value::from(v.to_string());
    }
    if let Ok(v) = row.try_get::<sqlx::types::Uuid, _>(idx) {
        return Value::from(v.to_string());
    }
    // Timestamps render ISO-8601: `timestamptz` normalised to UTC with an
    // offset, `timestamp` naive (Postgres stores no zone for it, so inventing
    // one would be a lie).
    if let Ok(v) = row.try_get::<chrono::DateTime<chrono::Utc>, _>(idx) {
        return Value::from(v.to_rfc3339());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDateTime, _>(idx) {
        // `NaiveDateTime::to_string()` emits a *space* between date and time.
        // The spec (03-mcp-tools.md) documents `timestamp` as ISO-8601, which
        // demands the `T` separator. `%.f` preserves fractional seconds when
        // present and elides them when zero, matching Postgres round-tripping.
        return Value::from(v.format("%Y-%m-%dT%H:%M:%S%.f").to_string());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDate, _>(idx) {
        return Value::from(v.to_string());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveTime, _>(idx) {
        return Value::from(v.to_string());
    }
    // `bytea` as Postgres' own `\x`-prefixed hex, so it round-trips through
    // psql and is unmistakably not text.
    if let Ok(v) = row.try_get::<Vec<u8>, _>(idx) {
        return Value::from(format!("\\x{}", hex(&v)));
    }

    // Arrays, enums, ranges, PostGIS, user-defined types … all land here.
    // The marker is deliberately *not* null: it says "this cell exists and
    // holds a value the gateway can't render", and names the type so the
    // caller can cast it (`SELECT my_enum::text`).
    unsupported(Some(type_name))
}

/// The marker object substituted for an unrenderable cell.
fn unsupported(type_name: Option<String>) -> Value {
    let name = type_name.unwrap_or_else(|| "unknown".to_string());
    Value::Object(serde_json::Map::from_iter([(
        UNSUPPORTED_TYPE_KEY.to_string(),
        Value::from(name),
    )]))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String is infallible; the Result exists only to satisfy
        // the `Write` trait.
        let _ = write!(out, "{b:02x}");
        out
    })
}
