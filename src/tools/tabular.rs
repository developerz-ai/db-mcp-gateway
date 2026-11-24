//! The plain `{columns, rows, truncated, elapsed_ms}` success shape shared by
//! the introspection tools, and the sized row result of `run_query` /
//! `sample_table`: the same shape plus the [`caps::Sizing`] fields.

pub(super) mod caps;
pub(super) mod columns;

use serde::Serialize;
use serde_json::Value;

use crate::config::ServerKind;
use crate::exec::ExecResult;

use caps::{ByteCaps, RowLimit, Sizing};

use super::audit_dispatch::{Outcome, OutcomeCode, error_outcome, success_outcome};

#[derive(Debug, Serialize)]
struct TabularPayload<'a> {
    columns: &'a [String],
    rows: &'a [Vec<Value>],
    truncated: bool,
    elapsed_ms: u64,
}

/// Success outcome carrying `rows` (already filtered by the caller) under
/// `result`'s columns, truncation flag and timing.
pub(super) fn tabular_outcome(id: Value, result: &ExecResult, rows: &[Vec<Value>]) -> Outcome {
    let payload = TabularPayload {
        columns: &result.columns,
        rows,
        truncated: result.truncated,
        elapsed_ms: result.elapsed_ms,
    };
    let Ok(text) = serde_json::to_string(&payload) else {
        return error_outcome(OutcomeCode::Internal, "failed to serialize result");
    };
    success_outcome(
        id,
        text,
        Some(i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX)),
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
        Some(result.truncated),
    )
}

/// How a row result is sized: the row limit it ran under, the caller's
/// byte caps, and the server kind its paging hint speaks for.
#[derive(Debug, Clone, Copy)]
pub(super) struct RowShaping {
    pub limit: RowLimit,
    pub caps: ByteCaps,
    pub kind: ServerKind,
}

#[derive(Debug, Serialize)]
struct RowsPayload<'a, E> {
    columns: &'a [String],
    /// The type of each column, beside `columns`; absent on a backend with
    /// no type info.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    column_types: &'a [String],
    rows: &'a [Vec<Value>],
    #[serde(flatten)]
    sizing: &'a Sizing,
    elapsed_ms: u64,
    #[serde(flatten)]
    extra: E,
}

/// Success outcome for a row result sized by `shaping`, with the tool's own
/// `extra` fields beside the shared ones.
pub(super) fn rows_outcome<E: Serialize>(
    id: Value,
    result: ExecResult,
    shaping: RowShaping,
    extra: E,
) -> Outcome {
    let (rows, sizing) = caps::shape(
        result.rows,
        result.truncated,
        shaping.limit,
        shaping.caps,
        shaping.kind,
    );
    let payload = RowsPayload {
        columns: &result.columns,
        column_types: &result.column_types,
        rows: &rows,
        sizing: &sizing,
        elapsed_ms: result.elapsed_ms,
        extra,
    };
    let Ok(text) = serde_json::to_string(&payload) else {
        return error_outcome(OutcomeCode::Internal, "failed to serialize result");
    };
    success_outcome(
        id,
        text,
        Some(i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX)),
        Some(i64::try_from(rows.len()).unwrap_or(i64::MAX)),
        Some(sizing.truncated),
    )
}
