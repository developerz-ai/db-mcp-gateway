//! The plain `{columns, rows, truncated, elapsed_ms}` success shape shared by
//! the introspection tools.

use serde::Serialize;
use serde_json::Value;

use crate::exec::ExecResult;

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
