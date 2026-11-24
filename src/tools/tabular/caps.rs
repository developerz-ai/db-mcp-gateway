//! Sizing a row result for the caller's context window: the caller's byte
//! cap (`max_bytes`) and per-cell cap (`max_cell_bytes`), and the
//! `row_limit` / `truncated_by` / `hint` fields that say why rows stopped
//! and how to get the rest.
//!
//! Both caps weigh the JSON the caller receives, not the decoded size the
//! exec-layer budget weighs: they are applied to the rows the adapter
//! returned, after that budget, so the stricter of the two always wins.

use std::io;
use std::num::NonZeroU32;

use serde::Serialize;
use serde_json::Value;

use crate::audit::prefix_at_char_boundary;
use crate::config::ServerKind;
use crate::exec::MAX_RESULT_BYTES;

/// The key of the object that stands in for a cell past `max_cell_bytes`:
/// `{"$dbmcp_truncated": {"bytes": <JSON size of the cell>, "preview": "…"}}`.
pub(in crate::tools) const CELL_MARKER: &str = "$dbmcp_truncated";

/// The caller's byte caps, both optional and both at least 1.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::tools) struct ByteCaps {
    pub max_bytes: Option<NonZeroU32>,
    pub max_cell_bytes: Option<NonZeroU32>,
}

/// The row limit the call ran under, and what the caller asked for (its
/// `limit`, else the tool's default): the effective limit is below `asked`
/// only when the grant or the gateway ceiling clipped it.
#[derive(Debug, Clone, Copy)]
pub(in crate::tools) struct RowLimit {
    pub effective: u32,
    pub asked: u32,
}

/// Why a result holds fewer rows than the query produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::tools) enum TruncatedBy {
    /// The caller's `limit`, or the tool default: a larger `limit` returns more.
    Limit,
    /// The grant's `row_limit` or the gateway ceiling, below what was asked.
    GrantRowLimit,
    /// The caller's `max_bytes` or the gateway's 32 MiB result budget.
    ByteCap,
}

/// The sizing fields of a row result, flattened into its payload.
#[derive(Debug, Serialize)]
pub(in crate::tools) struct Sizing {
    pub truncated: bool,
    row_limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated_by: Option<TruncatedBy>,
    /// How to get the rows past the cut; present only when truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    /// Cells replaced by the [`CELL_MARKER`] object.
    #[serde(skip_serializing_if = "is_zero")]
    cells_truncated: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Apply the caller's caps to `rows` (what the adapter returned, with its
/// `truncated` flag) and say why the result stops where it does.
pub(in crate::tools) fn shape(
    mut rows: Vec<Vec<Value>>,
    exec_truncated: bool,
    limit: RowLimit,
    caps: ByteCaps,
    kind: ServerKind,
) -> (Vec<Vec<Value>>, Sizing) {
    let at_row_limit = rows.len() >= usize::try_from(limit.effective).unwrap_or(usize::MAX);
    let cells_truncated = caps
        .max_cell_bytes
        .map_or(0, |cap| cap_cells(&mut rows, cap));
    let byte_capped = caps
        .max_bytes
        .is_some_and(|cap| keep_within(&mut rows, cap));
    // Rows run out at the row limit only when every row was kept; otherwise
    // a byte budget cut first (the gateway's when the adapter stopped short).
    let truncated_by = match (byte_capped, exec_truncated) {
        (true, _) => Some(TruncatedBy::ByteCap),
        (false, true) if !at_row_limit => Some(TruncatedBy::ByteCap),
        (false, true) if limit.effective < limit.asked => Some(TruncatedBy::GrantRowLimit),
        (false, true) => Some(TruncatedBy::Limit),
        (false, false) => None,
    };
    let sizing = Sizing {
        truncated: truncated_by.is_some(),
        row_limit: limit.effective,
        truncated_by,
        hint: truncated_by.map(|by| hint(by, kind)),
        cells_truncated,
    };
    (rows, sizing)
}

fn hint(by: TruncatedBy, kind: ServerKind) -> String {
    let cause = match by {
        TruncatedBy::Limit => "more rows match: raise `limit`, or page",
        TruncatedBy::GrantRowLimit => "your grant caps the rows per call: page",
        TruncatedBy::ByteCap => {
            "the result hit the byte cap: select fewer or narrower columns, set \
             `max_cell_bytes`, or page"
        }
    };
    let paging = match kind {
        ServerKind::Mongo => {
            "with run_query: sort on `_id` and filter `{\"_id\": {\"$gt\": <last _id>}}`"
        }
        ServerKind::Redis => "with the reply's SCAN cursor, or a narrower range",
        ServerKind::Postgres | ServerKind::Mysql | ServerKind::Mssql => {
            "with run_query by key: ORDER BY a unique key, then WHERE key > the last row's key"
        }
    };
    format!("{cause} {paging}")
}

/// Replace every cell whose JSON is longer than `cap` bytes with the marker
/// object; the count replaced.
fn cap_cells(rows: &mut [Vec<Value>], cap: NonZeroU32) -> usize {
    let cap = usize::try_from(cap.get()).unwrap_or(usize::MAX);
    let mut replaced = 0;
    for cell in rows.iter_mut().flatten() {
        let bytes = json_len(cell);
        if bytes > cap {
            *cell = marker(cell, bytes, cap);
            replaced += 1;
        }
    }
    replaced
}

/// A string previews its own text; any other value its JSON text.
fn marker(cell: &Value, bytes: usize, cap: usize) -> Value {
    let json;
    let text = match cell {
        Value::String(s) => s.as_str(),
        other => {
            json = other.to_string();
            json.as_str()
        }
    };
    serde_json::json!({
        CELL_MARKER: { "bytes": bytes, "preview": prefix_at_char_boundary(text, cap) }
    })
}

/// Keep the leading rows whose JSON array fits in `cap` (clamped to the
/// gateway budget); `true` when a row was dropped.
fn keep_within(rows: &mut Vec<Vec<Value>>, cap: NonZeroU32) -> bool {
    let cap = usize::try_from(cap.get())
        .unwrap_or(usize::MAX)
        .min(MAX_RESULT_BYTES);
    // `[` and `]`, then each row plus its separating comma.
    let mut used: usize = 2;
    let keep = rows
        .iter()
        .take_while(|row| {
            used = used.saturating_add(json_len(row)).saturating_add(1);
            used <= cap + 1
        })
        .count();
    let dropped = keep < rows.len();
    rows.truncate(keep);
    dropped
}

/// The length of `value`'s compact JSON, counted without building it. A
/// value that cannot be serialised weighs `usize::MAX`, past every cap.
fn json_len(value: &impl Serialize) -> usize {
    let mut counter = ByteCounter(0);
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => counter.0,
        Err(_) => usize::MAX,
    }
}

struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "caps_tests.rs"]
mod tests;
