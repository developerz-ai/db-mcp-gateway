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

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::prefix_at_char_boundary;
use crate::config::ServerKind;
use crate::exec::MAX_RESULT_BYTES;

/// The key of the object that stands in for a cell past `max_cell_bytes`:
/// `{"$dbmcp_truncated": {"bytes": <JSON size of the cell>, "preview": "…"}}`.
pub(in crate::tools) const CELL_MARKER: &str = "$dbmcp_truncated";

/// The smallest `max_bytes`: the JSON of an empty `rows` array, `[]`.
const MIN_MAX_BYTES: u32 = 2;

/// A caller's `max_bytes`, at least [`MIN_MAX_BYTES`]: a smaller cap could
/// never be met, so it is refused before the target is read.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(try_from = "u32")]
pub struct MaxBytes(u32);

#[derive(Debug, thiserror::Error)]
#[error("`max_bytes` must be at least {MIN_MAX_BYTES}, the size of an empty `rows` array")]
pub struct MaxBytesTooSmall;

impl TryFrom<u32> for MaxBytes {
    type Error = MaxBytesTooSmall;

    fn try_from(bytes: u32) -> Result<Self, Self::Error> {
        if bytes < MIN_MAX_BYTES {
            return Err(MaxBytesTooSmall);
        }
        Ok(Self(bytes))
    }
}

/// The caller's byte caps, both optional.
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::tools) struct ByteCaps {
    pub max_bytes: Option<MaxBytes>,
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
    // The ceiling holds even with no caller cap: shaping can grow a result.
    let byte_cap = caps
        .max_bytes
        .map_or(MAX_RESULT_BYTES, |cap| {
            usize::try_from(cap.0).unwrap_or(usize::MAX)
        })
        .min(MAX_RESULT_BYTES);
    let (cells_truncated, byte_capped) = shape_rows(&mut rows, caps.max_cell_bytes, byte_cap);
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

/// Row by row: cap the row's cells at `cell_cap`, then keep it while the
/// JSON array still fits in `cap` bytes. Stops at the first row that does
/// not fit, so no row past the cut is ever shaped — a wide result with a
/// tiny `max_cell_bytes` builds markers for the rows it returns, not for all
/// of them. The cells replaced in the kept rows, and `true` when a row was
/// dropped.
fn shape_rows(
    rows: &mut Vec<Vec<Value>>,
    cell_cap: Option<NonZeroU32>,
    cap: usize,
) -> (usize, bool) {
    // `[` and `]`, then each row plus its separating comma.
    let mut used: usize = 2;
    let mut replaced = 0;
    let mut keep = rows.len();
    for (index, row) in rows.iter_mut().enumerate() {
        let row_replaced = cell_cap.map_or(0, |cell_cap| cap_cells(row, cell_cap));
        used = used.saturating_add(json_len(row)).saturating_add(1);
        if used > cap + 1 {
            keep = index;
            break;
        }
        replaced += row_replaced;
    }
    let dropped = keep < rows.len();
    rows.truncate(keep);
    (replaced, dropped)
}

/// Replace every cell of `row` whose JSON is longer than `cap` bytes with
/// the marker object; the count replaced.
fn cap_cells(row: &mut [Value], cap: NonZeroU32) -> usize {
    let cap = usize::try_from(cap.get()).unwrap_or(usize::MAX);
    let mut replaced = 0;
    for cell in row {
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
