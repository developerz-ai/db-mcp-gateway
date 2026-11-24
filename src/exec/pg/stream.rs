//! Row collection for one statement: stream it, weigh each row before and
//! after decoding, and stop collecting when the result budget runs out.

use futures::StreamExt;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{Column, Either, Executor, Postgres, Row, Transaction};
use tokio::sync::Semaphore;

use super::super::adapter::ExecError;
use super::super::budget::ResultBudget;
use super::super::query::ExecQuery;
use super::super::sql_guard::Access;
use super::decode::{RowWeight, decode_row, decoders};
use super::error::classify;

/// A row at least this big on the wire decodes under the adapter's
/// large-row gate. Decoding copies the row, and an array can decode to
/// several times its wire size before the byte cap sees it.
const LARGE_ROW_BYTES: usize = 1024 * 1024;

/// How many large rows one adapter decodes at a time.
pub(super) const LARGE_ROW_DECODES: usize = 2;

/// Rows collected so far plus what the stream said about the statement.
pub(super) struct Collected {
    pub(super) columns: Vec<String>,
    pub(super) rows: Vec<Vec<Value>>,
    pub(super) truncated: bool,
    pub(super) rows_affected: u64,
}

/// Stream the statement, collecting rows until the budget runs out. A read
/// stops there (the caller cancels the rest); a write keeps draining so the
/// statement runs to completion and its `rows_affected` is exact.
pub(super) async fn stream_rows(
    tx: &mut Transaction<'_, Postgres>,
    query: &ExecQuery<'_>,
    role: &str,
    large_rows: &Semaphore,
) -> Result<Collected, ExecError> {
    let mut budget = ResultBudget::new(query.row_limit);
    let mut collected = Collected {
        columns: Vec::new(),
        rows: Vec::new(),
        truncated: false,
        rows_affected: 0,
    };
    let mut decoders_for_rows = Vec::new();

    // Unnamed statement: ad-hoc SQL must not accumulate in the connection's
    // prepared-statement cache. Running the caller's SQL is this path's job:
    // the guard, the grant and the role's privileges bound it, not sqlx.
    let mut sqlx_query = sqlx::query(sqlx::AssertSqlSafe(query.sql)).persistent(false);
    for bind in query.binds {
        sqlx_query = sqlx_query.bind(*bind);
    }
    // `Executor::fetch_many` (not the deprecated `Query::fetch_many`) is the
    // one stream that yields the statement's completion — and with it
    // `rows_affected` — alongside its rows.
    let mut stream = (&mut **tx).fetch_many(sqlx_query);
    while let Some(item) = stream.next().await {
        let row = match item.map_err(|e| classify(e, role, query.sql))? {
            Either::Left(done) => {
                collected.rows_affected += done.rows_affected();
                continue;
            }
            Either::Right(row) => row,
        };
        if collected.truncated {
            continue; // draining a write
        }
        if collected.columns.is_empty() {
            collected.columns = row.columns().iter().map(|c| c.name().to_string()).collect();
            decoders_for_rows = decoders(&row);
        }
        // Cheapest check first, and nothing is decoded that cannot be kept:
        // not the row past the row cap, not a row whose wire form alone is
        // past the byte cap. Only then is the decoded row weighed.
        let wire_len = wire_len(&row);
        let admitted = budget.has_row_left() && budget.fits_wire(wire_len) && {
            let _gate = if wire_len >= LARGE_ROW_BYTES {
                // The gate is never closed; were it, refuse rather than
                // decode ungated.
                Some(
                    large_rows
                        .acquire()
                        .await
                        .map_err(|_| ExecError::Unavailable)?,
                )
            } else {
                None
            };
            // A JSON cell is weighed while it is parsed; every other type is
            // bounded by its wire size and weighed once decoded.
            match decode_row(&row, &decoders_for_rows, RowWeight::new(&budget)) {
                Ok(decoded) if budget.admit(&decoded) => {
                    collected.rows.push(decoded);
                    true
                }
                _ => false,
            }
        };
        if !admitted {
            collected.truncated = true;
            if query.access == Access::ReadOnly {
                break;
            }
        }
    }
    Ok(collected)
}

/// Bytes the row's cells occupy in the driver's buffer; SQL NULL has none.
fn wire_len(row: &PgRow) -> usize {
    (0..row.len())
        .filter_map(|idx| row.try_get_raw(idx).ok())
        .filter_map(|raw| raw.as_bytes().ok().map(<[u8]>::len))
        .sum()
}
