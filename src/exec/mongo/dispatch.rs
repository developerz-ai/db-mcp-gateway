//! Command dispatch: run one rejector-accepted command under the gateway's
//! `maxTimeMS` budget and the kill-on-drop guard, collecting results up to
//! the row and byte budget.

use std::time::{Duration, Instant};

use mongodb::bson::{Bson, Document, RawDocument, doc};
use serde_json::Value;

use super::super::adapter::{
    ExecError, ExecResult, MAX_RESULT_BYTES, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms,
};
use super::super::budget::ResultBudget;
use super::super::query::ExecQuery;
use super::bson_json::bson_to_json;
use super::cancel::{self, Reservation};
use super::{CONNECT_TIMEOUT, MongoAdapter, rejector};

/// What one document of a cursor becomes in the result.
pub(super) type Render = fn(&RawDocument) -> Result<Value, ExecError>;

impl MongoAdapter {
    /// `DbAdapter::execute` (see its doc for the guards), each cursor
    /// document turned into its cell by `render`.
    pub(super) async fn run(
        &self,
        query: &ExecQuery<'_>,
        render: Render,
    ) -> Result<ExecResult, ExecError> {
        rejector::validate_command(query.sql)
            .map_err(|err| ExecError::Forbidden(err.to_string()))?;

        // The caller's share of the pool, then a connection of it, both
        // taken outside the time budget as the pg adapter's acquire is.
        let slot = self.callers.take(CONNECT_TIMEOUT).await?;
        let reservation = Reservation {
            _connection: self.reserve_connection().await?,
            _slot: slot,
        };
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        let dispatch = self.dispatch(query, effective_ms, render, reservation);
        match tokio::time::timeout(budget, dispatch).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    /// Parse, stamp the DB-side budget, and run one already-accepted command.
    /// `reservation` is held until the command is done, its cancel included.
    /// Split out of [`Self::run`] so the `tokio::time::timeout` there covers the cursor drain as well as the initial dispatch.
    async fn dispatch(
        &self,
        query: &ExecQuery<'_>,
        effective_ms: u32,
        render: Render,
        reservation: Reservation,
    ) -> Result<ExecResult, ExecError> {
        let mut cmd: Document = serde_json::from_str(query.sql).map_err(|_| ExecError::Sql)?;
        let command_name = first_command_name(&cmd).ok_or(ExecError::Sql)?;

        // Unconditional: `insert` overwrites, so a caller-supplied
        // `maxTimeMS` in the raw command can only ever be replaced by the
        // gateway's clamped value — it can't be used to buy more budget.
        cmd.insert("maxTimeMS", i64::from(effective_ms));
        cap_server_side(&mut cmd, &command_name, query.row_limit);
        // Marker for the cancel guard's `currentOp` lookup — see
        // `cancel::stamp_marker` and `DbAdapter::execute`'s doc comment.
        let marker = cancel::stamp_marker(&mut cmd);
        let mut kill_guard = cancel::KillOpOnDrop::armed(
            self.client.clone(),
            marker,
            self.detached.clone(),
            reservation,
        );

        let started = Instant::now();
        // Wrapped in a block so `?` inside it is captured into `result`
        // rather than skipping `kill_guard.disarm()` below — same posture as
        // `pg::run_query`'s `CancelOnDrop`.
        let result = async {
            let (column, collected) = match command_name.as_str() {
                "find" | "aggregate" | "listCollections" | "listIndexes" => {
                    ("document", self.drain_cursor(cmd, query, render).await?)
                }
                "count" => ("count", self.count(cmd, query).await?),
                "distinct" => ("value", self.distinct(cmd, query).await?),
                // Rejector already filters to the commands above.
                // This arm exists for type-system completeness — if the
                // rejector's allow-list and dispatch table drift, fail loudly.
                other => {
                    return Err(ExecError::Forbidden(format!(
                        "command `{other}` is rejector-allowed but not dispatch-wired"
                    )));
                }
            };
            Ok(ExecResult {
                columns: vec![column.to_string()],
                column_types: Vec::new(),
                rows: collected.rows,
                truncated: collected.truncated,
                elapsed_ms: started.elapsed().as_millis() as u64,
                rows_affected: None,
            })
        }
        .await;
        // Command finished (success or typed error) — no orphaned operation
        // to kill. Guard stays armed ONLY if this future is dropped while
        // awaiting above (agent disconnect / outer `tokio::time::timeout`).
        kill_guard.disarm();
        result
    }

    /// Cursor-returning commands: the initial response *and* follow-up
    /// `getMore` calls, until the budget runs out.
    async fn drain_cursor(
        &self,
        cmd: Document,
        query: &ExecQuery<'_>,
        render: Render,
    ) -> Result<Rows, ExecError> {
        let db = self.client.database(&self.database_name);
        let mut cursor = db
            .run_cursor_command(cmd)
            .await
            .map_err(|e| self.classify(e, query.sql))?;
        let mut budget = ResultBudget::new(query.row_limit);
        // The documents are held to the byte cap too: a rendered row may
        // weigh far less than the document it was read from.
        let mut wire_left = MAX_RESULT_BYTES;
        let mut rows = Vec::new();
        while cursor
            .advance()
            .await
            .map_err(|e| self.classify(e, query.sql))?
        {
            let document = cursor.current();
            let cut = match wire_left.checked_sub(document.as_bytes().len()) {
                Some(left) if budget.has_row_left() => {
                    wire_left = left;
                    let row = vec![render(document)?];
                    let admitted = budget.admit(&row);
                    if admitted {
                        rows.push(row);
                    }
                    !admitted
                }
                _ => true,
            };
            if cut {
                return Ok(Rows {
                    rows,
                    truncated: true,
                });
            }
        }
        Ok(Rows {
            rows,
            truncated: false,
        })
    }

    /// `count` answers in one field, `n`. A reply without it is a decode
    /// error, never a `null` count.
    async fn count(&self, cmd: Document, query: &ExecQuery<'_>) -> Result<Rows, ExecError> {
        let db = self.client.database(&self.database_name);
        let response = db
            .run_command(cmd)
            .await
            .map_err(|e| self.classify(e, query.sql))?;
        let n = response
            .get_i64("n")
            .or_else(|_| response.get_i32("n").map(i64::from))
            .map_err(|_| ExecError::Decode)?;
        // The result shape is fixed at one row, so the row cap (which may be
        // 0 for an internal caller) has to be applied explicitly.
        let mut budget = ResultBudget::new(query.row_limit);
        let row = vec![Value::from(n)];
        Ok(if budget.admit(&row) {
            Rows {
                rows: vec![row],
                truncated: false,
            }
        } else {
            Rows {
                rows: Vec::new(),
                truncated: true,
            }
        })
    }

    /// `distinct` answers with every value in one array; the budget applies
    /// to it value by value.
    async fn distinct(&self, cmd: Document, query: &ExecQuery<'_>) -> Result<Rows, ExecError> {
        let db = self.client.database(&self.database_name);
        let mut response = db
            .run_command(cmd)
            .await
            .map_err(|e| self.classify(e, query.sql))?;
        let Some(Bson::Array(values)) = response.remove("values") else {
            return Err(ExecError::Decode);
        };
        let mut budget = ResultBudget::new(query.row_limit);
        let mut rows = Vec::new();
        for value in values {
            let row = vec![bson_to_json(value)?];
            if !budget.admit(&row) {
                return Ok(Rows {
                    rows,
                    truncated: true,
                });
            }
            rows.push(row);
        }
        Ok(Rows {
            rows,
            truncated: false,
        })
    }
}

/// Collected rows and whether the budget cut them short.
struct Rows {
    rows: Vec<Vec<Value>>,
    truncated: bool,
}

/// Push the row cap to the server so it stops producing what the gateway
/// would discard: `row_limit + 1` documents (one past the cap, so
/// `truncated` can still be detected). A caller's own smaller `find` limit
/// is kept. `count` and `distinct` answer in one reply and need nothing.
///
/// An aggregation's batch is one larger than its `$limit`: a batch the limit
/// fills exactly leaves the cursor open on the server, for the driver to
/// close with a `killCursors` that no permit reserves a connection for.
fn cap_server_side(cmd: &mut Document, command: &str, row_limit: u32) {
    let cap = i64::from(row_limit) + 1;
    match command {
        "find" => {
            let limit = match cmd.get("limit") {
                Some(Bson::Int32(n)) if *n > 0 => i64::from(*n).min(cap),
                Some(Bson::Int64(n)) if *n > 0 => (*n).min(cap),
                _ => cap,
            };
            cmd.insert("limit", limit);
            cmd.insert("batchSize", limit);
        }
        "aggregate" => {
            if let Ok(pipeline) = cmd.get_array_mut("pipeline") {
                pipeline.push(Bson::Document(doc! { "$limit": cap }));
            }
            cmd.insert("cursor", doc! { "batchSize": cap + 1 });
        }
        _ => {}
    }
}

/// Pluck the wire-order first key (the command name) out of an already-
/// parsed `Document`. Mongo's wire convention is "first key is the
/// command name" — bson 3's `Document` preserves insertion order so
/// `keys().next()` returns it.
fn first_command_name(doc: &Document) -> Option<String> {
    doc.keys().next().map(|k| k.to_string())
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
