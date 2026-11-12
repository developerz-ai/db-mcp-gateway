//! Command dispatch: run one rejector-accepted command under the gateway's
//! `maxTimeMS` budget and the kill-on-drop guard, collecting results up to
//! the row and byte budget.

use std::sync::atomic::Ordering;
use std::time::Instant;

use futures::StreamExt;
use mongodb::bson::{Bson, Document, doc};
use mongodb::error::{Error as MongoError, ErrorKind};
use serde_json::Value;

use super::super::adapter::{ExecError, ExecResult};
use super::super::budget::ResultBudget;
use super::super::query::ExecQuery;
use super::MongoAdapter;
use super::bson_json::{bson_to_json, doc_to_json};
use super::cancel;

impl MongoAdapter {
    /// Parse, stamp the DB-side budget, and run one already-accepted command.
    /// Split out of `DbAdapter::execute` so the `tokio::time::timeout`
    /// there covers the cursor drain as well as the initial dispatch.
    pub(super) async fn dispatch(
        &self,
        query: &ExecQuery<'_>,
        effective_ms: u32,
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
        let mut kill_guard =
            cancel::KillOpOnDrop::armed(self.client.clone(), marker, self.detached.clone());

        let started = Instant::now();
        // Wrapped in a block so `?` inside it is captured into `result`
        // rather than skipping `kill_guard.disarm()` below — same posture as
        // `pg::run_query_inner`'s `CancelOnDrop`.
        let result = async {
            let (column, collected) = match command_name.as_str() {
                "find" | "aggregate" | "listCollections" | "listIndexes" => {
                    ("document", self.drain_cursor(cmd, query.row_limit).await?)
                }
                "count" => ("count", self.count(cmd, query.row_limit).await?),
                "distinct" => ("value", self.distinct(cmd, query.row_limit).await?),
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
    async fn drain_cursor(&self, cmd: Document, row_limit: u32) -> Result<Rows, ExecError> {
        let db = self.client.database(&self.database_name);
        let mut cursor = db
            .run_cursor_command(cmd)
            .await
            .map_err(|e| self.classify(e))?;
        let mut budget = ResultBudget::new(row_limit);
        let mut rows = Vec::new();
        while let Some(doc_result) = cursor.next().await {
            let doc = doc_result.map_err(|e| self.classify(e))?;
            let row = vec![doc_to_json(doc)?];
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

    /// `count` answers in one field, `n`. A reply without it is a decode
    /// error, never a `null` count.
    async fn count(&self, cmd: Document, row_limit: u32) -> Result<Rows, ExecError> {
        let db = self.client.database(&self.database_name);
        let response = db.run_command(cmd).await.map_err(|e| self.classify(e))?;
        let n = response
            .get_i64("n")
            .or_else(|_| response.get_i32("n").map(i64::from))
            .map_err(|_| ExecError::Decode)?;
        // The result shape is fixed at one row, so the row cap (which may be
        // 0 for an internal caller) has to be applied explicitly.
        let mut budget = ResultBudget::new(row_limit);
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
    async fn distinct(&self, cmd: Document, row_limit: u32) -> Result<Rows, ExecError> {
        let db = self.client.database(&self.database_name);
        let mut response = db.run_command(cmd).await.map_err(|e| self.classify(e))?;
        let Some(Bson::Array(values)) = response.remove("values") else {
            return Err(ExecError::Decode);
        };
        let mut budget = ResultBudget::new(row_limit);
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

    /// Map a driver error to [`ExecError`], same semantics as the pg side:
    ///
    /// - `maxTimeMS` exhaustion (code 50, `MaxTimeMSExpired`) → `Timeout`.
    /// - Rejected credentials → `Connection`, and the adapter goes stale so
    ///   the registry re-opens it with a freshly resolved password.
    /// - Connection / IO / selection failures → `Unavailable`.
    /// - Anything else (a malformed command, a missing collection) → `Sql`.
    ///
    /// Never renders the driver error: only its kind is logged.
    fn classify(&self, err: MongoError) -> ExecError {
        let (kind, mapped) = match err.kind.as_ref() {
            ErrorKind::Command(cmd_err) if cmd_err.code == 50 => ("command", ExecError::Timeout),
            ErrorKind::Authentication { .. } => {
                self.stale.store(true, Ordering::Relaxed);
                ("authentication", ExecError::Connection)
            }
            ErrorKind::Io(_) => ("io", ExecError::Unavailable),
            ErrorKind::ConnectionPoolCleared { .. } => ("pool_cleared", ExecError::Unavailable),
            ErrorKind::DnsResolve { .. } => ("dns", ExecError::Unavailable),
            ErrorKind::ServerSelection { .. } => ("server_selection", ExecError::Unavailable),
            ErrorKind::Command(_) => ("command", ExecError::Sql),
            _ => ("other", ExecError::Sql),
        };
        let code = match err.kind.as_ref() {
            ErrorKind::Command(cmd_err) => cmd_err.code,
            _ => 0,
        };
        tracing::warn!(error_kind = kind, code, "target command failed");
        mapped
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
            cmd.insert("cursor", doc! { "batchSize": cap });
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
mod tests {
    use super::*;

    #[test]
    fn find_limit_is_capped_but_a_smaller_one_kept() {
        let mut cmd = doc! { "find": "c", "limit": 1000 };
        cap_server_side(&mut cmd, "find", 10);
        assert_eq!(cmd.get_i64("limit").ok(), Some(11));
        assert_eq!(cmd.get_i64("batchSize").ok(), Some(11));

        let mut cmd = doc! { "find": "c", "limit": 3 };
        cap_server_side(&mut cmd, "find", 10);
        assert_eq!(cmd.get_i64("limit").ok(), Some(3));

        // `limit: 0` means "no limit" to mongo — never pass it through.
        let mut cmd = doc! { "find": "c", "limit": 0 };
        cap_server_side(&mut cmd, "find", 0);
        assert_eq!(cmd.get_i64("limit").ok(), Some(1));
    }

    #[test]
    fn aggregate_gets_a_trailing_limit_stage() {
        let mut cmd = doc! { "aggregate": "c", "pipeline": [ { "$match": {} } ], "cursor": {} };
        cap_server_side(&mut cmd, "aggregate", 4);
        let pipeline = cmd.get_array("pipeline").expect("pipeline");
        assert_eq!(
            pipeline.last(),
            Some(&Bson::Document(doc! { "$limit": 5_i64 }))
        );
        assert_eq!(
            cmd.get_document("cursor")
                .expect("cursor")
                .get_i64("batchSize")
                .ok(),
            Some(5)
        );
    }
}
