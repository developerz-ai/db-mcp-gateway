//! Command dispatch: run one rejector-accepted command under the gateway's
//! `maxTimeMS` budget and the kill-on-drop guard, draining cursors up to the
//! row cap.

use std::time::Instant;

use futures::StreamExt;
use mongodb::bson::{Bson, Document};
use mongodb::error::{Error as MongoError, ErrorKind};
use serde_json::Value;

use super::super::adapter::{ExecError, ExecQuery, ExecResult};
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
        // Marker for the cancel guard's `currentOp` lookup — see
        // `cancel::stamp_marker` and this method's own doc comment above.
        let marker = cancel::stamp_marker(&mut cmd);
        let mut kill_guard = cancel::KillOpOnDrop::armed(self.client.clone(), marker);

        let started = Instant::now();
        let db = self.client.database(&self.database_name);

        // Wrapped in a block so `?` inside each arm exits the block (captured
        // into `result`) rather than this function — an early function return
        // would skip `kill_guard.disarm()` below. Harmless either way (the
        // guard is best-effort: a currentOp lookup against an already-errored
        // operation just finds nothing), but disarming on every normal
        // completion — success or typed error — is the correct target, same
        // posture as `pg::run_query_inner`'s `CancelOnDrop`.
        let result: Result<ExecResult, ExecError> = async {
            match command_name.as_str() {
                // Cursor-returning commands. `run_cursor_command` handles the
                // initial response *and* follow-up `getMore` calls so we can
                // drain past the first batch when the user asks for more rows.
                "find" | "aggregate" => {
                    let mut cursor = db.run_cursor_command(cmd).await.map_err(classify)?;
                    let limit = query.row_limit as usize;
                    let mut rows: Vec<Vec<Value>> = Vec::new();
                    let mut truncated = false;
                    while let Some(doc_result) = cursor.next().await {
                        if rows.len() >= limit {
                            truncated = true;
                            break;
                        }
                        let doc = doc_result.map_err(classify)?;
                        rows.push(vec![doc_to_json(doc)]);
                    }
                    Ok(ExecResult {
                        columns: vec!["document".to_string()],
                        rows,
                        truncated,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }
                // Scalar commands. The response shape carries the answer in
                // a single field that's documented per command name.
                "count" => {
                    let response = db.run_command(cmd).await.map_err(classify)?;
                    let n = response
                        .get_i64("n")
                        .or_else(|_| response.get_i32("n").map(i64::from));
                    // `row_limit == 0` is a valid grant constraint (authz
                    // proptests generate it) and the exec invariant is
                    // "never emit more rows than configured" — the cursor
                    // arms above honor it implicitly via `rows.len() >= limit`
                    // / `.take(limit)`; the scalar arm has to do it explicitly
                    // because its result shape is fixed at one row.
                    let (rows, truncated) = if query.row_limit == 0 {
                        (Vec::new(), true)
                    } else {
                        let value = match n {
                            Ok(v) => Value::from(v),
                            Err(_) => Value::Null,
                        };
                        (vec![vec![value]], false)
                    };
                    Ok(ExecResult {
                        columns: vec!["count".to_string()],
                        rows,
                        truncated,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }
                "distinct" => {
                    let response = db.run_command(cmd).await.map_err(classify)?;
                    let values: Vec<Bson> =
                        response.get_array("values").cloned().unwrap_or_default();
                    let limit = query.row_limit as usize;
                    let truncated = values.len() > limit;
                    let rows: Vec<Vec<Value>> = values
                        .into_iter()
                        .take(limit)
                        .map(|b| vec![bson_to_json(b)])
                        .collect();
                    Ok(ExecResult {
                        columns: vec!["value".to_string()],
                        rows,
                        truncated,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }
                // Rejector already filters to find/aggregate/count/distinct.
                // This arm exists for type-system completeness — if the
                // rejector's allow-list and dispatch table drift, fail loudly.
                other => Err(ExecError::Forbidden(format!(
                    "command `{other}` is rejector-allowed but not dispatch-wired"
                ))),
            }
        }
        .await;
        // Command finished (success or typed error) — no orphaned operation
        // to kill. Guard stays armed ONLY if this future is dropped while
        // awaiting above (agent disconnect / outer `tokio::time::timeout`).
        kill_guard.disarm();
        result
    }
}

/// Pluck the wire-order first key (the command name) out of an already-
/// parsed `Document`. Mongo's wire convention is "first key is the
/// command name" — bson 3's `Document` preserves insertion order so
/// `keys().next()` returns it.
fn first_command_name(doc: &Document) -> Option<String> {
    doc.keys().next().map(|k| k.to_string())
}

/// Map a `mongodb::error::Error` to our typed `ExecError`. The mapping
/// preserves the same semantics as `pg::classify`:
///
/// - `maxTimeMS` exhaustion → `Timeout`. Mongo's wire-protocol code is
///   `50` (`MaxTimeMSExpired`), surfaced via `ErrorKind::Command`.
/// - Connection / IO failures → `Unavailable`.
/// - Anything else (including a `Command` error for malformed BSON or a
///   non-existent collection) → `Sql`.
///
/// `Display` MUST NOT carry credentials. The driver's error renderings
/// don't include the connection URI in practice, but we map to typed
/// variants whose `Display` we control just in case.
fn classify(err: MongoError) -> ExecError {
    match err.kind.as_ref() {
        ErrorKind::Command(cmd_err) if cmd_err.code == 50 => ExecError::Timeout,
        ErrorKind::Io(_)
        | ErrorKind::ConnectionPoolCleared { .. }
        | ErrorKind::DnsResolve { .. }
        | ErrorKind::ServerSelection { .. } => ExecError::Unavailable,
        _ => ExecError::Sql,
    }
}
