//! The single chokepoint every tool dispatch flows through: refuses if the
//! state DB is missing (audit unavailable), runs the tool's `compute` future,
//! writes the audit row, returns the response. Audit-write failure aborts the
//! request — never let a response go out unaudited (CLAUDE.md non-negotiable).
//!
//! Extracted from the original `run_query` so each tool gets the same
//! guarantees without re-implementing the chokepoint.

use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Instant;

use metrics::{counter, histogram};
use serde_json::Value;
use sqlx::PgPool;

use crate::audit::{self, AuditRow};
use crate::auth::Identity;
use crate::exec::ExecError;
use crate::transport::jsonrpc::{ErrorObject, Response};
use crate::transport::protocol::{CallToolResult, TextContent};

/// Per-call counter — `tool` is the tool name, `outcome` is the spec 03 code
/// (`success`/`forbidden`/`timeout`/…). Both labels are bounded.
const METRIC_TOOL_CALLS: &str = "tool_calls";
/// Wall-clock the tool's own work took (from the `Outcome.elapsed_ms` the tool
/// reports). Excludes the audit write — that has its own histogram.
const METRIC_QUERY_DURATION: &str = "query_duration_seconds";
/// Wall-clock the synchronous audit insert took. Spec calls audit-write a
/// hot-path concern; this is the metric the alert in #22 will fire on.
const METRIC_AUDIT_WRITE_DURATION: &str = "audit_write_duration_seconds";

/// Result of a tool's compute step. Carries the response to send back AND
/// the audit fields the helper will persist.
pub struct Outcome {
    pub response: Response,
    /// `"success"` or a spec 03 error code (`forbidden`, `timeout`,
    /// `syntax_error`, `unavailable`, `reason_required`, `internal`,
    /// `forbidden_sql`).
    pub code: &'static str,
    pub elapsed_ms: Option<i64>,
    /// Rows returned to the agent (after any truncation). `None` for tools
    /// that don't return rows.
    pub row_count: Option<i64>,
    /// `Some(true)` if the row cap clipped the result; `None` for tools
    /// that don't have a row cap.
    pub truncated: Option<bool>,
    /// User-facing error message we surfaced; mirrored to the audit row.
    /// `None` on success. MUST be the typed string we sent, never a raw
    /// DB error.
    pub error_message: Option<String>,
}

/// Audit context known up-front from the tool's arguments — before any work
/// runs. `server`/`database` are `Some` for per-DB tools; `sql` is `Some` for
/// query tools (`run_query`, `sample_table`'s generated SQL).
pub struct AuditHeader<'a> {
    pub tool: &'static str,
    pub server: Option<&'a str>,
    pub database: Option<&'a str>,
    pub sql: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// Backend kind — `"postgres"` / `"mongo"` — derived from `server.kind`.
    /// `None` for tools that don't dispatch to a target DB (`list_servers`).
    /// Spec 12 line 241 / #58 acceptance.
    pub db_type: Option<&'a str>,
}

/// Per-request context the transport layer captures (IP, agent client).
/// Threaded through `dispatch_call` so every tool's audit row gets the same
/// view of the request, with no per-tool plumbing.
#[derive(Debug, Default, Clone)]
pub struct RequestContext {
    pub ip: Option<IpAddr>,
    pub agent_client: Option<String>,
}

impl RequestContext {
    /// Build from an axum `ConnectInfo<SocketAddr>` + an optional User-Agent
    /// header. Both are best-effort; missing values just stay `None`.
    pub fn from_request(addr: Option<SocketAddr>, user_agent: Option<&str>) -> Self {
        Self {
            ip: addr.map(|a| a.ip()),
            agent_client: user_agent.map(str::to_string),
        }
    }
}

/// Drop-fired guard that writes a `"cancelled"` audit row if the dispatch
/// future is dropped before `disarm()` is called. The detached
/// `tokio::spawn` lets the audit write outlive the cancellation.
///
/// Why this shape: when an agent disconnects, axum drops the handler
/// future, which drops the in-flight `audit_dispatch` future mid-`.await`.
/// Without a guard, the audit row is never written. We can't use async
/// `Drop` (doesn't exist in Rust today), so we spawn the write on the
/// runtime instead — the spawned task runs to completion independently
/// of the parent future's lifecycle.
///
/// Server-side query cancellation is handled separately, in the exec layer:
/// `PgAdapter` captures the backend PID and fires `pg_cancel_backend` from a
/// detached task on drop, because dropping a `sqlx::Transaction` only closes
/// the socket — it does NOT stop the query already running on the backend.
/// (Mongo relies on `maxTimeMS` plus cursor-drop.) This guard's only job is
/// the audit row.
struct CancelledAuditGuard {
    /// `Some` until `disarm()` is called. On `Drop` we spawn a detached
    /// write of this row with `outcome = "cancelled"`.
    row: Option<AuditRow>,
    /// Cloned pool handle — needed inside the spawned task. `PgPool` is
    /// `Arc`-internally so cloning is cheap.
    state_db: Option<PgPool>,
    /// Tool name kept separately for the metric counter emitted from the
    /// drop path (audit row's `tool` field is moved into the spawn).
    tool: &'static str,
}

impl CancelledAuditGuard {
    fn disarm(mut self) {
        self.row = None;
        self.state_db = None;
    }
}

impl Drop for CancelledAuditGuard {
    fn drop(&mut self) {
        let Some(mut row) = self.row.take() else {
            return;
        };
        let Some(pool) = self.state_db.take() else {
            return;
        };
        row.outcome = "cancelled".to_string();
        // Distinct error_message so operators can tell a cancelled row
        // from a forbidden one when scanning the table at speed.
        row.error_message = Some("client disconnected before completion".to_string());
        counter!(
            METRIC_TOOL_CALLS,
            "tool" => self.tool,
            "outcome" => "cancelled",
        )
        .increment(1);
        // Detached spawn. We can't await it; if it fails, there's no
        // surface to report the failure to — the agent already disconnected.
        // Operator sees the failure in tracing via audit::log's internal
        // error path.
        tokio::spawn(async move {
            if let Err(err) = audit::log(&pool, &row).await {
                tracing::error!(%err, "cancelled audit row write failed");
            }
        });
    }
}

pub async fn audit_dispatch<Fut>(
    id: Value,
    identity: &Identity,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    header: AuditHeader<'_>,
    work: Fut,
) -> Response
where
    Fut: Future<Output = Outcome>,
{
    let Some(state_db) = state_db else {
        counter!(
            METRIC_TOOL_CALLS,
            "tool" => header.tool,
            "outcome" => "unavailable",
        )
        .increment(1);
        // Contract (issue #14): exactly one dispatch line per call, even when
        // we refuse before running the tool. `duration_ms = 0` because no
        // tool work happened.
        tracing::info!(
            request_id = %id,
            user_sub = %identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            outcome = "unavailable",
            duration_ms = 0_i64,
            "tool dispatched"
        );
        return Response::error(
            id,
            ErrorObject::internal(format!(
                "audit log unavailable — refusing to dispatch {}",
                header.tool
            )),
        );
    };

    // Arm the cancellation guard BEFORE awaiting the work. If `work.await`
    // is dropped (agent disconnect), the guard's `Drop` impl fires and
    // spawns a detached `outcome = "cancelled"` audit write. CLAUDE.md
    // *§Cancellation safety*: "audit row outcome: cancelled."
    //
    // The guard carries a pre-built row so the spawned task doesn't need
    // to re-thread identity / context across the spawn boundary.
    let cancel_guard = CancelledAuditGuard {
        row: Some(AuditRow {
            request_id: id.to_string(),
            user_sub: identity.user_sub.clone(),
            user_email: identity.user_email.clone(),
            groups: identity.groups.clone(),
            tool: header.tool.to_string(),
            server: header.server.map(str::to_string),
            database: header.database.map(str::to_string),
            sql: header.sql.map(str::to_string),
            reason: header.reason.map(str::to_string),
            outcome: String::new(), // overwritten in Drop
            elapsed_ms: None,       // unknown — work was cancelled
            row_count: None,
            truncated: None,
            error_message: None, // set in Drop
            agent_client: request_ctx.agent_client.clone(),
            ip: request_ctx.ip.map(|i| i.to_string()),
            db_type: header.db_type.map(str::to_string),
        }),
        state_db: Some(state_db.clone()),
        tool: header.tool,
    };
    let outcome = work.await;
    // Work completed normally — release the guard so its Drop is a no-op.
    cancel_guard.disarm();

    counter!(
        METRIC_TOOL_CALLS,
        "tool" => header.tool,
        "outcome" => outcome.code,
    )
    .increment(1);
    if let Some(elapsed_ms) = outcome.elapsed_ms {
        histogram!(METRIC_QUERY_DURATION, "tool" => header.tool).record(elapsed_ms as f64 / 1000.0);
    }

    // Single per-dispatch log line carrying the documented field contract
    // (issue #14): request_id, user_sub, tool, server, db, outcome,
    // duration_ms. Lives at the chokepoint so every tool gets it without
    // per-tool code. `server` + `db` together fully scope the call per spec
    // 03; emitting only `db` makes correlation ambiguous across servers.
    tracing::info!(
        request_id = %id,
        user_sub = %identity.user_sub,
        tool = %header.tool,
        server = header.server.unwrap_or(""),
        db = header.database.unwrap_or(""),
        outcome = %outcome.code,
        duration_ms = outcome.elapsed_ms.unwrap_or(0),
        "tool dispatched"
    );

    let row = AuditRow {
        request_id: id.to_string(),
        user_sub: identity.user_sub.clone(),
        user_email: identity.user_email.clone(),
        groups: identity.groups.clone(),
        tool: header.tool.to_string(),
        server: header.server.map(str::to_string),
        database: header.database.map(str::to_string),
        sql: header.sql.map(str::to_string),
        reason: header.reason.map(str::to_string),
        outcome: outcome.code.to_string(),
        elapsed_ms: outcome.elapsed_ms,
        row_count: outcome.row_count,
        truncated: outcome.truncated,
        error_message: outcome.error_message,
        agent_client: request_ctx.agent_client.clone(),
        ip: request_ctx.ip.map(|i| i.to_string()),
        db_type: header.db_type.map(str::to_string),
    };
    let audit_started = Instant::now();
    let audit_result = audit::log(state_db, &row).await;
    histogram!(METRIC_AUDIT_WRITE_DURATION).record(audit_started.elapsed().as_secs_f64());
    if let Err(err) = audit_result {
        // Don't embed the underlying error string in the response (could leak
        // DB connection details on some sqlx error paths). Operator sees the
        // chained source via the tracing event.
        //
        // `duration_ms` keeps the same contract as the success log: wall-clock
        // the tool itself took. The audit-insert latency is a separate field
        // (`audit_write_duration_ms`) so consumers comparing dispatch lines
        // across success/failure don't see two different semantics.
        tracing::error!(
            %err,
            request_id = %id,
            user_sub = %identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            duration_ms = outcome.elapsed_ms.unwrap_or(0),
            audit_write_duration_ms = audit_started.elapsed().as_millis() as u64,
            "audit write failed; aborting tool response"
        );
        return Response::error(
            id,
            ErrorObject::internal("audit write failed; request rejected"),
        );
    }

    outcome.response
}

/// Build a structured tool error response per spec 03 §Errors. `request_id`
/// is duplicated inside the JSON body so agents that only read the tool
/// payload still get it.
pub fn tool_error(id: Value, code: &'static str, message: &str) -> Response {
    let body = serde_json::json!({
        "request_id": id.clone(),
        "code": code,
        "message": message,
    });
    Response::result(
        id,
        &CallToolResult {
            content: vec![TextContent::new(body.to_string())],
            is_error: true,
        },
    )
}

/// Build a successful tool result from a JSON-serialised payload string.
pub fn tool_success(id: Value, text: String) -> Response {
    Response::result(
        id,
        &CallToolResult {
            content: vec![TextContent::new(text)],
            is_error: false,
        },
    )
}

/// Shortcut for the common error-outcome shape: a typed tool_error response
/// plus the matching audit fields (the message is mirrored into
/// `error_message` so operators can read it from the audit row).
pub fn error_outcome(id: Value, code: &'static str, message: &str) -> Outcome {
    Outcome {
        response: tool_error(id, code, message),
        code,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: Some(message.to_string()),
    }
}

/// Per-tool wording for the user-facing strings inside
/// [`outcome_from_exec_error`]. Each tool defines a const of these so the
/// shared mapping can stay one function while error messages keep their
/// tool-specific shape. Spec 03 error *codes* are NOT configurable here —
/// they're fixed by the shared mapping below.
#[derive(Debug)]
pub struct ToolErrorMessages {
    /// Message for `ExecError::Timeout`. Per-tool because EXPLAIN says
    /// "EXPLAIN exceeded …" while `run_query` says "query exceeded …".
    pub timeout: &'static str,
    /// Message for `ExecError::Sql`. Per-tool because `describe_schema`
    /// surfaces "catalog query was rejected" while `run_query` says
    /// "the target DB rejected the SQL".
    pub sql_rejected: &'static str,
    /// Prefix for `ExecError::Forbidden(reason)`. The final message is
    /// `"<prefix> rejected by gateway: <reason>"`. Per-tool because the
    /// noun changes: "query" / "EXPLAIN" / "sample" / "catalog query".
    pub forbidden_prefix: &'static str,
}

/// Map an `ExecError` to the spec 03 outcome code + a user-facing message,
/// then build the matching `Outcome` with `elapsed_ms` filled from the
/// `started` wall clock so error paths still carry duration into the
/// audit row.
///
/// The four tool-specific call sites used to duplicate this match in 5
/// arms × 4 files = 20 arms total; adding `ExecError::NotImplemented` in
/// #57 made that pain visible. Per-tool wording rides in
/// [`ToolErrorMessages`] so the shared mapping stays one function.
pub fn outcome_from_exec_error(
    id: Value,
    err: ExecError,
    started: Instant,
    messages: &ToolErrorMessages,
) -> Outcome {
    let owned;
    let (code, message): (&str, &str) = match err {
        ExecError::Timeout => ("timeout", messages.timeout),
        ExecError::Connection | ExecError::Unavailable => {
            ("unavailable", "target database is unreachable")
        }
        ExecError::Sql => ("syntax_error", messages.sql_rejected),
        ExecError::Forbidden(reason) => {
            owned = format!(
                "{prefix} rejected by gateway: {reason}",
                prefix = messages.forbidden_prefix,
            );
            ("forbidden_sql", owned.as_str())
        }
        ExecError::PasswordUnresolved { .. }
        | ExecError::UnsupportedAdapter(_)
        | ExecError::NotImplemented { .. } => ("internal", "server-side configuration error"),
    };
    let mut outcome = error_outcome(id, code, message);
    outcome.elapsed_ms = Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX));
    outcome
}

/// Shortcut for the success shape with row/truncation metadata.
pub fn success_outcome(
    id: Value,
    text: String,
    elapsed_ms: Option<i64>,
    row_count: Option<i64>,
    truncated: Option<bool>,
) -> Outcome {
    Outcome {
        response: tool_success(id, text),
        code: "success",
        elapsed_ms,
        row_count,
        truncated,
        error_message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_payload_shape() {
        let response = tool_error(Value::from(7), "forbidden", "nope");
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["result"]["isError"], true);
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        let body: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["message"], "nope");
        assert_eq!(body["request_id"], 7);
    }

    #[test]
    fn tool_success_payload_shape() {
        let response = tool_success(Value::from(1), r#"{"hello":"world"}"#.to_string());
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["isError"], false);
        assert_eq!(
            value["result"]["content"][0]["text"],
            r#"{"hello":"world"}"#
        );
    }

    #[test]
    fn error_outcome_mirrors_message_into_audit() {
        let outcome = error_outcome(Value::from(1), "forbidden", "no grants");
        assert_eq!(outcome.code, "forbidden");
        assert_eq!(outcome.error_message.as_deref(), Some("no grants"));
        assert!(outcome.row_count.is_none());
    }

    /// Defense-in-depth backstop: an undispatchable `kind` is now rejected at
    /// boot (`config::yaml` validation), so a validated config never reaches
    /// `UnsupportedAdapter`. If an internal caller ever does, the tool must
    /// still map it to the stable `internal` code with a generic message —
    /// never the raw `ServerKind` debug, which could hint at backend topology.
    #[test]
    fn unsupported_adapter_maps_to_internal_without_leaking_kind() {
        use crate::config::ServerKind;

        let messages = ToolErrorMessages {
            timeout: "t",
            sql_rejected: "s",
            forbidden_prefix: "query",
        };
        let outcome = outcome_from_exec_error(
            Value::from(1),
            ExecError::UnsupportedAdapter(ServerKind::Mysql),
            Instant::now(),
            &messages,
        );
        assert_eq!(outcome.code, "internal");
        assert_eq!(
            outcome.error_message.as_deref(),
            Some("server-side configuration error")
        );
        // The backend identity must not ride along into the client-facing text.
        let msg = outcome.error_message.unwrap_or_default().to_lowercase();
        assert!(!msg.contains("mysql"), "{msg}");
    }

    #[test]
    fn success_outcome_carries_row_metadata() {
        let outcome = success_outcome(
            Value::from(1),
            "{}".to_string(),
            Some(42),
            Some(100),
            Some(true),
        );
        assert_eq!(outcome.code, "success");
        assert_eq!(outcome.elapsed_ms, Some(42));
        assert_eq!(outcome.row_count, Some(100));
        assert_eq!(outcome.truncated, Some(true));
        assert!(outcome.error_message.is_none());
    }
}
