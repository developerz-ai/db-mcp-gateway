//! Cancellation drop-guard test for `audit_dispatch` (#58 acceptance).
//!
//! Headline contract: when an agent disconnects mid-query, axum drops
//! the handler future, which drops the in-flight `audit_dispatch`
//! future. The drop-guard inside `audit_dispatch` writes a
//! `outcome = "cancelled"` audit row on a detached `tokio::spawn` so the
//! audit record survives even though the parent future died. CLAUDE.md
//! *§Cancellation safety*: "audit row outcome: cancelled."
//!
//! This test exercises the production code path:
//!   1. Build a real `state_db` pool.
//!   2. Call `audit_dispatch` with a `work` future that never resolves.
//!   3. Spawn on a tokio task, give it a moment to reach `.await`.
//!   4. Abort the task (drops the dispatch future).
//!   5. Wait briefly for the detached audit-write spawn to land.
//!   6. Assert the audit row exists with `outcome = "cancelled"`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use db_mcp_gateway::audit;
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::config::StreamSinkConfig;
use db_mcp_gateway::state;
use db_mcp_gateway::tools::audit_dispatch::{AuditHeader, RequestContext, audit_dispatch};
use serde_json::Value;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

#[derive(Clone, Default)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for BufWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn pool() -> sqlx::PgPool {
    state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "cancel-test@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
    }
}

/// The headline #58 acceptance test for cancellation. A dispatch future
/// that never reaches `outcome` MUST still land a `cancelled` audit row.
#[tokio::test]
async fn dropped_dispatch_leaves_cancelled_audit_row() {
    let p = pool().await;
    let user = format!("cancel-test-{}", Uuid::new_v4().simple());
    let id = Value::from(Uuid::new_v4().to_string());
    let ctx = RequestContext::default();

    // The hanging work future: `pending` never resolves, so the
    // dispatch's `work.await` is the cancellation point.
    let pool_for_dispatch = p.clone();
    let id_in = id.clone();
    let user_in = user.clone();
    let task = tokio::spawn(async move {
        let identity = identity(&user_in);
        let header = AuditHeader {
            tool: "run_query",
            server: Some("mongo"),
            database: Some("app"),
            sql: Some(r#"{"find":"users","filter":{}}"#),
            reason: None,
            db_type: Some("mongo"),
        };
        let _ = audit_dispatch(
            id_in,
            &identity,
            Some(&pool_for_dispatch),
            &ctx,
            header,
            &[],
            std::future::pending::<db_mcp_gateway::tools::audit_dispatch::Outcome>(),
        )
        .await;
    });

    // Let the dispatch reach the `work.await`. 50ms is plenty: the path
    // before the await is pure local work (build the guard, no I/O).
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    // Wait for the abort to propagate AND for the drop-spawned audit
    // write to complete. Two reasons we sleep more than the path
    // demands: tokio's `abort` is async, and `audit::log` does a real
    // INSERT round-trip on the state DB.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The cancelled row should be visible. `latest_for_user_tool` filters
    // by (user_sub, tool) — we used a per-test user so no other row
    // collides.
    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs");
    let row = row.expect("cancelled audit row was written");
    assert_eq!(row.outcome, "cancelled");
    assert_eq!(row.user_sub, user);
    assert_eq!(row.tool, "run_query");
    assert_eq!(row.server.as_deref(), Some("mongo"));
    assert_eq!(row.database.as_deref(), Some("app"));
    assert_eq!(row.db_type.as_deref(), Some("mongo"));
    assert_eq!(
        row.error_message.as_deref(),
        Some("client disconnected before completion")
    );

    // Cleanup so reruns don't pile up cancellation rows for this user.
    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&p)
        .await
        .unwrap();
}

/// Cancellation with a configured `stdout` sink: the detached fallback
/// runs `audit::log` first and then `audit::stream::send`, so the streamed
/// event must be emitted after the durable cancelled row lands. Regression
/// guard for spec 07 — a cancellation must not silently skip SIEM export
/// when the operator has wired stdout streaming.
#[tokio::test]
async fn dropped_dispatch_streams_cancelled_row_when_stdout_configured() {
    let p = pool().await;
    let user = format!("cancel-test-stream-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let id = Value::from(Uuid::new_v4().to_string());
    let ctx = RequestContext {
        request_id,
        ..RequestContext::default()
    };

    let buf = BufWriter::default();
    // Global subscriber so the detached `tokio::spawn` fired from the
    // guard's Drop lands under the same capture — `set_default`'s
    // thread-local guard doesn't cover tasks spawned onto other worker
    // threads, and the multi-thread runtime is where axum actually runs.
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let pool_for_dispatch = p.clone();
    let id_in = id.clone();
    let user_in = user.clone();
    let task = tokio::spawn(async move {
        let identity = identity(&user_in);
        let header = AuditHeader {
            tool: "run_query",
            server: Some("prod"),
            database: Some("app"),
            sql: Some("SELECT 1"),
            reason: None,
            db_type: Some("postgres"),
        };
        let _ = audit_dispatch(
            id_in,
            &identity,
            Some(&pool_for_dispatch),
            &ctx,
            header,
            &[StreamSinkConfig::Stdout],
            std::future::pending::<db_mcp_gateway::tools::audit_dispatch::Outcome>(),
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    // Wait for the abort to propagate AND for the drop-spawned audit
    // write + stream to complete.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("cancelled audit row was written");
    assert_eq!(row.outcome, "cancelled");
    assert_eq!(row.request_id, request_id.to_string());

    let raw = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let event = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| {
            v["target"].as_str() == Some("audit_stream")
                && v["request_id"].as_str() == Some(&*request_id.to_string())
        })
        .unwrap_or_else(|| panic!("no audit_stream event for cancelled row in:\n{raw}"));
    assert_eq!(event["outcome"].as_str(), Some("cancelled"));
    assert_eq!(event["user_sub"].as_str(), Some(&*user));

    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&p)
        .await
        .unwrap();
}

/// Counter-test: a dispatch that *does* complete writes the normal
/// outcome — the guard must NOT fire when `disarm()` runs. Pins that
/// `disarm` actually disarms (regression would be: cancelled row written
/// every successful dispatch).
#[tokio::test]
async fn completed_dispatch_does_not_leave_cancelled_row() {
    use db_mcp_gateway::tools::audit_dispatch::Outcome;
    use db_mcp_gateway::transport::jsonrpc::Response;

    let p = pool().await;
    let user = format!("cancel-test-{}", Uuid::new_v4().simple());
    let id = Value::from(Uuid::new_v4().to_string());
    let ctx = RequestContext::default();

    let identity = identity(&user);
    let header = AuditHeader {
        tool: "run_query",
        server: Some("prod"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    };
    let id_for_outcome = id.clone();
    let work = async move {
        Outcome {
            response: Response::result(id_for_outcome, &serde_json::json!({"ok":true})),
            code: "success",
            elapsed_ms: Some(7),
            row_count: Some(1),
            truncated: Some(false),
            error_message: None,
        }
    };
    let _ = audit_dispatch(id, &identity, Some(&p), &ctx, header, &[], work).await;
    // Give the detached write (audit::log) time to land.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("audit row was written");
    assert_eq!(
        row.outcome, "success",
        "completed dispatch must NOT mark cancelled"
    );

    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&p)
        .await
        .unwrap();
}

/// Regression for the #136 audit finding "audit request_id is the raw
/// client-controlled JSON-RPC id": `audit_calls.request_id` must be a
/// gateway-minted UUID, not derived from the caller's `id` — which is
/// arbitrary JSON (a string with embedded quotes here, exercising the
/// exact shape that used to leak `"` characters straight into the column
/// via `id.to_string()`).
#[tokio::test]
async fn audit_row_request_id_is_gateway_uuid_not_client_id() {
    use db_mcp_gateway::tools::audit_dispatch::Outcome;
    use db_mcp_gateway::transport::jsonrpc::Response;

    let p = pool().await;
    let user = format!("cancel-test-{}", Uuid::new_v4().simple());
    // Deliberately hostile client id: embedded quotes, the exact shape that
    // used to end up verbatim (with escaping) in `audit_calls.request_id`
    // under `id.to_string()`.
    let id = Value::from(r#"weird"client"id"#);
    // `from_request` mints a real UUID, same as the production transport
    // layer — `default()` (nil UUID) is used elsewhere in this file where
    // the value doesn't matter; here it's the whole point.
    let ctx = RequestContext::from_request(None, None);
    let expected_request_id = ctx.request_id.to_string();

    let identity = identity(&user);
    let header = AuditHeader {
        tool: "run_query",
        server: Some("prod"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    };
    let id_for_outcome = id.clone();
    let work = async move {
        Outcome {
            response: Response::result(id_for_outcome, &serde_json::json!({"ok":true})),
            code: "success",
            elapsed_ms: Some(1),
            row_count: Some(1),
            truncated: Some(false),
            error_message: None,
        }
    };
    let _ = audit_dispatch(id.clone(), &identity, Some(&p), &ctx, header, &[], work).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let row = audit::latest_for_user_tool(&p, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("audit row was written");

    assert_eq!(
        row.request_id, expected_request_id,
        "audit row must carry the gateway-minted request_id from RequestContext"
    );
    assert!(
        Uuid::parse_str(&row.request_id).is_ok(),
        "request_id must be a well-formed UUID, got {:?}",
        row.request_id
    );
    assert!(
        !row.request_id.contains('"'),
        "request_id must never carry the raw client id's quoting, got {:?}",
        row.request_id
    );
    assert_ne!(
        row.request_id,
        id.to_string(),
        "request_id must NOT be derived from the client's JSON-RPC id"
    );

    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&p)
        .await
        .unwrap();
}
