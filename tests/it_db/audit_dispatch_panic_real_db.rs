//! A tool whose work panics still completes its audit row: `audit_dispatch`
//! records `internal` (not `cancelled`) and answers the stable `internal`
//! tool error, so a defect in one tool never leaves a call unaccounted for
//! or kills the caller's connection. A panic in work whose intent recorded
//! write access keeps the may-have-committed flag a dropped call would get.

use crate::common::audit::{DispatchSinks, latest_audit};
use crate::common::env::state_pool;
use db_mcp_gateway::audit::intent::{CallIntent, WRITE_MAY_HAVE_COMMITTED};
use db_mcp_gateway::audit::{self, OutcomeCode};
use db_mcp_gateway::auth::{Identity, IdentityKind, SessionId};
use db_mcp_gateway::exec::Access;
use db_mcp_gateway::tools::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, Upstream, audit_dispatch,
};
use serde_json::Value;
use uuid::Uuid;

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "panic-test@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
        kind: IdentityKind::Sso,
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn panicking_work_is_audited_as_internal() {
    let pool = state_pool().await;
    let user = format!("panic-test-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let ctx = RequestContext {
        ip: None,
        agent_client: None,
        request_id,
        upstream: Upstream::default(),
    };
    let header = AuditHeader {
        tool: "run_query",
        server: Some("target"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    };
    let work = async { panic!("decoder hit a value it cannot represent") as Outcome };

    let sinks = DispatchSinks::new(&[]);
    let response = audit_dispatch(
        Value::from(1),
        &identity(&user),
        &ctx,
        header,
        sinks.store(&pool),
        work,
    )
    .await;

    let body = serde_json::to_value(&response).expect("response serialises");
    let text = body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool error carries a text payload: {body}"));
    let payload: Value = serde_json::from_str(text).expect("payload is JSON");
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(payload["code"], "internal", "{payload}");
    assert_eq!(payload["request_id"], request_id.to_string(), "{payload}");
    assert!(
        !text.contains("decoder hit"),
        "the panic message must not reach the client: {text}"
    );

    let row = latest_audit(&pool, &user, "run_query", "panicking tool").await;
    assert_eq!(row.outcome, OutcomeCode::Internal);
    assert_eq!(row.request_id, request_id.to_string());
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn panicking_write_work_keeps_the_may_have_committed_flag() {
    let pool = state_pool().await;
    let user = format!("panic-write-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    let ctx = RequestContext {
        ip: None,
        agent_client: None,
        request_id,
        upstream: Upstream::default(),
    };
    let header = AuditHeader {
        tool: "run_query",
        server: Some("target"),
        database: Some("app"),
        sql: Some("DELETE FROM orders WHERE id = 7"),
        reason: None,
        db_type: Some("postgres"),
    };
    let intent_pool = pool.clone();
    let intent_user = user.clone();
    // As a write tool does: the intent commits, then the work panics
    // mid-statement — after which nobody knows whether it committed.
    let work = async move {
        audit::intent::record(
            &intent_pool,
            &CallIntent {
                request_id,
                user_sub: &intent_user,
                user_email: "panic-test@example.com",
                tool: "run_query",
                server: "target",
                database: "app",
                db_type: Some("postgres"),
                access: Access::ReadWrite,
                sql: Some("DELETE FROM orders WHERE id = 7"),
                reason: None,
                upstream_actor: None,
                upstream_run_id: None,
            },
        )
        .await
        .expect("intent commits");
        panic!("decoder hit a value it cannot represent") as Outcome
    };

    let sinks = DispatchSinks::new(&[]);
    audit_dispatch(
        Value::from(1),
        &identity(&user),
        &ctx,
        header,
        sinks.store(&pool),
        work,
    )
    .await;

    let row = latest_audit(&pool, &user, "run_query", "panicking write").await;
    assert_eq!(row.outcome, OutcomeCode::Internal);
    let message = row.error_message.unwrap_or_default();
    assert!(
        message.contains(WRITE_MAY_HAVE_COMMITTED),
        "a panicked write must say it may have committed: {message:?}"
    );
}
