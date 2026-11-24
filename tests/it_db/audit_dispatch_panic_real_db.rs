//! A tool whose work panics still completes its audit row: `audit_dispatch`
//! records `internal` (not `cancelled`) and answers the stable `internal`
//! tool error, so a defect in one tool never leaves a call unaccounted for
//! or kills the caller's connection.

use crate::common::audit::{DispatchSinks, latest_audit};
use crate::common::env::state_pool;
use db_mcp_gateway::audit::OutcomeCode;
use db_mcp_gateway::auth::{Identity, IdentityKind, SessionId};
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
