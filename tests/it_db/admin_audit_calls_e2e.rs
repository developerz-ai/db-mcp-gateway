//! `GET /admin/v1/audit/calls` NDJSON (plan 101 O10 f): filters, the SQL
//! opt-in, the limit, and the `admin.audit_calls` row the read itself writes.

use db_mcp_gateway::audit::{self, AuditRow, OutcomeCode};
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::admin_o10_support::{O10, unique};
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::{state_db_url, state_pool};

fn row(sub: &str, tool: &str, outcome: OutcomeCode) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: unique("req"),
        user_sub: sub.to_string(),
        user_email: "caller@example.com".into(),
        groups: vec!["g".into()],
        tool: tool.into(),
        server: Some("prod".into()),
        database: Some("app".into()),
        sql: Some("SELECT secret_column FROM t WHERE id = $1".into()),
        params: Some(serde_json::json!([42])),
        reason: None,
        outcome,
        elapsed_ms: Some(3),
        row_count: Some(1),
        truncated: Some(false),
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".into()),
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    }
}

async fn lines(h: &O10, query: &str) -> (StatusCode, Vec<Value>) {
    let resp = h
        .http()
        .get(format!("{}/admin/v1/audit/calls?{query}", h.url))
        .bearer_auth(&h.admin)
        .send()
        .await
        .expect("get");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    let parsed = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    (status, parsed)
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn audit_stream_filters_hides_sql_by_default_and_is_itself_audited() {
    let h = O10::spawn().await;
    let caller = unique("o10-caller");
    for (tool, outcome) in [
        ("run_query", OutcomeCode::Success),
        ("run_query", OutcomeCode::Forbidden),
        ("describe_schema", OutcomeCode::Success),
    ] {
        audit::log(&h.pool, &row(&caller, tool, outcome))
            .await
            .expect("seed");
    }

    let (status, all) = lines(&h, &format!("user={caller}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(all.len(), 3);
    assert!(
        all.iter()
            .all(|l| l.get("sql").is_none() && l.get("params").is_none()),
        "no SQL without opt-in"
    );
    assert_eq!(h.admin_reads("admin.audit_calls").await, 1, "read audited");

    let (_, filtered) = lines(
        &h,
        &format!("user={caller}&tool=run_query&outcome=forbidden"),
    )
    .await;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["outcome"], "forbidden");

    let (_, with_sql) = lines(&h, &format!("user={caller}&include_sql=true&limit=1")).await;
    assert_eq!(with_sql.len(), 1, "limit applies");
    assert_eq!(
        with_sql[0]["sql"],
        "SELECT secret_column FROM t WHERE id = $1"
    );
    assert_eq!(with_sql[0]["params"], serde_json::json!([42]));
    assert_eq!(with_sql[0]["sql_truncated"], false);
    // The read's own row says what it asked for, disclosure flag included.
    let requests: Vec<Value> = sqlx::query_scalar(
        "SELECT params FROM audit_calls WHERE user_sub = $1 AND tool = 'admin.audit_calls' \
         ORDER BY occurred_at",
    )
    .bind(&h.admin_sub)
    .fetch_all(&h.pool)
    .await
    .expect("admin read rows");
    let disclosed = requests.last().expect("the include_sql read");
    assert_eq!(disclosed["include_sql"], true, "{disclosed}");
    assert_eq!(disclosed["user"], caller.as_str(), "{disclosed}");
    assert_eq!(disclosed["limit"], 1, "{disclosed}");
    assert_eq!(requests[0]["include_sql"], false, "{}", requests[0]);

    let (_, none) = lines(&h, &format!("user={caller}&since=2999-01-01T00:00:00Z")).await;
    assert!(none.is_empty());

    let (status, _) = lines(&h, "outcome=not-a-code").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = lines(&h, "colour=blue").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown filter refused");
    assert_eq!(
        h.admin_reads("admin.audit_calls").await,
        4,
        "refusals read nothing"
    );

    let outsider = h.bearer(&caller, &["not-admin"]).await;
    let resp = h
        .http()
        .get(format!("{}/admin/v1/audit/calls", h.url))
        .bearer_auth(outsider)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    delete_audit_calls(&h.pool, &caller).await;
    h.cleanup().await;
}

/// An export whose reader stalls must not pin a state-DB connection: with a
/// one-connection pool, a second admin read still gets through while the
/// first body sits unread (megabytes of SQL, past every socket buffer).
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_stalled_export_does_not_hold_the_state_connection() {
    let seed_pool = state_pool().await;
    let caller = unique("o10-stall");
    let mut big = row(&caller, "run_query", OutcomeCode::Success);
    big.sql = Some(format!("SELECT '{}'", "x".repeat(60_000)));
    for _ in 0..300 {
        big.id = Uuid::new_v4();
        big.request_id = unique("req");
        audit::log(&seed_pool, &big).await.expect("seed");
    }
    let one = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&state_db_url())
        .await
        .expect("state DB up");
    let h = O10::spawn_with(one).await;

    let stalled = h
        .http()
        .get(format!(
            "{}/admin/v1/audit/calls?user={caller}&include_sql=true",
            h.url
        ))
        .bearer_auth(&h.admin)
        .send()
        .await
        .expect("headers arrive");
    assert_eq!(stalled.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, second) = lines(&h, "user=nobody-o10&limit=1").await;
    assert_eq!(status, StatusCode::OK, "{second:?}");

    let all = stalled.text().await.expect("stalled body completes");
    assert_eq!(all.lines().count(), 300);
    delete_audit_calls(&seed_pool, &caller).await;
    h.cleanup().await;
}
