//! `audit_calls.sql_sha256` (migrations 0026/0027): every inserted row gets
//! the digest of its stored `sql` from the state DB itself — whichever
//! release or path wrote it — and a `get_query_history` hash lookup seeks
//! `audit_calls_history_sha_idx` instead of hashing the caller's history.

use db_mcp_gateway::audit::{self, AuditRow, HistoryQuery, OutcomeCode};
use db_mcp_gateway::state::audit::{HISTORY_BY_DIGEST_SQL, select_user_history};
use sqlx::Row as _;
use uuid::Uuid;

use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;

fn call(sub: &str, sql: &str) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: Uuid::new_v4().to_string(),
        user_sub: sub.into(),
        user_email: "digest@example.com".into(),
        groups: vec![],
        tool: "run_query".into(),
        server: Some("prod".into()),
        database: Some("app".into()),
        sql: Some(sql.into()),
        reason: None,
        outcome: OutcomeCode::Success,
        elapsed_ms: Some(1),
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
        params: None,
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn every_row_carries_its_digest_and_the_lookup_seeks_it() {
    let p = state_pool().await;
    let sub = format!("digest-{}", Uuid::new_v4().simple());
    for sql in ["SELECT 1", "SELECT 2", "SELECT 1", "SELECT 'é'"] {
        audit::log(&p, &call(&sub, sql)).await.expect("row");
    }
    // A writer that knows nothing of the column — an older release.
    sqlx::query(
        "INSERT INTO audit_calls (id, request_id, user_sub, user_email, groups, tool, \
           server_name, database_name, sql, outcome) \
         VALUES (gen_random_uuid(), $1, $2, 'old@example.com', '[]', 'run_query', \
           'prod', 'app', 'SELECT 1', 'success')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&sub)
    .execute(&p)
    .await
    .expect("legacy-shaped insert");

    let mismatched: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_calls WHERE user_sub = $1 \
           AND sql_sha256 IS DISTINCT FROM sha256(convert_to(sql, 'UTF8'))",
    )
    .bind(&sub)
    .fetch_one(&p)
    .await
    .expect("count");
    assert_eq!(mismatched, 0, "the DB fills the digest on every insert");

    let hash: String = sqlx::query_scalar("SELECT encode(sha256('SELECT 1'::bytea), 'hex')")
        .fetch_one(&p)
        .await
        .expect("hash");
    let page = select_user_history(
        &p,
        &HistoryQuery {
            user_sub: &sub,
            server: "prod",
            database: "app",
            upstream_run_id: None,
            sql_sha256: Some(&hash),
            since: None,
            before: None,
            limit: 10,
        },
    )
    .await
    .expect("history");
    assert_eq!(page.entries.len(), 3);
    assert!(
        page.entries
            .iter()
            .all(|e| e.sql_sha256.as_deref() == Some(hash.as_str()))
    );

    let mut tx = p.begin().await.expect("tx");
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .expect("planner setting");
    // The production statement, planned as a generic prepared plan (what a
    // cached sqlx statement runs after five executions): the digest must be
    // an index condition, or a rare hash still walks the caller's history.
    // Simple protocol: an extended-protocol prepare would demand the `$n`.
    let plan = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "EXPLAIN (GENERIC_PLAN) {HISTORY_BY_DIGEST_SQL}"
    )))
    .fetch_all(&mut *tx)
    .await
    .expect("explain")
    .iter()
    .map(|row| row.try_get::<String, _>(0).expect("plan line"))
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        plan.contains("audit_calls_history_sha_idx")
            && plan
                .lines()
                .any(|line| line.contains("Index Cond") && line.contains("sql_sha256")),
        "{plan}"
    );
    let indexed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes \
         WHERE tablename = 'audit_calls' AND indexname = 'audit_calls_history_sha_idx')",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("pg_indexes");
    assert!(indexed, "0027 index missing");
    tx.rollback().await.expect("rollback");

    delete_audit_calls(&p, &sub).await;
}
