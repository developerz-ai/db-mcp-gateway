//! Real-DB evidence for the guard's Unicode-escaped identifier refusal:
//! Postgres decodes `U&"\0070g_terminate_backend"` to `pg_terminate_backend`,
//! and the read role — shared by every identity on the read tier — may
//! terminate another session of the same role. So one identity's read can
//! kill another identity's query unless the guard refuses the form.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::common::pg_target::{
    READ_ROLE, READ_ROLE_PASSWORD, TARGET_DB, TARGET_HOST, TARGET_PORT, writable_adapter,
};
use db_mcp_gateway::exec::sql_guard::{GuardError, check_sql};
use db_mcp_gateway::exec::{Access, DbAdapter, ExecQuery};

fn read_query(sql: &str) -> ExecQuery<'_> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 10,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn unicode_escaped_terminate_kills_another_identitys_query_so_the_guard_refuses_it() {
    let attacker = writable_adapter().await;

    // Another identity's query: same read role, its own backend.
    let url = format!(
        "postgres://{READ_ROLE}:{READ_ROLE_PASSWORD}@{TARGET_HOST}:{TARGET_PORT}/{TARGET_DB}"
    );
    let victim = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("victim connects as the read role");
    let mut victim_conn = victim.acquire().await.expect("victim connection");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *victim_conn)
        .await
        .expect("victim pid");
    let victim_query = tokio::spawn(async move {
        sqlx::query("SELECT pg_sleep(20)")
            .execute(&mut *victim_conn)
            .await
            .map(|_| ())
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let sql = format!(r#"SELECT current_user::text, U&"\0070g_terminate_backend"({pid})"#);
    let result = attacker
        .execute(read_query(&sql))
        .await
        .expect("the unguarded read path runs it");
    assert_eq!(result.rows[0][0].as_str(), Some(READ_ROLE));
    assert_eq!(result.rows[0][1], serde_json::Value::Bool(true));

    let victim_outcome = tokio::time::timeout(Duration::from_secs(10), victim_query)
        .await
        .expect("victim ended long before its sleep")
        .expect("victim task joins");
    assert!(victim_outcome.is_err(), "victim's query was terminated");

    for access in [Access::ReadOnly, Access::ReadWrite] {
        assert_eq!(
            check_sql(&sql, access),
            Err(GuardError::UnicodeEscapedIdentifier)
        );
    }
}
