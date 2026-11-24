//! The state-DB role split documented in `deployment/operations.md`
//! §"State DB roles" (plan 101 U8), run for real: a fresh database owned by
//! one role and migrated by it, the doc's grant block applied, then the
//! gateway's runtime role boots, writes and prunes audit rows, and is refused
//! an `UPDATE` or `TRUNCATE` on `audit_calls`. The SQL is read from the doc,
//! so the doc cannot drift from what this test proves.

use std::num::NonZeroU32;
use std::time::Duration;

use crate::common::env::state_db_url;
use db_mcp_gateway::audit::reaper::ReapCursor;
use db_mcp_gateway::audit::{self, AuditRow, OutcomeCode};
use db_mcp_gateway::state;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

const OPERATIONS_DOC: &str = include_str!("../../website/docs/deployment/operations.md");
const POOL_SIZE: NonZeroU32 = NonZeroU32::new(2).expect("2 is non-zero");
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The ```sql block between the doc's `state-db-role-grants` markers.
fn documented_grants() -> &'static str {
    let start = OPERATIONS_DOC
        .find("{/* state-db-role-grants:start */}")
        .expect("start marker in operations.md");
    let block = &OPERATIONS_DOC[start..];
    let end = block
        .find("{/* state-db-role-grants:end */}")
        .expect("end marker");
    let block = &block[..end];
    let sql = block.find("```sql\n").expect("sql fence") + "```sql\n".len();
    let close = block[sql..].find("```").expect("closing fence");
    &block[sql..sql + close]
}

fn url_for(role: &str, password: &str, database: &str) -> String {
    let mut url = url::Url::parse(&state_db_url()).expect("STATE_DB_URL parses");
    url.set_username(role).unwrap();
    url.set_password(Some(password)).unwrap();
    url.set_path(database);
    url.to_string()
}

fn row(user_sub: &str) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: Uuid::new_v4().to_string(),
        user_sub: user_sub.into(),
        user_email: "role-split@example.com".into(),
        groups: vec![],
        tool: "list_servers".into(),
        server: None,
        database: None,
        sql: None,
        reason: None,
        outcome: OutcomeCode::Success,
        elapsed_ms: Some(1),
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: None,
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    }
}

async fn sqlstate(pool: &PgPool, sql: &'static str) -> Option<String> {
    let err = pool.execute(sql).await.err()?;
    err.as_database_error()
        .and_then(|db| db.code())
        .map(|code| code.into_owned())
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn runtime_role_appends_and_prunes_but_cannot_rewrite_audit_rows() {
    let suffix = Uuid::new_v4().simple().to_string();
    let (owner, app, database) = (
        format!("rs_owner_{suffix}"),
        format!("rs_app_{suffix}"),
        format!("rs_{suffix}"),
    );
    let admin = PgPool::connect(&state_db_url()).await.expect("state DB up");
    for sql in [
        format!("CREATE ROLE {owner} LOGIN PASSWORD 'owner-{suffix}'"),
        format!("CREATE ROLE {app} LOGIN PASSWORD 'app-{suffix}'"),
        format!("CREATE DATABASE {database} OWNER {owner}"),
    ] {
        admin
            .execute(sqlx::AssertSqlSafe(sql))
            .await
            .expect("setup");
    }

    let owner_pool = state::connect(
        &url_for(&owner, &format!("owner-{suffix}"), &database),
        POOL_SIZE,
    )
    .await
    .expect("owner migrates");
    let grants = documented_grants().replace("gateway_app", &app);
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&owner_pool)
        .await
        .expect("documented grants apply");

    // The boot path: migrator check with nothing to apply, under the app role.
    let app_pool = state::connect(
        &url_for(&app, &format!("app-{suffix}"), &database),
        POOL_SIZE,
    )
    .await
    .expect("runtime role boots");
    audit::log(&app_pool, &row("role-split"))
        .await
        .expect("append");
    let history: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_calls")
        .fetch_one(&app_pool)
        .await
        .expect("read");
    assert_eq!(history, 1);
    audit::pruner::run_once(&app_pool, 90)
        .await
        .expect("pruner runs as the runtime role");
    audit::reaper::run_once(&app_pool, Duration::ZERO, &mut ReapCursor::default())
        .await
        .expect("reaper runs as the runtime role");

    for sql in [
        "UPDATE audit_calls SET outcome = 'success'",
        "UPDATE audit_call_intents SET sql = NULL",
        "UPDATE permissions_audit SET actor_email = 'x'",
        "TRUNCATE audit_calls",
        "DELETE FROM _sqlx_migrations",
    ] {
        assert_eq!(
            sqlstate(&app_pool, sql).await.as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{sql}"
        );
    }

    app_pool.close().await;
    owner_pool.close().await;
    for sql in [
        format!("DROP DATABASE {database} WITH (FORCE)"),
        format!("DROP ROLE {app}"),
        format!("DROP ROLE {owner}"),
    ] {
        admin
            .execute(sqlx::AssertSqlSafe(sql))
            .await
            .expect("teardown");
    }
}
