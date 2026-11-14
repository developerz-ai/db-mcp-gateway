//! Real-DB evidence for the SQL guard's "messages to other sessions" and
//! "dynamic SQL" denylist entries: a read — the read role, a `READ ONLY`
//! transaction — still delivers a `NOTIFY` to every `LISTEN`er on the target,
//! directly or from inside SQL text handed to `ts_stat`. Neither the role nor
//! the transaction stops it, so the guard must.

use std::time::Duration;

use sqlx::postgres::PgListener;
use uuid::Uuid;

use crate::common::pg_target::{READ_ROLE, writable_adapter};
use crate::common::pg_target::{TARGET_DB, TARGET_HOST, TARGET_PASSWORD, TARGET_PORT, TARGET_USER};
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

async fn listener(channel: &str) -> PgListener {
    let url = format!(
        "postgres://{TARGET_USER}:{TARGET_PASSWORD}@{TARGET_HOST}:{TARGET_PORT}/{TARGET_DB}"
    );
    let mut listener = PgListener::connect(&url).await.expect("listener connects");
    listener.listen(channel).await.expect("LISTEN");
    listener
}

/// Runs `sql` on the unguarded exec read path and returns the payload a
/// `LISTEN`er on `channel` received, if any.
async fn notification_from_read(channel: &str, sql: &str) -> Option<String> {
    let mut listener = listener(channel).await;
    let adapter = writable_adapter().await;
    let result = adapter
        .execute(read_query(sql))
        .await
        .expect("the read path runs it");
    assert_eq!(
        result.rows[0][0].as_str(),
        Some(READ_ROLE),
        "ran as the non-superuser read role"
    );
    tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .ok()
        .map(|n| n.expect("listener stays up").payload().to_owned())
}

fn channel() -> String {
    format!("dbmcp_guard_{}", Uuid::new_v4().simple())
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn pg_notify_escapes_a_read_only_transaction_so_the_guard_denies_it() {
    let channel = channel();
    let sql = format!("SELECT current_user::text, pg_notify('{channel}', 'from a read')");

    let delivered = notification_from_read(&channel, &sql).await;
    assert_eq!(delivered.as_deref(), Some("from a read"));

    assert_eq!(
        check_sql(&sql, Access::ReadOnly),
        Err(GuardError::DeniedFunction("pg_notify"))
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn sql_text_in_ts_stat_hides_a_denied_call_so_the_guard_denies_it() {
    let channel = channel();
    let sql = format!(
        "SELECT current_user::text, (SELECT count(*) FROM ts_stat(\
         'SELECT to_tsvector(''probe'') FROM (SELECT pg_notify(''{channel}'', ''hidden'')) s'))"
    );

    let delivered = notification_from_read(&channel, &sql).await;
    assert_eq!(delivered.as_deref(), Some("hidden"));

    assert_eq!(
        check_sql(&sql, Access::ReadOnly),
        Err(GuardError::DeniedFunction("ts_stat"))
    );
}
