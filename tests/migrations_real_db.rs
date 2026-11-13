//! State-DB migrations from empty (plan 101, slice 03): every migration
//! applies to a fresh database, a second run is a no-op, and the objects the
//! audit slice reads exist afterwards.
//!
//! Runs in a throwaway database on the dev state server so the shared
//! `gateway` database's migration history is never the thing under test.

mod common;

use std::num::NonZeroU32;

use common::env::state_db_url;
use db_mcp_gateway::state;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

/// `url` with its database path replaced by `database`.
fn url_for(url: &str, database: &str) -> String {
    let (base, _) = url
        .rsplit_once('/')
        .expect("state DB URL has a database path");
    format!("{base}/{database}")
}

async fn index_exists(pool: &PgPool, table: &str, index: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = $1 AND indexname = $2)",
    )
    .bind(table)
    .bind(index)
    .fetch_one(pool)
    .await
    .expect("pg_indexes lookup")
}

async fn columns(pool: &PgPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_name = $1 ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("information_schema lookup")
}

#[tokio::test]
async fn migrations_apply_from_empty_and_rerun_as_a_no_op() {
    // A plain connection, not a gateway pool: the gateway pools set a request
    // statement_timeout, and DROP DATABASE (which checkpoints) can outlast it
    // on a loaded server.
    let mut admin = PgConnection::connect(&state_db_url())
        .await
        .expect("admin connection");
    let database = format!("migrations_{}", Uuid::new_v4().simple());
    admin
        .execute(format!("CREATE DATABASE \"{database}\"").as_str())
        .await
        .expect("create scratch database");
    let url = url_for(&state_db_url(), &database);
    let size = NonZeroU32::new(2).expect("non-zero");

    let fresh = state::connect(&url, size)
        .await
        .expect("every migration applies to an empty database");
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&fresh)
        .await
        .expect("migration history");
    state::connect(&url, size)
        .await
        .expect("a second run over a migrated database is a no-op")
        .close()
        .await;
    let reapplied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&fresh)
        .await
        .expect("migration history");

    let intent_columns = columns(&fresh, "audit_call_intents").await;
    let session_columns = columns(&fresh, "sessions").await;
    let intents_idx = index_exists(
        &fresh,
        "audit_call_intents",
        "audit_call_intents_occurred_at_idx",
    )
    .await;
    let history_idx = index_exists(&fresh, "audit_calls", "audit_calls_history_idx").await;
    let mut superseded_idx = Vec::new();
    for index in ["audit_calls_user_sub_idx", "audit_calls_db_type_idx"] {
        if index_exists(&fresh, "audit_calls", index).await {
            superseded_idx.push(index);
        }
    }

    fresh.close().await;
    admin
        .execute(format!("DROP DATABASE \"{database}\" WITH (FORCE)").as_str())
        .await
        .expect("drop scratch database");
    admin.close().await.expect("close admin connection");

    assert_eq!(applied, reapplied, "re-run must not apply anything");
    for column in [
        "request_id",
        "occurred_at",
        "user_sub",
        "user_email",
        "tool",
        "server_name",
        "database_name",
        "db_type",
        "access",
    ] {
        assert!(
            intent_columns.iter().any(|c| c == column),
            "audit_call_intents.{column} missing: {intent_columns:?}"
        );
    }
    assert!(intents_idx, "0010 index missing");
    assert!(history_idx, "0011 index missing");
    assert!(superseded_idx.is_empty(), "0015 left {superseded_idx:?}");
    assert!(
        !session_columns.iter().any(|c| c == "agent_client"),
        "0016 left sessions.agent_client: {session_columns:?}"
    );
}
