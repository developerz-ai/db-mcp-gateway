//! `audit_call_intents` — phase one of the two-phase audit write, and the
//! reaper's sweep that turns an intent with no completion into an
//! `abandoned` `audit_calls` row.

use std::time::Duration;

use sqlx::PgPool;

use crate::audit::CallIntent;
use crate::audit::OutcomeCode;
use crate::exec::sql_guard::Access;

/// Insert one intent row. No `ON CONFLICT`: `request_id` is minted per
/// dispatch and a dispatch reaches the target at most once, so a duplicate
/// is a bug worth failing on.
pub async fn insert_intent(pool: &PgPool, intent: &CallIntent<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_call_intents \
         (request_id, user_sub, user_email, tool, server_name, database_name, db_type, access, \
          upstream_actor, upstream_run_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(intent.request_id.to_string())
    .bind(intent.user_sub)
    .bind(intent.user_email)
    .bind(intent.tool)
    .bind(intent.server)
    .bind(intent.database)
    .bind(intent.db_type)
    .bind(access_label(intent.access))
    .bind(intent.upstream_actor)
    .bind(intent.upstream_run_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Of `request_ids`, the ones whose intent row belongs to `user_sub` on
/// `(server, database)`. Every call that reaches a target commits an intent
/// first, so this is the ownership check `db_activity` and `cancel_query`
/// apply before showing or touching another request.
pub async fn select_owned_request_ids(
    pool: &PgPool,
    user_sub: &str,
    server: &str,
    database: &str,
    request_ids: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT request_id FROM audit_call_intents \
         WHERE user_sub = $1 AND server_name = $2 AND database_name = $3 \
           AND request_id = ANY($4)",
    )
    .bind(user_sub)
    .bind(server)
    .bind(database)
    .bind(request_ids)
    .fetch_all(pool)
    .await
}

fn access_label(access: Access) -> &'static str {
    match access {
        Access::ReadOnly => "read",
        Access::ReadWrite => "write",
    }
}

/// Under the transaction-scoped advisory lock `lock_key`, write an
/// `abandoned` `audit_calls` row for every intent older than `grace` that has
/// no `audit_calls` row with its `request_id`. `Ok(None)` when another
/// replica holds the lock. The xact-scoped lock releases on commit or
/// rollback, so a dropped connection can never strand it on a pooled session.
pub async fn reap_abandoned_intents(
    pool: &PgPool,
    lock_key: i64,
    grace: Duration,
) -> Result<Option<u64>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(lock_key)
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        tx.rollback().await?;
        return Ok(None);
    }
    let grace_secs = grace.as_secs_f64();
    let reaped = sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, tool, server_name, database_name, db_type, \
          outcome, error_message, occurred_at, upstream_actor, upstream_run_id) \
         SELECT gen_random_uuid(), i.request_id, i.user_sub, i.user_email, i.tool, \
                i.server_name, i.database_name, i.db_type, $1, \
                'no completion recorded before the gateway stopped (access: ' || i.access || ')', \
                i.occurred_at, i.upstream_actor, i.upstream_run_id \
         FROM audit_call_intents i \
         WHERE i.occurred_at < now() - make_interval(secs => $2) \
           AND NOT EXISTS (SELECT 1 FROM audit_calls c WHERE c.request_id = i.request_id)",
    )
    .bind(OutcomeCode::Abandoned.as_str())
    .bind(grace_secs)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(Some(reaped))
}
