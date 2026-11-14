//! `audit_call_intents` — phase one of the two-phase audit write, and the
//! reaper's sweep that turns an intent with no completion into an
//! `abandoned` `audit_calls` row.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::audit::CallIntent;
use crate::audit::OutcomeCode;
use crate::exec::sql_guard::Access;

/// Insert one intent row. No `ON CONFLICT`: `request_id` is minted per
/// dispatch and a dispatch reaches the target at most once, so a duplicate
/// is a bug worth failing on.
pub async fn insert_intent(pool: &PgPool, intent: &CallIntent<'_>) -> Result<(), sqlx::Error> {
    let (sql, sql_truncated) = match intent.sql.map(crate::audit::cap_stored_sql) {
        Some((sql, truncated)) => (Some(sql), truncated),
        None => (None, false),
    };
    sqlx::query(
        "INSERT INTO audit_call_intents \
         (request_id, user_sub, user_email, tool, server_name, database_name, db_type, access, \
          upstream_actor, upstream_run_id, sql, sql_truncated, reason) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
    .bind(sql)
    .bind(sql_truncated)
    .bind(intent.reason)
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

/// The access the intent of `request_id` recorded; `None` when the dispatch
/// never committed one (it stopped before reaching the target).
pub async fn select_intent_access(
    pool: &PgPool,
    request_id: &str,
) -> Result<Option<Access>, sqlx::Error> {
    let label: Option<String> =
        sqlx::query_scalar("SELECT access FROM audit_call_intents WHERE request_id = $1")
            .bind(request_id)
            .fetch_optional(pool)
            .await?;
    label
        .map(|label| match label.as_str() {
            "read" => Ok(Access::ReadOnly),
            "write" => Ok(Access::ReadWrite),
            other => Err(sqlx::Error::Decode(
                format!("unknown intent access `{other}`").into(),
            )),
        })
        .transpose()
}

fn access_label(access: Access) -> &'static str {
    match access {
        Access::ReadOnly => "read",
        Access::ReadWrite => "write",
    }
}

/// The `(occurred_at, request_id)` key of one intent row: the reaper's
/// keyset position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentKey {
    pub occurred_at: DateTime<Utc>,
    pub request_id: String,
}

/// What one reaper batch did.
#[derive(Debug)]
pub struct ReapBatch {
    /// Aged intents examined (at most the batch limit).
    pub scanned: u64,
    /// `abandoned` rows written for those without a completion.
    pub reaped: u64,
    /// The last intent examined; `None` when nothing was.
    pub last: Option<IntentKey>,
}

/// Under the transaction-scoped advisory lock `lock_key`, examine up to
/// `limit` intents older than `grace` that sort after `after`, oldest first,
/// and write an `abandoned` `audit_calls` row for each with no `audit_calls`
/// row of its `request_id`. `Ok(None)` when another replica holds the lock.
/// The xact-scoped lock releases on commit or rollback, so a dropped
/// connection can never strand it on a pooled session.
pub async fn reap_abandoned_batch(
    pool: &PgPool,
    lock_key: i64,
    grace: Duration,
    after: Option<&IntentKey>,
    limit: i64,
) -> Result<Option<ReapBatch>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(lock_key)
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        tx.rollback().await?;
        return Ok(None);
    }
    // The bare `occurred_at >= $3` duplicates the row comparison's leading
    // column so the scan is an `audit_call_intents_occurred_at_idx` range even
    // under a generic plan; `-infinity` / `''` stand for "from the start".
    let row = sqlx::query(
        "WITH scanned AS ( \
           SELECT request_id, occurred_at FROM audit_call_intents \
           WHERE occurred_at < now() - make_interval(secs => $2) \
             AND occurred_at >= COALESCE($3, '-infinity'::timestamptz) \
             AND (occurred_at, request_id) \
                 > (COALESCE($3, '-infinity'::timestamptz), COALESCE($4, '')) \
           ORDER BY occurred_at, request_id \
           LIMIT $5 \
         ), reaped AS ( \
           INSERT INTO audit_calls \
           (id, request_id, user_sub, user_email, tool, server_name, database_name, db_type, \
            outcome, error_message, occurred_at, upstream_actor, upstream_run_id, \
            sql, sql_truncated, reason) \
           SELECT gen_random_uuid(), i.request_id, i.user_sub, i.user_email, i.tool, \
                  i.server_name, i.database_name, i.db_type, $1, \
                  'no completion recorded before the gateway stopped (access: ' || i.access || ')', \
                  i.occurred_at, i.upstream_actor, i.upstream_run_id, \
                  i.sql, i.sql_truncated, i.reason \
           FROM scanned s JOIN audit_call_intents i ON i.request_id = s.request_id \
           WHERE NOT EXISTS (SELECT 1 FROM audit_calls c WHERE c.request_id = i.request_id) \
           RETURNING 1 \
         ), last AS ( \
           SELECT occurred_at, request_id FROM scanned \
           ORDER BY occurred_at DESC, request_id DESC LIMIT 1 \
         ) \
         SELECT (SELECT count(*) FROM scanned) AS scanned, \
                (SELECT count(*) FROM reaped) AS reaped, \
                (SELECT occurred_at FROM last) AS last_occurred_at, \
                (SELECT request_id FROM last) AS last_request_id",
    )
    .bind(OutcomeCode::Abandoned.as_str())
    .bind(grace.as_secs_f64())
    .bind(after.map(|key| key.occurred_at))
    .bind(after.map(|key| key.request_id.as_str()))
    .bind(limit)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let scanned: i64 = row.try_get("scanned")?;
    let reaped: i64 = row.try_get("reaped")?;
    let last_occurred_at: Option<DateTime<Utc>> = row.try_get("last_occurred_at")?;
    let last_request_id: Option<String> = row.try_get("last_request_id")?;
    let last = last_occurred_at
        .zip(last_request_id)
        .map(|(occurred_at, request_id)| IntentKey {
            occurred_at,
            request_id,
        });
    Ok(Some(ReapBatch {
        scanned: u64::try_from(scanned).unwrap_or(0),
        reaped: u64::try_from(reaped).unwrap_or(0),
        last,
    }))
}
