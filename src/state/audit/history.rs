//! `get_query_history`'s read of `audit_calls`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::audit::{HistoryCursor, HistoryEntry, HistoryPage, HistoryQuery, cap_history_sql};

/// SECURITY-CRITICAL — used by `tools::get_query_history`. One page of the
/// caller's `audit_calls` rows for `(server, database)`, newest first, scoped
/// by the SSO-verified `user_sub` (never a client-supplied field). Keyset
/// pagination on `(occurred_at, id)`: one extra row is fetched to learn
/// whether a next page exists. `audit_calls_history_idx` (migration 0011)
/// covers the WHERE and the ORDER BY.
pub async fn select_user_history(
    pool: &PgPool,
    query: &HistoryQuery<'_>,
) -> Result<HistoryPage, sqlx::Error> {
    let (before_at, before_id) = match query.before {
        Some(cursor) => (Some(cursor.occurred_at), Some(cursor.id)),
        None => (None, None),
    };
    // Explicit casts so the bind types are unambiguous when a value is NULL.
    let rows = sqlx::query(
        "SELECT id, request_id, sql, reason, outcome, elapsed_ms, row_count, occurred_at \
         FROM audit_calls \
         WHERE user_sub = $1 AND server_name = $2 AND database_name = $3 \
           AND ($4::timestamptz IS NULL OR occurred_at >= $4::timestamptz) \
           AND ($5::timestamptz IS NULL OR (occurred_at, id) < ($5::timestamptz, $6::uuid)) \
         ORDER BY occurred_at DESC, id DESC \
         LIMIT $7",
    )
    .bind(query.user_sub)
    .bind(query.server)
    .bind(query.database)
    .bind(query.since)
    .bind(before_at)
    .bind(before_id)
    .bind(i64::from(query.limit) + 1)
    .fetch_all(pool)
    .await?;

    let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > limit;
    let mut entries = Vec::with_capacity(rows.len().min(limit));
    let mut last = None;
    for row in rows.iter().take(limit) {
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at")?;
        let id: Uuid = row.try_get("id")?;
        let (sql, sql_truncated) = cap_history_sql(row.try_get("sql")?);
        entries.push(HistoryEntry {
            request_id: row.try_get("request_id")?,
            sql,
            sql_truncated,
            reason: row.try_get("reason")?,
            occurred_at: occurred_at.to_rfc3339(),
            elapsed_ms: row.try_get("elapsed_ms")?,
            row_count: row.try_get("row_count")?,
            outcome: row.try_get("outcome")?,
        });
        last = Some(HistoryCursor { occurred_at, id });
    }
    Ok(HistoryPage {
        entries,
        next: if has_more { last } else { None },
    })
}
