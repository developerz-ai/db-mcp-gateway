//! `get_query_history`'s read of `audit_calls`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::audit::{HistoryCursor, HistoryEntry, HistoryPage, HistoryQuery, cap_history_sql};

/// One history page's SQL; `$digest` is either nothing or the digest
/// predicate, so each variant is a static string.
macro_rules! history_sql {
    ($digest:literal) => {
        concat!(
            "SELECT id, request_id, sql, sql_truncated, reason, outcome, elapsed_ms, row_count, \
                    rows_affected, occurred_at, \
                    encode(sql_sha256, 'hex') AS sql_sha256 \
             FROM audit_calls \
             WHERE user_sub = $1 AND server_name = $2 AND database_name = $3 \
               AND ($4::timestamptz IS NULL OR occurred_at >= $4::timestamptz) \
               AND ($5::timestamptz IS NULL OR (occurred_at, id) < ($5::timestamptz, $6::uuid)) \
               AND ($8::text IS NULL OR upstream_run_id = $8::text) ",
            $digest,
            "ORDER BY occurred_at DESC, id DESC \
             LIMIT $7"
        )
    };
}

const HISTORY_SQL: &str = history_sql!("");
/// The digest lookup. Its own statement, not an optional `($9 IS NULL OR …)`
/// predicate: a generic prepared plan cannot use an optional predicate as an
/// index condition, so the digest would only filter the caller's whole
/// history.
pub const HISTORY_BY_DIGEST_SQL: &str = history_sql!("AND sql_sha256 = decode($9::text, 'hex') ");

/// SECURITY-CRITICAL — used by `tools::get_query_history`. One page of the
/// caller's `audit_calls` rows for `(server, database)`, newest first, scoped
/// by the authenticated `user_sub` (never a client-supplied field) and, for a
/// service caller that claims one, its run id. Keyset
/// pagination on `(occurred_at, id)`: one extra row is fetched to learn
/// whether a next page exists. `audit_calls_history_idx` (migration 0011)
/// covers the WHERE and the ORDER BY; with a `sql_sha256` filter,
/// `audit_calls_history_sha_idx` (0027) seeks the stored digest (0026), so a
/// rare hash costs its matches, not the caller's whole history.
pub async fn select_user_history(
    pool: &PgPool,
    query: &HistoryQuery<'_>,
) -> Result<HistoryPage, sqlx::Error> {
    let (before_at, before_id) = match query.before {
        Some(cursor) => (Some(cursor.occurred_at), Some(cursor.id)),
        None => (None, None),
    };
    let sql = match query.sql_sha256 {
        Some(_) => HISTORY_BY_DIGEST_SQL,
        None => HISTORY_SQL,
    };
    // Explicit casts so the bind types are unambiguous when a value is NULL.
    let mut statement = sqlx::query(sql)
        .bind(query.user_sub)
        .bind(query.server)
        .bind(query.database)
        .bind(query.since)
        .bind(before_at)
        .bind(before_id)
        .bind(i64::from(query.limit) + 1)
        .bind(query.upstream_run_id);
    if let Some(digest) = query.sql_sha256 {
        statement = statement.bind(digest);
    }
    let rows = statement.fetch_all(pool).await?;

    let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > limit;
    let mut entries = Vec::with_capacity(rows.len().min(limit));
    let mut last = None;
    for row in rows.iter().take(limit) {
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at")?;
        let id: Uuid = row.try_get("id")?;
        let (sql, cut_here) = cap_history_sql(row.try_get("sql")?);
        let cut_at_store: bool = row.try_get("sql_truncated")?;
        entries.push(HistoryEntry {
            request_id: row.try_get("request_id")?,
            sql,
            sql_truncated: cut_here || cut_at_store,
            sql_sha256: row.try_get("sql_sha256")?,
            reason: row.try_get("reason")?,
            occurred_at: occurred_at.to_rfc3339(),
            elapsed_ms: row.try_get("elapsed_ms")?,
            row_count: row.try_get("row_count")?,
            rows_affected: row.try_get("rows_affected")?,
            outcome: row.try_get("outcome")?,
        });
        last = Some(HistoryCursor { occurred_at, id });
    }
    Ok(HistoryPage {
        entries,
        next: if has_more { last } else { None },
    })
}
