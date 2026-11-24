//! `GET /admin/v1/audit/calls` — `audit_calls` rows as NDJSON (one JSON
//! object per line, newest first), filtered by `user`, `server`, `db`,
//! `tool`, `outcome`, `since` / `until` (RFC 3339; `since` inclusive, `until`
//! exclusive) and capped by `limit` (default 1000, clamped to 1..=10 000).
//!
//! The statement text and its bound `params` stay out unless the caller asks
//! with `include_sql=true`. The read is audited (`admin.audit_calls`, the
//! filters and `include_sql` in its `params`) before the first byte streams.
//! Rows are read in keyset batches bounded by rows and by bytes, and no
//! state-DB connection is held while a batch waits for the reader, so a
//! stalled client pins nothing the audit write path needs and holds at most a
//! few [`BATCH_BYTES`] of encoded lines however large `include_sql` rows are. A failure after streaming started ends the body
//! with one `{"error": …}` line instead of a row.

use axum::body::Body;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use futures::TryStreamExt as _;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use sqlx::Row;
use sqlx::postgres::PgRow;
use tokio::sync::mpsc;

use crate::audit::OutcomeCode;

use super::ReadState;
use super::error::AdminError;
use super::middleware::AdminActor;
use super::page_query::invalid_query;
use super::read_audit::{AdminRead, ReadScope, audit_read};

pub const DEFAULT_LIMIT: u32 = 1_000;
pub const MAX_LIMIT: u32 = 10_000;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCallsQuery {
    /// Matches `user_sub` or `user_email`.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub db: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    #[serde(default)]
    pub until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub include_sql: bool,
}

const SELECT: &str = "SELECT id, request_id, occurred_at, user_sub, user_email, groups, tool, \
        server_name, database_name, \
        CASE WHEN $9::bool THEN sql END AS sql, \
        CASE WHEN $9::bool THEN sql_truncated END AS sql_truncated, \
        CASE WHEN $9::bool THEN params END AS params, \
        reason, outcome, elapsed_ms, row_count, truncated, rows_affected, error_message, \
        agent_client, ip, db_type, upstream_actor, upstream_run_id \
     FROM audit_calls \
     WHERE ($1::text IS NULL OR user_sub = $1 OR user_email = $1) \
       AND ($2::text IS NULL OR server_name = $2) \
       AND ($3::text IS NULL OR database_name = $3) \
       AND ($4::text IS NULL OR tool = $4) \
       AND ($5::text IS NULL OR outcome = $5) \
       AND ($6::timestamptz IS NULL OR occurred_at >= $6) \
       AND ($7::timestamptz IS NULL OR occurred_at < $7) \
       AND ($10::timestamptz IS NULL OR (occurred_at, id) < ($10, $11)) \
     ORDER BY occurred_at DESC, id DESC LIMIT $8";

/// Batches buffered between the query task and the response body.
const BATCH_BUFFER: usize = 2;

/// Rows one query reads before its connection goes back to the pool.
const BATCH_ROWS: i64 = 200;

/// Encoded bytes a batch stops at: with `include_sql`, 200 rows of 64 KiB
/// statements and params would otherwise be ~25 MiB per export.
const BATCH_BYTES: usize = 1 << 20;

pub async fn stream(
    State(state): State<ReadState>,
    Extension(actor): Extension<AdminActor>,
    query: Result<Query<AuditCallsQuery>, QueryRejection>,
) -> Result<Response, AdminError> {
    let rid = actor.request_id.as_str();
    let Query(query) = query.map_err(|_| invalid_query(rid))?;
    if let Some(outcome) = &query.outcome
        && OutcomeCode::parse(outcome).is_none()
    {
        return Err(AdminError::invalid("unknown outcome").with_request_id(rid));
    }
    if let (Some(since), Some(until)) = (query.since, query.until)
        && since >= until
    {
        return Err(AdminError::invalid("since must be before until").with_request_id(rid));
    }
    let request = requested(&query);
    let scope = ReadScope {
        server: query.server.as_deref(),
        database: query.db.as_deref(),
        row_count: None,
        request: Some(&request),
    };
    audit_read(&state.state_db, &actor, AdminRead::AuditCalls, scope).await?;

    let (tx, rx) = mpsc::channel::<String>(BATCH_BUFFER);
    let pool = state.state_db.clone();
    let request_id = actor.request_id.clone();
    tokio::spawn(async move { produce(pool, query, tx, request_id).await });
    let body = Body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|line| (Ok::<_, std::convert::Infallible>(line), rx))
    }));
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    Ok(response)
}

/// What the read asked for, as its audit row records it.
fn requested(q: &AuditCallsQuery) -> JsonValue {
    json!({
        "user": q.user,
        "server": q.server,
        "db": q.db,
        "tool": q.tool,
        "outcome": q.outcome,
        "since": q.since,
        "until": q.until,
        "limit": q.limit,
        "include_sql": q.include_sql,
    })
}

/// Run the query batch by batch and push each batch's lines as one chunk. A
/// closed channel means the client went away: stop reading. `request_id`
/// only labels the log line.
async fn produce(
    pool: sqlx::PgPool,
    q: AuditCallsQuery,
    tx: mpsc::Sender<String>,
    request_id: String,
) {
    let mut remaining = i64::from(q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT));
    let mut after: Option<(DateTime<Utc>, uuid::Uuid)> = None;
    while remaining > 0 {
        let asked = remaining.min(BATCH_ROWS);
        let batch = match fetch_batch(&pool, &q, after, asked).await {
            Ok(batch) => batch,
            Err(()) => {
                // The cause can carry row text; only the stage is logged.
                tracing::error!(%request_id, "admin audit stream failed mid-body");
                let _ = tx.send(error_line()).await;
                return;
            }
        };
        let rows = i64::try_from(batch.rows).unwrap_or(i64::MAX);
        let more = batch.full || rows == asked;
        remaining -= rows;
        if !batch.text.is_empty() && tx.send(batch.text).await.is_err() {
            return;
        }
        if !more {
            return;
        }
        after = batch.last;
    }
}

#[derive(Debug, Default)]
struct Batch {
    /// One NDJSON line per row.
    text: String,
    rows: usize,
    /// Keyset position of the batch's last row.
    last: Option<(DateTime<Utc>, uuid::Uuid)>,
    /// Stopped at [`BATCH_BYTES`], before the query ran out of rows.
    full: bool,
}

impl Batch {
    /// Append one row's line; `true` once the batch holds [`BATCH_BYTES`].
    fn push(&mut self, line: &JsonValue, at: (DateTime<Utc>, uuid::Uuid)) -> bool {
        self.text.push_str(&line.to_string());
        self.text.push('\n');
        self.rows += 1;
        self.last = Some(at);
        self.full = self.text.len() >= BATCH_BYTES;
        self.full
    }
}

/// One page, read until `limit` rows or [`BATCH_BYTES`]: its connection is
/// back in the pool before any line is sent.
async fn fetch_batch(
    pool: &sqlx::PgPool,
    q: &AuditCallsQuery,
    after: Option<(DateTime<Utc>, uuid::Uuid)>,
    limit: i64,
) -> Result<Batch, ()> {
    let mut rows = sqlx::query(SELECT)
        .bind(q.user.as_deref())
        .bind(q.server.as_deref())
        .bind(q.db.as_deref())
        .bind(q.tool.as_deref())
        .bind(q.outcome.as_deref())
        .bind(q.since)
        .bind(q.until)
        .bind(limit)
        .bind(q.include_sql)
        .bind(after.map(|(at, _)| at))
        .bind(after.map(|(_, id)| id))
        .fetch(pool);
    let mut batch = Batch::default();
    // Rows past the byte bound are left to the next batch's keyset.
    while let Some(row) = rows.try_next().await.map_err(|_| ())? {
        let at = (
            row.try_get("occurred_at").map_err(|_| ())?,
            row.try_get("id").map_err(|_| ())?,
        );
        if batch.push(&row_json(&row).map_err(|_| ())?, at) {
            break;
        }
    }
    Ok(batch)
}

fn error_line() -> String {
    format!(
        "{}\n",
        json!({ "error": { "code": "internal", "message": "audit stream interrupted" } })
    )
}

fn row_json(row: &PgRow) -> Result<JsonValue, sqlx::Error> {
    let mut line = json!({
        "id": row.try_get::<uuid::Uuid, _>("id")?,
        "request_id": row.try_get::<String, _>("request_id")?,
        "occurred_at": row.try_get::<DateTime<Utc>, _>("occurred_at")?,
        "user_sub": row.try_get::<String, _>("user_sub")?,
        "user_email": row.try_get::<String, _>("user_email")?,
        "groups": row.try_get::<Option<JsonValue>, _>("groups")?,
        "tool": row.try_get::<String, _>("tool")?,
        "server": row.try_get::<Option<String>, _>("server_name")?,
        "database": row.try_get::<Option<String>, _>("database_name")?,
        "reason": row.try_get::<Option<String>, _>("reason")?,
        "outcome": row.try_get::<String, _>("outcome")?,
        "elapsed_ms": row.try_get::<Option<i64>, _>("elapsed_ms")?,
        "row_count": row.try_get::<Option<i64>, _>("row_count")?,
        "truncated": row.try_get::<Option<bool>, _>("truncated")?,
        "rows_affected": row.try_get::<Option<i64>, _>("rows_affected")?,
        "error_message": row.try_get::<Option<String>, _>("error_message")?,
        "agent_client": row.try_get::<Option<String>, _>("agent_client")?,
        "ip": row.try_get::<Option<String>, _>("ip")?,
        "db_type": row.try_get::<Option<String>, _>("db_type")?,
        "upstream_actor": row.try_get::<Option<String>, _>("upstream_actor")?,
        "upstream_run_id": row.try_get::<Option<String>, _>("upstream_run_id")?,
    });
    // `sql_truncated` is NULL exactly when the statement was not asked for.
    if let Some(truncated) = row.try_get::<Option<bool>, _>("sql_truncated")?
        && let Some(map) = line.as_object_mut()
    {
        map.insert(
            "sql".into(),
            json!(row.try_get::<Option<String>, _>("sql")?),
        );
        map.insert("sql_truncated".into(), json!(truncated));
        map.insert(
            "params".into(),
            row.try_get::<Option<JsonValue>, _>("params")?
                .unwrap_or(JsonValue::Null),
        );
    }
    Ok(line)
}

#[cfg(test)]
#[path = "audit_calls_tests.rs"]
mod tests;
