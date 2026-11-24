//! `GET /admin/v1/audit/calls` — `audit_calls` rows as NDJSON (one JSON
//! object per line, newest first), filtered by `user`, `server`, `db`,
//! `tool`, `outcome`, `since` / `until` (RFC 3339; `since` inclusive, `until`
//! exclusive) and capped by `limit` (default 1000, clamped to 1..=10 000).
//!
//! The statement text and its bound `params` stay out unless the caller asks
//! with `include_sql=true`. The read is audited (`admin.audit_calls`, the
//! filters and `include_sql` in its `params`) before the first byte streams.
//! Keyset batches are bounded by rows and bytes in the query itself, so
//! Postgres sends only rows a batch emits, and no state-DB connection is held
//! while a batch waits for the reader: a stalled client pins nothing the audit
//! write path needs and holds about a few [`BATCH_BYTES`] of lines however
//! large `include_sql` rows are. A failure after streaming started ends the
//! body with one `{"error": …}` line instead of a row.

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
use sql::SELECT;

#[path = "audit_calls_sql.rs"]
mod sql;

pub const DEFAULT_LIMIT: u32 = 1_000;
pub const MAX_LIMIT: u32 = 10_000;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditCallsQuery {
    /// Matches `user_sub` or `user_email`.
    pub user: Option<String>,
    pub server: Option<String>,
    pub db: Option<String>,
    pub tool: Option<String>,
    pub outcome: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub include_sql: bool,
}

/// Batches buffered between the query task and the response body.
const BATCH_BUFFER: usize = 2;

/// Rows one query reads before its connection goes back to the pool.
const BATCH_ROWS: i64 = 200;

/// The smallest candidate window: after a batch the byte bound cut short,
/// the next query reads twice what fit (at least this many) instead of the
/// full [`BATCH_ROWS`], so a wide export does not make the state DB size
/// rows it will only hold back.
const MIN_WINDOW: i64 = 16;

/// Line bytes (bounded per row by [`SELECT`]'s `width`) a batch stops at: with
/// `include_sql`, 200 rows of 64 KiB statements and params would otherwise be
/// ~25 MiB per export.
const BATCH_BYTES: i64 = 1 << 20;

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
    let mut window = BATCH_ROWS;
    while remaining > 0 {
        let asked = remaining.min(window);
        let batch = match fetch_batch(&pool, &q, after, asked).await {
            Ok(batch) => batch,
            Err(()) => {
                // The cause can carry row text; only the stage is logged.
                tracing::error!(%request_id, "admin audit stream failed mid-body");
                let _ = tx.send(error_line()).await;
                return;
            }
        };
        let more = batch.more(asked);
        remaining -= batch.rows;
        window = (batch.rows * 2).clamp(MIN_WINDOW, BATCH_ROWS);
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
    rows: i64,
    /// Rows the keyset page held before [`BATCH_BYTES`] cut it.
    page_rows: i64,
    /// Keyset position of the batch's last row.
    last: Option<(DateTime<Utc>, uuid::Uuid)>,
}

impl Batch {
    fn push(&mut self, line: &JsonValue, at: (DateTime<Utc>, uuid::Uuid)) {
        self.text.push_str(&line.to_string());
        self.text.push('\n');
        self.rows += 1;
        self.last = Some(at);
    }

    /// Rows may follow: the byte bound cut the page, or the page was full.
    fn more(&self, asked: i64) -> bool {
        self.rows < self.page_rows || self.page_rows == asked
    }
}

/// One page of at most `limit` rows and about [`BATCH_BYTES`], read to the
/// end — the next batch's keyset starts after its last row — with its
/// connection back in the pool before any line is sent.
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
        .bind(BATCH_BYTES)
        .fetch(pool);
    let mut batch = Batch::default();
    while let Some(row) = rows.try_next().await.map_err(|_| ())? {
        let at = (
            row.try_get("occurred_at").map_err(|_| ())?,
            row.try_get("id").map_err(|_| ())?,
        );
        batch.page_rows = row.try_get("page_rows").map_err(|_| ())?;
        batch.push(&row_json(&row).map_err(|_| ())?, at);
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
