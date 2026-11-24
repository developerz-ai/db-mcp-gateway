//! `GET /admin/v1/audit/calls` NDJSON (plan 101 O10 f): filters, the SQL
//! opt-in, the limit, and the `admin.audit_calls` row the read itself writes.

use db_mcp_gateway::audit::{self, AuditRow, OutcomeCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::admin_o10_support::{O10, unique};
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::{state_db_url, state_pool};

fn row(sub: &str, tool: &str, outcome: OutcomeCode) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: unique("req"),
        user_sub: sub.to_string(),
        user_email: "caller@example.com".into(),
        groups: vec!["g".into()],
        tool: tool.into(),
        server: Some("prod".into()),
        database: Some("app".into()),
        sql: Some("SELECT secret_column FROM t WHERE id = $1".into()),
        params: Some(serde_json::json!([42])),
        reason: None,
        outcome,
        elapsed_ms: Some(3),
        row_count: Some(1),
        truncated: Some(false),
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".into()),
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    }
}

async fn lines(h: &O10, query: &str) -> (StatusCode, Vec<Value>) {
    let resp = h
        .http()
        .get(format!("{}/admin/v1/audit/calls?{query}", h.url))
        .bearer_auth(&h.admin)
        .send()
        .await
        .expect("get");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    let parsed = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    (status, parsed)
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn audit_stream_filters_hides_sql_by_default_and_is_itself_audited() {
    let h = O10::spawn().await;
    let caller = unique("o10-caller");
    for (tool, outcome) in [
        ("run_query", OutcomeCode::Success),
        ("run_query", OutcomeCode::Forbidden),
        ("describe_schema", OutcomeCode::Success),
    ] {
        audit::log(&h.pool, &row(&caller, tool, outcome))
            .await
            .expect("seed");
    }

    let (status, all) = lines(&h, &format!("user={caller}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(all.len(), 3);
    assert!(
        all.iter()
            .all(|l| l.get("sql").is_none() && l.get("params").is_none()),
        "no SQL without opt-in"
    );
    assert_eq!(h.admin_reads("admin.audit_calls").await, 1, "read audited");

    let (_, filtered) = lines(
        &h,
        &format!("user={caller}&tool=run_query&outcome=forbidden"),
    )
    .await;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["outcome"], "forbidden");

    let (_, with_sql) = lines(&h, &format!("user={caller}&include_sql=true&limit=1")).await;
    assert_eq!(with_sql.len(), 1, "limit applies");
    assert_eq!(
        with_sql[0]["sql"],
        "SELECT secret_column FROM t WHERE id = $1"
    );
    assert_eq!(with_sql[0]["params"], serde_json::json!([42]));
    assert_eq!(with_sql[0]["sql_truncated"], false);
    // The read's own row says what it asked for, disclosure flag included.
    let requests: Vec<Value> = sqlx::query_scalar(
        "SELECT params FROM audit_calls WHERE user_sub = $1 AND tool = 'admin.audit_calls' \
         ORDER BY occurred_at",
    )
    .bind(&h.admin_sub)
    .fetch_all(&h.pool)
    .await
    .expect("admin read rows");
    let disclosed = requests.last().expect("the include_sql read");
    assert_eq!(disclosed["include_sql"], true, "{disclosed}");
    assert_eq!(disclosed["user"], caller.as_str(), "{disclosed}");
    assert_eq!(disclosed["limit"], 1, "{disclosed}");
    assert_eq!(requests[0]["include_sql"], false, "{}", requests[0]);

    let (_, none) = lines(&h, &format!("user={caller}&since=2999-01-01T00:00:00Z")).await;
    assert!(none.is_empty());

    let (status, _) = lines(&h, "outcome=not-a-code").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = lines(&h, "colour=blue").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown filter refused");
    assert_eq!(
        h.admin_reads("admin.audit_calls").await,
        4,
        "refusals read nothing"
    );

    let outsider = h.bearer(&caller, &["not-admin"]).await;
    let resp = h
        .http()
        .get(format!("{}/admin/v1/audit/calls", h.url))
        .bearer_auth(outsider)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    delete_audit_calls(&h.pool, &caller).await;
    h.cleanup().await;
}

/// An export whose reader stalls must not pin a state-DB connection: with a
/// one-connection pool, a second admin read still gets through while the
/// first body sits unread (megabytes of SQL, past every socket buffer).
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_stalled_export_does_not_hold_the_state_connection() {
    let seed_pool = state_pool().await;
    let caller = unique("o10-stall");
    let mut big = row(&caller, "run_query", OutcomeCode::Success);
    big.sql = Some(format!("SELECT '{}'", "x".repeat(60_000)));
    for _ in 0..300 {
        big.id = Uuid::new_v4();
        big.request_id = unique("req");
        audit::log(&seed_pool, &big).await.expect("seed");
    }
    let one = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&state_db_url())
        .await
        .expect("state DB up");
    let h = O10::spawn_with(one).await;

    let stalled = h
        .http()
        .get(format!(
            "{}/admin/v1/audit/calls?user={caller}&include_sql=true",
            h.url
        ))
        .bearer_auth(&h.admin)
        .send()
        .await
        .expect("headers arrive");
    assert_eq!(stalled.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, second) = lines(&h, "user=nobody-o10&limit=1").await;
    assert_eq!(status, StatusCode::OK, "{second:?}");

    let all = stalled.text().await.expect("stalled body completes");
    assert_eq!(all.lines().count(), 300);
    delete_audit_calls(&seed_pool, &caller).await;
    h.cleanup().await;
}

/// A TCP relay in front of the state DB that counts the bytes Postgres sends.
async fn counting_relay() -> (String, Arc<AtomicU64>) {
    let mut url = url::Url::parse(&state_db_url()).expect("state DB URL");
    let upstream = format!(
        "{}:{}",
        url.host_str().expect("host"),
        url.port().unwrap_or(5432)
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("relay");
    let port = listener.local_addr().expect("relay addr").port();
    let from_db = Arc::new(AtomicU64::new(0));
    let counter = from_db.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let server = TcpStream::connect(&upstream).await.expect("state DB");
            let (mut client_rx, mut client_tx) = client.into_split();
            let (mut server_rx, mut server_tx) = server.into_split();
            tokio::spawn(async move { tokio::io::copy(&mut client_rx, &mut server_tx).await });
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n @ 1..) = server_rx.read(&mut buf).await {
                    counter.fetch_add(n as u64, Ordering::Relaxed);
                    if client_tx.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    url.set_host(Some("127.0.0.1")).expect("host");
    url.set_port(Some(port)).expect("port");
    (url.to_string(), from_db)
}

/// Wide rows span many byte-bounded pages: every row arrives exactly once,
/// newest first, and Postgres sends about what the body carries — a page is
/// bounded in the query itself, not cut short after the rows already came.
#[tokio::test]
#[serial_test::parallel(world)]
async fn wide_rows_page_by_bytes_without_refetching() {
    let seed_pool = state_pool().await;
    let caller = unique("o10-wide");
    let mut wide = row(&caller, "run_query", OutcomeCode::Success);
    for i in 0..240 {
        wide.id = Uuid::new_v4();
        wide.request_id = unique("req");
        wide.sql = Some(format!("SELECT '{}'", "x".repeat(20_000 + (i % 7) * 6_000)));
        audit::log(&seed_pool, &wide).await.expect("seed");
    }
    let expected: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_calls WHERE user_sub = $1 ORDER BY occurred_at DESC, id DESC",
    )
    .bind(&caller)
    .fetch_all(&seed_pool)
    .await
    .expect("seeded ids");

    let (relay_url, from_db) = counting_relay().await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&relay_url)
        .await
        .expect("state DB through the relay");
    let h = O10::spawn_with(pool).await;
    let before = from_db.load(Ordering::Relaxed);
    let body = h
        .http()
        .get(format!(
            "{}/admin/v1/audit/calls?user={caller}&include_sql=true",
            h.url
        ))
        .bearer_auth(&h.admin)
        .send()
        .await
        .expect("get")
        .text()
        .await
        .expect("body");
    let sent = from_db.load(Ordering::Relaxed) - before;

    let ids: Vec<Uuid> = body
        .lines()
        .map(|l| {
            let line: Value = serde_json::from_str(l).expect("each line is JSON");
            line["id"].as_str().expect("id").parse().expect("uuid")
        })
        .collect();
    assert_eq!(ids, expected, "every row exactly once, newest first");
    let body_len = body.len() as u64;
    assert!(
        sent < body_len + body_len / 2,
        "Postgres sent {sent} bytes for a {body_len}-byte body"
    );
    delete_audit_calls(&seed_pool, &caller).await;
    h.cleanup().await;
}

/// `BATCH_BYTES` in `src/transport/admin/audit_calls.rs`.
const BATCH_BYTES: usize = 1 << 20;

/// The body of a raw HTTP/1.1 GET, one entry per chunk: the export sends each
/// batch as one chunk, so this is what each batch buffered.
async fn body_chunks(url: &str, path_and_query: &str, bearer: &str) -> Vec<Vec<u8>> {
    let url = url::Url::parse(url).expect("gateway URL");
    let host = format!(
        "{}:{}",
        url.host_str().expect("host"),
        url.port().expect("port")
    );
    let mut conn = TcpStream::connect(&host).await.expect("gateway");
    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {bearer}\r\n\
         Connection: close\r\n\r\n"
    );
    conn.write_all(request.as_bytes()).await.expect("request");
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).await.expect("response");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("end of headers");
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
    let mut rest = &raw[split + 4..];
    let mut chunks = Vec::new();
    loop {
        let eol = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size = std::str::from_utf8(&rest[..eol]).expect("ascii size");
        let size = usize::from_str_radix(size.split(';').next().expect("size"), 16).expect("hex");
        rest = &rest[eol + 2..];
        if size == 0 {
            return chunks;
        }
        chunks.push(rest[..size].to_vec());
        rest = &rest[size + 2..];
    }
}

/// Rows whose stored size says little about their JSON line — `params` that
/// compress to almost nothing, `sql` of control characters that escape to six
/// bytes each — still keep every batch within the byte target plus one row,
/// and every row arrives exactly once, newest first.
#[tokio::test]
#[serial_test::parallel(world)]
async fn compressible_and_escaped_rows_keep_batches_within_the_byte_target() {
    let seed_pool = state_pool().await;
    let caller = unique("o10-packed");
    let mut packed = row(&caller, "run_query", OutcomeCode::Success);
    for i in 0..120 {
        packed.id = Uuid::new_v4();
        packed.request_id = unique("req");
        if i % 2 == 0 {
            packed.sql = Some("SELECT $1".into());
            packed.params = Some(serde_json::json!(["x".repeat(60_000)]));
        } else {
            packed.sql = Some("\u{1}".repeat(30_000));
            packed.params = Some(serde_json::json!([1]));
        }
        audit::log(&seed_pool, &packed).await.expect("seed");
    }
    let expected: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_calls WHERE user_sub = $1 ORDER BY occurred_at DESC, id DESC",
    )
    .bind(&caller)
    .fetch_all(&seed_pool)
    .await
    .expect("seeded ids");
    let h = O10::spawn().await;

    let chunks = body_chunks(
        &h.url,
        &format!("/admin/v1/audit/calls?user={caller}&include_sql=true"),
        &h.admin,
    )
    .await;
    let mut ids = Vec::new();
    for chunk in &chunks {
        let text = std::str::from_utf8(chunk).expect("UTF-8 batch");
        let widest = text.lines().map(|l| l.len() + 1).max().expect("a line");
        assert!(
            chunk.len() <= BATCH_BYTES + widest,
            "a {}-byte batch past {BATCH_BYTES} + one {widest}-byte row",
            chunk.len()
        );
        for line in text.lines() {
            let line: Value = serde_json::from_str(line).expect("each line is JSON");
            ids.push(
                line["id"]
                    .as_str()
                    .expect("id")
                    .parse::<Uuid>()
                    .expect("uuid"),
            );
        }
    }
    assert_eq!(ids, expected, "every row exactly once, newest first");
    assert!(chunks.len() > 1, "the rows span several batches");
    delete_audit_calls(&seed_pool, &caller).await;
    h.cleanup().await;
}
