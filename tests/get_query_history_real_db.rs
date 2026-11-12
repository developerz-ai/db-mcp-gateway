//! End-to-end test for `get_query_history`: login via mock OIDC, run a couple
//! of `run_query` calls to populate the audit table, then call
//! `tools/call get_query_history` and assert (a) the caller's own rows come
//! back, (b) a *smuggled* `user` field in the JSON-RPC arguments is rejected
//! at the boundary, (c) the page ceiling clamps a hostile `limit`, (d) long
//! SQL is truncated in the response, (e) keyset pages never overlap and
//! (f) the history query is served by `audit_calls_history_idx` (0011).
//!
//! Every integration test that hits a tool asserts an audit row exists.

mod common;

use std::time::Duration;

use common::cleanup::delete_audit_calls;
use common::gateway::{LoggedInGateway, spawn_logged_in};
use common::idp::MockUser;
use db_mcp_gateway::audit::{AuditRow, HISTORY_SQL_MAX_BYTES, OutcomeCode, log};
use serde_json::{Value, json};
use uuid::Uuid;

const E2E_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: historians
    grants:
      - { server: target, database: app, action: history_read }
      - { server: target, database: app, action: query_read }
"#;

/// The default gateway: a caller in `historians`, which holds `history_read`.
async fn boot_gateway() -> LoggedInGateway {
    boot_gateway_with("historians", "test-user", E2E_YAML).await
}

/// Boot a gateway whose caller belongs to `group`, against `yaml`.
async fn boot_gateway_with(group: &str, sub_prefix: &str, yaml: &str) -> LoggedInGateway {
    let user_sub = format!("{sub_prefix}-{}", Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: format!("{user_sub}@example.com"),
        groups: vec![group.to_string()],
    };
    spawn_logged_in(yaml, user).await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
}

async fn write_audit_row(
    pool: &sqlx::PgPool,
    user_sub: &str,
    sql: &str,
    occurred_at_secs_ago: i64,
) {
    let row = AuditRow {
        id: Uuid::new_v4(),
        request_id: Uuid::new_v4().to_string(),
        user_sub: user_sub.to_string(),
        user_email: format!("{user_sub}@example.com"),
        groups: vec!["historians".to_string()],
        tool: "run_query".to_string(),
        server: Some("target".to_string()),
        database: Some("app".to_string()),
        sql: Some(sql.to_string()),
        reason: None,
        outcome: OutcomeCode::Success,
        elapsed_ms: Some(42),
        row_count: Some(1),
        truncated: Some(false),
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".to_string()),
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    };
    log(pool, &row).await.expect("audit insert");
    // Bump occurred_at backwards so the test is deterministic regardless of
    // write timing. `log` already committed with `occurred_at = now()`;
    // shifting it is a one-line UPDATE.
    let shifted = chrono::Utc::now() - chrono::Duration::seconds(occurred_at_secs_ago);
    sqlx::query("UPDATE audit_calls SET occurred_at = $1 WHERE id = $2")
        .bind(shifted)
        .bind(row.id)
        .execute(pool)
        .await
        .expect("shift occurred_at");
}

/// CLAUDE.md: "Every integration test that hits a tool asserts an audit row
/// exists. Tool failed authz → audit row with `outcome: forbidden`."
///
/// The dispatch audit row is what makes this tool accountable — without it a
/// caller could read other users' query metadata with no trace. A regression
/// that dropped the audit write would otherwise pass every assertion in this
/// file, since they all stop at the JSON-RPC envelope.
///
/// `sql` must be NULL: this tool takes no SQL, and a non-NULL value would mean
/// the dispatch header was populated from the wrong tool's arguments.
async fn assert_dispatch_audited(pool: &sqlx::PgPool, user_sub: &str, outcome: &str) {
    #[derive(sqlx::FromRow)]
    struct DispatchRow {
        outcome: String,
        sql: Option<String>,
        server_name: Option<String>,
        database_name: Option<String>,
    }

    let row: Option<DispatchRow> = sqlx::query_as(
        "SELECT outcome, sql, server_name, database_name \
         FROM audit_calls \
         WHERE user_sub = $1 AND tool = 'get_query_history' \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(user_sub)
    .fetch_optional(pool)
    .await
    .expect("audit query");

    let row = row.unwrap_or_else(|| panic!("no `get_query_history` audit row for {user_sub}"));
    assert_eq!(row.outcome, outcome, "audit row outcome for {user_sub}");
    assert!(
        row.sql.is_none(),
        "get_query_history writes no SQL, got {:?}",
        row.sql,
    );
    assert_eq!(row.server_name.as_deref(), Some("target"));
    assert_eq!(row.database_name.as_deref(), Some("app"));
}

async fn call_history(url: &str, bearer: &str, arguments: Value) -> Value {
    client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_query_history",
                "arguments": arguments
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("history result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

#[tokio::test]
async fn history_returns_only_callers_own_rows() {
    let booted = boot_gateway().await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

    // Seed three rows for `sub`, plus one row for a *different* user.
    // The history read MUST only return `sub`'s rows.
    write_audit_row(pool, sub, "SELECT 1", 5).await;
    write_audit_row(pool, sub, "SELECT 2", 4).await;
    write_audit_row(pool, sub, "SELECT 3", 3).await;
    write_audit_row(pool, "someone-else", "SELECT sensitive", 2).await;

    let resp = call_history(
        url,
        bearer,
        json!({ "server": "target", "database": "app", "limit": 50 }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        3,
        "must only return caller's 3 rows, got {entries:?}",
    );
    // ORDER BY occurred_at DESC — newest first.
    assert_eq!(entries[0]["sql"], "SELECT 3");
    assert_eq!(entries[1]["sql"], "SELECT 2");
    assert_eq!(entries[2]["sql"], "SELECT 1");
    assert_eq!(body["truncated"], false);
    // Every entry has the documented wire shape.
    for entry in entries {
        assert!(entry["request_id"].is_string());
        assert!(entry["occurred_at"].is_string());
        assert_eq!(entry["outcome"], "success");
    }

    assert_dispatch_audited(pool, sub, "success").await;
}

/// THE SECURITY TEST at the integration boundary. A caller smuggles a
/// `user` field through JSON-RPC; the gateway must reject it at the
/// `#[serde(deny_unknown_fields)]` boundary, NOT silently drop it (which
/// would leave the door open for a future regression that adds a `user`
/// field without realising it can override scoping).
#[tokio::test]
async fn history_rejects_smuggled_user_field() {
    let booted = boot_gateway().await;
    let (url, bearer) = (booted.url.as_str(), booted.bearer.as_str());

    let resp = call_history(
        url,
        bearer,
        json!({
            "server": "target",
            "database": "app",
            "user": "someone-else", // <- smuggling attempt
        }),
    )
    .await;
    // The dispatcher returns an `invalid_params` JSON-RPC error envelope
    // (NOT a successful tool call with `isError: true` — `deny_unknown_fields`
    // fires before any tool code runs).
    assert!(
        resp["error"].is_object(),
        "expected JSON-RPC error envelope, got {resp}",
    );
    let err = &resp["error"];
    assert!(
        err["code"].as_i64() == Some(-32602), // JSON-RPC invalid params
        "expected invalid_params (-32602), got {err}",
    );

    // The smuggling attempt itself is audited — with no target, since the
    // arguments never parsed.
    let row = common::audit::latest_audit(
        &booted.state_db,
        &booted.user_sub,
        "get_query_history",
        "smuggled user",
    )
    .await;
    assert_eq!(row.outcome, "invalid_arguments");
    assert_eq!(row.server, None);
    assert_eq!(row.database, None);
}

/// A caller asking for `u32::MAX` rows gets the ceiling, not the whole
/// audit table slice they happen to be entitled to. (We can't assert the
/// *exact* number here without seeding > ceiling rows; the unit test on
/// `effective_limit` covers the clamp logic. Here we just confirm the call
/// succeeds and `truncated: true` is set.)
#[tokio::test]
async fn history_clamps_hostile_limit_to_ceiling() {
    let booted = boot_gateway().await;
    let (url, bearer) = (booted.url.as_str(), booted.bearer.as_str());

    let resp = call_history(
        url,
        bearer,
        json!({
            "server": "target",
            "database": "app",
            "limit": u32::MAX,
        }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(
        body["truncated"], true,
        "ceiling clamp must flag truncation"
    );

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "success").await;
}

#[tokio::test]
async fn history_forbidden_without_grant() {
    // A caller with `query_read` only — NOT `history_read`. Per #170 the
    // grant is standalone; `query_read` does not imply it.
    const QUERY_ONLY_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }

permissions:
  - group: query-only
    grants:
      - { server: target, database: app, action: query_read }
"#;
    let booted = boot_gateway_with("query-only", "queryonly", QUERY_ONLY_YAML).await;

    let resp = call_history(
        &booted.url,
        &booted.bearer,
        json!({ "server": "target", "database": "app" }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["code"], "forbidden");

    // A denial is exactly the event an audit log exists to record.
    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "forbidden").await;
}

/// The advertised schema says `"limit": { "minimum": 1 }`. A `limit: 0` that
/// reached the query would return `entries: []` — indistinguishable from "you
/// have no history", which is a wrong answer rather than an error. Reject it
/// at the boundary, where the rest of this tool's input validation lives.
///
/// The rejection MUST still leave an audit row (`outcome: invalid_arguments`).
/// Without it, a caller sweeping bad `limit` values to probe the tool's
/// bounds against another user's server leaves no trail — .coderabbit.yaml
/// §src/audit: "flag any code path that completes a tool call without an
/// audit row".
#[tokio::test]
async fn history_rejects_zero_limit() {
    let booted = boot_gateway().await;

    let resp = call_history(
        &booted.url,
        &booted.bearer,
        json!({ "server": "target", "database": "app", "limit": 0 }),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "expected JSON-RPC error envelope, got {resp}",
    );
    assert_eq!(
        resp["error"]["code"].as_i64(),
        Some(-32602),
        "expected invalid_params, got {}",
        resp["error"],
    );

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "invalid_arguments").await;
}

/// Mirror the `limit: 0` audit-row requirement for the `since` parse failure:
/// a caller sweeping malformed timestamps against a server they can see must
/// still leave a `outcome: invalid_arguments` row. The two paths share
/// `invalid_arguments_outcome`, so this is defence-in-depth against a future
/// change that specialises one path and forgets the audit hook.
#[tokio::test]
async fn history_rejects_malformed_since_and_audits_it() {
    let booted = boot_gateway().await;

    let resp = call_history(
        &booted.url,
        &booted.bearer,
        json!({ "server": "target", "database": "app", "since": "yesterday" }),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "expected JSON-RPC error envelope, got {resp}",
    );
    assert_eq!(
        resp["error"]["code"].as_i64(),
        Some(-32602),
        "expected invalid_params, got {}",
        resp["error"],
    );

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "invalid_arguments").await;
}

/// Seed `count` history rows for `user_sub` in one statement, one second
/// apart, newest first by `n`.
async fn seed_rows(pool: &sqlx::PgPool, user_sub: &str, database: &str, count: i32) {
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, tool, server_name, database_name, sql, outcome, \
          occurred_at) \
         SELECT gen_random_uuid(), gen_random_uuid()::text, $1, 'seed@example.com', 'run_query', \
                'target', $2, 'SELECT ' || n, 'success', now() - make_interval(secs => n) \
         FROM generate_series(1, $3) AS n",
    )
    .bind(user_sub)
    .bind(database)
    .bind(count)
    .execute(pool)
    .await
    .expect("seed history rows");
}

/// A page is at most 1 000 entries however large `limit` is; the rest is
/// reachable through `next_cursor`.
#[tokio::test]
async fn history_page_is_capped_at_the_ceiling() {
    let booted = boot_gateway().await;
    seed_rows(&booted.state_db, &booted.user_sub, "app", 1005).await;

    let resp = call_history(
        &booted.url,
        &booted.bearer,
        json!({ "server": "target", "database": "app", "limit": 100_000 }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["entries"].as_array().unwrap().len(), 1000);
    assert_eq!(body["truncated"], true);
    assert!(body["next_cursor"].is_string(), "{}", body["next_cursor"]);

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "success").await;
    delete_audit_calls(&booted.state_db, &booted.user_sub).await;
}

/// One huge statement must not make the response huge: `sql` is cut and
/// flagged.
#[tokio::test]
async fn history_truncates_oversized_sql() {
    let booted = boot_gateway().await;
    let long_sql = format!("SELECT '{}'", "x".repeat(10 * 1024));
    write_audit_row(&booted.state_db, &booted.user_sub, &long_sql, 1).await;

    let resp = call_history(
        &booted.url,
        &booted.bearer,
        json!({ "server": "target", "database": "app" }),
    )
    .await;
    let body = payload(&resp);
    let entry = &body["entries"][0];
    let sql = entry["sql"].as_str().expect("sql string");
    assert!(sql.len() <= HISTORY_SQL_MAX_BYTES, "{}", sql.len());
    assert!(long_sql.starts_with(sql));
    assert_eq!(entry["sql_truncated"], true);

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "success").await;
}

/// Walking `next_cursor` visits every entry once, newest first, and ends
/// with a `null` cursor.
#[tokio::test]
async fn history_keyset_pages_do_not_overlap() {
    let booted = boot_gateway().await;
    seed_rows(&booted.state_db, &booted.user_sub, "app", 5).await;

    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    for _ in 0..3 {
        let mut arguments = json!({ "server": "target", "database": "app", "limit": 2 });
        if !cursor.is_null() {
            arguments["cursor"] = cursor.clone();
        }
        let body = payload(&call_history(&booted.url, &booted.bearer, arguments).await);
        for entry in body["entries"].as_array().unwrap() {
            seen.push(entry["sql"].as_str().unwrap().to_string());
        }
        cursor = body["next_cursor"].clone();
    }
    assert!(cursor.is_null(), "last page has no cursor, got {cursor}");
    let expected: Vec<String> = (1..=5).map(|n| format!("SELECT {n}")).collect();
    assert_eq!(seen, expected);

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "success").await;
    delete_audit_calls(&booted.state_db, &booted.user_sub).await;
}

/// A cursor the gateway did not mint is an argument error, audited.
#[tokio::test]
async fn history_rejects_forged_cursor() {
    let booted = boot_gateway().await;
    let resp = call_history(
        &booted.url,
        &booted.bearer,
        json!({ "server": "target", "database": "app", "cursor": "not-a-cursor" }),
    )
    .await;
    assert_eq!(resp["error"]["code"].as_i64(), Some(-32602), "{resp}");

    assert_dispatch_audited(&booted.state_db, &booted.user_sub, "invalid_arguments").await;
}

/// The 0011 index serves the history query's filter and keyset order with
/// no sort step. The SQL is copied from
/// `src/state/audit/history.rs` on purpose (see
/// `tests/permissions_indexes_mysql.rs`): a rewrite that stops matching the
/// index shows up as a diff between the two.
#[tokio::test]
async fn history_query_uses_the_history_index() {
    let booted = boot_gateway().await;
    let pool = &booted.state_db;
    // Skewed on purpose: most of the caller's rows are for another database,
    // the shape where 0003's `(user_sub, occurred_at)` index must filter
    // row by row and 0011's index seeks straight to the page.
    seed_rows(pool, &booted.user_sub, "app", 200).await;
    seed_rows(pool, &booted.user_sub, "other", 4000).await;
    sqlx::query("ANALYZE audit_calls")
        .execute(pool)
        .await
        .expect("analyze");

    // The table is shared with every other test, so its statistics — and
    // the planner's choice between the 0003 and 0011 indexes — drift run to
    // run. Pin what 0011 is for instead: with sorting priced out, the only
    // cheap plan is an index that serves both the WHERE and the
    // `(occurred_at, id)` order, and only `audit_calls_history_idx` does.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL enable_sort = off")
        .execute(&mut *tx)
        .await
        .expect("disable sort");
    sqlx::query("SET LOCAL enable_incremental_sort = off")
        .execute(&mut *tx)
        .await
        .expect("disable incremental sort");
    let plan: Value = sqlx::query_scalar(&format!(
        "EXPLAIN (FORMAT JSON) \
         SELECT id, request_id, sql, reason, outcome, elapsed_ms, row_count, occurred_at \
         FROM audit_calls \
         WHERE user_sub = '{sub}' AND server_name = 'target' AND database_name = 'app' \
           AND (NULL::timestamptz IS NULL OR occurred_at >= NULL::timestamptz) \
           AND (NULL::timestamptz IS NULL OR (occurred_at, id) < (NULL::timestamptz, NULL::uuid)) \
         ORDER BY occurred_at DESC, id DESC \
         LIMIT 101",
        sub = booted.user_sub,
    ))
    .fetch_one(&mut *tx)
    .await
    .expect("explain runs");
    tx.rollback().await.expect("rollback");
    let plan = plan.to_string();
    assert!(plan.contains("audit_calls_history_idx"), "{plan}");
    assert!(
        !plan.contains("Sort\""),
        "index must serve the order: {plan}"
    );
    delete_audit_calls(pool, &booted.user_sub).await;
}

/// Agents sharing one service token do not read each other's history: a
/// caller that claims a run id sees only that run's rows; one that claims
/// none sees every row of the identity. A row stored with `sql_truncated`
/// (cut at the audit cap, migration 0014) stays flagged in history.
#[tokio::test]
async fn history_filters_by_claimed_run_id() {
    use db_mcp_gateway::audit::HistoryQuery;
    use db_mcp_gateway::state::audit::select_user_history;

    let pool = common::env::state_pool().await;
    let user_sub = format!("service:history-{}", Uuid::new_v4().simple());
    for (run, sql_truncated) in [("run-a", true), ("run-b", false)] {
        sqlx::query(
            "INSERT INTO audit_calls \
             (id, request_id, user_sub, user_email, tool, server_name, database_name, sql, \
              outcome, upstream_run_id, upstream_actor, rows_affected, sql_truncated) \
             VALUES (gen_random_uuid(), gen_random_uuid()::text, $1, 'svc@x.invalid', \
                     'run_query', 'target', 'app', $2, 'success', $2, 'alice', 3, $3)",
        )
        .bind(&user_sub)
        .bind(run)
        .bind(sql_truncated)
        .execute(&pool)
        .await
        .expect("seed run row");
    }
    let query = |run: Option<&'static str>| HistoryQuery {
        user_sub: &user_sub,
        server: "target",
        database: "app",
        upstream_run_id: run,
        since: None,
        before: None,
        limit: 10,
    };

    let run_a = select_user_history(&pool, &query(Some("run-a")))
        .await
        .unwrap();
    assert_eq!(run_a.entries.len(), 1);
    assert_eq!(run_a.entries[0].sql.as_deref(), Some("run-a"));
    assert!(run_a.entries[0].sql_truncated, "stored flag survives");
    assert_eq!(run_a.entries[0].rows_affected, Some(3));

    let unknown = select_user_history(&pool, &query(Some("run-z")))
        .await
        .unwrap();
    assert!(unknown.entries.is_empty());

    let all = select_user_history(&pool, &query(None)).await.unwrap();
    assert_eq!(all.entries.len(), 2);

    delete_audit_calls(&pool, &user_sub).await;
}
