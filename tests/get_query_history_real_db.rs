//! End-to-end test for `get_query_history`: login via mock OIDC, run a couple
//! of `run_query` calls to populate the audit table, then call
//! `tools/call get_query_history` and assert (a) the caller's own rows come
//! back, (b) a *smuggled* `user` field in the JSON-RPC arguments is rejected
//! at the boundary, and (c) the limit ceiling clamps a hostile
//! `limit: u32::MAX` request and the response is actually capped at the
//! ceiling rather than silently returning the whole audit slice.
//!
//! Every integration test that calls a tool asserts an audit row was (or
//! was not) written by the dispatch chokepoint. The only intentional
//! no-audit exception is the smuggled-`user` case: `deny_unknown_fields`
//! fires during argument deserialization, BEFORE the tool body runs and
//! BEFORE `audit_dispatch` is reached — the JSON-RPC `invalid_params`
//! envelope is the only signal. That is pinned as a no-audit assertion
//! (see `history_rejects_smuggled_user_field`) so a future refactor that
//! routes this through `audit_dispatch` updates the test on purpose.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockUser, spawn_mock_idp};
use db_mcp_gateway::audit::{AuditRow, latest_for_user_tool, log};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, ServiceTokenStore, SessionStore};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::transport::{self, AppState, AuthFacade, PendingFlows};
use serde_json::{Value, json};
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5443/gateway".to_string()
    })
}

const E2E_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5444
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

struct BootedGateway {
    url: String,
    bearer: String,
    state_db: sqlx::PgPool,
    user_sub: String,
}

async fn boot_gateway() -> BootedGateway {
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)");

    let user_sub = format!("test-user-{}", Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: format!("{user_sub}@example.com"),
        groups: vec!["historians".to_string()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway_url = format!("http://{addr}");

    let auth_config = AuthConfig {
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        client_secret: idp.client_secret.clone(),
        audience: idp.client_id.clone(),
        redirect_url: format!("{gateway_url}/auth/callback"),
        ..AuthConfig::default()
    };
    let sessions = SessionStore::new(pool.clone());
    let oidc = OidcClient::new(auth_config.clone()).expect("OidcClient http builder");

    let config = Config {
        bind: addr,
        ..Config::default()
    };
    let config_file = ConfigFile::from_yaml_str(E2E_YAML).expect("e2e yaml is well-formed");

    let app = transport::router(
        &config,
        AppState {
            auth: Some(AuthFacade {
                config: Arc::new(auth_config),
                sessions,
                oidc,
                service_tokens: ServiceTokenStore::default(),
                flows: PendingFlows::default(),
                codes: db_mcp_gateway::transport::AuthCodes::default(),
                refresh: db_mcp_gateway::transport::RefreshTokens::default(),
            }),
            config: Arc::new(config_file),
            state_db: Some(pool.clone()),
            adapter_registry: AdapterRegistry::new(),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
            mcp_path: std::sync::Arc::from("/mcp"),
            client_registry: db_mcp_gateway::transport::ClientRegistry::default(),
        },
    )
    .expect("router builds");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let login: Value = client
        .post(format!("{gateway_url}/auth/login"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = login["login_url"].as_str().unwrap();
    let authorize = client.get(login_url).send().await.unwrap();
    let callback = authorize.headers()["location"]
        .to_str()
        .unwrap()
        .to_string();
    let cb: Value = client
        .get(&callback)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bearer = cb["session_token"].as_str().unwrap().to_string();
    BootedGateway {
        url: gateway_url,
        bearer,
        state_db: pool,
        user_sub,
    }
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
        outcome: "success".to_string(),
        elapsed_ms: Some(42),
        row_count: Some(1),
        truncated: Some(false),
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".to_string()),
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

/// Seed `count` audit rows for `user_sub` against `(server='target',
/// database='app')` in a single bulk INSERT driven by `generate_series`.
/// Used to push the caller's history past the per-call ceiling so
/// truncation can be observed at the integration level. One INSERT with
/// `generate_series` is ~1s for 100k rows; the per-row `write_audit_row`
/// helper (which UPDATEs `occurred_at` individually) would take minutes.
/// `tool` is set to `run_query` so the bulk seed is visibly distinct from
/// any `get_query_history` audit row the dispatch chokepoint writes — the
/// integration test's `latest_for_user_tool(..., "get_query_history")`
/// lookup therefore reads the dispatch's row, not the seed.
async fn bulk_seed_audit_rows(pool: &sqlx::PgPool, user_sub: &str, count: i64) {
    let email = format!("{user_sub}@example.com");
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, groups, tool, server_name, database_name, \
          sql, reason, outcome, elapsed_ms, row_count, truncated, error_message, \
          agent_client, ip, db_type) \
         SELECT gen_random_uuid(), gen_random_uuid()::text, $1, $2, \
                '[\"historians\"]'::jsonb, 'run_query', 'target', 'app', \
                'SELECT ' || i::text, NULL, 'success', 1, 1, false, \
                NULL, NULL, NULL, 'postgres' \
         FROM generate_series(1, $3) AS i",
    )
    .bind(user_sub)
    .bind(&email)
    .bind(count)
    .execute(pool)
    .await
    .expect("bulk seed audit rows");
}

/// Exact audit-row count for a (user_sub, tool) pair. Companion to
/// `latest_for_user_tool`, which only proves that AT LEAST ONE row exists
/// for the dispatch — it does NOT prove the chokepoint wrote exactly one
/// row per dispatch. A duplicate-audit-write regression (e.g. a fallback
/// path that INSERTs without `ON CONFLICT (id) DO NOTHING`) would slip past
/// every `latest_for_user_tool` presence check. Counting first and asserting
/// `== 1` BEFORE the row-field assertions is the structural fix: a future
/// regression that writes two rows trips the count assertion immediately
/// with a debuggable error, instead of silently passing because the latest
/// row's fields happen to match.
#[cfg(any(test, debug_assertions))]
async fn audit_count_for_user_tool(pool: &sqlx::PgPool, user_sub: &str, tool: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_calls WHERE user_sub = $1 AND tool = $2")
        .bind(user_sub)
        .bind(tool)
        .fetch_one(pool)
        .await
        .expect("audit count")
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

    // Audit invariant: the dispatch chokepoint wrote exactly one
    // `get_query_history` row attributed to the authenticated user.
    //
    // Count FIRST and assert `== 1` before the row-field checks. A future
    // regression that writes a duplicate row (e.g. a fallback insert that
    // forgets `ON CONFLICT (id) DO NOTHING`) would still pass the
    // `latest_for_user_tool` presence check below — `latest` only proves
    // "at least one row exists", not "exactly one was written". The count
    // check trips the duplicate-write regression immediately with a clear
    // message; the row-field checks below then verify the *latest* row is
    // well-formed (a duplicate write is allowed to fail here too — the
    // count check has already produced a debuggable error).
    assert_eq!(
        audit_count_for_user_tool(pool, sub, "get_query_history").await,
        1,
        "the dispatch chokepoint must write exactly one audit row per \
         get_query_history dispatch (duplicate-write regression guard)",
    );
    let row = latest_for_user_tool(pool, sub, "get_query_history")
        .await
        .expect("audit lookup runs")
        .expect("history read wrote an audit row");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.user_sub, sub);
    assert_eq!(row.user_email, format!("{sub}@example.com"));
    assert_eq!(row.groups, vec!["historians".to_string()]);
    assert_eq!(row.server.as_deref(), Some("target"));
    assert_eq!(row.database.as_deref(), Some("app"));
    // History read carries no SQL — that column is documented as NULL.
    assert_eq!(row.sql, None);
}

/// THE SECURITY TEST at the integration boundary. A caller smuggles a
/// `user` field through JSON-RPC; the gateway must reject it at the
/// `#[serde(deny_unknown_fields)]` boundary, NOT silently drop it (which
/// would leave the door open for a future regression that adds a `user`
/// field without realising it can override scoping).
#[tokio::test]
async fn history_rejects_smuggled_user_field() {
    let booted = boot_gateway().await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

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

    // Documented no-audit exception: `deny_unknown_fields` fires during
    // `serde_json::from_value::<Arguments>` — argument deserialization is
    // rejected before the tool body runs and before `audit_dispatch` is
    // reached. The JSON-RPC `invalid_params` envelope above is the only
    // signal back to the caller. Pin the absence so a future refactor that
    // DOES route this through `audit_dispatch` updates the test on purpose.
    let smuggled_row = latest_for_user_tool(pool, sub, "get_query_history")
        .await
        .expect("audit lookup runs");
    assert!(
        smuggled_row.is_none(),
        "smuggled-user rejection must NOT write an audit row \
         (deny_unknown_fields fires before audit_dispatch) — got {smuggled_row:?}",
    );
}

/// A caller asking for `u32::MAX` rows gets the ceiling, not the whole
/// audit table slice they happen to be entitled to. The clamp logic has a
/// unit test on `effective_limit`; this integration test proves the
/// dispatch chokepoint actually applies it — by seeding more rows than the
/// ceiling for the authenticated user, calling `history` with `u32::MAX`,
/// and asserting the response is *provably capped* (length == ceiling, NOT
/// the whole slice) and `truncated` is `true`. Without the seed the test
/// would pass on an empty result — a hostile caller could otherwise slide
/// through with a 0-row response.
#[tokio::test]
async fn history_clamps_hostile_limit_to_ceiling() {
    let booted = boot_gateway().await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

    // The gateway ceiling is the only thing between a caller asking for
    // `u32::MAX` rows and the dispatcher returning the whole audit slice
    // they happen to be entitled to. Seed one row past the ceiling so the
    // response is unambiguously capped.
    let ceiling = db_mcp_gateway::tools::GATEWAY_ROW_LIMIT_CEILING as i64;
    bulk_seed_audit_rows(pool, sub, ceiling + 1).await;

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
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len() as i64,
        ceiling,
        "ceiling clamp must cap the response at exactly the ceiling — got {} entries (ceiling = {ceiling})",
        entries.len(),
    );
    assert_eq!(
        body["truncated"], true,
        "ceiling clamp must flag truncation"
    );

    // Audit invariant: the dispatch chokepoint wrote exactly one
    // `get_query_history` row attributed to the authenticated user, with
    // `truncated = true` mirroring the response payload.
    //
    // Count FIRST (duplicate-write regression guard — see
    // `audit_count_for_user_tool`); `latest_for_user_tool` would still
    // pass on a regression that wrote two rows, because `latest` only
    // proves "at least one row exists", not "exactly one was written".
    assert_eq!(
        audit_count_for_user_tool(pool, sub, "get_query_history").await,
        1,
        "the dispatch chokepoint must write exactly one audit row per \
         ceiling-clamped get_query_history dispatch (duplicate-write \
         regression guard)",
    );
    let row = latest_for_user_tool(pool, sub, "get_query_history")
        .await
        .expect("audit lookup runs")
        .expect("ceiling-clamp call wrote an audit row");
    assert_eq!(row.outcome, "success");
    assert_eq!(row.user_sub, sub);
    assert_eq!(row.truncated, Some(true));
}

#[tokio::test]
async fn history_forbidden_without_grant() {
    // Boot a gateway whose user has `query_read` only — NOT `history_read`.
    // Per #170 the grant is standalone; `query_read` does not imply it.
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up");
    let user_sub = format!("queryonly-{}", Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: format!("{user_sub}@example.com"),
        groups: vec!["query-only".to_string()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let yaml = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5444
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }

permissions:
  - group: query-only
    grants:
      - { server: target, database: app, action: query_read }
"#;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway_url = format!("http://{addr}");
    let auth_config = AuthConfig {
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        client_secret: idp.client_secret.clone(),
        audience: idp.client_id.clone(),
        redirect_url: format!("{gateway_url}/auth/callback"),
        ..AuthConfig::default()
    };
    let sessions = SessionStore::new(pool.clone());
    let oidc = OidcClient::new(auth_config.clone()).expect("OidcClient");
    let config = Config {
        bind: addr,
        ..Config::default()
    };
    let config_file = ConfigFile::from_yaml_str(yaml).expect("yaml");
    let app = transport::router(
        &config,
        AppState {
            auth: Some(AuthFacade {
                config: Arc::new(auth_config),
                sessions,
                oidc,
                service_tokens: ServiceTokenStore::default(),
                flows: PendingFlows::default(),
                codes: db_mcp_gateway::transport::AuthCodes::default(),
                refresh: db_mcp_gateway::transport::RefreshTokens::default(),
            }),
            config: Arc::new(config_file),
            state_db: Some(pool.clone()),
            adapter_registry: AdapterRegistry::new(),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
            mcp_path: std::sync::Arc::from("/mcp"),
            client_registry: db_mcp_gateway::transport::ClientRegistry::default(),
        },
    )
    .expect("router");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let login: Value = c
        .post(format!("{gateway_url}/auth/login"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = login["login_url"].as_str().unwrap();
    let authorize = c.get(login_url).send().await.unwrap();
    let callback = authorize.headers()["location"]
        .to_str()
        .unwrap()
        .to_string();
    let cb: Value = c.get(&callback).send().await.unwrap().json().await.unwrap();
    let bearer = cb["session_token"].as_str().unwrap().to_string();

    let resp = call_history(
        &gateway_url,
        &bearer,
        json!({ "server": "target", "database": "app" }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["code"], "forbidden");

    // Audit invariant: the denied authz call still flows through
    // `audit_dispatch` (the authz check happens INSIDE the tool body, not
    // before it), so the audit row MUST be written with `outcome = 'forbidden'`
    // and the server/database the caller tried to reach.
    //
    // Count FIRST (duplicate-write regression guard — see
    // `audit_count_for_user_tool`); `latest_for_user_tool` would still
    // pass on a regression that wrote two rows, because `latest` only
    // proves "at least one row exists", not "exactly one was written".
    assert_eq!(
        audit_count_for_user_tool(&pool, &user_sub, "get_query_history").await,
        1,
        "the dispatch chokepoint must write exactly one audit row per \
         forbidden get_query_history dispatch (duplicate-write regression \
         guard)",
    );
    let row = latest_for_user_tool(&pool, &user_sub, "get_query_history")
        .await
        .expect("audit lookup runs")
        .expect("denied call wrote an audit row");
    assert_eq!(row.outcome, "forbidden");
    assert_eq!(row.user_sub, user_sub);
    assert_eq!(row.server.as_deref(), Some("target"));
    assert_eq!(row.database.as_deref(), Some("app"));
    assert_eq!(row.groups, vec!["query-only".to_string()]);
}
