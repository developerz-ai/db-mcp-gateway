//! End-to-end test for `get_query_history`: login via mock OIDC, run a couple
//! of `run_query` calls to populate the audit table, then call
//! `tools/call get_query_history` and assert (a) the caller's own rows come
//! back, (b) a *smuggled* `user` field in the JSON-RPC arguments is rejected
//! at the boundary, and (c) the limit ceiling clamps a hostile
//! `limit: u32::MAX` request.
//!
//! Every integration test that hits a tool asserts an audit row exists.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockUser, spawn_mock_idp};
use db_mcp_gateway::audit::{AuditRow, log};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::transport::{self, AppState, AuthFacade, PendingFlows};
use serde_json::{Value, json};
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

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

struct BootedGateway {
    url: String,
    bearer: String,
    state_db: sqlx::PgPool,
    user_sub: String,
}

/// The default gateway: a caller in `historians`, which holds `history_read`.
async fn boot_gateway() -> BootedGateway {
    boot_gateway_with("historians", "test-user", E2E_YAML).await
}

/// Boot a gateway whose caller belongs to `group`, against `yaml`.
///
/// Parameterized rather than copied: every field added to `AppState` would
/// otherwise need the same edit in two places, and the copy silently rots
/// when only one is updated.
async fn boot_gateway_with(group: &str, sub_prefix: &str, yaml: &str) -> BootedGateway {
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)");

    let user_sub = format!("{sub_prefix}-{}", Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: format!("{user_sub}@example.com"),
        groups: vec![group.to_string()],
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
    let config_file = ConfigFile::from_yaml_str(yaml).expect("e2e yaml is well-formed");

    let app = transport::router(
        &config,
        AppState {
            auth: Some(AuthFacade {
                config: Arc::new(auth_config),
                sessions,
                oidc,
                flows: PendingFlows::default(),
                codes: db_mcp_gateway::transport::AuthCodes::default(),
                refresh: db_mcp_gateway::transport::RefreshTokens::default(),
                service_tokens: Default::default(),
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
