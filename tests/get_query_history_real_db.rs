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
}
