//! E2E for `run_query`: walk the full mock-OIDC login flow, then exercise
//! the tool against the local target-db (`bin/dev up` → :5434).
//!
//! Three acceptance properties, taken straight from #4:
//!   1. quick query succeeds with rows
//!   2. query exceeding `statement_timeout_ms` returns the typed `timeout`
//!      MCP error — killed at the DB, never a raw sqlx string
//!   3. row cap truncates and flags `truncated: true`
//!
//! Also asserts the forbidden path: a request against a server the caller
//! has no grant on returns `forbidden`, never reveals whether the server
//! exists.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockUser, spawn_mock_idp};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::exec::PoolRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::transport::{self, AppState, AuthFacade, PendingFlows};
use serde_json::{Value, json};

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

/// Config pointing the `target` server at the live `target-db` from
/// `docker-compose.dev.yml`. The `engineers` group gets a fast 200ms
/// `statement_timeout_ms` on `target/app` so a `pg_sleep(2)` is guaranteed
/// to trip it without test runs blocking for 2s on success.
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
        description: Local target-db
  - name: hidden
    kind: postgres
    description: Caller has no grant on this one
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: engineers
    grants:
      - server: target
        database: app
        action: query_read
        constraints:
          statement_timeout_ms: 200
          row_limit: 50
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

    let user_sub = format!("test-user-{}", uuid::Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: "rq-e2e@example.com".to_string(),
        groups: vec!["engineers".to_string()],
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
                flows: PendingFlows::default(),
            }),
            config: Arc::new(config_file),
            state_db: Some(pool.clone()),
            pool_registry: PoolRegistry::new(),
        },
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Walk login → return (gateway_url, bearer).
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

async fn call_run_query(
    url: &str,
    bearer: &str,
    server: &str,
    database: &str,
    sql: &str,
    limit: Option<u32>,
) -> Value {
    let mut args = json!({ "server": server, "database": database, "sql": sql });
    if let Some(l) = limit {
        args["limit"] = json!(l);
    }
    client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "run_query", "arguments": args }
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
        .expect("run_query result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

/// Fetch and assert the most recent audit row for the caller's `run_query`
/// matches the expected outcome. CLAUDE.md non-negotiable: every tool
/// dispatch must produce an audited row.
async fn assert_audit_outcome(
    pool: &sqlx::PgPool,
    user_sub: &str,
    expected_outcome: &str,
    label: &str,
) {
    use db_mcp_gateway::audit::latest_for_user_tool;
    let row = latest_for_user_tool(pool, user_sub, "run_query")
        .await
        .expect("audit lookup query runs")
        .unwrap_or_else(|| panic!("no audit row for `{label}` — request was unaudited"));
    assert_eq!(
        row.outcome, expected_outcome,
        "`{label}` audit outcome (got {})",
        row.outcome
    );
}

#[tokio::test]
async fn run_query_full_acceptance() {
    let booted = boot_gateway().await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

    // 1. Quick query: 1 row, not truncated. Audit row: outcome=success.
    let resp = call_run_query(
        url,
        bearer,
        "target",
        "app",
        "SELECT 1::int8 AS n, 'hi'::text AS greeting",
        None,
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["columns"], json!(["n", "greeting"]));
    assert_eq!(body["rows"][0][0], 1);
    assert_eq!(body["rows"][0][1], "hi");
    assert_eq!(body["truncated"], false);
    assert_audit_outcome(pool, sub, "success", "quick SELECT").await;

    // 2. Timeout: pg_sleep(2) under a 200ms grant. Audit row: outcome=timeout.
    let resp = call_run_query(url, bearer, "target", "app", "SELECT pg_sleep(2)", None).await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["code"], "timeout", "{body}");
    assert_audit_outcome(pool, sub, "timeout", "pg_sleep timeout").await;

    // 3. Row cap: generate 1000 rows with caller limit=10 → grant cap 50 →
    //    effective 10 → truncated=true. Audit row: outcome=success (the
    //    query itself succeeded; truncation is a flag, not an error).
    let resp = call_run_query(
        url,
        bearer,
        "target",
        "app",
        "SELECT generate_series(1, 1000)::int8 AS n",
        Some(10),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["rows"].as_array().unwrap().len(), 10);
    assert_eq!(body["truncated"], true);
    assert_audit_outcome(pool, sub, "success", "truncated query").await;

    // 4. Forbidden: `hidden` server is configured but engineer has no grant.
    //    Tool must return `forbidden` — never reveal whether `hidden` exists.
    //    Audit row: outcome=forbidden (CLAUDE.md: failed-authz tools still
    //    leave a row).
    let resp = call_run_query(url, bearer, "hidden", "app", "SELECT 1", None).await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["code"], "forbidden", "{body}");
    assert_audit_outcome(pool, sub, "forbidden", "hidden server").await;

    // 5. Forbidden also when the server name is bogus — same code, same
    //    message: no leakage of existence. Audit row: outcome=forbidden.
    let resp = call_run_query(url, bearer, "nonexistent", "app", "SELECT 1", None).await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(payload(&resp)["code"], "forbidden");
    assert_audit_outcome(pool, sub, "forbidden", "bogus server").await;
}
