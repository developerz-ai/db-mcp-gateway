//! End-to-end test for `explain`: login via mock OIDC, call `tools/call
//! explain` with a SELECT (success) and with a DELETE (must be rejected by
//! the AST guard with `forbidden_sql`). Asserts audit row exists with the
//! correct outcome in each case.

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

/// Same `target` server as the run_query e2e but no constraints — `explain`
/// shouldn't need a row cap and we want any timeout out of the way.
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
  - group: engineers
    grants:
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

    let user_sub = format!("test-user-{}", uuid::Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: "explain-e2e@example.com".to_string(),
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
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
        },
    );
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

async fn call_explain(url: &str, bearer: &str, sql: &str) -> Value {
    client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "explain",
                "arguments": { "server": "target", "database": "app", "sql": sql }
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
        .expect("explain result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

async fn assert_audit(pool: &sqlx::PgPool, user_sub: &str, expected: &str, label: &str) {
    use db_mcp_gateway::audit::latest_for_user_tool;
    let row = latest_for_user_tool(pool, user_sub, "explain")
        .await
        .expect("audit lookup runs")
        .unwrap_or_else(|| panic!("no audit row for `{label}` — request was unaudited"));
    assert_eq!(
        row.outcome, expected,
        "`{label}` outcome (got {})",
        row.outcome
    );
}

#[tokio::test]
async fn explain_full_acceptance() {
    let booted = boot_gateway().await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

    // 1. Happy path: EXPLAIN of a SELECT returns a plan with a Node Type.
    let resp = call_explain(url, bearer, "SELECT 1").await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert!(
        body["plan"][0]["Plan"]["Node Type"].is_string(),
        "plan shape unexpected: {body}"
    );
    assert_audit(pool, sub, "success", "EXPLAIN SELECT 1").await;

    // 2. AST guard: EXPLAIN of a DELETE must be rejected pre-DB. Even
    //    though Postgres' EXPLAIN-without-ANALYZE doesn't execute, we stay
    //    conservative — see `exec::sql_guard`. Audit records the rejection.
    let resp = call_explain(url, bearer, "DELETE FROM users").await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(payload(&resp)["code"], "forbidden_sql");
    assert_audit(pool, sub, "forbidden_sql", "EXPLAIN DELETE").await;

    // 3. Forbidden when caller has no grant on the (server, database).
    let resp = client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "explain",
                "arguments": { "server": "nonexistent", "database": "app", "sql": "SELECT 1" }
            }
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(payload(&resp)["code"], "forbidden");
    assert_audit(pool, sub, "forbidden", "EXPLAIN forbidden server").await;
}
