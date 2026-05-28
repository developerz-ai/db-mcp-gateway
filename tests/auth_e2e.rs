//! End-to-end auth test: drive the full login flow against an in-process mock
//! IdP, mint a session JWT, and call a real MCP tool with the bearer.
//!
//! Requires a running state Postgres (`bin/dev up`); see CLAUDE.md.

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

/// Config the e2e booted gateway sees. The user logs in with groups
/// `[engineers, oncall]`, so `engineers` grants visibility on `prod`,
/// `oncall` on `staging`. `analytics` is visible to neither and must be
/// filtered out of `list_servers`. The literal `hunter2` is in the YAML
/// so we can assert end-to-end that it never reaches the wire.
const E2E_CONFIG_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: E2E prod
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
  - name: staging
    kind: postgres
    description: E2E staging
    host: staging.example.invalid
    databases:
      - { name: app, role: ro, password: stagingpw }
  - name: analytics
    kind: mysql
    description: E2E analytics
    host: analytics.example.invalid
    databases:
      - { name: dw, role: ro, password: dwpw }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: schema_read }
  - group: oncall
    grants:
      - { server: staging, database: "*", action: query_read }
"#;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

#[tokio::test]
async fn login_via_mock_idp_then_call_tool() {
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)");
    // Don't TRUNCATE: tests must coexist with each other and any dev rows.

    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "e2e@example.com".to_string(),
        groups: vec!["engineers".into(), "oncall".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user.clone()).await;

    // Bind the gateway first so we know our redirect URL.
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
    let config_file = ConfigFile::from_yaml_str(E2E_CONFIG_YAML).expect("e2e yaml is well-formed");
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
            pool_registry: PoolRegistry::new(),
            state_db: Some(pool),
        },
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // 1. Start the flow: gateway hands back the IdP authorize URL.
    let login: Value = client
        .post(format!("{gateway_url}/auth/login"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = login["login_url"]
        .as_str()
        .expect("login_url string")
        .to_string();

    // 2. Simulate the browser hitting the IdP; mock redirects to our callback.
    let authorize = client.get(&login_url).send().await.unwrap();
    assert!(authorize.status().is_redirection());
    let callback = authorize
        .headers()
        .get("location")
        .expect("authorize sets Location")
        .to_str()
        .unwrap()
        .to_string();

    // 3. Our callback: exchange + verify + mint session JWT.
    let cb: Value = client
        .get(&callback)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = cb["session_token"]
        .as_str()
        .expect("session_token string")
        .to_string();
    assert!(!session_token.is_empty());

    // 4. With the bearer, tools/call list_servers returns the caller's
    //    visible servers — and only those. User is in `engineers + oncall`,
    //    so they see `prod` + `staging`, never `analytics`. Crucially, the
    //    literal password `hunter2` from the YAML must not appear anywhere
    //    in the wire response.
    let resp: Value = client
        .post(format!("{gateway_url}/mcp"))
        .bearer_auth(&session_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "list_servers" }
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let payload = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("list_servers result is JSON-stringified text content");
    assert!(payload.contains("\"name\":\"prod\""), "{payload}");
    assert!(payload.contains("\"name\":\"staging\""), "{payload}");
    assert!(!payload.contains("\"name\":\"analytics\""), "{payload}");
    let full_response = serde_json::to_string(&resp).unwrap();
    for forbidden in ["hunter2", "stagingpw", "dwpw"] {
        assert!(
            !full_response.contains(forbidden),
            "leak: `{forbidden}` appeared in tool response: {full_response}"
        );
    }

    // 5. Without a bearer, the same call → 401 with the full unauth contract:
    //    structured error.category/code and a login_url for the agent.
    let unauth = client
        .post(format!("{gateway_url}/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "list_servers" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);
    let unauth_body: Value = unauth.json().await.unwrap();
    assert_eq!(unauth_body["error"]["category"], "unauthenticated");
    assert_eq!(unauth_body["error"]["code"], "missing_bearer");
    assert_eq!(unauth_body["login_url"], "/auth/login");

    // 6. Logout revokes; subsequent call → 401 (same contract, code differs).
    let logout = client
        .post(format!("{gateway_url}/auth/logout"))
        .bearer_auth(&session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), reqwest::StatusCode::NO_CONTENT);

    let after_logout = client
        .post(format!("{gateway_url}/mcp"))
        .bearer_auth(&session_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "list_servers" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(after_logout.status(), reqwest::StatusCode::UNAUTHORIZED);
    let after_body: Value = after_logout.json().await.unwrap();
    assert_eq!(after_body["error"]["category"], "unauthenticated");
    assert_eq!(after_body["error"]["code"], "revoked_session");
    assert_eq!(after_body["login_url"], "/auth/login");
}
