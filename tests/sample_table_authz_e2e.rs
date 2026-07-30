//! Authz regression E2E for `sample_table` — the tool returns *row data*, so
//! it must be gated exactly like `run_query`:
//!
//!   1. a `schema_read`-only grant is metadata-only → `forbidden` (this used
//!      to succeed: `sample_table` evaluated `Action::SchemaRead`, which a
//!      bare `schema_read` grant satisfies, leaking table contents),
//!   2. a `query_read` grant samples rows,
//!   3. `constraints.require_reason` blocks a sample without a reason and the
//!      audit row carries the reason when one is supplied.
//!
//! Real Postgres throughout (`bin/dev up` → state DB :5435, target DB :5434).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockUser, spawn_mock_idp};
use db_mcp_gateway::audit::latest_for_user_tool;
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::config::{Config, ConfigFile, Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{AdapterRegistry, DbAdapter, ExecQuery, PgAdapter};
use db_mcp_gateway::state;
use db_mcp_gateway::transport::{self, AppState, AuthFacade, PendingFlows};
use serde_json::{Value, json};

const TOOL: &str = "sample_table";
const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 5434;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

/// One config, three groups: metadata-only, ordinary reader, and a reader
/// whose grant demands a reason. Each test logs in as a user in exactly one
/// of them.
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

permissions:
  - group: metadata-only
    grants:
      - { server: target, database: app, action: schema_read }
  - group: engineers
    grants:
      - { server: target, database: app, action: query_read }
  - group: reason-required
    grants:
      - server: target
        database: app
        action: query_read
        constraints:
          require_reason: true
"#;

struct BootedGateway {
    url: String,
    bearer: String,
    state_db: sqlx::PgPool,
    user_sub: String,
}

async fn boot_gateway(group: &str) -> BootedGateway {
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)");

    let user_sub = format!("test-user-{}", uuid::Uuid::new_v4().simple());
    let user = MockUser {
        sub: user_sub.clone(),
        email: "sample-authz-e2e@example.com".to_string(),
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
    let config_file = ConfigFile::from_yaml_str(E2E_YAML).expect("e2e yaml is well-formed");

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

async fn call_sample_table(booted: &BootedGateway, mut args: Value) -> Value {
    args["server"] = json!("target");
    args["database"] = json!("app");
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", booted.url))
        .bearer_auth(&booted.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": TOOL, "arguments": args }
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
        .expect("sample_table result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

/// The audit row is non-negotiable on every dispatch — fetch the caller's
/// latest `sample_table` row and return it for outcome/reason assertions.
async fn latest_audit(booted: &BootedGateway, label: &str) -> db_mcp_gateway::audit::AuditRow {
    latest_for_user_tool(&booted.state_db, &booted.user_sub, TOOL)
        .await
        .expect("audit lookup query runs")
        .unwrap_or_else(|| panic!("no audit row for `{label}` — request was unaudited"))
}

/// A real table with real rows in a throwaway schema — never a mock: the
/// point is that `sample_table` either does or does not hand these rows back.
struct Fixture {
    adapter: PgAdapter,
    schema: String,
}

impl Fixture {
    async fn create() -> Self {
        let database = Database {
            name: TARGET_DB.to_string(),
            role: TARGET_USER.to_string(),
            password: Password::Literal(TARGET_PASSWORD.into()),
            description: String::new(),
            auth_database: None,
        };
        let server = Server {
            name: "target".to_string(),
            kind: ServerKind::Postgres,
            description: String::new(),
            host: TARGET_HOST.to_string(),
            port: TARGET_PORT,
            tls: Tls::Insecure,
            databases: Vec::new(),
        };
        let adapter = PgAdapter::open(&server, &database)
            .await
            .expect("target-db reachable; run `bin/dev up`");
        let schema = format!("sampleauthz_{}", uuid::Uuid::new_v4().simple());
        let fixture = Self { adapter, schema };
        fixture
            .exec(&format!("CREATE SCHEMA \"{}\"", fixture.schema))
            .await;
        fixture
            .exec(&format!(
                "CREATE TABLE \"{}\".\"customers\" (id int, ssn text)",
                fixture.schema
            ))
            .await;
        fixture
            .exec(&format!(
                "INSERT INTO \"{}\".\"customers\" VALUES (1, '111-11-1111')",
                fixture.schema
            ))
            .await;
        fixture
    }

    async fn exec(&self, sql: &str) {
        self.adapter
            .execute(ExecQuery {
                sql,
                binds: &[],
                statement_timeout_ms: None,
                row_limit: 10,
            })
            .await
            .unwrap_or_else(|e| panic!("fixture SQL failed ({sql}): {e}"));
    }

    async fn drop_schema(&self) {
        self.exec(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .await;
    }
}

/// Regression: a `schema_read` grant is metadata-only. `sample_table` returns
/// rows, so it must deny — with an audited `forbidden` outcome.
#[tokio::test]
async fn schema_read_grant_cannot_sample_rows() {
    let fixture = Fixture::create().await;
    let booted = boot_gateway("metadata-only").await;

    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers" }),
    )
    .await;
    fixture.drop_schema().await;

    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["code"], "forbidden", "{body}");
    assert!(
        !resp.to_string().contains("111-11-1111"),
        "row data leaked to a schema_read-only caller: {resp}"
    );
    assert_eq!(
        latest_audit(&booted, "schema_read sample").await.outcome,
        "forbidden"
    );
}

/// The positive half of the same contract: `query_read` is the grant that
/// actually authorizes row data, and it still works.
#[tokio::test]
async fn query_read_grant_can_sample_rows() {
    let fixture = Fixture::create().await;
    let booted = boot_gateway("engineers").await;

    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers" }),
    )
    .await;
    fixture.drop_schema().await;

    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["columns"], json!(["id", "ssn"]));
    assert_eq!(body["rows"][0][0], 1);
    assert_eq!(body["rows"][0][1], "111-11-1111");
    assert_eq!(
        latest_audit(&booted, "query_read sample").await.outcome,
        "success"
    );
}

/// `require_reason` must not be dodgeable by sampling instead of querying:
/// no reason → `reason_required` and no rows; with a reason → success, and
/// the reason lands in the audit row.
#[tokio::test]
async fn require_reason_grant_blocks_sample_without_reason() {
    let fixture = Fixture::create().await;
    let booted = boot_gateway("reason-required").await;

    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers" }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(payload(&resp)["code"], "reason_required", "{resp}");
    assert!(
        !resp.to_string().contains("111-11-1111"),
        "row data returned despite require_reason: {resp}"
    );
    let row = latest_audit(&booted, "sample without reason").await;
    assert_eq!(row.outcome, "reason_required");
    assert_eq!(row.reason, None);

    // Empty string is not a reason.
    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers", "reason": "" }),
    )
    .await;
    assert_eq!(payload(&resp)["code"], "reason_required", "{resp}");

    let resp = call_sample_table(
        &booted,
        json!({
            "schema": fixture.schema,
            "table": "customers",
            "reason": "ticket OPS-42 data shape check"
        }),
    )
    .await;
    fixture.drop_schema().await;

    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let row = latest_audit(&booted, "sample with reason").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(
        row.reason.as_deref(),
        Some("ticket OPS-42 data shape check")
    );
}
