//! Gateways with no reachable IdP or state DB: wire-protocol, discovery and
//! service-token tests.

use std::time::Duration;

use db_mcp_gateway::auth::oauth::RefreshTokens;
use db_mcp_gateway::auth::{AuthConfig, ServiceTokenStore};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport::{self, AppState};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::gateway::{auth_facade, bind, config_file, serve};

/// No servers, no grants: for tests that never dispatch a DB tool.
pub const EMPTY_YAML: &str = "servers: []\npermissions: []\n";

/// Static bearer of the one service account in [`SERVICE_YAML`]: it
/// authenticates with no state DB, so offline gateways can reach `/mcp`.
pub const SERVICE_TOKEN: &str =
    "dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333";
pub const SERVICE_YAML: &str = "servers: []
permissions:
  - group: svc-transport
    grants: []
service_accounts:
  - name: transport-bot
    group: svc-transport
    token: dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333
";

/// A state pool that points nowhere: anything touching it fails like an
/// outage, after a short acquire timeout.
fn offline_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy_with(PgConnectOptions::new().host("offline.invalid"))
}

/// No reachable IdP or state DB, empty config: wire-protocol and discovery
/// tests. The OAuth metadata advertises `base_url` (the configured
/// `OIDC_REDIRECT_URL` origin is the gateway's public base).
pub fn offline_state(base_url: &str, yaml: &str) -> AppState {
    let auth_config = AuthConfig {
        issuer: "http://idp.invalid".to_string(),
        redirect_url: format!("{base_url}/auth/callback"),
        ..AuthConfig::default()
    };
    let config = config_file(yaml);
    let service_tokens = ServiceTokenStore::from_config(&config.service_accounts)
        .expect("fixture tokens satisfy the boot rules");
    let pool = offline_pool();
    let auth = auth_facade(
        &pool,
        &auth_config,
        RefreshTokens::default(),
        service_tokens,
    );
    AppState::for_tests(config, pool, auth)
}

/// [`offline_state`] with an empty config, for tests that never read the
/// advertised base URL.
pub fn authless_state() -> AppState {
    offline_state("http://localhost:8443", EMPTY_YAML)
}

/// Offline gateway with `config` (whose `bind` is overwritten with the real
/// address); returns the base URL.
pub async fn spawn_authless(config: Config) -> String {
    spawn_offline(config, EMPTY_YAML).await
}

/// [`spawn_authless`] serving `yaml` — e.g. `service_accounts:`, whose static
/// bearers authenticate with no state DB.
pub async fn spawn_offline(config: Config, yaml: &str) -> String {
    let (listener, addr) = bind().await;
    let url = format!("http://{addr}");
    let config = Config {
        bind: addr,
        ..config
    };
    let app = transport::router(&config, offline_state(&url, yaml)).expect("router builds");
    serve(listener, app);
    url
}
