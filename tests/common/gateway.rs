//! Boot a real gateway router on an ephemeral port. Every `AppState` and
//! `AuthConfig` literal in the test tree lives here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use db_mcp_gateway::auth::oauth::{
    AuthCodes, AuthFacade, ClientRegistry, PendingFlows, RefreshTokens,
};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, ServiceTokenStore, SessionStore};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{AdminBlock, Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::transport::{self, AppState};
use serde_json::Value;
use sqlx::PgPool;
use tokio::net::TcpListener;

use super::env::state_pool;
use super::idp::{MockIdpHandle, MockUser, spawn_mock_idp};

/// No servers, no grants: for tests that never dispatch a DB tool.
pub const EMPTY_YAML: &str = "servers: []\npermissions: []\n";

pub fn config_file(yaml: &str) -> ConfigFile {
    ConfigFile::from_yaml_str(yaml).expect("e2e yaml is well-formed")
}

/// The single `AppState` literal. Optional parts (cache, repo, metrics) are
/// `None`; callers set the public fields they need.
pub fn app_state(
    config: ConfigFile,
    state_db: Option<PgPool>,
    auth: Option<AuthFacade>,
) -> AppState {
    AppState {
        auth,
        config: Arc::new(config),
        adapter_registry: AdapterRegistry::new(),
        state_db,
        shutdown: Default::default(),
        metrics: None,
        permissions_cache: None,
        permissions_repo: None,
        mcp_path: Arc::from("/mcp"),
        client_registry: ClientRegistry::default(),
    }
}

/// No auth, no state DB, empty config: wire-protocol and discovery tests.
pub fn authless_state() -> AppState {
    app_state(config_file(EMPTY_YAML), None, None)
}

/// Bind `127.0.0.1:0`; returns the listener and its resolved address.
pub async fn bind() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("listener address");
    (listener, addr)
}

/// Serve `app` on `listener` in a background task.
pub fn serve(listener: TcpListener, app: Router) {
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
}

/// Authless gateway with `config` (whose `bind` is overwritten with the real
/// address); returns the base URL.
pub async fn spawn_authless(config: Config) -> String {
    let (listener, addr) = bind().await;
    let config = Config {
        bind: addr,
        ..config
    };
    let app = transport::router(&config, authless_state()).expect("router builds");
    serve(listener, app);
    format!("http://{addr}")
}

/// HTTP client that never follows redirects, so each OAuth hop is assertable.
pub fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// OIDC client fields a gateway uses to reach its IdP.
#[derive(Clone, Debug)]
struct IdpClient {
    issuer: String,
    client_id: String,
    client_secret: String,
}

impl IdpClient {
    /// Placeholder IdP for tests that mint sessions directly and never log in.
    fn unreachable() -> Self {
        Self {
            issuer: "http://idp.invalid".to_string(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
        }
    }
}

/// Builder for an authenticated gateway backed by the real state DB.
#[derive(Debug)]
pub struct GatewayBuilder {
    yaml: String,
    idp: IdpClient,
    admin: Option<AdminBlock>,
    cache: Option<PermissionsCache>,
    repo: Option<Arc<dyn PermissionsRepo>>,
    refresh: RefreshTokens,
}

impl GatewayBuilder {
    pub fn new(yaml: &str) -> Self {
        Self {
            yaml: yaml.to_string(),
            idp: IdpClient::unreachable(),
            admin: None,
            cache: None,
            repo: None,
            refresh: RefreshTokens::default(),
        }
    }

    pub fn idp(mut self, idp: &MockIdpHandle) -> Self {
        self.idp = IdpClient {
            issuer: idp.issuer.clone(),
            client_id: idp.client_id.clone(),
            client_secret: idp.client_secret.clone(),
        };
        self
    }

    /// Override the YAML `admin:` block with `group`, mounted iff `enabled`.
    pub fn admin(mut self, group: &str, enabled: bool) -> Self {
        self.admin = Some(AdminBlock {
            enabled,
            group: group.to_string(),
            session_max_age_secs: None,
        });
        self
    }

    pub fn cache(mut self, cache: PermissionsCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn repo(mut self, repo: Arc<dyn PermissionsRepo>) -> Self {
        self.repo = Some(repo);
        self
    }

    /// Share a refresh-token store with the test so it can edit chain state.
    pub fn refresh(mut self, refresh: RefreshTokens) -> Self {
        self.refresh = refresh;
        self
    }

    pub async fn spawn(self, pool: PgPool) -> TestGateway {
        let (listener, addr) = bind().await;
        let url = format!("http://{addr}");
        let auth_config = AuthConfig {
            issuer: self.idp.issuer,
            client_id: self.idp.client_id.clone(),
            client_secret: self.idp.client_secret,
            audience: self.idp.client_id,
            redirect_url: format!("{url}/auth/callback"),
            ..AuthConfig::default()
        };
        let sessions = SessionStore::new(pool.clone());
        let oidc = OidcClient::new(auth_config.clone()).expect("OidcClient http builder");

        let mut config_file = config_file(&self.yaml);
        if self.admin.is_some() {
            config_file.admin = self.admin;
        }
        let service_tokens = ServiceTokenStore::from_config(&config_file.service_accounts)
            .expect("fixture tokens satisfy the boot rules");
        let auth = AuthFacade {
            config: Arc::new(auth_config.clone()),
            sessions: sessions.clone(),
            oidc,
            flows: PendingFlows::default(),
            codes: AuthCodes::default(),
            refresh: self.refresh,
            service_tokens,
        };
        let mut state = app_state(config_file, Some(pool.clone()), Some(auth));
        state.permissions_cache = self.cache;
        state.permissions_repo = self.repo;

        let config = Config {
            bind: addr,
            ..Config::default()
        };
        serve(
            listener,
            transport::router(&config, state).expect("router builds"),
        );
        TestGateway {
            url,
            state_db: pool,
            auth_config,
            sessions,
        }
    }
}

/// A running gateway. `auth_config` carries the session signing key so tests
/// can mint bearers without the OIDC round-trip.
#[derive(Debug)]
pub struct TestGateway {
    pub url: String,
    pub state_db: PgPool,
    pub auth_config: AuthConfig,
    pub sessions: SessionStore,
}

/// A gateway plus a bearer obtained through the full mock-OIDC login.
#[derive(Debug)]
pub struct LoggedInGateway {
    pub url: String,
    pub bearer: String,
    pub state_db: PgPool,
    pub user_sub: String,
}

/// Boot a gateway on `yaml` and log `user` in through a fresh mock IdP.
pub async fn spawn_logged_in(yaml: &str, user: MockUser) -> LoggedInGateway {
    let pool = state_pool().await;
    let user_sub = user.sub.clone();
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let gw = GatewayBuilder::new(yaml).idp(&idp).spawn(pool).await;
    let bearer = login(&gw.url).await;
    LoggedInGateway {
        url: gw.url,
        bearer,
        state_db: gw.state_db,
        user_sub,
    }
}

/// Walk `/auth/login` → IdP authorize → `/auth/callback`; returns the
/// session bearer.
pub async fn login(gateway_url: &str) -> String {
    let client = no_redirect_client();
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
    cb["session_token"].as_str().unwrap().to_string()
}
