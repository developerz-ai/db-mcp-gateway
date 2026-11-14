//! Config hot reload (plan 101 slice 10 step 1): `config::reload::reload` swaps
//! the live config, service tokens and sinks atomically — or, on any error,
//! leaves all of them as they were. The SIGHUP wiring around it is unit-tested
//! in `src/startup/reload_tests.rs`.
//!
//! The grant-removal case writes audit rows to the real state DB; run under
//! the shared DB lock.

use std::sync::Arc;

use crate::common::audit::assert_audit_outcome;
use crate::common::env::state_pool;
use arc_swap::ArcSwap;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use db_mcp_gateway::auth::jwt::SessionJwt;
use db_mcp_gateway::auth::oauth::{AuthCodes, AuthFacade, PendingFlows, RefreshTokens};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, ServiceTokenStore, SessionStore};
use db_mcp_gateway::config::reload::{ReloadError, ReloadTargets, reload};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::transport::{self, AppState};
use sqlx::PgPool;
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TOKEN: &str = "dbmcp_svc_5555555555555555555555555555555555555555555555555555555555555555";
const SUB: &str = "service:reload-bot";

/// One postgres server, a service account, and (optionally) its grant.
fn yaml(host: &str, with_grant: bool, with_account: bool) -> String {
    let grants = if with_grant {
        "\n      - { server: s, database: d, action: schema_read }"
    } else {
        " []"
    };
    let accounts = if with_account {
        format!(
            "service_accounts:\n  - {{ name: reload-bot, group: svc-reload, token: {TOKEN} }}\n"
        )
    } else {
        String::new()
    };
    format!(
        "servers:\n  - name: s\n    kind: postgres\n    host: {host}\n    databases:\n      - {{ name: d, role: ro, password: \"${{ENV:PATH}}\" }}\npermissions:\n  - group: svc-reload\n    grants:{grants}\n{accounts}"
    )
}

struct Harness {
    file: NamedTempFile,
    state: AppState,
    targets: ReloadTargets,
}

impl Harness {
    fn new(pool: PgPool, initial: &str) -> Self {
        let file = NamedTempFile::new().expect("temp config");
        std::fs::write(file.path(), initial).expect("write config");
        let config = ConfigFile::load(file.path()).expect("initial config loads");
        let auth_config = AuthConfig {
            issuer: "http://idp.invalid".to_string(),
            client_id: "test".to_string(),
            ..AuthConfig::default()
        };
        let tokens = ServiceTokenStore::from_config(&config.service_accounts).expect("tokens");
        let auth = AuthFacade {
            jwt: SessionJwt::new(&auth_config.session_signing_key),
            config: Arc::new(auth_config.clone()),
            sessions: SessionStore::new(pool.clone()),
            oidc: OidcClient::new(auth_config).expect("oidc client"),
            flows: PendingFlows::default(),
            codes: AuthCodes::default(),
            refresh: RefreshTokens::default(),
            service_tokens: Arc::new(ArcSwap::from_pointee(tokens)),
        };
        let state = AppState::for_tests(config, pool, auth);
        let targets = ReloadTargets {
            path: file.path().to_path_buf(),
            config: state.mcp.config.clone(),
            audit_sinks: state.mcp.audit_sinks.clone(),
            service_tokens: state.oauth.auth.service_tokens.clone(),
            permissions_cache: state.mcp.permissions_cache.clone(),
            adapter_registry: state.mcp.adapter_registry.clone(),
        };
        Self {
            file,
            state,
            targets,
        }
    }

    fn rewrite(&self, contents: &str) {
        std::fs::write(self.file.path(), contents).expect("rewrite config");
    }

    async fn list_databases(&self) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_databases","arguments":{"server":"s"}}}"#,
            ))
            .expect("request");
        let router = transport::router(&Config::default(), self.state.clone()).expect("router");
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn host(&self) -> String {
        self.state.mcp.config.load().servers[0].host.clone()
    }
}

/// A pool that is never connected: these cases touch no database.
fn offline_pool() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy_with(sqlx::postgres::PgConnectOptions::new().host("offline.invalid"))
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn invalid_file_keeps_the_running_config() {
    let gw = Harness::new(offline_pool(), &yaml("h1", true, true));

    for broken in [
        "servers: [".to_string(),
        format!("{}\nunknown_section: 1\n", yaml("h2", true, true)),
        yaml("h2", true, true).replace("${ENV:PATH}", "${ENV:DB_MCP_RELOAD_TEST_UNSET}"),
        yaml("h2", true, true).replace(TOKEN, "dbmcp_svc_weak"),
    ] {
        gw.rewrite(&broken);
        assert!(reload(&gw.targets).await.is_err(), "accepted: {broken}");
        assert_eq!(gw.host(), "h1", "config half-applied from: {broken}");
        assert!(
            gw.targets
                .service_tokens
                .load()
                .authenticate(TOKEN)
                .is_some(),
            "service tokens swapped from: {broken}"
        );
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn boot_fixed_settings_are_refused_whole() {
    let gw = Harness::new(offline_pool(), &yaml("h1", true, true));
    gw.rewrite(&format!(
        "{}admin: {{ enabled: true, group: admins }}\n",
        yaml("h2", true, true)
    ));
    assert!(matches!(
        reload(&gw.targets).await,
        Err(ReloadError::BootFixed("admin"))
    ));
    assert_eq!(gw.host(), "h1");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn removed_service_account_gets_401_after_reload() {
    let gw = Harness::new(offline_pool(), &yaml("h1", true, true));
    let (before, _) = gw.list_databases().await;
    assert_ne!(before, StatusCode::UNAUTHORIZED);

    gw.rewrite(&yaml("h1", true, false));
    reload(&gw.targets).await.expect("reload");

    let (after, _) = gw.list_databases().await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn changed_host_evicts_exactly_that_pool() {
    let gw = Harness::new(offline_pool(), &yaml("h1", true, true));

    gw.rewrite(&yaml("h1", false, true));
    assert_eq!(reload(&gw.targets).await.expect("grant-only change"), 0);

    gw.rewrite(&yaml("h2", false, true));
    assert_eq!(reload(&gw.targets).await.expect("host change"), 1);
    assert_eq!(gw.host(), "h2");
}

/// Real state DB: the call is audited before and after the reload.
#[tokio::test]
#[serial_test::parallel(world)]
async fn removed_grant_is_forbidden_after_reload() {
    let gw = Harness::new(state_pool().await, &yaml("h1", true, true));
    let (_, before) = gw.list_databases().await;
    assert!(
        before.contains(r#"\"name\":\"d\""#),
        "grant not honoured: {before}"
    );
    assert_audit_outcome(
        &gw.state.mcp.state_db,
        SUB,
        "list_databases",
        "success",
        "before reload",
    )
    .await;

    gw.rewrite(&yaml("h1", false, true));
    reload(&gw.targets).await.expect("reload");

    let (_, after) = gw.list_databases().await;
    assert!(
        after.contains("forbidden"),
        "grant survived reload: {after}"
    );
    assert_audit_outcome(
        &gw.state.mcp.state_db,
        SUB,
        "list_databases",
        "forbidden",
        "after reload",
    )
    .await;
}
