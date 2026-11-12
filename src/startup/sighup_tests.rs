//! SIGHUP with TLS off reloads the config instead of killing the process (the
//! signal's default disposition did, before the handler was always installed).

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use db_mcp_gateway::audit::stream::StreamSinks;
use db_mcp_gateway::auth::ServiceTokenStore;
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::reload::ReloadTargets;
use db_mcp_gateway::config::{ConfigFile, TlsConfig};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use tokio_util::sync::CancellationToken;

use super::spawn_reload_on_sighup;

fn yaml(host: &str) -> String {
    format!("servers:\n  - {{ name: s, kind: postgres, host: {host} }}\n")
}

#[tokio::test]
async fn sighup_with_tls_off_reloads_and_keeps_running() {
    let file = tempfile::NamedTempFile::new().expect("temp config");
    std::fs::write(file.path(), yaml("h1")).expect("write");
    let config = ConfigFile::load(file.path()).expect("loads");
    // Never connected: the reload only invalidates the cache's slots.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy_with(sqlx::postgres::PgConnectOptions::new().host("offline.invalid"));
    let targets = ReloadTargets {
        path: file.path().to_path_buf(),
        audit_sinks: Arc::new(ArcSwap::from_pointee(StreamSinks::from_config(&[]))),
        config: Arc::new(ArcSwap::from_pointee(config)),
        service_tokens: Arc::new(ArcSwap::from_pointee(ServiceTokenStore::default())),
        permissions_cache: PermissionsCache::new(
            Arc::new(PgPermissionsRepo::new(pool)),
            Duration::from_secs(60),
        ),
        adapter_registry: AdapterRegistry::new(),
    };
    let live = targets.config.clone();
    let stop = CancellationToken::new();
    spawn_reload_on_sighup(TlsConfig::Disabled, None, targets, stop.clone()).expect("handler");

    std::fs::write(file.path(), yaml("h2")).expect("rewrite");
    // SAFETY: tokio installed a SIGHUP handler above; raising it signals this
    // process only, and no other test in this binary listens for it.
    assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while live.load().servers[0].host != "h2" {
        assert!(
            tokio::time::Instant::now() < deadline,
            "config not reloaded on SIGHUP"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.cancel();
}
