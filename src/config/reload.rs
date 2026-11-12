//! SIGHUP config reload (spec 08 §Hot reload): load → validate → resolve
//! secrets → build service tokens, then one swap of each live handle. Any
//! failure before the swap keeps the running config; nothing is half-applied.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::audit::stream::StreamSinks;
use crate::auth::{ServiceTokenError, ServiceTokenStore};
use crate::authz::PermissionsCache;
use crate::exec::AdapterRegistry;
use crate::state::permissions::PermissionsChange;

use super::{ConfigFile, ConfigLoadError};

/// The live handles a reload swaps. Clones of the ones `AppState` serves from.
#[derive(Clone, Debug)]
pub struct ReloadTargets {
    pub path: PathBuf,
    pub config: Arc<ArcSwap<ConfigFile>>,
    pub audit_sinks: Arc<ArcSwap<StreamSinks>>,
    pub service_tokens: Arc<ArcSwap<ServiceTokenStore>>,
    pub permissions_cache: PermissionsCache,
    pub adapter_registry: AdapterRegistry,
}

/// Why a reload left the running config in place. `Display` names files,
/// env vars and settings — never a config byte or a secret value.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error(transparent)]
    Load(#[from] ConfigLoadError),
    #[error(transparent)]
    ServiceTokens(#[from] ServiceTokenError),
    #[error("`{0}` is fixed at boot; restart the gateway to change it")]
    BootFixed(&'static str),
    #[error("config load task failed")]
    Join(#[from] tokio::task::JoinError),
}

/// Reload from `targets.path`. On success every handle holds the new config;
/// on error none changed. Returns the number of target pools evicted.
pub async fn reload(targets: &ReloadTargets) -> Result<usize, ReloadError> {
    let result = apply(targets).await;
    let outcome = if result.is_ok() { "ok" } else { "error" };
    metrics::counter!("config_reloads_total", "result" => outcome).increment(1);
    result
}

async fn apply(targets: &ReloadTargets) -> Result<usize, ReloadError> {
    let new = load_off_runtime(&targets.path).await?;
    let current = targets.config.load_full();
    if let Some(setting) = current.boot_fixed_change(&new) {
        return Err(ReloadError::BootFixed(setting));
    }
    let tokens = ServiceTokenStore::from_config(&new.service_accounts)?;
    let sinks = StreamSinks::from_config(&new.logging.stream);
    let changed = current.changed_databases(&new);

    // Point of no return: nothing below can fail.
    targets.config.store(Arc::new(new));
    targets.service_tokens.store(Arc::new(tokens));
    targets.audit_sinks.store(Arc::new(sinks));
    targets
        .permissions_cache
        .apply(&PermissionsChange::All)
        .await;
    for (server, database) in &changed {
        targets.adapter_registry.evict(server, database).await;
    }
    Ok(changed.len())
}

/// `ConfigFile::load` reads files (the config and `${FILE:…}` secrets) with
/// blocking I/O; keep it off the runtime workers.
async fn load_off_runtime(path: &Path) -> Result<ConfigFile, ReloadError> {
    let path = path.to_path_buf();
    Ok(tokio::task::spawn_blocking(move || ConfigFile::load(&path)).await??)
}
