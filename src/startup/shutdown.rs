//! The stages of a shutdown, and the sequence that runs them once the server
//! has stopped.

use std::time::Duration;

use db_mcp_gateway::audit::drain::{DRAIN_TIMEOUT, DetachedTasks};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

const POOL_CLOSE_BOUND: Duration = Duration::from_secs(10);

/// One token per stage, cancelled in field order. What a task still has to
/// see decides which one it follows.
#[derive(Debug, Clone, Default)]
pub(crate) struct Shutdown {
    /// The signal arrived: probes go 503, and the background loops and the
    /// SIGHUP loop end.
    pub(crate) stop: CancellationToken,
    /// In-flight requests are drained. Work they still depend on runs until
    /// then: the permissions listener keeps applying revocations.
    pub(crate) drained: CancellationToken,
    /// Detached audit work is drained and the pools are closed. Metrics run
    /// until then — listener, recorder upkeep, samplers — so an audit write
    /// that fails during the drain can still be scraped.
    pub(crate) finished: CancellationToken,
}

impl Shutdown {
    /// Run after `serve` returned, i.e. once the drain window closed: let
    /// detached audit writes finish (bounded), then close the pools so
    /// in-flight state-DB statements complete instead of being cut at exit.
    /// `stop` is cancelled here too, in case `serve` returned on an error.
    pub(crate) async fn finish(
        &self,
        detached: &DetachedTasks,
        pools: impl IntoIterator<Item = (&'static str, PgPool)>,
    ) {
        self.stop.cancel();
        self.drained.cancel();
        if let Err(error) = detached.drain(DRAIN_TIMEOUT).await {
            tracing::error!(%error, "detached audit work still running at shutdown; the reaper will mark it abandoned");
        }
        for (name, pool) in pools {
            close_pool(name, pool).await;
        }
        self.finished.cancel();
    }
}

/// Close a state-DB pool, bounded so a wedged connection cannot hold the pod
/// past its termination grace period.
async fn close_pool(name: &'static str, pool: PgPool) {
    if tokio::time::timeout(POOL_CLOSE_BOUND, pool.close())
        .await
        .is_err()
    {
        tracing::warn!(pool = name, "state DB pool did not close within bound");
    }
}
