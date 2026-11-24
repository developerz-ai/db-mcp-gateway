//! `state_db_pool_*`: the gateway's own pools (request, background, MySQL
//! permissions store), sampled on a timer like the target pools.

use std::time::Duration;

use metrics::gauge;
use sqlx::{Database, Pool};
use tokio_util::sync::CancellationToken;

/// Same cadence as the target pool samplers, well inside the idle timeout.
pub(crate) const SAMPLE_EVERY: Duration = Duration::from_secs(15);

/// Sample `pool` as `pool="<name>"` until `shutdown` or the pool closes.
pub(crate) fn spawn_state_pool_sampler<DB: Database>(
    name: &'static str,
    pool: Pool<DB>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SAMPLE_EVERY);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    if pool.is_closed() {
                        return;
                    }
                    publish(name, &pool);
                }
            }
        }
    });
}

fn publish<DB: Database>(name: &'static str, pool: &Pool<DB>) {
    let open = pool.size();
    let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
    gauge!("state_db_pool_size", "pool" => name)
        .set(f64::from(pool.options().get_max_connections()));
    gauge!("state_db_pool_connections_in_use", "pool" => name)
        .set(f64::from(open.saturating_sub(idle)));
    gauge!("state_db_pool_connections_idle", "pool" => name).set(f64::from(idle));
}
