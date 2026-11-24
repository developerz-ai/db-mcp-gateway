//! The target pool series every adapter publishes (Postgres tiers, Mongo,
//! Redis): `pool_size`, `pool_connections_in_use`, `pool_connections_idle`,
//! sampled on a timer while the pool lives, and `pool_acquire_wait_seconds`
//! per acquire. Sampling, not set-on-change: a quiet pool's gauges stay
//! inside the recorder's idle timeout and still read its true state, and a
//! dropped pool's stop being refreshed and leave the scrape (plan 101 O3).
//! Lives beside the Postgres tiers; the other adapters reach it the way they
//! reach `resolve_password`.

use std::sync::Weak;
use std::time::Duration;

use metrics::{gauge, histogram};

/// Far inside the recorder's one-hour idle timeout.
const SAMPLE_EVERY: Duration = Duration::from_secs(15);

/// One pool's state at a sample.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PoolSample {
    pub(crate) max: u32,
    pub(crate) in_use: u32,
    /// `None` where the driver does not expose it (Mongo).
    pub(crate) idle: Option<u32>,
}

/// Publish `sample(source)` every [`SAMPLE_EVERY`], the first at once, until
/// `source` is dropped. The sampler holds only a `Weak`, so it never keeps a
/// pool open.
pub(crate) fn spawn_sampler<T, F>(source: Weak<T>, sample: F)
where
    T: Send + Sync + 'static,
    F: Fn(&T) + Send + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SAMPLE_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(source) = source.upgrade() else {
                return;
            };
            sample(&source);
        }
    });
}

/// `db` is the configured `server/database`; `pool_kind` a fixed word.
pub(crate) fn publish(db: &str, pool_kind: &'static str, sample: PoolSample) {
    gauge!("pool_size", "db" => db.to_owned(), "pool_kind" => pool_kind).set(f64::from(sample.max));
    gauge!("pool_connections_in_use", "db" => db.to_owned(), "pool_kind" => pool_kind)
        .set(f64::from(sample.in_use));
    if let Some(idle) = sample.idle {
        gauge!("pool_connections_idle", "db" => db.to_owned(), "pool_kind" => pool_kind)
            .set(f64::from(idle));
    }
}

/// How long one acquire waited, whether it got a connection or timed out.
pub(crate) fn record_acquire_wait(db: &str, pool_kind: &'static str, waited: Duration) {
    histogram!("pool_acquire_wait_seconds", "db" => db.to_owned(), "pool_kind" => pool_kind)
        .record(waited.as_secs_f64());
}

/// A sqlx pool's sample: open connections not idle are in use.
pub(crate) fn sqlx_sample<DB: sqlx::Database>(pool: &sqlx::Pool<DB>) -> PoolSample {
    let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
    PoolSample {
        max: pool.options().get_max_connections(),
        in_use: pool.size().saturating_sub(idle),
        idle: Some(idle),
    }
}

/// A permit-gated pool's sample (Mongo, Redis): leased permits are
/// connections in use.
pub(crate) fn permits_sample(
    permits: &tokio::sync::Semaphore,
    max: u32,
    idle: Option<u32>,
) -> PoolSample {
    let free = u32::try_from(permits.available_permits()).unwrap_or(u32::MAX);
    PoolSample {
        max,
        in_use: max.saturating_sub(free),
        idle,
    }
}
