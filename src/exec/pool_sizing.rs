//! Per-`(server, database)` connection-pool sizing, shared by every adapter.
//!
//! Pools are lazy and shrink to nothing: `min_connections` defaults to 0 and
//! idle connections close after `idle_timeout`, so an idle gateway holds no
//! target connection at all.
//!
//! A pool is also shared out: [`CallerSlots`] keeps any one caller from
//! holding every connection of a database.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::config::{Database, PoolConfig, Server};

use super::adapter::{Caller, ExecError, current_caller};

/// Default upper bound on one database's query pool.
///
/// Sized from the 2026-11-12 production baseline (plan 101,
/// `01-live-baseline.md`): the busier deployment ran 104 tool calls in 11.9
/// days (≤ 24/day, 3 users) at p95 100 ms, the other none — concurrency per
/// database is effectively 0–1. Four covers an agent fanning a few queries
/// out in parallel, and with the 30 s statement ceiling bounds what one
/// database's callers can pin on the target. Operators raise it per database
/// in YAML once agent traffic is measured.
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 4;

/// Idle connections close after this long. The same baseline shows calls
/// arriving in short bursts hours apart: five minutes keeps a burst on warm
/// connections and returns to zero target connections between bursts.
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Sizing for one database's pool. Built from config; every field is already
/// validated (`max_connections >= 1`, `min_connections <= max_connections`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizing {
    pub max_connections: u32,
    pub min_connections: u32,
    pub idle_timeout: Duration,
}

/// The merged `pool:` settings ask for more idle connections than the pool
/// may hold — possible when the minimum and the maximum come from different
/// levels, which config validation checks one level at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("pool min_connections {min} exceeds max_connections {max}")]
pub struct InvalidPoolSizing {
    pub min: u32,
    pub max: u32,
}

impl PoolSizing {
    /// Merge per field: the database's `pool:` wins, then the server's, then
    /// the built-in default.
    pub fn resolve(server: &Server, database: &Database) -> Result<Self, InvalidPoolSizing> {
        let default = Self::default();
        let layers = [database.pool, server.pool];
        let max_connections =
            first(&layers, |p| p.max_connections).map_or(default.max_connections, |n| n.get());
        let min_connections =
            first(&layers, |p| p.min_connections).unwrap_or(default.min_connections);
        let idle_timeout = first(&layers, |p| p.idle_timeout_s)
            .map_or(default.idle_timeout, |s| Duration::from_secs(s.get()));
        if min_connections > max_connections {
            return Err(InvalidPoolSizing {
                min: min_connections,
                max: max_connections,
            });
        }
        Ok(Self {
            max_connections,
            min_connections,
            idle_timeout,
        })
    }
}

/// The first layer (most specific first) that sets the field.
fn first<T>(layers: &[Option<PoolConfig>], field: impl Fn(&PoolConfig) -> Option<T>) -> Option<T> {
    layers.iter().flatten().find_map(field)
}

impl Default for PoolSizing {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_POOL_MAX_CONNECTIONS,
            min_connections: 0,
            idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
        }
    }
}

/// Callers tracked before idle ones are swept. Subjects come from the IdP,
/// so the real count is the organisation's size; the sweep only bounds a
/// misbehaving one.
const SWEEP_CALLERS_AT: usize = 1_024;

/// One pool's connections, shared out per caller: each may hold all but one,
/// so a caller who fills its share with slow queries still leaves a
/// connection for everyone else. The transport's per-identity request cap
/// cannot do this — it is larger than a pool. A pool of one connection has
/// nothing to share out and is left whole.
#[derive(Debug)]
pub(crate) struct CallerSlots {
    per_caller: usize,
    slots: Mutex<HashMap<Caller, Arc<Semaphore>>>,
}

impl CallerSlots {
    pub(crate) fn new(sizing: PoolSizing) -> Self {
        let max = usize::try_from(sizing.max_connections).unwrap_or(usize::MAX);
        Self {
            per_caller: max.saturating_sub(1).max(1),
            slots: Mutex::default(),
        }
    }

    /// One of the current caller's slots, waited for at most `wait`; taken
    /// before the connection and held as long as it is. A caller already at
    /// its share for the whole wait gets [`ExecError::Unavailable`], as from
    /// a saturated pool. `None` outside any caller scope: the gateway's own
    /// work is not counted.
    pub(crate) async fn take(
        &self,
        wait: Duration,
    ) -> Result<Option<OwnedSemaphorePermit>, ExecError> {
        let Some(caller) = current_caller() else {
            return Ok(None);
        };
        let slots = self.slots_of(caller).await;
        match tokio::time::timeout(wait, slots.acquire_owned()).await {
            Ok(Ok(slot)) => Ok(Some(slot)),
            // Timed out; the semaphore is never closed.
            Ok(Err(_)) | Err(_) => Err(ExecError::Unavailable),
        }
    }

    async fn slots_of(&self, caller: Caller) -> Arc<Semaphore> {
        let mut slots = self.slots.lock().await;
        if slots.len() >= SWEEP_CALLERS_AT {
            // A held or awaited slot keeps a second reference alive.
            slots.retain(|_, held| Arc::strong_count(held) > 1);
        }
        let per_caller = self.per_caller;
        Arc::clone(
            slots
                .entry(caller)
                .or_insert_with(|| Arc::new(Semaphore::new(per_caller))),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use super::super::adapter::for_caller;
    use super::*;
    use crate::config::{Password, ServerKind, Tls};

    fn slots(max_connections: u32) -> CallerSlots {
        CallerSlots::new(PoolSizing {
            max_connections,
            ..PoolSizing::default()
        })
    }

    const SHORT: Duration = Duration::from_millis(20);

    #[tokio::test]
    async fn a_caller_holds_all_but_one_connection_at_most() {
        let slots = slots(3);
        for_caller(Caller::new("a"), async {
            let _first = slots.take(SHORT).await.expect("first slot");
            let _second = slots.take(SHORT).await.expect("second slot");
            let third = slots.take(SHORT).await;
            assert!(matches!(third, Err(ExecError::Unavailable)), "{third:?}");
            // Another caller's share is its own.
            let other = for_caller(Caller::new("b"), slots.take(SHORT)).await;
            assert!(matches!(other, Ok(Some(_))), "{other:?}");
        })
        .await;
        // Released with its holder.
        let again = for_caller(Caller::new("a"), slots.take(SHORT)).await;
        assert!(matches!(again, Ok(Some(_))), "{again:?}");
    }

    #[tokio::test]
    async fn a_pool_of_one_is_left_whole_and_unscoped_work_is_not_counted() {
        let slots = slots(1);
        let held = for_caller(Caller::new("a"), slots.take(SHORT)).await;
        assert!(matches!(held, Ok(Some(_))), "{held:?}");
        assert!(matches!(slots.take(SHORT).await, Ok(None)));
    }

    fn pool(max: Option<u32>, min: Option<u32>, idle: Option<u64>) -> Option<PoolConfig> {
        Some(PoolConfig {
            max_connections: max.and_then(NonZeroU32::new),
            min_connections: min,
            idle_timeout_s: idle.and_then(NonZeroU64::new),
        })
    }

    fn target(server: Option<PoolConfig>, database: Option<PoolConfig>) -> (Server, Database) {
        let database = Database {
            name: "app".into(),
            role: "ro".into(),
            password: Password::Literal("pw".into()),
            description: String::new(),
            auth_database: None,
            connect_name: None,
            pool: database,
            write_role: None,
            write_password: None,
        };
        let server = Server {
            name: "s".into(),
            kind: ServerKind::Postgres,
            description: String::new(),
            host: "h".into(),
            port: 5432,
            tls: Tls::Required,
            tls_ca_file: None,
            pool: server,
            databases: vec![],
        };
        (server, database)
    }

    #[test]
    fn database_beats_server_beats_default_per_field() {
        let (s, d) = target(pool(Some(10), Some(1), Some(60)), pool(Some(2), None, None));
        assert_eq!(
            PoolSizing::resolve(&s, &d),
            Ok(PoolSizing {
                max_connections: 2,
                min_connections: 1,
                idle_timeout: Duration::from_secs(60),
            })
        );
        let (s, d) = target(None, None);
        assert_eq!(PoolSizing::resolve(&s, &d), Ok(PoolSizing::default()));
    }

    #[test]
    fn merged_min_above_max_is_rejected() {
        let (s, d) = target(pool(None, Some(3), None), pool(Some(2), None, None));
        assert_eq!(
            PoolSizing::resolve(&s, &d),
            Err(InvalidPoolSizing { min: 3, max: 2 })
        );
    }
}
