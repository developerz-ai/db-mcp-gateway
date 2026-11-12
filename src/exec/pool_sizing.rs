//! Per-`(server, database)` connection-pool sizing, shared by every adapter.
//!
//! Pools are lazy and shrink to nothing: `min_connections` defaults to 0 and
//! idle connections close after `idle_timeout`, so an idle gateway holds no
//! target connection at all.

use std::time::Duration;

use crate::config::{Database, PoolConfig, Server};

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

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use super::*;
    use crate::config::{Password, ServerKind, Tls};

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
            pool: database,
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
