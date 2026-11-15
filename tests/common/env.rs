//! Connection strings for the `bin/dev up` stack, overridable by env var so
//! CI service containers can sit on other ports.
//!
//! Every dev-stack default lives here once: the RESP ports and admin
//! passwords below must match `docker-compose.dev.yml`, and the gateway's own
//! ACL user must match what `redis_target::ensure_read_user` provisions.

use std::num::NonZeroU32;

use db_mcp_gateway::state;
use sqlx::{MySqlPool, PgPool};

/// Five connections: plenty for one test binary's concurrent tests.
const TEST_POOL_SIZE: NonZeroU32 = NonZeroU32::new(5).expect("5 is non-zero");

/// Gateway state DB (Postgres, :5433).
pub fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

/// Target Postgres (:5434, or `TARGET_DB_PORT`) as a plain DSN, for monitor
/// connections that bypass the adapter.
pub fn target_db_url() -> String {
    std::env::var("TARGET_DB_URL").unwrap_or_else(|_| super::pg_target::owner_url())
}

/// Target Redis (:6380) — the RESP target `redis:8.4-alpine` in the dev stack.
pub fn redis_target_port() -> u16 {
    std::env::var("TARGET_REDIS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(6380)
}

/// Target Dragonfly (:6381) — the second RESP target, covered by the same
/// integration suite so its ACL and protocol behaviour stay pinned.
pub fn dragonfly_target_port() -> u16 {
    std::env::var("TARGET_DRAGONFLY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(6381)
}

/// The `default` superuser's password on `target-redis`, i.e. the
/// `--requirepass` in `docker-compose.dev.yml`. The gateway never connects as
/// `default` — tests use it for ACL admin and seeding only.
pub fn redis_admin_password() -> String {
    std::env::var("TARGET_REDIS_PASSWORD").unwrap_or_else(|_| "redis-dev-only".into())
}

/// Ditto for `target-dragonfly`.
pub fn dragonfly_admin_password() -> String {
    std::env::var("TARGET_DRAGONFLY_PASSWORD").unwrap_or_else(|_| "dragonfly-dev-only".into())
}

/// The least-privilege ACL user the gateway connects as (`role` in YAML), on
/// both RESP targets. A constant, not an env knob:
/// `redis_target::ensure_read_user` provisions this user itself, so an override
/// would only break its own `ACL SETUSER`.
pub const REDIS_READ_USER: &str = "gateway_ro";
/// That ACL user's password, set alongside it.
pub const REDIS_READ_PASSWORD: &str = "gateway-ro-dev-only";

/// MySQL permissions store (:3307).
pub fn mysql_dsn() -> String {
    std::env::var("PERMISSIONS_DB_DSN").unwrap_or_else(|_| {
        "mysql://permissions:permissions-dev-only@localhost:3307/permissions".to_string()
    })
}

/// Migrated state-DB pool, five connections.
pub async fn state_pool() -> PgPool {
    state::connect(&state_db_url(), TEST_POOL_SIZE)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

/// Migrated MySQL permissions-store pool, five connections.
pub async fn mysql_pool() -> MySqlPool {
    state::connect_permissions_mysql(&mysql_dsn(), TEST_POOL_SIZE)
        .await
        .expect("mysql permissions store up (run `bin/dev up`)")
}
