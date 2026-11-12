//! Connection strings for the `bin/dev up` stack, overridable by env var so
//! CI service containers can sit on other ports.

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

/// Target Postgres (:5434) as a plain DSN, for monitor connections that
/// bypass the adapter.
pub fn target_db_url() -> String {
    std::env::var("TARGET_DB_URL")
        .unwrap_or_else(|_| "postgres://app:app-dev-only@localhost:5434/app".into())
}

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
