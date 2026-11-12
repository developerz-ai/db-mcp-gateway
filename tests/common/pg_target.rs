//! Fixtures for the target Postgres (`target-db`, :5434, user/db `app`).

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{PgAdapter, PoolSizing};

pub const TARGET_HOST: &str = "localhost";
pub const TARGET_PORT: u16 = 5434;
pub const TARGET_USER: &str = "app";
pub const TARGET_PASSWORD: &str = "app-dev-only";
pub const TARGET_DB: &str = "app";

/// The `target` server, holding [`database`].
pub fn server() -> Server {
    Server {
        name: "target".to_string(),
        kind: ServerKind::Postgres,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: TARGET_PORT,
        tls: Tls::Insecure,
        tls_ca_file: None,
        pool: None,
        databases: vec![database()],
    }
}

pub fn database() -> Database {
    Database {
        name: TARGET_DB.to_string(),
        role: TARGET_USER.to_string(),
        password: Password::Literal(TARGET_PASSWORD.into()),
        description: String::new(),
        auth_database: None,
        pool: None,
    }
}

pub async fn adapter() -> PgAdapter {
    adapter_with(PoolSizing::default()).await
}

/// An adapter whose query pool holds exactly one connection, so consecutive
/// calls are guaranteed to share a backend — what a test of state leaking
/// between pooled callers needs.
pub async fn single_connection_adapter() -> PgAdapter {
    adapter_with(PoolSizing {
        max_connections: 1,
        ..PoolSizing::default()
    })
    .await
}

async fn adapter_with(sizing: PoolSizing) -> PgAdapter {
    PgAdapter::open(&server(), &database(), sizing, DetachedTasks::new())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}
