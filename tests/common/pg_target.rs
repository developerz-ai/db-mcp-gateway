//! Fixtures for the target Postgres (`target-db`, :5434, user/db `app`).

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::PgAdapter;

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
    }
}

pub async fn adapter() -> PgAdapter {
    PgAdapter::open(&server(), &database())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}
