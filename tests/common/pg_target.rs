//! Fixtures for the target Postgres (`target-db`, :5434, user/db `app`).
//!
//! The port is `TARGET_DB_PORT` when set, so the same suite runs against
//! another Postgres-wire target — `bin/test-yugabyte` points it at
//! `target-yugabyte` (:5435).

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{PgAdapter, PoolSizing};
use sqlx::postgres::PgPoolOptions;
use sqlx::AssertSqlSafe;
use tokio::sync::OnceCell;

pub const TARGET_HOST: &str = "localhost";
const DEFAULT_TARGET_PORT: u16 = 5434;
pub const TARGET_USER: &str = "app";
pub const TARGET_PASSWORD: &str = "app-dev-only";
pub const TARGET_DB: &str = "app";

/// The placeholder [`config_yaml`] swaps for [`target_port`]. Left
/// unreplaced it is not a valid port, so a forgotten call fails config parse.
pub const PORT_PLACEHOLDER: &str = "__TARGET_PORT__";

/// The target's port: `TARGET_DB_PORT`, else the dev stack's 5434.
pub fn target_port() -> u16 {
    match std::env::var("TARGET_DB_PORT") {
        Ok(port) => port
            .parse()
            .unwrap_or_else(|err| panic!("TARGET_DB_PORT={port:?} is not a port: {err}")),
        Err(_) => DEFAULT_TARGET_PORT,
    }
}

/// `TARGET_FLAVOR=yugabyte`: the target is YugabyteDB YSQL, not Postgres.
pub fn is_yugabyte() -> bool {
    std::env::var("TARGET_FLAVOR").is_ok_and(|flavor| flavor == "yugabyte")
}

/// A gateway config template with every [`PORT_PLACEHOLDER`] set to
/// [`target_port`].
pub fn config_yaml(template: &str) -> String {
    template.replace(PORT_PLACEHOLDER, &target_port().to_string())
}

/// The owner (`app`) DSN of the target, for fixture setup that bypasses the
/// gateway.
pub fn owner_url() -> String {
    format!(
        "postgres://{TARGET_USER}:{TARGET_PASSWORD}@{TARGET_HOST}:{}/{TARGET_DB}",
        target_port()
    )
}

/// The read-only role of [`writable_database`]: SELECT on `public`, nothing
/// else. Created by [`ensure_read_role`]; the gateway never provisions it.
pub const READ_ROLE: &str = "dbmcp_test_ro";
pub const READ_ROLE_PASSWORD: &str = "ro-dev-only";

/// The `target` server, holding [`database`].
pub fn server() -> Server {
    Server {
        name: "target".to_string(),
        kind: ServerKind::Postgres,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: target_port(),
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
        write_role: None,
        write_password: None,
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

/// [`database`] split into two tiers, the way a deployment with writes is
/// configured: reads connect as [`READ_ROLE`], `query_write` as `app`.
pub fn writable_database() -> Database {
    Database {
        role: READ_ROLE.to_string(),
        password: Password::Literal(READ_ROLE_PASSWORD.into()),
        write_role: Some(TARGET_USER.to_string()),
        write_password: Some(Password::Literal(TARGET_PASSWORD.into())),
        ..database()
    }
}

/// An adapter over [`writable_database`], its read role provisioned first.
pub async fn writable_adapter() -> PgAdapter {
    ensure_read_role().await;
    PgAdapter::open(
        &server(),
        &writable_database(),
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("target-db reachable; run `bin/dev up`")
}

/// Create [`READ_ROLE`] once per test binary, as the operator would: LOGIN,
/// SELECT on every current and future table in `public`. Serialized on an
/// advisory lock so concurrent binaries cannot race the catalog updates —
/// except on YugabyteDB, which refuses advisory locks (`0A000`, preview flag
/// off as in production); its suite runs one test at a time instead.
pub async fn ensure_read_role() {
    static READY: OnceCell<()> = OnceCell::const_new();
    READY
        .get_or_init(|| async {
            let owner = PgPoolOptions::new()
                .max_connections(1)
                .connect(&owner_url())
                .await
                .expect("target-db reachable; run `bin/dev up`");
            let mut tx = owner.begin().await.expect("begin");
            let lock = (!is_yugabyte()).then(|| "SELECT pg_advisory_xact_lock(424242)".to_string());
            for sql in lock.into_iter().chain([
                format!(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{READ_ROLE}') \
                     THEN CREATE ROLE {READ_ROLE} LOGIN PASSWORD '{READ_ROLE_PASSWORD}'; END IF; END $$"
                ),
                format!("GRANT CONNECT ON DATABASE {TARGET_DB} TO {READ_ROLE}"),
                format!("GRANT USAGE ON SCHEMA public TO {READ_ROLE}"),
                format!("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {READ_ROLE}"),
                format!(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {TARGET_USER} IN SCHEMA public \
                     GRANT SELECT ON TABLES TO {READ_ROLE}"
                ),
            ]) {
                sqlx::query(AssertSqlSafe(&sql))
                    .execute(&mut *tx)
                    .await
                    .unwrap_or_else(|err| panic!("provision {READ_ROLE}: {err}"));
            }
            tx.commit().await.expect("commit read role");
        })
        .await;
}
