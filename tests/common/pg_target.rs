//! Fixtures for the target Postgres (`target-db`, :5434, user/db `app`).

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{PgAdapter, PoolSizing};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::OnceCell;

pub const TARGET_HOST: &str = "localhost";
pub const TARGET_PORT: u16 = 5434;
pub const TARGET_USER: &str = "app";
pub const TARGET_PASSWORD: &str = "app-dev-only";
pub const TARGET_DB: &str = "app";

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
/// advisory lock so concurrent binaries cannot race the catalog updates.
pub async fn ensure_read_role() {
    static READY: OnceCell<()> = OnceCell::const_new();
    READY
        .get_or_init(|| async {
            let url = format!(
                "postgres://{TARGET_USER}:{TARGET_PASSWORD}@{TARGET_HOST}:{TARGET_PORT}/{TARGET_DB}"
            );
            let owner = PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .expect("target-db reachable; run `bin/dev up`");
            let mut tx = owner.begin().await.expect("begin");
            for sql in [
                "SELECT pg_advisory_xact_lock(424242)".to_string(),
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
            ] {
                sqlx::query(&sql)
                    .execute(&mut *tx)
                    .await
                    .unwrap_or_else(|err| panic!("provision {READ_ROLE}: {err}"));
            }
            tx.commit().await.expect("commit read role");
        })
        .await;
}
