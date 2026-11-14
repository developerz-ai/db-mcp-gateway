//! Fixtures for the Redis-protocol targets: `target-redis` (:6380) and
//! `target-dragonfly` (:6381). Every Redis test runs against both
//! ([`Flavor::ALL`]), so a protocol difference fails the suite.
//!
//! The containers' `default` user is the superuser, which the gateway
//! refuses; [`ensure_read_user`] creates the least-privilege ACL user an
//! operator would (`+@read -keys`, keys scoped to [`KEY_PATTERN`]) through
//! the admin side connection.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{PoolSizing, RedisAdapter};
use redis::aio::MultiplexedConnection;
use redis::{Client, ConnectionAddr, IntoConnectionInfo, RedisConnectionInfo};
use uuid::Uuid;

pub const TARGET_HOST: &str = "localhost";
/// The gateway's ACL user. Same name on both servers.
pub const READ_USER: &str = "gateway_ro";
pub const READ_PASSWORD: &str = "gateway-ro-dev-only";
/// Every key a test seeds lives under this prefix; the ACL user can read
/// nothing else.
pub const KEY_PREFIX: &str = "gw:";
const KEY_PATTERN: &str = "~gw:*";
/// A non-zero logical database, so the tests prove `name` selects it.
pub const DB_INDEX: &str = "3";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Redis,
    Dragonfly,
}

impl Flavor {
    pub const ALL: [Flavor; 2] = [Flavor::Redis, Flavor::Dragonfly];

    pub fn name(self) -> &'static str {
        match self {
            Flavor::Redis => "redis",
            Flavor::Dragonfly => "dragonfly",
        }
    }

    pub fn port(self) -> u16 {
        let (var, default) = match self {
            Flavor::Redis => ("TARGET_REDIS_PORT", 6380),
            Flavor::Dragonfly => ("TARGET_DRAGONFLY_PORT", 6381),
        };
        std::env::var(var)
            .ok()
            .and_then(|port| port.parse().ok())
            .unwrap_or(default)
    }

    fn admin_password(self) -> String {
        let (var, default) = match self {
            Flavor::Redis => ("TARGET_REDIS_PASSWORD", "redis-dev-only"),
            Flavor::Dragonfly => ("TARGET_DRAGONFLY_PASSWORD", "dragonfly-dev-only"),
        };
        std::env::var(var).unwrap_or_else(|_| default.to_string())
    }
}

/// A `kind: redis` server named after `flavor`, holding [`database`].
pub fn server(flavor: Flavor) -> Server {
    Server {
        name: flavor.name().to_string(),
        kind: ServerKind::Redis,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: flavor.port(),
        tls: Tls::Insecure,
        tls_ca_file: None,
        pool: None,
        databases: vec![database()],
    }
}

pub fn database() -> Database {
    Database {
        name: DB_INDEX.to_string(),
        role: READ_USER.to_string(),
        password: Password::Literal(READ_PASSWORD.into()),
        description: String::new(),
        auth_database: None,
        pool: None,
        write_role: None,
        write_password: None,
    }
}

/// The gateway's adapter for `flavor`, its ACL user provisioned first.
pub async fn adapter(flavor: Flavor, sizing: PoolSizing) -> RedisAdapter {
    ensure_read_user(flavor).await;
    RedisAdapter::open(&server(flavor), &database(), sizing)
        .await
        .expect("redis adapter opens")
}

/// Side connection as the `default` superuser, on [`DB_INDEX`] — setup,
/// teardown and `CLIENT PAUSE` only. NEVER a production path.
pub async fn admin(flavor: Flavor) -> MultiplexedConnection {
    let settings = RedisConnectionInfo::default()
        .set_password(flavor.admin_password())
        .set_db(DB_INDEX.parse().expect("numeric index"));
    let info = ConnectionAddr::Tcp(TARGET_HOST.to_string(), flavor.port())
        .into_connection_info()
        .expect("connection info")
        .set_redis_settings(settings);
    Client::open(info)
        .expect("client builds")
        .get_multiplexed_async_connection()
        .await
        .unwrap_or_else(|err| panic!("{} reachable; run `bin/dev up`: {err}", flavor.name()))
}

/// Create (or re-assert) the least-privilege ACL user: read commands only,
/// no `KEYS`, keys under [`KEY_PREFIX`] only, plus `SELECT` so the client
/// can switch to [`DB_INDEX`] on connect. One command, so applied atomically
/// even while another test is using the user.
pub async fn ensure_read_user(flavor: Flavor) {
    let mut conn = admin(flavor).await;
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(READ_USER)
        .arg("on")
        .arg(format!(">{READ_PASSWORD}"))
        .arg("resetkeys")
        .arg(KEY_PATTERN)
        .arg("-@all")
        .arg("+@read")
        .arg("-keys")
        .arg("+select")
        .exec_async(&mut conn)
        .await
        .unwrap_or_else(|err| panic!("ACL SETUSER on {}: {err}", flavor.name()));
}

/// Run one command on the admin side connection (seeding, inspection).
pub async fn admin_cmd(conn: &mut MultiplexedConnection, argv: &[&str]) -> redis::Value {
    let mut cmd = redis::cmd(argv[0]);
    cmd.arg(&argv[1..]);
    cmd.query_async(conn)
        .await
        .unwrap_or_else(|err| panic!("admin {argv:?}: {err}"))
}

/// A fresh key under [`KEY_PREFIX`], so concurrent runs never share data.
pub fn unique_key(label: &str) -> String {
    format!("{KEY_PREFIX}{label}:{}", Uuid::new_v4().simple())
}

/// Best-effort delete of everything a test seeded.
pub async fn delete_keys(conn: &mut MultiplexedConnection, keys: &[&str]) {
    let _ = redis::cmd("DEL")
        .arg(keys)
        .query_async::<redis::Value>(conn)
        .await;
}
