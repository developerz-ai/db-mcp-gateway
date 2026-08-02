//! `AdapterRegistry::get_or_open` must not hold the registry lock across the
//! per-database connect (#136).
//!
//! `PgAdapter::open` establishes its pools eagerly, bounded only by the pool
//! acquire timeout. The registry used to do that work while holding the map's
//! write lock, so one unreachable database parked the lock for the whole
//! timeout — and because tokio's `RwLock` is write-preferring, every later
//! caller queued behind it, stalling even already-open healthy databases.
//!
//! The property is observable as timing: two unreachable databases opened
//! concurrently should cost *one* timeout, not two stacked back to back.
//!
//! No mocking and no docker — the unreachable database is a real TCP listener
//! that accepts and then never speaks Postgres. That is a genuine socket
//! behaviour, just cheaper to arrange than a wedged Postgres.

use std::time::{Duration, Instant};

use db_mcp_gateway::config::{ConfigFile, Database, Server};
use db_mcp_gateway::exec::AdapterRegistry;

/// `PgAdapter`'s pool acquire timeout — how long a connect to an unresponsive
/// host takes to give up. Not exported, so it is restated here; the assertions
/// below only depend on it being the same for both servers.
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// A listener that completes the TCP handshake and then goes silent, so a
/// Postgres client blocks waiting for a startup response that never comes.
/// The accept loop holds each connection open for the life of the test.
async fn spawn_blackhole() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    port
}

fn config_for(first_port: u16, second_port: u16) -> ConfigFile {
    let yaml = format!(
        r#"
servers:
  - name: first
    kind: postgres
    description: Accepts TCP then never answers the startup handshake
    host: 127.0.0.1
    port: {first_port}
    tls: insecure
    databases:
      - name: app
        role: app
        password: unused
  - name: second
    kind: postgres
    description: A second, independent unreachable database
    host: 127.0.0.1
    port: {second_port}
    tls: insecure
    databases:
      - name: app
        role: app
        password: unused

permissions:
  - group: engineers
    grants:
      - server: first
        database: app
        action: query_read
"#
    );
    ConfigFile::from_yaml_str(&yaml).expect("registry test yaml is well-formed")
}

fn target<'a>(config: &'a ConfigFile, server: &str) -> (&'a Server, &'a Database) {
    let server = config
        .servers
        .iter()
        .find(|s| s.name == server)
        .expect("server is in the test config");
    let database = server
        .databases
        .iter()
        .find(|d| d.name == "app")
        .expect("database is in the test config");
    (server, database)
}

/// Opening one database must not serialize behind another database's open.
#[tokio::test]
async fn opens_for_different_databases_do_not_serialize() {
    let config = config_for(spawn_blackhole().await, spawn_blackhole().await);
    let registry = AdapterRegistry::new();

    // Park a task inside `PgAdapter::open` against `first`. Pre-fix it holds
    // the registry write lock for the whole acquire timeout — the window
    // under test.
    let first = {
        let registry = registry.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let (server, database) = target(&config, "first");
            registry.get_or_open(server, database).await
        })
    };

    // Give the spawned task time to reach the connect. A loopback TCP
    // handshake is sub-millisecond, so this is far longer than it needs.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (server, database) = target(&config, "second");
    let started = Instant::now();
    let result = registry.get_or_open(server, database).await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "an unreachable database must surface a connection error"
    );
    assert!(
        first.await.expect("first open task ran").is_err(),
        "the fixture's first server must also be unreachable"
    );

    // Post-fix the two opens overlap, so `second` costs one timeout. Pre-fix
    // it waited out the rest of `first`'s timeout before starting its own,
    // landing near double. The midpoint separates the two cleanly.
    let serialized_floor = POOL_ACQUIRE_TIMEOUT + POOL_ACQUIRE_TIMEOUT / 2;
    assert!(
        elapsed < serialized_floor,
        "second database's open serialized behind the first: took {elapsed:?}, \
         expected roughly one {POOL_ACQUIRE_TIMEOUT:?} timeout"
    );
}

/// A failed open must leave the slot reusable. The map now keeps a `OnceCell`
/// per key whether or not the open succeeded, so this pins that an errored
/// attempt leaves the cell uninitialized rather than caching the failure or
/// wedging every later caller.
#[tokio::test]
async fn a_failed_open_is_retried_not_cached() {
    let config = config_for(spawn_blackhole().await, spawn_blackhole().await);
    let registry = AdapterRegistry::new();
    let (server, database) = target(&config, "first");

    for attempt in 1..=2 {
        assert!(
            registry.get_or_open(server, database).await.is_err(),
            "attempt {attempt} against an unreachable database must error"
        );
    }
}
