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
//!
//! Audit assertion intentionally skipped in every test here: they exercise the
//! exec layer's `AdapterRegistry` in isolation via `get_or_open`, never
//! entering the tool-dispatch path where audit rows are written. Audit
//! coverage for the tool path lives in the integration tests (see
//! `tests/it_db/run_query_e2e.rs` and `tests/it_db/cancellation_real_db.rs`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::mongo_target;
use db_mcp_gateway::config::{ConfigFile, Database, Password, Server};
use db_mcp_gateway::exec::{Access, AdapterRegistry, ExecError, ExecQuery};

/// `PgAdapter`'s pool acquire timeout — how long a connect to an unresponsive
/// host takes to give up. Not exported, so it is restated here.
///
/// Keep it in sync. The assertion thresholds at 1.5x this value, so it only
/// discriminates while the real timeout `R` sits inside `0.75x..1.5x` of what
/// is stated here: the fixed code costs ~`R` and must land under the
/// threshold, the serialized code costs ~`2R` and must land over it. Drift the
/// real value above 1.5x and correct code fails; below 0.75x and serialized
/// code slips through.
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the registry remembers a failed open. Not exported either.
const FAILED_OPEN_TTL: Duration = Duration::from_secs(5);

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

/// A failed open is remembered briefly — the next caller gets `unavailable`
/// at once instead of spending another acquire timeout (and a request
/// permit) on a target that just failed — and then retried. The slot is
/// never wedged.
#[tokio::test]
async fn a_failed_open_is_cached_briefly_then_retried() {
    let config = config_for(spawn_blackhole().await, spawn_blackhole().await);
    let registry = AdapterRegistry::new();
    let (server, database) = target(&config, "first");

    assert!(registry.get_or_open(server, database).await.is_err());

    let started = Instant::now();
    let cached = registry.get_or_open(server, database).await;
    assert!(
        matches!(cached, Err(ExecError::Unavailable)),
        "a just-failed target answers unavailable"
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the cached failure must not wait out another connect: {:?}",
        started.elapsed()
    );

    tokio::time::sleep(FAILED_OPEN_TTL).await;
    let started = Instant::now();
    assert!(registry.get_or_open(server, database).await.is_err());
    assert!(
        started.elapsed() >= POOL_ACQUIRE_TIMEOUT / 2,
        "after the TTL the open is attempted again: {:?}",
        started.elapsed()
    );
}

/// `evict` drops the adapter; concurrent callers after it converge on one
/// fresh adapter. Mongo opens without a round trip, so this needs no
/// reachable target.
#[tokio::test]
async fn evict_then_concurrent_reopen_converges_on_one_adapter() {
    let server = mongo_target::server("evict");
    let database = mongo_target::database();
    let registry = AdapterRegistry::new();

    let before = registry
        .get_or_open(&server, &database)
        .await
        .expect("opens");
    let again = registry
        .get_or_open(&server, &database)
        .await
        .expect("cached");
    assert!(
        Arc::ptr_eq(&before, &again),
        "steady state reuses the adapter"
    );

    registry.evict(&server.name, &database.name).await;
    let reopened = futures::future::join_all((0..8).map(|_| {
        let (registry, server, database) = (registry.clone(), server.clone(), database.clone());
        async move {
            registry
                .get_or_open(&server, &database)
                .await
                .expect("reopens")
        }
    }))
    .await;
    assert!(
        !Arc::ptr_eq(&before, &reopened[0]),
        "evict forces a new adapter"
    );
    assert!(
        reopened.iter().all(|a| Arc::ptr_eq(a, &reopened[0])),
        "concurrent callers share one reopened adapter"
    );
}

/// An adapter whose credentials the target rejects goes stale, and the
/// registry replaces it on the next lookup — the hook that lets a rotated
/// password take effect. Runs against the dev Mongo (:27018).
#[tokio::test]
async fn adapter_rejected_on_credentials_is_replaced() {
    let server = mongo_target::server("stale");
    let database = Database {
        password: Password::Literal("not-the-password".into()),
        ..mongo_target::database()
    };
    let registry = AdapterRegistry::new();

    let first = registry
        .get_or_open(&server, &database)
        .await
        .expect("opens");
    let err = first
        .execute(ExecQuery {
            sql: r#"{"count":"anything"}"#,
            binds: &[],
            statement_timeout_ms: Some(5_000),
            row_limit: 1,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect_err("wrong password must fail");
    assert!(matches!(err, ExecError::Connection), "got {err:?}");
    assert!(
        first.is_stale(),
        "a credential rejection marks the adapter stale"
    );

    let second = registry
        .get_or_open(&server, &database)
        .await
        .expect("reopens");
    assert!(
        !Arc::ptr_eq(&first, &second),
        "the stale adapter was replaced"
    );
}
