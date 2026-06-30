//! Real-DB tests for the session cache's revocation semantics (A3).
//!
//! Two `SessionStore`s over one state-DB pool model two HA replicas: they share
//! the state DB but hold independent in-memory caches. The tests prove three
//! halves of the documented contract:
//! - a session revoked on one replica is re-validated (and rejected) by another
//!   once that replica's cache entry ages past its freshness TTL (TTL=0 proxy
//!   and real elapsed-time variant);
//! - within the TTL, the other replica still serves the (now-revoked) session —
//!   the multi-replica staleness bound operators must size against.
//!
//! No mocking — these run against the real dev state DB (`bin/dev up`).

use std::time::Duration;

use db_mcp_gateway::auth::{AuthError, SessionCacheConfig, SessionStore};
use sqlx::PgPool;
use tokio::time::sleep;
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn pool() -> PgPool {
    db_mcp_gateway::state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

fn replica(pool: &PgPool, ttl: Duration) -> SessionStore {
    SessionStore::with_cache_config(
        pool.clone(),
        SessionCacheConfig {
            ttl,
            max_entries: 1000,
        },
    )
}

async fn create_session(store: &SessionStore, user_sub: &str) -> db_mcp_gateway::auth::Session {
    store
        .create(
            user_sub,
            "user@example.com",
            &["engineers".to_string()],
            Duration::from_secs(3600),
            None,
            None,
        )
        .await
        .expect("create session")
}

async fn cleanup(pool: &PgPool, user_sub: &str) {
    sqlx::query("DELETE FROM sessions WHERE user_sub = $1")
        .bind(user_sub)
        .execute(pool)
        .await
        .expect("cleanup sessions");
}

#[tokio::test]
async fn revocation_on_one_replica_is_seen_by_another_after_cache_ttl() {
    let pool = pool().await;
    let user_sub = format!("a3-cross-{}", Uuid::new_v4().simple());

    let replica_a = replica(&pool, Duration::from_secs(30));
    // Replica B re-validates every request (ttl = 0) — the safety net at its
    // extreme, standing in for "the entry has aged past the TTL".
    let replica_b = replica(&pool, Duration::ZERO);

    let session = create_session(&replica_a, &user_sub).await;
    // B sees the session as active before the revoke.
    assert!(replica_b.lookup(session.id).await.is_ok());

    // A revokes: its own cache entry is evicted and the DB row is marked.
    replica_a.revoke(session.id).await.expect("revoke");

    // B holds no fresh entry, so it re-reads the DB and observes the revoke.
    let err = replica_b
        .lookup(session.id)
        .await
        .expect_err("revoked session must be rejected after re-validation");
    assert!(matches!(err, AuthError::RevokedSession), "got {err:?}");

    cleanup(&pool, &user_sub).await;
}

#[tokio::test]
async fn revocation_is_stale_on_another_replica_within_cache_ttl() {
    let pool = pool().await;
    let user_sub = format!("a3-stale-{}", Uuid::new_v4().simple());

    let replica_a = replica(&pool, Duration::from_secs(3600));
    let replica_b = replica(&pool, Duration::from_secs(3600));

    let session = create_session(&replica_a, &user_sub).await;
    // B caches the active session.
    assert!(replica_b.lookup(session.id).await.is_ok());

    // A revokes — evicting only A's cache.
    replica_a.revoke(session.id).await.expect("revoke");

    // Within the freshness window B still serves the cached (now-revoked)
    // session: the documented HA staleness bound, not a bug.
    assert!(
        replica_b.lookup(session.id).await.is_ok(),
        "within the cache TTL, the revoke has not yet propagated to replica B"
    );

    // A, which evicted on revoke, rejects on the very next call.
    let err = replica_a
        .lookup(session.id)
        .await
        .expect_err("revoking replica rejects immediately");
    assert!(matches!(err, AuthError::RevokedSession), "got {err:?}");

    cleanup(&pool, &user_sub).await;
}

/// Real elapsed-time variant: use a genuine non-zero TTL and sleep past it so
/// that the cache entry becomes stale by the clock rather than by TTL=0 proxy.
///
/// This proves the path that operators actually rely on in production: a session
/// revoked on one replica is denied by another after at most `ttl` wall-clock
/// time, not only in the degenerate TTL=0 case.
#[tokio::test]
async fn revocation_denied_after_real_ttl_elapses() {
    let pool = pool().await;
    let user_sub = format!("a3-elapsed-{}", Uuid::new_v4().simple());

    // Short TTL so the test stays fast; long enough that the first lookup hits
    // the cache (not yet stale) and only the second (after sleep) re-validates.
    let ttl = Duration::from_millis(120);
    let replica_a = replica(&pool, Duration::from_secs(3600));
    let replica_b = replica(&pool, ttl);

    let session = create_session(&replica_a, &user_sub).await;

    // B caches the session as active (first lookup warms the cache).
    assert!(
        replica_b.lookup(session.id).await.is_ok(),
        "initial lookup ok"
    );

    // A revokes — writes revoked_at to the DB, evicts A's cache entry.
    replica_a.revoke(session.id).await.expect("revoke");

    // B's entry is still fresh: within the TTL it serves the (now-revoked) session.
    assert!(
        replica_b.lookup(session.id).await.is_ok(),
        "still within TTL — B serves stale cached entry"
    );

    // Let B's cache entry age past its TTL.
    sleep(ttl + Duration::from_millis(50)).await;

    // B's entry is now stale → re-reads the DB → sees revoked_at → rejects.
    let err = replica_b
        .lookup(session.id)
        .await
        .expect_err("revoked session must be denied after TTL elapses");
    assert!(matches!(err, AuthError::RevokedSession), "got {err:?}");

    cleanup(&pool, &user_sub).await;
}
