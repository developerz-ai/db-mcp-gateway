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
//! Also covers logout-everywhere, session GC and the state-DB-failure class.
//!
//! No mocking — these run against the real dev state DB (`bin/dev up`).

use std::time::Duration;

use crate::common::env::state_pool;
use db_mcp_gateway::auth::{AuthError, SessionCacheConfig, SessionStore};
use sqlx::PgPool;
use tokio::time::sleep;
use uuid::Uuid;

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
    let pool = state_pool().await;
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
    let pool = state_pool().await;
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

/// Real elapsed-time variant: use a genuine non-zero TTL and poll until the
/// cache entry goes stale by the clock rather than by TTL=0 proxy. The
/// rejection must land no earlier than `ttl` after the warm-up and well
/// before the deadline — measured, not slept.
///
/// This proves the path that operators actually rely on in production: a session
/// revoked on one replica is denied by another after at most `ttl` wall-clock
/// time, not only in the degenerate TTL=0 case.
#[tokio::test]
async fn revocation_denied_after_real_ttl_elapses() {
    let pool = state_pool().await;
    let user_sub = format!("a3-elapsed-{}", Uuid::new_v4().simple());

    // Short enough to keep the test fast; long enough that a revoke on a
    // loaded CI runner still lands well inside it.
    let ttl = Duration::from_secs(1);
    let replica_a = replica(&pool, Duration::from_secs(3600));
    let replica_b = replica(&pool, ttl);

    let session = create_session(&replica_a, &user_sub).await;

    // B caches the session as active (first lookup warms the cache). The
    // entry is stamped no earlier than `warmed`.
    let warmed = std::time::Instant::now();
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

    // Once B's entry ages past the TTL it re-reads the DB, sees revoked_at
    // and rejects.
    let deadline = warmed + ttl + Duration::from_secs(5);
    let err = loop {
        match replica_b.lookup(session.id).await {
            Err(err) => break err,
            Ok(_) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "revoked session still served long after the TTL"
                );
                sleep(Duration::from_millis(25)).await;
            }
        }
    };
    assert!(matches!(err, AuthError::RevokedSession), "got {err:?}");
    assert!(
        warmed.elapsed() >= ttl,
        "rejected before the cache TTL — the entry was never served from cache"
    );

    cleanup(&pool, &user_sub).await;
}

/// Logout-everywhere: every live session of the subject is rejected at once,
/// on the revoking replica, without waiting for a cache TTL.
#[tokio::test]
async fn revoke_all_for_sub_rejects_every_session_of_that_subject() {
    let pool = state_pool().await;
    let user_sub = format!("a3-all-{}", Uuid::new_v4().simple());
    let other_sub = format!("a3-all-other-{}", Uuid::new_v4().simple());
    let store = replica(&pool, Duration::from_secs(3600));

    let laptop = create_session(&store, &user_sub).await;
    let phone = create_session(&store, &user_sub).await;
    let other = create_session(&store, &other_sub).await;
    // Warm the cache so the test proves the revoke tombstones, not just misses.
    assert!(store.lookup(laptop.id).await.is_ok());

    assert_eq!(
        store.revoke_all_for_sub(&user_sub).await.expect("revoke"),
        2
    );
    for id in [laptop.id, phone.id] {
        let err = store.lookup(id).await.expect_err("revoked");
        assert!(matches!(err, AuthError::RevokedSession), "got {err:?}");
    }
    assert!(
        store.lookup(other.id).await.is_ok(),
        "other subject untouched"
    );

    cleanup(&pool, &user_sub).await;
    cleanup(&pool, &other_sub).await;
}

/// GC deletes rows expired past the grace window and keeps live rows —
/// including revoked-but-unexpired ones, which are the denylist entry for a
/// still-signed JWT.
#[tokio::test]
async fn gc_deletes_long_expired_rows_and_keeps_the_rest() {
    let pool = state_pool().await;
    let user_sub = format!("a3-gc-{}", Uuid::new_v4().simple());
    let store = replica(&pool, Duration::ZERO);

    let live = create_session(&store, &user_sub).await;
    let revoked = create_session(&store, &user_sub).await;
    store.revoke(revoked.id).await.expect("revoke");
    let expired = Uuid::new_v4();
    let recently_expired = Uuid::new_v4();
    for (id, ended) in [(expired, "3 hours"), (recently_expired, "5 minutes")] {
        sqlx::query(
            "INSERT INTO sessions (id, user_sub, user_email, issued_at, expires_at) \
             VALUES ($1, $2, 'gc@example.com', now() - interval '1 day', now() - $3::interval)",
        )
        .bind(id)
        .bind(&user_sub)
        .bind(ended)
        .execute(&pool)
        .await
        .expect("insert expired row");
    }

    store.gc_expired().await.expect("gc");

    let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM sessions WHERE user_sub = $1")
        .bind(&user_sub)
        .fetch_all(&pool)
        .await
        .expect("remaining rows");
    assert!(!remaining.contains(&expired), "long-expired row deleted");
    for kept in [
        Uuid::from(live.id),
        Uuid::from(revoked.id),
        recently_expired,
    ] {
        assert!(remaining.contains(&kept), "{kept} kept");
    }

    cleanup(&pool, &user_sub).await;
}

/// An expired session is rejected even when the row was never revoked.
#[tokio::test]
async fn expired_session_is_rejected() {
    let pool = state_pool().await;
    let user_sub = format!("a3-exp-{}", Uuid::new_v4().simple());
    let store = replica(&pool, Duration::ZERO);
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sessions (id, user_sub, user_email, issued_at, expires_at) \
         VALUES ($1, $2, 'exp@example.com', now() - interval '2 hours', now() - interval '1 minute')",
    )
    .bind(id)
    .bind(&user_sub)
    .execute(&pool)
    .await
    .expect("insert expired row");

    let err = store.lookup(id.into()).await.expect_err("expired");
    assert!(matches!(err, AuthError::ExpiredSession), "got {err:?}");

    cleanup(&pool, &user_sub).await;
}

/// A state-DB failure is `AuthError::State` — the gateway's fault, which the
/// transport maps to 5xx — never a credential error that would force re-login.
#[tokio::test]
async fn lookup_with_closed_pool_is_a_state_error() {
    let pool = state_pool().await;
    let store = replica(&pool, Duration::ZERO);
    pool.close().await;
    let err = store
        .lookup(Uuid::new_v4().into())
        .await
        .expect_err("closed pool");
    assert!(matches!(err, AuthError::State(_)), "got {err:?}");
    assert!(!err.is_credential_failure());
}
