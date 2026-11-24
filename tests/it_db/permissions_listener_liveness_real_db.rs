//! Liveness of the permissions `LISTEN` connection (plan 101, A3).
//!
//! A revoke reaches another replica through `NOTIFY`. When that replica's
//! listener connection dies, the notification is lost; what bounds the
//! revoke is then how fast the listener notices and flushes — never the
//! cache TTL, 10 minutes here. Two ways to die are covered, both against
//! the real state DB:
//!
//! - announced — the backend is terminated, the socket closes;
//! - silent — a TCP proxy stops forwarding without closing, the way a NAT
//!   or firewall drops an idle flow. Nothing errors; only the self-ping
//!   deadline can notice.

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::blackhole_proxy::Proxy;
use crate::common::env::{state_db_url, state_pool};
use db_mcp_gateway::auth::{Identity, IdentityKind, SessionId};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::state::permissions::pg::notify::{self, Liveness};
use db_mcp_gateway::state::permissions::pg::{PgPermissionsRepo, grants};
use db_mcp_gateway::state::permissions::{
    DbType, GrantAction, GrantTarget, PermissionsChange, PermissionsSeed,
};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

const CACHE_TTL: Duration = Duration::from_secs(600);
const CONVERGE_WITHIN: Duration = Duration::from_secs(10);
const RECOVERED: &str = "permissions listener recovered; grant cache flushed";

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    fn contains(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.0.lock().unwrap()).contains(needle)
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Capture this thread's log lines. `#[tokio::test]` is current-thread, so
/// the spawned listener logs here too.
fn capture_logs() -> (Logs, tracing::subscriber::DefaultGuard) {
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    (logs.clone(), tracing::subscriber::set_default(subscriber))
}

/// One user holding one live `query_read` grant.
struct Seeded {
    sub: String,
    server: String,
    grant_id: Uuid,
}

async fn seed(pool: &PgPool, tag: &str) -> Seeded {
    let sub = format!("{tag}-{}", Uuid::new_v4().simple());
    let server = format!("{tag}-server-{}", Uuid::new_v4().simple());
    let repo = PgPermissionsRepo::new(pool.clone());
    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    let grant = repo
        .create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            serde_json::json!({}),
        )
        .await
        .unwrap();
    Seeded {
        sub,
        server,
        grant_id: grant.id,
    }
}

async fn cleanup(pool: &PgPool, seeded: &Seeded) {
    let deletes = [
        (
            "DELETE FROM permissions_grants WHERE user_id IN \
             (SELECT id FROM permissions_users WHERE user_sub = $1)",
            &seeded.sub,
        ),
        (
            "DELETE FROM permissions_databases WHERE server = $1",
            &seeded.server,
        ),
        (
            "DELETE FROM permissions_users WHERE user_sub = $1",
            &seeded.sub,
        ),
    ];
    for (sql, key) in deletes {
        sqlx::query(sql)
            .bind(key)
            .execute(pool)
            .await
            .expect("cleanup succeeds");
    }
}

fn identity(sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: sub.to_string(),
        user_email: format!("{sub}@example.com"),
        groups: Vec::new(),
        issued_at: chrono::Utc::now(),
        kind: IdentityKind::Sso,
    }
}

/// A second replica: its own cache, fed by its own listener on `pool`.
struct Replica {
    cache: PermissionsCache,
    flushes: Arc<AtomicUsize>,
    listener: tokio::task::JoinHandle<()>,
}

fn replica(state: &PgPool, listener_pool: PgPool, liveness: Liveness) -> Replica {
    let repo = Arc::new(PgPermissionsRepo::new(state.clone()));
    let cache = PermissionsCache::new(repo, CACHE_TTL);
    let flushes = Arc::new(AtomicUsize::new(0));
    let listener = tokio::spawn({
        let (cache, flushes) = (cache.clone(), flushes.clone());
        notify::listen_with(listener_pool, liveness, move |change| {
            let (cache, flushes) = (cache.clone(), flushes.clone());
            async move {
                if change == PermissionsChange::All {
                    flushes.fetch_add(1, Ordering::SeqCst);
                }
                cache.apply(&change).await;
            }
        })
    });
    Replica {
        cache,
        flushes,
        listener,
    }
}

impl Replica {
    async fn grant_count(&self, sub: &str) -> usize {
        self.cache.get_for(&identity(sub)).await.unwrap().len()
    }

    /// Every (re)subscribe flushes once, so this counts subscriptions.
    async fn await_flushes(&self, at_least: usize) {
        eventually("listener (re)subscribed", || async {
            self.flushes.load(Ordering::SeqCst) >= at_least
        })
        .await;
    }
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + CONVERGE_WITHIN;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what}: not within {CONVERGE_WITHIN:?}");
}

/// Another replica's admin revoke: the row change and its `NOTIFY` commit
/// together.
async fn revoke_and_notify(pool: &PgPool, seeded: &Seeded) {
    let mut tx = pool.begin().await.unwrap();
    let revoked = grants::tx_revoke_grant(&mut tx, seeded.grant_id).await;
    assert!(revoked.unwrap());
    notify::tx_notify(&mut tx, &PermissionsChange::User(seeded.sub.clone()))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn state_options() -> PgConnectOptions {
    PgConnectOptions::from_str(&state_db_url()).expect("STATE_DB_URL parses")
}

async fn pool_with(options: PgConnectOptions) -> PgPool {
    PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn revoke_lands_after_the_listener_backend_is_terminated() {
    let (logs, _guard) = capture_logs();
    let p = state_pool().await;
    let seeded = seed(&p, "liveness-kill").await;
    // Lets `pg_stat_activity` single out this test's listener backend.
    let app = format!("liveness-{}", Uuid::new_v4().simple());
    let listener_pool = pool_with(state_options().application_name(&app)).await;
    let b = replica(&p, listener_pool, Liveness::default());
    b.await_flushes(1).await;
    assert_eq!(b.grant_count(&seeded.sub).await, 1);

    let killed: i64 = sqlx::query_scalar(
        "SELECT count(*) FILTER (WHERE pg_terminate_backend(pid)) FROM pg_stat_activity \
         WHERE application_name = $1 AND query ILIKE 'LISTEN %'",
    )
    .bind(&app)
    .fetch_one(&p)
    .await
    .unwrap();
    assert_eq!(killed, 1, "exactly the listener backend is terminated");
    revoke_and_notify(&p, &seeded).await;

    eventually("revoke reaches the replica", || async {
        b.grant_count(&seeded.sub).await == 0
    })
    .await;
    b.await_flushes(2).await;
    eventually("recovery is logged", || async { logs.contains(RECOVERED) }).await;

    b.listener.abort();
    cleanup(&p, &seeded).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn revoke_lands_after_the_listener_connection_goes_silent() {
    let (logs, _guard) = capture_logs();
    let p = state_pool().await;
    let seeded = seed(&p, "liveness-silent").await;
    let direct = state_options();
    let proxy = Proxy::start((direct.get_host().to_string(), direct.get_port())).await;
    // Plaintext, so the proxy can spot the `LISTEN` statement.
    let via_proxy = direct
        .host("127.0.0.1")
        .port(proxy.addr.port())
        .ssl_mode(PgSslMode::Disable);
    let liveness = Liveness {
        ping_every: Duration::from_millis(250),
        deadline: Duration::from_secs(2),
    };
    let b = replica(&p, pool_with(via_proxy).await, liveness);
    b.await_flushes(1).await;
    assert_eq!(b.grant_count(&seeded.sub).await, 1);

    assert_eq!(proxy.freeze_listeners(), 1);
    revoke_and_notify(&p, &seeded).await;
    assert_eq!(
        b.grant_count(&seeded.sub).await,
        1,
        "the drop is silent: the NOTIFY is lost and nothing has errored yet"
    );

    eventually("revoke reaches the replica", || async {
        b.grant_count(&seeded.sub).await == 0
    })
    .await;
    assert!(logs.contains("heard no ping within the liveness deadline"));
    eventually("recovery is logged", || async { logs.contains(RECOVERED) }).await;

    b.listener.abort();
    cleanup(&p, &seeded).await;
}
