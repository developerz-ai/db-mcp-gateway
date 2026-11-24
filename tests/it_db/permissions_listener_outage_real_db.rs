//! A permissions listener that cannot get back: the state DB's `LISTEN`
//! connection goes silent and every reconnect hangs, the way a partitioned
//! network behaves. Notifications are lost for the whole outage, so the
//! replica's grant cache must not hold anything longer than one liveness
//! beat — never the cache TTL (10 minutes here), never "until LISTEN is
//! back". Against the real state DB, behind a proxy that stays down.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const CACHE_TTL: Duration = Duration::from_secs(600);
const CONVERGE_WITHIN: Duration = Duration::from_secs(10);

/// TCP forwarder that, once [`Self::go_down`] is called, blackholes every
/// connection — open ones and every new one — and never comes back.
struct OutageProxy {
    port: u16,
    down: CancellationToken,
}

impl OutageProxy {
    async fn start(upstream: (String, u16)) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let down = CancellationToken::new();
        let accepting = down.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = socket.accept().await {
                tokio::spawn(forward(client, upstream.clone(), accepting.clone()));
            }
        });
        Self { port, down }
    }

    fn go_down(&self) {
        self.down.cancel();
    }
}

async fn forward(mut client: TcpStream, upstream: (String, u16), down: CancellationToken) {
    if down.is_cancelled() {
        // Accepted, then silent: a connect that never completes its startup.
        return std::future::pending().await;
    }
    let Ok(mut server) = TcpStream::connect(upstream).await else {
        return;
    };
    tokio::select! {
        _ = copy_bidirectional(&mut client, &mut server) => {}
        // Both sockets stay open and silent until the test ends.
        () = down.cancelled() => std::future::pending::<()>().await,
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

async fn grant_count(cache: &PermissionsCache, sub: &str) -> usize {
    cache.get_for(&identity(sub)).await.unwrap().len()
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

async fn cleanup(pool: &PgPool, sub: &str, server: &str) {
    let deletes = [
        (
            "DELETE FROM permissions_grants WHERE user_id IN \
             (SELECT id FROM permissions_users WHERE user_sub = $1)",
            sub,
        ),
        (
            "DELETE FROM permissions_databases WHERE server = $1",
            server,
        ),
        ("DELETE FROM permissions_users WHERE user_sub = $1", sub),
    ];
    for (sql, key) in deletes {
        sqlx::query(sql).bind(key).execute(pool).await.unwrap();
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn grant_changes_land_while_the_listener_cannot_reconnect() {
    let p = state_pool().await;
    let repo = PgPermissionsRepo::new(p.clone());
    let sub = format!("outage-{}", Uuid::new_v4().simple());
    let server = format!("outage-server-{}", Uuid::new_v4().simple());
    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    let grant = || {
        repo.create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            serde_json::json!({}),
        )
    };
    let first = grant().await.unwrap();

    let direct = PgConnectOptions::from_str(&state_db_url()).unwrap();
    let proxy = OutageProxy::start((direct.get_host().to_string(), direct.get_port())).await;
    let via_proxy = direct
        .host("127.0.0.1")
        .port(proxy.port)
        .ssl_mode(PgSslMode::Disable);
    let listener_pool = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(via_proxy)
        .await
        .unwrap();
    let cache = PermissionsCache::new(Arc::new(PgPermissionsRepo::new(p.clone())), CACHE_TTL);
    let liveness = Liveness {
        ping_every: Duration::from_millis(250),
        deadline: Duration::from_secs(2),
    };
    let listener = tokio::spawn({
        let cache = cache.clone();
        notify::listen_with(listener_pool, liveness, move |change| {
            let cache = cache.clone();
            async move { cache.apply(&change).await }
        })
    });
    // Subscribed: a committed revoke arrives by NOTIFY.
    eventually("listener subscribed", || async {
        grant_count(&cache, &sub).await == 1
    })
    .await;

    proxy.go_down();
    // Revoked with its NOTIFY, which the dead connection never delivers.
    let mut tx = p.begin().await.unwrap();
    assert!(grants::tx_revoke_grant(&mut tx, first.id).await.unwrap());
    notify::tx_notify(&mut tx, &PermissionsChange::User(sub.clone()))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    eventually(
        "revoke lands once the liveness deadline is missed",
        || async { grant_count(&cache, &sub).await == 0 },
    )
    .await;

    // Still down — every reconnect hangs — and the replica has just cached
    // "no grants". A new grant must still reach it within a beat, not at
    // the TTL and not when LISTEN comes back.
    grant().await.unwrap();
    eventually("grant lands while the listener stays down", || async {
        grant_count(&cache, &sub).await == 1
    })
    .await;

    listener.abort();
    cleanup(&p, &sub, &server).await;
}
