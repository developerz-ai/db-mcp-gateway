//! Cross-replica cache invalidation over Postgres `LISTEN/NOTIFY`.
//!
//! An admin write queues a `NOTIFY` inside its transaction ([`tx_notify`]);
//! Postgres delivers it to every listening replica only if that transaction
//! commits. [`listen`] feeds each delivery to the caller. A dropped listener
//! connection can lose notifications, so every (re)connect reports
//! [`PermissionsChange::All`] — the bound is the reconnect delay, not the TTL.
//!
//! A drop is not always announced: a NAT or firewall can discard the
//! connection without a FIN, and a receive on it then waits forever. So the
//! listener pings itself — every [`Liveness::ping_every`] another pool
//! connection sends a `NOTIFY` on a second channel the listener also
//! listens on — and treats [`Liveness::deadline`] of silence as a lost
//! connection: a ping that reaches the server but not the listener means
//! the listener's own connection is gone.

use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;

use sqlx::postgres::PgListener;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::time::{MissedTickBehavior, timeout};

use super::super::{PermissionsChange, RepoError};

const CHANNEL: &str = "dbmcp_permissions";
/// Separate from [`CHANNEL`] so a replica that predates the ping never
/// decodes one as a change and flushes its cache on every beat.
const PING_CHANNEL: &str = "dbmcp_permissions_ping";
const RECONNECT_MIN: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// How the listener proves its connection still delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Liveness {
    /// Interval between self-pings.
    pub ping_every: Duration,
    /// Silence longer than this — no ping, no change — is a lost connection.
    /// Several `ping_every` long, so one slow ping is not a miss.
    pub deadline: Duration,
}

impl Default for Liveness {
    fn default() -> Self {
        Self {
            ping_every: Duration::from_secs(5),
            deadline: Duration::from_secs(15),
        }
    }
}

/// Queue a change notification; delivered on commit, discarded on rollback.
pub async fn tx_notify(
    tx: &mut Transaction<'_, Postgres>,
    change: &PermissionsChange,
) -> Result<(), RepoError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANNEL)
        .bind(change.encode())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Run forever: listen on the invalidation channel and hand every change to
/// `on_change`. Connection failures back off and retry; they never end the
/// loop, because a replica that stops listening serves stale grants.
pub async fn listen<F, Fut>(pool: PgPool, on_change: F)
where
    F: Fn(PermissionsChange) -> Fut,
    Fut: Future<Output = ()>,
{
    listen_with(pool, Liveness::default(), on_change).await;
}

/// [`listen`] with an explicit liveness cadence.
pub async fn listen_with<F, Fut>(pool: PgPool, liveness: Liveness, on_change: F)
where
    F: Fn(PermissionsChange) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut backoff = RECONNECT_MIN;
    let mut recovering = false;
    loop {
        match subscribe(&pool, liveness.deadline).await {
            Ok(mut listener) => {
                backoff = RECONNECT_MIN;
                on_change(PermissionsChange::All).await;
                if recovering {
                    tracing::info!("permissions listener recovered; grant cache flushed");
                }
                tokio::select! {
                    () = drain(&mut listener, liveness.deadline, &on_change) => {}
                    never = ping(&pool, liveness.ping_every) => match never {},
                }
            }
            Err(error_type) => {
                tracing::warn!(error_type, "permissions listener connect failed");
            }
        }
        recovering = true;
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// Bounded by `deadline`: the pool can hand out a connection that is as
/// silently dead as the one being replaced.
async fn subscribe(pool: &PgPool, deadline: Duration) -> Result<PgListener, &'static str> {
    let connect = async {
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen_all([CHANNEL, PING_CHANNEL]).await?;
        Ok::<_, sqlx::Error>(listener)
    };
    match timeout(deadline, connect).await {
        Ok(Ok(listener)) => Ok(listener),
        Ok(Err(err)) => Err(error_kind(&err)),
        Err(_) => Err("timeout"),
    }
}

/// Deliver notifications until the connection drops or goes silent.
async fn drain<F, Fut>(listener: &mut PgListener, deadline: Duration, on_change: &F)
where
    F: Fn(PermissionsChange) -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        // Only the receive is under the deadline; on a miss the listener is
        // dropped, so the cancelled receive is never resumed.
        match timeout(deadline, listener.try_recv()).await {
            Ok(Ok(Some(n))) if n.channel() == PING_CHANNEL => {}
            Ok(Ok(Some(n))) => on_change(PermissionsChange::decode(n.payload())).await,
            Ok(Ok(None)) => {
                tracing::warn!("permissions listener connection lost; reconnecting");
                return;
            }
            Ok(Err(err)) => {
                tracing::warn!(error_type = %error_kind(&err), "permissions listener failed");
                return;
            }
            Err(_) => {
                tracing::warn!(
                    deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                    "permissions listener heard no ping within the liveness deadline; reconnecting"
                );
                return;
            }
        }
    }
}

/// Beat [`PING_CHANNEL`] forever. A failed or slow ping is not acted on
/// here: the listener's deadline is the single judge of liveness.
async fn ping(pool: &PgPool, every: Duration) -> Infallible {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let send = sqlx::query("SELECT pg_notify($1, '')")
            .bind(PING_CHANNEL)
            .execute(pool);
        match timeout(every, send).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                tracing::debug!(error_type = %error_kind(&err), "permissions listener ping failed");
            }
            Err(_) => tracing::debug!("permissions listener ping timed out"),
        }
    }
}

/// Error class only — a sqlx `Display` can quote connection detail.
fn error_kind(err: &sqlx::Error) -> &'static str {
    match err {
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::PoolTimedOut => "pool_timed_out",
        sqlx::Error::PoolClosed => "pool_closed",
        _ => "other",
    }
}
