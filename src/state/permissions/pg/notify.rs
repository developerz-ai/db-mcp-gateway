//! Cross-replica cache invalidation over Postgres `LISTEN/NOTIFY`.
//!
//! An admin write queues a `NOTIFY` inside its transaction ([`tx_notify`]);
//! Postgres delivers it to every listening replica only if that transaction
//! commits. [`listen`] feeds each delivery to the caller. A dropped listener
//! connection can lose notifications, so every (re)connect reports
//! [`PermissionsChange::All`] — the bound is the reconnect delay, not the TTL.

use std::future::Future;
use std::time::Duration;

use sqlx::postgres::PgListener;
use sqlx::{PgPool, Postgres, Transaction};

use super::super::{PermissionsChange, RepoError};

const CHANNEL: &str = "dbmcp_permissions";
const RECONNECT_MIN: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

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
    let mut backoff = RECONNECT_MIN;
    loop {
        match subscribe(&pool).await {
            Ok(mut listener) => {
                backoff = RECONNECT_MIN;
                on_change(PermissionsChange::All).await;
                drain(&mut listener, &on_change).await;
            }
            Err(err) => {
                tracing::warn!(error_type = %error_kind(&err), "permissions listener connect failed");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

async fn subscribe(pool: &PgPool) -> Result<PgListener, sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    Ok(listener)
}

/// Deliver notifications until the connection drops.
async fn drain<F, Fut>(listener: &mut PgListener, on_change: &F)
where
    F: Fn(PermissionsChange) -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        match listener.try_recv().await {
            Ok(Some(n)) => on_change(PermissionsChange::decode(n.payload())).await,
            Ok(None) => {
                tracing::warn!("permissions listener connection lost; reconnecting");
                return;
            }
            Err(err) => {
                tracing::warn!(error_type = %error_kind(&err), "permissions listener failed");
                return;
            }
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
