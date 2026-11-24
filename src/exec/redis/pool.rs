//! Connection pool for one Redis `(server, database)`: at most
//! `max_connections` connections, each leased to one caller at a time, so a
//! slow command never queues another caller's command behind it on the same
//! socket.
//!
//! The one rule that makes this pool different from a general-purpose one: a
//! connection goes back to the pool only when its command completed with a
//! full reply ([`Lease::release`]). A lease dropped any other way — the
//! gateway's timeout fired, the agent disconnected, the socket failed — is
//! discarded with its connection, so a reply still in flight can never be
//! read by the next caller.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use redis::aio::MultiplexedConnection;
use redis::{AsyncConnectionConfig, Client, RedisError};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::super::pool_sizing::PoolSizing;

/// Bound on opening one connection (TCP, TLS and the `AUTH` handshake) — the
/// analogue of the pg pool's acquire timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Idle {
    conn: MultiplexedConnection,
    since: Instant,
}

pub(super) struct ConnPool {
    client: Client,
    config: AsyncConnectionConfig,
    permits: Arc<Semaphore>,
    idle: Mutex<Vec<Idle>>,
    idle_timeout: Duration,
}

impl ConnPool {
    /// No connection is opened here: the first lease opens one. A background
    /// sweep closes connections idle past `idle_timeout`, and stops once the
    /// pool is dropped.
    pub(super) fn new(client: Client, sizing: PoolSizing) -> Arc<Self> {
        let config = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            // The adapter bounds every command with the gateway budget; a
            // driver-side response timeout would only race it.
            .set_response_timeout(None);
        let max = usize::try_from(sizing.max_connections).unwrap_or(usize::MAX);
        let pool = Arc::new(Self {
            client,
            config,
            permits: Arc::new(Semaphore::new(max)),
            idle: Mutex::new(Vec::new()),
            idle_timeout: sizing.idle_timeout,
        });
        tokio::spawn(sweep_idle(Arc::downgrade(&pool), sizing.idle_timeout));
        pool
    }

    /// A connection for exclusive use: a fresh idle one, else a new one.
    /// Waits for a permit while `max_connections` are leased — the caller's
    /// time budget bounds that wait.
    pub(super) async fn lease(self: &Arc<Self>) -> Result<Lease, RedisError> {
        // A closed semaphore is impossible (never closed); treat it as I/O.
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| RedisError::from(std::io::Error::other("redis pool closed")))?;
        let (conn, reused) = match self.take_fresh_idle().await {
            Some(conn) => (conn, true),
            None => (self.connect().await?, false),
        };
        Ok(Lease {
            pool: Arc::clone(self),
            conn,
            reused,
            _permit: permit,
        })
    }

    async fn connect(&self) -> Result<MultiplexedConnection, RedisError> {
        self.client
            .get_multiplexed_async_connection_with_config(&self.config)
            .await
    }

    async fn take_fresh_idle(&self) -> Option<MultiplexedConnection> {
        let mut idle = self.idle.lock().await;
        while let Some(entry) = idle.pop() {
            if entry.since.elapsed() < self.idle_timeout {
                return Some(entry.conn);
            }
        }
        None
    }

    async fn close_expired(&self) {
        let timeout = self.idle_timeout;
        self.idle
            .lock()
            .await
            .retain(|entry| entry.since.elapsed() < timeout);
    }
}

/// Close idle connections past their timeout, until the pool is gone.
async fn sweep_idle(pool: Weak<ConnPool>, every: Duration) {
    let mut ticker = tokio::time::interval(every);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(pool) = pool.upgrade() else {
            return;
        };
        pool.close_expired().await;
    }
}

/// One leased connection. Dropping it discards the connection; only
/// [`Lease::release`] returns it to the pool.
pub(super) struct Lease {
    pool: Arc<ConnPool>,
    conn: MultiplexedConnection,
    /// Taken from the idle list rather than opened for this lease.
    reused: bool,
    _permit: OwnedSemaphorePermit,
}

impl Lease {
    pub(super) fn conn(&mut self) -> &mut MultiplexedConnection {
        &mut self.conn
    }

    /// Whether the connection sat idle in the pool before this lease — the
    /// only kind the server (or a proxy, a NAT) can have closed unseen.
    pub(super) fn reused(&self) -> bool {
        self.reused
    }

    /// Replace the connection with a freshly opened one, keeping the permit.
    pub(super) async fn reconnect(&mut self) -> Result<(), RedisError> {
        self.conn = self.pool.connect().await?;
        self.reused = false;
        Ok(())
    }

    /// Return the connection: call only after a complete reply was read.
    /// The permit is released when `self` drops, after the push.
    pub(super) async fn release(self) {
        self.pool.idle.lock().await.push(Idle {
            conn: self.conn,
            since: Instant::now(),
        });
    }
}
