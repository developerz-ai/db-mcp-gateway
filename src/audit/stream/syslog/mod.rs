//! The `syslog` stream sink: RFC 5424 messages over UDP, TCP or TLS,
//! fire-and-forget. Each row is delivered on its own detached task; the
//! durable `audit_calls` row is already committed, so a failed delivery is a
//! counted drop, never a failed request.

mod format;
mod tls;
mod transport;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use metrics::counter;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::STREAM_DROPPED;
use crate::audit::AuditRow;
use crate::audit::drain::DetachedTasks;
use transport::{Connection, DeliveryError};

#[cfg(test)]
pub(super) use format::{MAX_MESSAGE_BYTES, TRUNCATION_MARKER, format_rfc5424, message};
pub use tls::{SyslogTls, SyslogTlsError};
pub use transport::SyslogTransport;

/// Rows one sink may have waiting or in delivery at once. A stream receiver
/// that stalls serialises deliveries behind its connection; past this many,
/// new rows are dropped and counted instead of piling up detached tasks.
const MAX_IN_FLIGHT: usize = 1024;

/// How long a row waits for the connection a previous row holds.
const QUEUE_WAIT: Duration = Duration::from_secs(10);

/// At most one error line per this window; the line carries the count of
/// rows dropped since the previous one. The `audit_stream_dropped_total`
/// counter sees every drop.
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// One configured syslog receiver. Connects once, then reuses the
/// connection; a failed send forgets it so the next row reconnects (the
/// receiver may have moved or restarted).
#[derive(Debug)]
pub(super) struct SyslogSink {
    host: String,
    port: u16,
    transport: SyslogTransport,
    /// Held across the send so stream frames never interleave and concurrent
    /// rows wait for one connect instead of each opening their own.
    connection: Mutex<Option<Connection>>,
    in_flight: Arc<Semaphore>,
    created: Instant,
    /// Millis since `created` before which no error line is logged.
    next_error_log_ms: AtomicU64,
    dropped_since_log: AtomicU64,
}

impl SyslogSink {
    pub(super) fn new(host: String, port: u16, transport: SyslogTransport) -> Self {
        Self {
            host,
            port,
            transport,
            connection: Mutex::new(None),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            created: Instant::now(),
            next_error_log_ms: AtomicU64::new(0),
            dropped_since_log: AtomicU64::new(0),
        }
    }

    /// Queue `row` for delivery on `tasks`; returns immediately.
    pub(super) fn spawn_delivery(self: &Arc<Self>, row: &AuditRow, tasks: &DetachedTasks) {
        let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            self.record_drop(&DeliveryError::Busy);
            return;
        };
        let sink = Arc::clone(self);
        let message = format::message(row);
        tasks.spawn(async move { sink.deliver(&message, permit).await });
    }

    async fn deliver(&self, message: &str, _permit: OwnedSemaphorePermit) {
        if let Err(err) = self.try_deliver(message).await {
            self.record_drop(&err);
        }
    }

    async fn try_deliver(&self, message: &str) -> Result<(), DeliveryError> {
        let mut slot = tokio::time::timeout(QUEUE_WAIT, self.connection.lock())
            .await
            .map_err(|_| DeliveryError::TimedOut("wait for the connection"))?;
        // A reused stream may have been closed by the receiver since the last
        // row; one reconnect covers a restarted receiver.
        if let Some(connection) = slot.as_mut() {
            if connection.send(message).await.is_ok() {
                return Ok(());
            }
            *slot = None;
        }
        let mut connection = Connection::open(&self.host, self.port, &self.transport).await?;
        connection.send(message).await?;
        *slot = Some(connection);
        Ok(())
    }

    fn record_drop(&self, err: &DeliveryError) {
        counter!(STREAM_DROPPED, "sink" => "syslog").increment(1);
        self.dropped_since_log.fetch_add(1, Ordering::Relaxed);
        let now_ms = u64::try_from(self.created.elapsed().as_millis()).unwrap_or(u64::MAX);
        let due = self.next_error_log_ms.load(Ordering::Relaxed);
        if now_ms < due {
            return;
        }
        let next = now_ms.saturating_add(ERROR_LOG_INTERVAL.as_secs() * 1000);
        // Only the caller that wins the swap logs; the rest are counted.
        if self
            .next_error_log_ms
            .compare_exchange(due, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let dropped = self.dropped_since_log.swap(0, Ordering::Relaxed);
        tracing::error!(
            err = %err,
            source = ?std::error::Error::source(err),
            host = %self.host,
            port = self.port,
            transport = self.transport.label(),
            dropped,
            "syslog stream sink: audit rows dropped"
        );
    }
}

#[cfg(test)]
mod tests;
