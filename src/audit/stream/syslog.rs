//! The `syslog` stream sink: RFC 5424 over UDP, fire-and-forget.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::SecondsFormat;
use metrics::counter;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::STREAM_DROPPED;
use crate::audit::{AuditRow, prefix_at_char_boundary};

/// RFC 5424 PRI: `facility * 8 + severity`. `local0` (16) is the
/// conventional facility for application-generated audit/security events;
/// `informational` (6) matches "audit row streamed", not an error.
const SYSLOG_PRI: u8 = 16 * 8 + 6;
const SYSLOG_APP_NAME: &str = "db-mcp-gateway";

/// Largest datagram sent. rsyslog's default `maxMessageSize` is 8 KiB and a
/// 100 KB statement exceeds the UDP payload limit outright, so a row that
/// would not fit is cut to fit rather than dropped.
pub(super) const MAX_DATAGRAM_BYTES: usize = 8192;
/// Appended wherever a cut happened, so a receiver never mistakes a cut
/// statement for the whole one.
pub(super) const TRUNCATION_MARKER: &str = "...[truncated]";

/// Hard ceiling on any single delivery step (DNS resolution, local UDP bind,
/// `send_to`), so a wedged resolver or black-holed network sheds detached
/// tasks instead of accumulating them.
const SYSLOG_STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// At most one error line per this window; the line carries the count of
/// rows dropped since the previous one. The `audit_stream_dropped_total`
/// counter sees every drop.
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
enum DeliveryError {
    #[error("DNS resolution failed")]
    Resolve(#[source] std::io::Error),
    #[error("host resolved to no addresses")]
    NoAddress,
    #[error("local UDP bind failed")]
    Bind(#[source] std::io::Error),
    #[error("send failed")]
    Send(#[source] std::io::Error),
    #[error("{0} timed out")]
    TimedOut(&'static str),
}

#[derive(Debug)]
struct Connection {
    socket: UdpSocket,
    addr: SocketAddr,
}

/// One configured syslog receiver. Resolves and binds once, then reuses the
/// socket; a failed send forgets it so the next row re-resolves (the
/// receiver may have moved).
#[derive(Debug)]
pub(super) struct SyslogSink {
    host: String,
    port: u16,
    connection: Mutex<Option<Arc<Connection>>>,
    created: Instant,
    /// Millis since `created` before which no error line is logged.
    next_error_log_ms: AtomicU64,
    dropped_since_log: AtomicU64,
}

impl SyslogSink {
    pub(super) fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            connection: Mutex::new(None),
            created: Instant::now(),
            next_error_log_ms: AtomicU64::new(0),
            dropped_since_log: AtomicU64::new(0),
        }
    }

    /// Send one datagram; on failure count the drop and log, rate-limited.
    pub(super) async fn deliver(&self, datagram: String) {
        if let Err(err) = self.try_deliver(datagram.as_bytes()).await {
            counter!(STREAM_DROPPED, "sink" => "syslog").increment(1);
            self.log_drop(&err);
        }
    }

    async fn try_deliver(&self, datagram: &[u8]) -> Result<(), DeliveryError> {
        let connection = self.connection().await?;
        let sent = tokio::time::timeout(
            SYSLOG_STEP_TIMEOUT,
            connection.socket.send_to(datagram, connection.addr),
        )
        .await;
        let result = match sent {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(err)) => Err(DeliveryError::Send(err)),
            Err(_) => Err(DeliveryError::TimedOut("send")),
        };
        *self.connection.lock().await = None;
        result
    }

    async fn connection(&self) -> Result<Arc<Connection>, DeliveryError> {
        // Held across the open so concurrent rows wait for one resolution
        // instead of each resolving on its own.
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot.as_ref() {
            return Ok(Arc::clone(connection));
        }
        let connection = Arc::new(self.open().await?);
        *slot = Some(Arc::clone(&connection));
        Ok(connection)
    }

    async fn open(&self) -> Result<Connection, DeliveryError> {
        let lookup = tokio::net::lookup_host((self.host.as_str(), self.port));
        let mut addrs = tokio::time::timeout(SYSLOG_STEP_TIMEOUT, lookup)
            .await
            .map_err(|_| DeliveryError::TimedOut("DNS resolution"))?
            .map_err(DeliveryError::Resolve)?;
        let addr = addrs.next().ok_or(DeliveryError::NoAddress)?;
        // Unspecified local port on the matching family; `send_to` names the
        // receiver, so no `connect()`.
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::time::timeout(SYSLOG_STEP_TIMEOUT, UdpSocket::bind(bind_addr))
            .await
            .map_err(|_| DeliveryError::TimedOut("local UDP bind"))?
            .map_err(DeliveryError::Bind)?;
        Ok(Connection { socket, addr })
    }

    fn log_drop(&self, err: &DeliveryError) {
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
            dropped,
            "syslog stream sink: audit rows dropped"
        );
    }
}

/// Format one audit row as an RFC 5424 syslog message, MSG body = the row
/// as JSON (same data the durable `audit_calls` row holds — see
/// [`AuditRow`]'s `Serialize` doc). Pure and synchronous so it's unit-
/// testable without a socket.
pub(super) fn format_rfc5424(row: &AuditRow) -> String {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let pid = std::process::id();
    // `unwrap_or_default()` can't actually trigger for this struct (no
    // non-string map keys, no NaN floats) but keeps a serialization
    // regression from panicking the fire-and-forget path — same reasoning
    // as `send_stdout`'s `groups` encoding.
    let body = serde_json::to_string(row).unwrap_or_default();
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // HOSTNAME and STRUCTURED-DATA are RFC 5424 NILVALUE ("-") — the
    // gateway doesn't track its own hostname, and the JSON body already
    // carries every field, so there's nothing structured data would add.
    format!("<{SYSLOG_PRI}>1 {timestamp} - {SYSLOG_APP_NAME} {pid} audit - {body}")
}

/// [`format_rfc5424`], cut to [`MAX_DATAGRAM_BYTES`]. The `sql` field is cut
/// first so the body stays valid JSON; only if that cannot make it fit is
/// the message itself cut.
pub(super) fn datagram(row: &AuditRow) -> String {
    let message = format_rfc5424(row);
    let Some(excess) = message.len().checked_sub(MAX_DATAGRAM_BYTES) else {
        return message;
    };
    // Every raw byte cut from `sql` removes at least one byte of its JSON
    // encoding, so cutting `excess + marker` raw bytes is enough.
    if let Some(sql) = row.sql.as_deref()
        && let Some(keep) = sql.len().checked_sub(excess + TRUNCATION_MARKER.len())
    {
        let mut shrunk = row.clone();
        shrunk.sql = Some(format!(
            "{}{TRUNCATION_MARKER}",
            prefix_at_char_boundary(sql, keep)
        ));
        let message = format_rfc5424(&shrunk);
        if message.len() <= MAX_DATAGRAM_BYTES {
            return message;
        }
    }
    let keep = MAX_DATAGRAM_BYTES - TRUNCATION_MARKER.len();
    format!(
        "{}{TRUNCATION_MARKER}",
        prefix_at_char_boundary(&message, keep)
    )
}
