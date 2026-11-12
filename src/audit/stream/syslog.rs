//! The `syslog` stream sink: RFC 5424 over UDP, fire-and-forget.

use std::time::Duration;

use chrono::SecondsFormat;

use crate::audit::AuditRow;

/// RFC 5424 PRI: `facility * 8 + severity`. `local0` (16) is the
/// conventional facility for application-generated audit/security events;
/// `informational` (6) matches "audit row streamed", not an error.
const SYSLOG_PRI: u8 = 16 * 8 + 6;
const SYSLOG_APP_NAME: &str = "db-mcp-gateway";

/// Hard ceiling on any single syslog-delivery step (DNS resolution, local
/// UDP bind, `send_to`). Bounds the lifetime of every detached delivery
/// task so a wedged resolver or a broken network can't accumulate
/// long-lived tasks under sustained audit-event volume — each attempt
/// either succeeds, fails, or times out within this budget and drops.
/// 5s is comfortably above healthy DNS + loopback UDP send latency
/// (single-digit milliseconds on well-behaved networks) while still small
/// enough that a wedged path sheds tasks fast.
const SYSLOG_STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Format one audit row as an RFC 5424 syslog message, MSG body = the row
/// as JSON (same data the durable `audit_calls` row holds — see
/// [`AuditRow`]'s `Serialize` doc). Pure and synchronous so it's unit-
/// testable without a socket; [`send_syslog`] is the only caller.
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

/// Best-effort UDP send. Spawns a detached task so DNS resolution and the
/// send itself never delay the caller — a broken or unreachable syslog
/// receiver must not slow down, let alone fail, the agent's request
/// (CLAUDE.md non-negotiable #4 applies to the durable write only; this is
/// the sidecar spec 07 describes). Binds a fresh ephemeral socket per call
/// rather than pooling one in shared state: simplest correct thing, and
/// audit-row volume doesn't warrant the plumbing yet.
///
/// Every step (DNS, bind, send) is wrapped in [`SYSLOG_STEP_TIMEOUT`] so a
/// wedged resolver or a black-holed network can't keep the detached task
/// alive indefinitely. A timed-out step logs and drops — no retry, no
/// queue: audit-row rate is low enough that the next event just tries
/// again, and the durable row is already committed.
pub(super) fn send_syslog(host: &str, port: u16, row: &AuditRow) {
    let message = format_rfc5424(row);
    let host = host.to_string();
    tokio::spawn(async move {
        let lookup = tokio::time::timeout(
            SYSLOG_STEP_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await;
        let mut addrs = match lookup {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(err)) => {
                tracing::error!(%err, host, port, "syslog stream sink: DNS resolution failed");
                return;
            }
            Err(_) => {
                tracing::error!(
                    host,
                    port,
                    timeout_ms = SYSLOG_STEP_TIMEOUT.as_millis() as u64,
                    "syslog stream sink: DNS resolution timed out"
                );
                return;
            }
        };
        let Some(addr) = addrs.next() else {
            tracing::error!(
                host,
                port,
                "syslog stream sink: host resolved to no addresses"
            );
            return;
        };
        // Bind an unspecified local port on the matching family — `send_to`
        // below targets `addr` explicitly, so no `connect()` is needed.
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let bind =
            tokio::time::timeout(SYSLOG_STEP_TIMEOUT, tokio::net::UdpSocket::bind(bind_addr)).await;
        let socket = match bind {
            Ok(Ok(socket)) => socket,
            Ok(Err(err)) => {
                tracing::error!(%err, "syslog stream sink: local UDP bind failed");
                return;
            }
            Err(_) => {
                tracing::error!(
                    timeout_ms = SYSLOG_STEP_TIMEOUT.as_millis() as u64,
                    "syslog stream sink: local UDP bind timed out"
                );
                return;
            }
        };
        let send = tokio::time::timeout(
            SYSLOG_STEP_TIMEOUT,
            socket.send_to(message.as_bytes(), addr),
        )
        .await;
        match send {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                tracing::error!(%err, host, port, "syslog stream sink: send failed");
            }
            Err(_) => {
                tracing::error!(
                    host,
                    port,
                    timeout_ms = SYSLOG_STEP_TIMEOUT.as_millis() as u64,
                    "syslog stream sink: send timed out"
                );
            }
        }
    });
}
