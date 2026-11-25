//! Every series the gateway exports: name, type and label names. The single
//! list docs, dashboards and alerts are pinned against
//! (`tests/it_offline/metrics_catalogue.rs` checks it against the emit sites).
//! Data only, with no path outside this file, so a test can `#[path]`-include it.
//!
//! No label carries a user, email, SQL text, request id or host. `db` is the
//! configured `server/database` pair, never a name the caller typed.

use Kind::{Counter, Gauge, Histogram};

/// The Prometheus type a series renders as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Counter,
    Gauge,
    Histogram,
}

/// One exported series.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Metric {
    pub(crate) name: &'static str,
    pub(crate) kind: Kind,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the catalogue tests and the docs pin")
    )]
    pub(crate) labels: &'static [&'static str],
    /// The `# HELP` line.
    pub(crate) help: &'static str,
}

const fn metric(
    name: &'static str,
    kind: Kind,
    labels: &'static [&'static str],
    help: &'static str,
) -> Metric {
    Metric {
        name,
        kind,
        labels,
        help,
    }
}

pub(crate) const CATALOGUE: &[Metric] = &[
    metric(
        "tool_calls",
        Counter,
        &["tool", "outcome", "access"],
        "Tool calls by the spec 03 outcome code the client saw.",
    ),
    metric(
        "tool_calls_by_db",
        Counter,
        &["db", "outcome", "access"],
        "Tool calls that named a configured database, by outcome.",
    ),
    metric(
        "query_duration_seconds",
        Histogram,
        &["tool", "db"],
        "Wall-clock of a tool's own work, audit write excluded.",
    ),
    metric(
        "audit_write_duration_seconds",
        Histogram,
        &[],
        "Wall-clock of the synchronous completion-row insert.",
    ),
    metric(
        "audit_fallback_failures_total",
        Counter,
        &[],
        "Fallback audit writes (after a disconnect, or a failed completion write) that failed.",
    ),
    metric(
        "audit_failure_recent",
        Gauge,
        &["kind"],
        "1 while an MCP tool call's audit write failed recently, else 0 (write: answered audit_unavailable, 15 min; fallback: the detached write after a disconnect or a failed completion write, 30 min).",
    ),
    metric(
        "audit_abandoned_total",
        Counter,
        &[],
        "Intent rows the reaper recorded as abandoned.",
    ),
    metric(
        "audit_pruner_runs_total",
        Counter,
        &["result"],
        "Audit retention prune runs.",
    ),
    metric(
        "audit_pruner_last_success_timestamp",
        Gauge,
        &[],
        "Unix seconds of the last successful audit prune.",
    ),
    metric(
        "audit_reaper_last_success_timestamp",
        Gauge,
        &[],
        "Unix seconds of the last completed abandoned-call reaper sweep.",
    ),
    metric(
        "login_failures_total",
        Counter,
        &["code"],
        "Bridge logins refused, by cause (email_unverified, id_token, idp_exchange, state_unavailable).",
    ),
    metric(
        "audit_stream_dropped_total",
        Counter,
        &["sink"],
        "Audit stream deliveries that failed.",
    ),
    metric(
        "requests_shed_total",
        Counter,
        &["scope"],
        "Requests refused by a concurrency cap.",
    ),
    metric(
        "handler_panics_total",
        Counter,
        &["layer"],
        "Panics caught and answered as internal.",
    ),
    metric(
        "pool_size",
        Gauge,
        &["db", "pool_kind"],
        "Configured maximum connections of a target pool.",
    ),
    metric(
        "pool_connections_in_use",
        Gauge,
        &["db", "pool_kind"],
        "Target pool connections leased to a call.",
    ),
    metric(
        "pool_connections_idle",
        Gauge,
        &["db", "pool_kind"],
        "Open, idle target pool connections (Postgres and Redis).",
    ),
    metric(
        "pool_acquire_wait_seconds",
        Histogram,
        &["db", "pool_kind"],
        "Wait for a target pool connection, timed-out waits included.",
    ),
    metric(
        "state_db_pool_size",
        Gauge,
        &["pool"],
        "Configured maximum connections of a state DB pool.",
    ),
    metric(
        "state_db_pool_connections_in_use",
        Gauge,
        &["pool"],
        "State DB pool connections in use.",
    ),
    metric(
        "state_db_pool_connections_idle",
        Gauge,
        &["pool"],
        "Open, idle state DB pool connections.",
    ),
    metric("sessions_created_total", Counter, &[], "Sessions created."),
    metric("sessions_revoked_total", Counter, &[], "Sessions revoked."),
    metric(
        "config_reloads_total",
        Counter,
        &["result"],
        "SIGHUP config reloads.",
    ),
    metric(
        "config_reload_last_success_timestamp",
        Gauge,
        &[],
        "Unix seconds of the boot load or last successful reload.",
    ),
    metric(
        "config_info",
        Gauge,
        &["hash"],
        "1 for the config file currently loaded, by SHA-256 prefix.",
    ),
    metric(
        "tls_cert_not_after_timestamp",
        Gauge,
        &[],
        "Unix seconds the served TLS certificate expires.",
    ),
    metric(
        "build_info",
        Gauge,
        &["version", "git_sha"],
        "1, labelled with the running build.",
    ),
    metric(
        "process_start_time_seconds",
        Gauge,
        &[],
        "Unix seconds this process booted.",
    ),
    metric(
        "log_lines_dropped_total",
        Counter,
        &[],
        "Log lines dropped by the full non-blocking log queue.",
    ),
];
