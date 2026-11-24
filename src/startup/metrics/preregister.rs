//! Counters registered at `0` for every stable label set, so the first event
//! of a kind is an increase from `0` rather than a new series `increase()`
//! cannot see (plan 101 O4).

use db_mcp_gateway::audit::OutcomeCode;
use db_mcp_gateway::config::ConfigFile;
use db_mcp_gateway::mcp::protocol::{RUN_QUERY_TOOL, TOOLS_LIST};
use metrics::counter;

/// Every code a dispatch can report. `abandoned` is the reaper's, never a
/// dispatch's. [`exhaustive`] stops a new code from being missed here.
const DISPATCH_OUTCOMES: [OutcomeCode; 15] = [
    OutcomeCode::Success,
    OutcomeCode::DryRun,
    OutcomeCode::Forbidden,
    OutcomeCode::ForbiddenSql,
    OutcomeCode::PermissionDenied,
    OutcomeCode::UndefinedObject,
    OutcomeCode::InvalidArguments,
    OutcomeCode::ReasonRequired,
    OutcomeCode::Timeout,
    OutcomeCode::SyntaxError,
    OutcomeCode::Unavailable,
    OutcomeCode::UnsupportedBackend,
    OutcomeCode::Internal,
    OutcomeCode::Cancelled,
    OutcomeCode::AuditUnavailable,
];

/// The fixed-label counters, plus `tool_calls` for every tool and code.
pub(crate) fn register_static() {
    for name in [
        "audit_fallback_failures_total",
        "audit_abandoned_total",
        "sessions_created_total",
        "sessions_revoked_total",
        "log_lines_dropped_total",
    ] {
        counter!(name).increment(0);
    }
    for code in [
        "email_unverified",
        "id_token",
        "idp_exchange",
        "state_unavailable",
    ] {
        counter!("login_failures_total", "code" => code).increment(0);
    }
    for result in ["ok", "error"] {
        counter!("audit_pruner_runs_total", "result" => result).increment(0);
        counter!("config_reloads_total", "result" => result).increment(0);
    }
    for scope in ["global", "identity", "oauth"] {
        counter!("requests_shed_total", "scope" => scope).increment(0);
    }
    counter!("audit_stream_dropped_total", "sink" => "syslog").increment(0);
    for layer in ["http", "tool_work"] {
        counter!("handler_panics_total", "layer" => layer).increment(0);
    }
    for tool in TOOLS_LIST.tools.iter().map(|tool| tool.name) {
        for code in DISPATCH_OUTCOMES {
            for access in accesses(tool == RUN_QUERY_TOOL, code) {
                counter!("tool_calls", "tool" => tool, "outcome" => code.as_str(), "access" => access)
                    .increment(0);
            }
        }
    }
}

/// `tool_calls_by_db` for every database in `config`. Run at boot and after
/// each reload; a database a reload removed keeps its counters (counters
/// never expire), one added gets its own.
pub(crate) fn register_targets(config: &ConfigFile) {
    for server in &config.servers {
        for database in &server.databases {
            let db = format!("{}/{}", server.name, database.name);
            let writable = database.write_role.is_some();
            for code in DISPATCH_OUTCOMES {
                for access in accesses(writable, code) {
                    counter!("tool_calls_by_db", "db" => db.clone(), "outcome" => code.as_str(), "access" => access)
                        .increment(0);
                }
            }
        }
    }
}

/// The `access` values a call can report: `unknown` only for a call dropped
/// before it decided, `write` only where a write can happen.
fn accesses(writable: bool, code: OutcomeCode) -> impl Iterator<Item = &'static str> {
    let write = writable.then_some("write");
    let unknown = (code == OutcomeCode::Cancelled).then_some("unknown");
    std::iter::once("read").chain(write).chain(unknown)
}

/// Compile-time guard: a code added to [`OutcomeCode`] fails this match,
/// pointing at [`DISPATCH_OUTCOMES`].
#[cfg(test)]
pub(super) fn exhaustive(code: OutcomeCode) {
    use OutcomeCode::*;
    match code {
        Success | DryRun | Forbidden | ForbiddenSql | PermissionDenied | UndefinedObject
        | InvalidArguments | ReasonRequired | Timeout | SyntaxError | Unavailable
        | UnsupportedBackend | Internal | Cancelled | AuditUnavailable | Abandoned => {}
    }
}
