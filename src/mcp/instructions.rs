//! The `initialize` instructions: how an agent should drive the tools, in the
//! few hundred words a client puts in its system prompt. Numbers come from
//! the enforcing constants (`super::limits`), codes from [`OutcomeCode`].

use crate::audit::OutcomeCode;

use super::jsonrpc::SERVER_OVERLOADED;
use super::limits::{result_cap, row_ceiling, run_query_default_rows, timeout_ceiling};

/// What to do on each tool error code an agent can act on.
const ON_ERROR: [(OutcomeCode, &str); 13] = [
    (
        OutcomeCode::Forbidden,
        "no grant for that server, database or action; see list_servers / list_databases",
    ),
    (
        OutcomeCode::ForbiddenSql,
        "statement not allowed (write without a grant, DDL, several statements); send one read",
    ),
    (
        OutcomeCode::ReasonRequired,
        "ask the user why, retry with `reason`",
    ),
    (
        OutcomeCode::InvalidArguments,
        "fix the arguments per the tool schema",
    ),
    (OutcomeCode::SyntaxError, "fix the query"),
    (
        OutcomeCode::UndefinedObject,
        "no such table or column; check describe_schema",
    ),
    (
        OutcomeCode::PermissionDenied,
        "the database role lacks the privilege; do not retry",
    ),
    (OutcomeCode::Timeout, "narrow the query or explain it first"),
    (
        OutcomeCode::UnsupportedBackend,
        "the tool is not offered for that server kind",
    ),
    (OutcomeCode::Cancelled, "cancel_query stopped it"),
    (
        OutcomeCode::Unavailable,
        "transient; retry in a few seconds",
    ),
    (
        OutcomeCode::AuditUnavailable,
        "not recorded, so refused; retry later",
    ),
    (OutcomeCode::Internal, "give the operator the request_id"),
];

pub(super) fn build() -> String {
    let mut text = format!(
        "db-mcp-gateway: audited database access under your SSO grants. Servers and databases \
         are logical names; hosts and credentials are never shown.\n\
         \n\
         Call order: list_servers, list_databases, describe_schema, then sample_table or \
         run_query; explain a costly query first. whoami shows your grants.\n\
         \n\
         run_query `sql` by server kind:\n\
         - postgres: one SQL statement\n\
         - mongo: a JSON command document, e.g. {{\"find\":\"users\",\"filter\":{{}}}}\n\
         - redis: a JSON argv array, e.g. [\"HGETALL\",\"user:1\"]\n\
         Mongo and Redis are read-only. explain, table_stats, db_activity, cancel_query: \
         Postgres only. describe_schema, sample_table: not Redis.\n\
         \n\
         Limits: {default} rows unless you pass `limit` (max {ceiling}; a grant may lower \
         both), {cap} per result; past either `truncated` is true, so narrow the query or \
         page on a key. Timeout {timeout}.\n\
         \n\
         Pass `reason` (why you are calling) when the grant sets require_reason.\n\
         \n\
         Errors are tool results with isError and {{request_id, code, message}}. `write`: \
         unknown or applied means the change may have landed; check before retrying. Codes:\n",
        default = run_query_default_rows(),
        ceiling = row_ceiling(),
        cap = result_cap(),
        timeout = timeout_ceiling(),
    );
    for (code, advice) in ON_ERROR {
        text.push_str(&format!("- {code}: {advice}\n"));
    }
    text.push_str(&format!(
        "HTTP 429 / 503 (JSON-RPC {SERVER_OVERLOADED}): too many calls in flight; wait \
         data.retry_after_s and retry."
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clients put this in a system prompt; keep it a hint, not a manual.
    #[test]
    fn instructions_stay_under_2_kib() {
        let text = build();
        assert!(text.len() < 2048, "{} bytes:\n{text}", text.len());
    }

    #[test]
    fn instructions_quote_the_enforced_limits() {
        let text = build();
        for limit in [
            run_query_default_rows(),
            row_ceiling(),
            result_cap(),
            timeout_ceiling(),
        ] {
            assert!(text.contains(&limit), "missing {limit}");
        }
    }
}
