//! The tools that run caller-supplied work on a target: sampling, planning,
//! querying and cancelling.

use serde_json::json;

use super::REASON_DESCRIPTION;
use crate::mcp::limits::{
    result_cap, row_ceiling, run_query_default_rows, sample_default_rows, timeout_ceiling,
};
use crate::mcp::protocol::{
    CANCEL_QUERY_TOOL, EXPLAIN_TOOL, RUN_QUERY_TOOL, SAMPLE_TABLE_TOOL, Tool, ToolAnnotations,
};

const MAX_BYTES_DESCRIPTION: &str = "Cap on the JSON size of the returned rows: the leading \
                                     rows that fit are kept, truncated_by: byte_cap.";
const MAX_CELL_BYTES_DESCRIPTION: &str = "Replace any cell whose JSON is longer with a \
                                          {\"$dbmcp_truncated\": {bytes, preview}} marker; \
                                          drops no row.";

const PARAMS_DESCRIPTION: &str = "Postgres only: values bound to $1..$n, in order — never \
                                  parsed as SQL. JSON null, boolean, integer, number, string, \
                                  array/object bind as an untyped NULL, bool, int8, float8, \
                                  text, jsonb; cast in the SQL for any other type \
                                  ($1::date). At most 100, each at most 64 KiB of JSON.";

/// The `params` property `run_query` and `explain` share.
fn params_schema() -> serde_json::Value {
    json!({
        "type": "array",
        "maxItems": 100,
        // Any JSON value; a type list is beyond some clients' schema support.
        "items": {},
        "description": PARAMS_DESCRIPTION
    })
}

const SQL_DESCRIPTION: &str = "By server kind: postgres — one SQL statement; mongo — a JSON \
                               command document, e.g. {\"find\":\"users\",\"filter\":{}}; \
                               redis — a JSON argv array, e.g. [\"HGETALL\",\"user:1\"].";

pub(super) fn sample_table() -> Tool {
    Tool {
        name: SAMPLE_TABLE_TOOL,
        title: "Sample table",
        description: format!(
            "A few rows of one table — `SELECT * FROM \"<schema>\".\"<table>\" \
             LIMIT n`, default {} rows, at most {}; `columns` keeps only those. Mongo: \
             a limited `find` on the collection, one `document` column per row \
             (`columns` picks top-level fields). Not on Redis. Schema and table are \
             plain identifiers (letters, digits, `_`; a Mongo collection may also \
             hold `-` and `.`). Same result shape as run_query. Needs query_read.",
            sample_default_rows(),
            row_ceiling(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server":   { "type": "string" },
                "database": { "type": "string" },
                "table":    { "type": "string" },
                "schema":   { "type": "string" },
                "limit":    { "type": "integer", "minimum": 1 },
                "columns":  { "type": "array", "items": { "type": "string" },
                              "minItems": 1, "uniqueItems": true },
                "max_bytes":      { "type": "integer", "minimum": 2,
                                    "description": MAX_BYTES_DESCRIPTION },
                "max_cell_bytes": { "type": "integer", "minimum": 1,
                                    "description": MAX_CELL_BYTES_DESCRIPTION },
                "reason":   { "type": "string", "description": REASON_DESCRIPTION }
            },
            "required": ["server", "database", "table"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn explain() -> Tool {
    Tool {
        name: EXPLAIN_TOOL,
        title: "Explain query",
        description: format!(
            "The query plan from `EXPLAIN (FORMAT JSON)`, plus a `summary`: the root's \
             total_cost and plan_rows, seq_scans (relations read by a sequential scan) \
             and node_count. Plain EXPLAIN never executes the statement; INSERT/UPDATE/DELETE need a query_write \
             grant. `analyze: true` runs the statement for real timings — read \
             statements only, inside a read-only transaction and the {} statement \
             timeout. Postgres only.",
            timeout_ceiling(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server":   { "type": "string" },
                "database": { "type": "string" },
                "sql":      { "type": "string" },
                "analyze":  { "type": "boolean", "default": false },
                "params":   params_schema(),
                "reason":   { "type": "string", "description": REASON_DESCRIPTION }
            },
            "required": ["server", "database", "sql"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::mutating(false),
    }
}

pub(super) fn run_query() -> Tool {
    Tool {
        name: RUN_QUERY_TOOL,
        title: "Run query",
        description: format!(
            "Run one statement under your grants. `sql` depends on the server \
             kind (see its description). Returns columns, rows, truncated, row_limit, \
             elapsed_ms and, for a write, rows_affected. Rows: default {}, `limit` \
             up to {}, a grant may lower both; a result stops at {}. When `truncated`, \
             `truncated_by` says which cap hit and `hint` how to page for the rest. \
             Statement timeout {} (a grant may lower it). \
             Read-only unless a query_write grant allows one INSERT/UPDATE/DELETE \
             on Postgres; `dry_run: true` runs that write and rolls it back (triggers \
             fire; sequences advance). Mongo \
             and Redis are always read-only.",
            run_query_default_rows(),
            row_ceiling(),
            result_cap(),
            timeout_ceiling(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server":   { "type": "string" },
                "database": { "type": "string" },
                "sql":      { "type": "string", "description": SQL_DESCRIPTION },
                "limit":    { "type": "integer", "minimum": 1 },
                "params":   params_schema(),
                "dry_run":  { "type": "boolean", "default": false },
                "max_bytes":      { "type": "integer", "minimum": 2,
                                    "description": MAX_BYTES_DESCRIPTION },
                "max_cell_bytes": { "type": "integer", "minimum": 1,
                                    "description": MAX_CELL_BYTES_DESCRIPTION },
                "reason":   { "type": "string", "description": REASON_DESCRIPTION }
            },
            "required": ["server", "database", "sql"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::mutating(true),
    }
}

pub(super) fn cancel_query() -> Tool {
    Tool {
        name: CANCEL_QUERY_TOOL,
        title: "Cancel query",
        description: "Cancel one of your own running queries by its gateway \
                      `request_id` (from the error body, `x-request-id`, or \
                      db_activity). Postgres only. Needs query_read on the \
                      database."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server":   { "type": "string" },
                "database": { "type": "string" },
                "request_id": { "type": "string", "format": "uuid" },
                "reason":   { "type": "string", "description": REASON_DESCRIPTION }
            },
            "required": ["server", "database", "request_id"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::mutating(false),
    }
}
