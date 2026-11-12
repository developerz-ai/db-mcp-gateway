//! The advertised `tools/list`: one name, description and input schema per
//! tool `crate::tools::dispatch_call` routes. Wire contract:
//! website/docs/initial-idea/03-mcp-tools.md.

use serde_json::json;

use super::protocol::{
    CANCEL_QUERY_TOOL, DB_ACTIVITY_TOOL, DESCRIBE_SCHEMA_TOOL, EXPLAIN_TOOL,
    GET_QUERY_HISTORY_TOOL, LIST_DATABASES_TOOL, LIST_SERVERS_TOOL, RUN_QUERY_TOOL,
    SAMPLE_TABLE_TOOL, TABLE_STATS_TOOL, Tool, ToolsListResult,
};

const REASON_DESCRIPTION: &str =
    "Why you are making this call; required when the grant sets require_reason.";

impl ToolsListResult {
    pub(super) fn build() -> Self {
        Self {
            tools: vec![
                Tool {
                    name: LIST_SERVERS_TOOL,
                    description: "List the database servers the caller is permitted to see. \
                                  Returns logical name, kind, and description — no connection info.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: LIST_DATABASES_TOOL,
                    description: "List databases on a configured server that the caller is \
                                  permitted to see. Returns logical name + description — \
                                  no connection info.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server": { "type": "string" }
                        },
                        "required": ["server"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: DESCRIBE_SCHEMA_TOOL,
                    description: "Return tables + columns + types for a given database. \
                                  Optional `schema` (default `public`) and `table` narrow \
                                  the result. On Mongo: collections and their indexes. \
                                  No row data is returned.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "schema":   { "type": "string" },
                            "table":    { "type": "string" }
                        },
                        "required": ["server", "database"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: SAMPLE_TABLE_TOOL,
                    description: "Return a small sample of rows from a table — `SELECT * \
                                  FROM \"<schema>\".\"<table>\" LIMIT n` (on Mongo, a \
                                  limited `find`). Useful for \"what does this data look \
                                  like\" without writing SQL. Schema and table identifiers \
                                  must be plain alphanumerics.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "table":    { "type": "string" },
                            "schema":   { "type": "string" },
                            "limit":    { "type": "integer", "minimum": 1 },
                            "reason":   { "type": "string" }
                        },
                        "required": ["server", "database", "table"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: EXPLAIN_TOOL,
                    description: "Return the query plan via `EXPLAIN (FORMAT JSON)`. Plain \
                                  EXPLAIN never executes the statement; INSERT/UPDATE/DELETE \
                                  need a query_write grant. `analyze: true` runs the \
                                  statement for real timings — read statements only, inside \
                                  a read-only transaction and the statement timeout.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "sql":      { "type": "string" },
                            "analyze":  { "type": "boolean", "default": false },
                            "reason":   { "type": "string" }
                        },
                        "required": ["server", "database", "sql"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: RUN_QUERY_TOOL,
                    description: "Execute SQL against a configured (server, database) under the \
                                  caller's grants. Returns columns, rows, truncation flag, \
                                  elapsed_ms and, for a write, rows_affected. Statement timeout \
                                  + row cap enforced by policy. Writes (single INSERT/UPDATE/ \
                                  DELETE) need a query_write grant; `dry_run: true` runs the \
                                  write, reports rows_affected and rolls it back.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "sql":      { "type": "string" },
                            "limit":    { "type": "integer", "minimum": 1 },
                            "dry_run":  { "type": "boolean", "default": false },
                            "reason":   { "type": "string" }
                        },
                        "required": ["server", "database", "sql"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: GET_QUERY_HISTORY_TOOL,
                    description: "Return the caller's recent queries against a configured \
                                  (server, database): SQL, timestamp, duration, row count, and \
                                  outcome. Lets the agent recover context across sessions. \
                                  Scoping is on the authenticated identity, NEVER on a \
                                  client-supplied user field; a service token that sends \
                                  `x-dbmcp-run-id` sees only that run's entries.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "since":    { "type": "string", "format": "date-time",
                                           "description": "RFC 3339 timestamp; only entries \
                                                            occurred at or after this instant are \
                                                            returned." },
                            "limit":    { "type": "integer", "minimum": 1, "maximum": 1000,
                                           "description": "Max entries to return; clamped to \
                                                            the gateway ceiling." },
                            "cursor":   { "type": "string",
                                           "description": "Opaque `next_cursor` from a previous \
                                                            page; returns the entries after it." },
                            "reason":   { "type": "string", "description": REASON_DESCRIPTION }
                        },
                        "required": ["server", "database"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: TABLE_STATS_TOOL,
                    description: "Table health for a schema (default `public`) or one table: \
                                  total size, row estimate, dead tuples, last vacuum/analyze, \
                                  and per-index size + scan count. Needs schema_read.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "schema":   { "type": "string" },
                            "table":    { "type": "string" },
                            "reason":   { "type": "string", "description": REASON_DESCRIPTION }
                        },
                        "required": ["server", "database"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: DB_ACTIVITY_TOOL,
                    description: "Queries the gateway is running on this database right now: \
                                  pid, state, duration, wait event, and the gateway request_id. \
                                  Query text only for your own requests. Needs schema_read.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":   { "type": "string" },
                            "database": { "type": "string" },
                            "reason":   { "type": "string", "description": REASON_DESCRIPTION }
                        },
                        "required": ["server", "database"],
                        "additionalProperties": false
                    }),
                },
                Tool {
                    name: CANCEL_QUERY_TOOL,
                    description: "Cancel one of your own running queries by its gateway \
                                  `request_id` (from the error body, `x-request-id`, or \
                                  db_activity). Needs query_read on the database.",
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "server":     { "type": "string" },
                            "database":   { "type": "string" },
                            "request_id": { "type": "string", "format": "uuid" },
                            "reason":     { "type": "string", "description": REASON_DESCRIPTION }
                        },
                        "required": ["server", "database", "request_id"],
                        "additionalProperties": false
                    }),
                },
            ],
        }
    }
}
