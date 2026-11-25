//! Discovery and metadata tools: where the caller can go, what is there,
//! and what it already did. None reads row data.

use serde_json::json;

use super::{REASON_DESCRIPTION, RUN_SCOPED_DESCRIPTION};
use crate::mcp::protocol::{
    DB_ACTIVITY_TOOL, DESCRIBE_SCHEMA_TOOL, GET_QUERY_HISTORY_TOOL, LIST_DATABASES_TOOL,
    LIST_SERVERS_TOOL, TABLE_STATS_TOOL, Tool, ToolAnnotations, WHOAMI_TOOL,
};

pub(super) fn list_servers() -> Tool {
    Tool {
        name: LIST_SERVERS_TOOL,
        title: "List servers",
        description: "List the database servers you may use: logical name, kind \
                      (postgres, mongo, redis), description and `databases` — each with \
                      the actions, tools and limits your grants give you there. No \
                      connection info. Start here."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn list_databases() -> Tool {
    Tool {
        name: LIST_DATABASES_TOOL,
        title: "List databases",
        description: "List the databases you may use on `server`, or on every \
                      server you can see when `server` is omitted: logical name, \
                      description, kind, your actions, whether writes can succeed, \
                      the tools that work there and the row/timeout/reason limits \
                      your grants enforce. No connection info."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": { "type": "string",
                            "description": "Logical server name from \
                                            list_servers; omit for all." }
            },
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn describe_schema() -> Tool {
    Tool {
        name: DESCRIBE_SCHEMA_TOOL,
        title: "Describe schema",
        description: "Tables, columns and types of a database. `detail`: `names` \
                      (tables and their kind), `columns` (default), `full` (real \
                      types, keys, indexes, comments, row estimates). Optional \
                      `schema` (default `public`) and `table` narrow the result; \
                      `search` keeps tables whose name or a column name contains the \
                      term, across every schema unless `schema` is given. Mongo: \
                      collections and their indexes (`schema` ignored); `full` also \
                      infers fields from a few sampled documents, which needs \
                      query_read. Not on Redis. Needs schema_read."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server":   { "type": "string" },
                "database": { "type": "string" },
                "schema":   { "type": "string" },
                "table":    { "type": "string" },
                "detail":   { "type": "string", "enum": ["names", "columns", "full"],
                              "default": "columns" },
                "search":   { "type": "string",
                              "description": "Case-insensitive substring of a table or \
                                              column name." },
                "reason":   { "type": "string", "description": REASON_DESCRIPTION }
            },
            "required": ["server", "database"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn get_query_history() -> Tool {
    Tool {
        name: GET_QUERY_HISTORY_TOOL,
        title: "Query history",
        description: "Your recent queries against a (server, database), newest \
                      first: SQL and its sql_sha256, timestamp, duration, row count \
                      and outcome; `sql_sha256` narrows to one statement's runs. \
                      Recovers context across sessions. Scoped to your \
                      authenticated identity, never to a client-supplied user; a \
                      service token that sends `x-dbmcp-run-id` sees only that \
                      run's entries. Needs history_read."
            .to_owned(),
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
                "sql_sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$",
                               "description": "Hex SHA-256 of the stored SQL (an \
                                                entry's sql_sha256); only its \
                                                entries are returned." },
                "reason":   { "type": "string", "description": REASON_DESCRIPTION }
            },
            "required": ["server", "database"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn table_stats() -> Tool {
    Tool {
        name: TABLE_STATS_TOOL,
        title: "Table stats",
        description: "Table health for a schema (default `public`) or one table: \
                      total size, row estimate, dead tuples, last vacuum/analyze, \
                      and per-index size + scan count. Postgres only. Needs \
                      schema_read."
            .to_owned(),
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
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn db_activity() -> Tool {
    Tool {
        name: DB_ACTIVITY_TOOL,
        title: "Database activity",
        description: "Your own statements the gateway is running on this database \
                      right now: pid, request_id, pool, state, wait event and \
                      running_ms. No query text — see get_query_history. Postgres \
                      only. Needs schema_read."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server":   { "type": "string" },
                "database": { "type": "string" },
                "reason":   { "type": "string", "description": REASON_DESCRIPTION },
                "run_scoped": { "type": "boolean", "default": false,
                                "description": RUN_SCOPED_DESCRIPTION }
            },
            "required": ["server", "database"],
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}

pub(super) fn whoami() -> Tool {
    Tool {
        name: WHOAMI_TOOL,
        title: "Who am I",
        description: "Your authenticated identity, groups, session expiry and the \
                      grants that apply to you. No database call."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        annotations: ToolAnnotations::read_only(),
    }
}
