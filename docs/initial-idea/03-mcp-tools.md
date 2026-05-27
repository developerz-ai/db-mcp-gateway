# 03 — MCP Tool Surface

The set of tools the gateway exposes to agents. This is the agent-facing contract. Keep it small and boring.

## Design rules

1. **Read-only by default.** A write-capable tool exists only if [06-permissions](06-permissions.md) explicitly enables it for the calling identity.
2. **Every tool accepts `server` + `database`** (except `list_servers` / `list_databases`). The pair fully scopes the call.
3. **`reason` is optional in the protocol but may be required by policy.** If policy requires it and it's absent, the gateway returns a structured error telling the agent to ask the user for one.
4. **Results are size-capped.** All result-returning tools take a `limit` parameter; the gateway clamps it to a per-database max.
5. **No tool exposes credentials, connection strings, or hostnames.** Servers and databases are referenced by their config-defined logical name.

## Tools

### `list_servers`

Returns the servers the caller can see — logical name, kind (`postgres`, `mysql`, `mssql`, …), human description. No connection info.

### `list_databases`

Args: `server`. Returns databases on that server visible to the caller, with description and tags.

### `describe_schema`

Args: `server`, `database`, optional `schema`, optional `table`. Returns tables/columns/types/PK/FK/indexes. Cached aggressively — schema doesn't change per query.

### `sample_table`

Args: `server`, `database`, `table`, optional `limit` (default 10, capped). Returns a small sample. Useful for "what does this data look like" without writing SQL.

### `run_query`

Args: `server`, `database`, `sql`, optional `limit`, optional `reason`. Executes under the read-only role with statement timeout. Returns rows + truncation flag + execution stats. The primary tool.

### `explain`

Args: `server`, `database`, `sql`. Returns `EXPLAIN` (or vendor equivalent) without executing. Lets the agent estimate cost before running expensive queries.

### `get_query_history`

Args: optional `database`, optional `since`, optional `limit`. Returns *the caller's own* recent queries (SQL + timestamp + duration + row count). Lets the agent recover context across sessions without exposing other users' queries.

## Errors

Errors are structured JSON, not free-text strings. Categories:

| Code | When |
|---|---|
| `unauthenticated` | Token missing/expired — agent triggers re-login |
| `forbidden` | Authenticated but permission denied for this server/db/action |
| `reason_required` | Policy requires a reason for this call; none provided |
| `timeout` | Statement timeout fired |
| `row_limit_exceeded` | Result truncated at configured cap |
| `syntax_error` | DB rejected the SQL |
| `unavailable` | DB unreachable or pool exhausted |
| `internal` | Bug. Has a request ID that matches a server-side log line |

Every error includes a `request_id` the user can paste back to ops.

## What we don't expose

- No DDL tools (`create_table`, `drop_table`, …) — those don't belong in a debugging gateway.
- No DML tools (`insert`, `update`, `delete`) at the protocol layer. If writes are enabled by policy, they go through `run_query` with the role having write grants; the audit log captures the SQL.
- No raw `pg_dump` / `mysqldump` style export. Bulk export is a different product.
- No "run on all databases" — every call is scoped to one DB.
