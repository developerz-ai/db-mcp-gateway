# 03 — MCP Tool Surface

The set of tools the gateway exposes to agents. This is the agent-facing contract. Keep it small and boring.

## Design rules

1. **Read-only by default.** A write-capable tool exists only if [06-permissions](06-permissions.md) explicitly enables it for the calling identity.
2. **Every tool accepts `server` + `database`** (except `list_servers` / `list_databases`). The pair fully scopes the call.
3. **`reason` is optional in the protocol but may be required by policy.** If policy requires it and it's absent, the gateway returns a structured error telling the agent to ask the user for one.
4. **Results are size-capped.** `run_query` and `sample_table` accept a caller-supplied `limit`; most-restrictive-wins: the effective row limit is `min(caller.limit, grant.row_limit, gateway-ceiling)`. The **gateway-wide ceiling is 100,000 rows** and applies regardless of what the caller asks for or whether the grant sets `row_limit` — an absent or oversized grant still clamps to the ceiling, never "unbounded". A grant may only tighten below the ceiling; it may not loosen past it. When neither the caller nor the grant names a limit, `run_query` defaults to **1,000 rows** and `sample_table` defaults to **10 rows**. Other result-returning tools (`list_servers`, `list_databases`, `describe_schema`, `explain`) do not accept a caller `limit`; they enforce internal caps sized to their output shape.
5. **No tool exposes credentials, connection strings, or hostnames.** Servers and databases are referenced by their config-defined logical name.

## Tools

### `list_servers`

Returns the servers the caller can see — logical name, kind (`postgres`, `mysql`, `mssql`, …), human description. No connection info.

### `list_databases`

Args: `server`. Returns databases on that server visible to the caller, with description and tags.

### `describe_schema`

Args: `server`, `database`, optional `schema`, optional `table`. Returns tables/columns/types/PK/FK/indexes. Cached aggressively — schema doesn't change per query.

### `sample_table`

Args: `server`, `database`, `table`, optional `schema`, optional `limit` (default 10, capped), optional `reason`. Returns a small sample. Useful for "what does this data look like" without writing SQL.

**Requires `query_read`, not `schema_read`.** This tool returns row data, so it is authorized exactly like `run_query` and honours the same `require_reason` constraint. A `schema_read` grant covers metadata only (`describe_schema`, `list_databases`).

### `run_query`

Args: `server`, `database`, `sql`, optional `limit`, optional `reason`. Executes under the caller's grant with statement timeout. Returns rows + truncation flag + execution stats. The primary tool.

**Read vs. write is per-grant.** With a `query_read` grant the sql guard accepts only read-only statements (`SELECT` / `EXPLAIN`). A `query_write` grant on the target `(server, database)` additionally lets a single top-level `INSERT` / `UPDATE` / `DELETE` through — **data writes only**. Schema modification (`CREATE` / `ALTER` / `DROP` / `TRUNCATE`), `GRANT` / `REVOKE`, `COPY`, transaction control, and multi-statement bodies are rejected in **both** modes; the gateway never issues DDL. Writes also require the target-DB role to actually hold write privileges — the gateway does not provision them (see [06-permissions](06-permissions.md) and CLAUDE.md non-negotiable #3). Writes commit synchronously before the response returns, and every write is audited exactly like a read. Mongo targets remain read-only regardless of grant.

**Statement-timeout ceiling:** every query is subject to a hard 30 s ceiling regardless of the per-grant `statement_timeout_ms` value. A grant may set a shorter timeout; it may not exceed 30 s — the gateway clamps it. The timeout is enforced both DB-side (`SET LOCAL statement_timeout`) and by a Tokio guard as belt-and-suspenders. A query that exceeds it returns `timeout`.

**`EXPLAIN ANALYZE` is rejected.** `EXPLAIN ANALYZE` executes the query and can therefore run write-containing CTEs on a read-only role, defeating the read-only guarantee. The sql guard rejects it before the query reaches the DB; the caller receives `forbidden_sql`.

### `explain`

Args: `server`, `database`, `sql`, optional `reason`. Returns `EXPLAIN` (or vendor equivalent) without executing. Lets the agent estimate cost before running expensive queries. Honours the same `require_reason` constraint as `run_query`.

**`EXPLAIN ANALYZE` is rejected** — same reason as in `run_query`. Use plain `EXPLAIN` instead.

### `get_query_history`

Args: optional `database`, optional `since`, optional `limit`. Returns *the caller's own* recent queries (SQL + timestamp + duration + row count). Lets the agent recover context across sessions without exposing other users' queries.

## Errors

Errors are structured JSON, not free-text strings. Shape: `{ "error": { "category": "<code>", "code": "<detail>" } }`.

| Code | HTTP | When |
|---|---|---|
| `unauthenticated` | 401 | Token missing/expired — agent triggers re-login |
| `forbidden` | 403 | Authenticated but permission denied for this server/db/action |
| `forbidden_sql` | 403 | SQL rejected before reaching the DB: statement not covered by the grant (a write without `query_write`, or a schema mod / `COPY` / multi-statement in any mode), `EXPLAIN ANALYZE`, or dangerous function (`pg_read_file`, `lo_export`, …) |
| `reason_required` | 400 | Policy requires a reason for this call; none provided |
| `timeout` | 408 | Statement timeout fired (30 s ceiling) |
| `row_limit_exceeded` | 200 | Result truncated at configured cap (flag in response, not an error response) |
| `syntax_error` | 400 | DB rejected the SQL |
| `unavailable` | 503 | DB unreachable or pool exhausted |
| `rate_limited` | 429 | Calling identity has too many concurrent in-flight requests (per-identity cap). `Retry-After: 1` header is set. |
| `service_overloaded` | 503 | Gateway-wide concurrency ceiling reached. `Retry-After: 1` header is set. |
| `internal` | 500 | Bug. Has a request ID that matches a server-side log line |

Every error includes a `request_id` the user can paste back to ops.

## Resource safety

Two independent concurrency caps protect the query path:

| Limit | Default | Response when exceeded |
|---|---|---|
| **Global** (process-wide) | 512 concurrent requests | `503` `service_overloaded` |
| **Per-identity** (per SSO `sub`) | 16 concurrent requests | `429` `rate_limited` |

Both caps are checked on the bearer-gated router *after* authentication. A per-identity permit is held for the full lifetime of the request. The global cap is checked first to keep the per-identity map lookup cheap on a saturated gateway.

The **global** cap also fronts the unauthenticated OAuth flow routes — `POST /auth/login`, `GET /auth/callback`, `GET /authorize`, `POST /token`, `POST /revoke`, `POST /register` — because each writes into a size-capped in-memory store (`PendingFlows`, `AuthCodes`) or drives IdP/DB work, so an unauthenticated flood must be bounded the same way authenticated traffic is. When the cap is exhausted these routes return `503` `service_overloaded` with `Retry-After: 1`, identical to the bearer-gated path. The per-identity cap does not apply here (no `Identity` extension exists pre-session). Discovery metadata, `/healthz`, `/readyz`, and `/metrics` are deliberately *not* gated — probes are trusted infra traffic and discovery documents are static.

The 30 s statement-timeout ceiling (see `run_query` above) is the complementary per-query bound: it limits how long one request can hold its permits.

## What we don't expose

- No DDL tools (`create_table`, `drop_table`, …) — those don't belong in a debugging gateway.
- No DML tools (`insert`, `update`, `delete`) at the protocol layer. If writes are enabled by policy, they go through `run_query` with the role having write grants; the audit log captures the SQL.
- No raw `pg_dump` / `mysqldump` style export. Bulk export is a different product.
- No "run on all databases" — every call is scoped to one DB.
