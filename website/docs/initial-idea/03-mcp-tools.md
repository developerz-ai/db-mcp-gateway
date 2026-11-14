# 03 — MCP Tool Surface

The set of tools the gateway exposes to agents. This is the agent-facing contract. Keep it small and boring.

## Design rules

1. **Read-only by default.** A write-capable tool exists only if [06-permissions](06-permissions.md) explicitly enables it for the calling identity.
2. **Every tool accepts `server` + `database`** (except `list_servers` / `list_databases`). The pair fully scopes the call.
3. **`reason` is optional in the protocol but may be required by policy.** If policy requires it and it's absent, the gateway returns a structured error telling the agent to ask the user for one.
4. **Results are size-capped.** `run_query` and `sample_table` accept a caller-supplied `limit`; most-restrictive-wins: the effective row limit is `min(caller.limit, grant.row_limit, gateway-ceiling)`. The **gateway-wide ceiling is 100,000 rows** and applies regardless of what the caller asks for or whether the grant sets `row_limit` — an absent or oversized grant still clamps to the ceiling, never "unbounded". A grant may only tighten below the ceiling; it may not loosen past it. When neither the caller nor the grant names a limit, `run_query` defaults to **1,000 rows** and `sample_table` defaults to **10 rows**. Results are also capped at **32 MiB of decoded values** per call (`exec::MAX_RESULT_BYTES`), whatever the row limit: past it the gateway stops collecting and sets `truncated: true`, exactly as for the row cap. Mongo commands get the same row and byte budget; `find` and `aggregate` also carry a server-side limit of `row_limit + 1`. Other result-returning tools (`list_servers`, `list_databases`, `describe_schema`, `explain`) do not accept a caller `limit`; they enforce internal caps sized to their output shape.
5. **No tool exposes credentials, connection strings, or hostnames.** Servers and databases are referenced by their config-defined logical name.

## Tools

### `list_servers`

Returns the servers the caller can see — logical name, kind (`postgres`, `mysql`, `mssql`, …), human description. No connection info.

### `list_databases`

Args: `server`. Returns databases on that server visible to the caller, with description and tags.

### `describe_schema`

Args: `server`, `database`, optional `schema` (default `public`), optional `table`, optional `reason`. Honours the grant's `require_reason` constraint like every tool that reaches the target: without a non-blank `reason` the call gets `reason_required` (audited) and the catalog is never read. Returns `{ "tables": [{ "schema", "name", "columns": [{ "name", "data_type", "nullable" }] }], "truncated": bool }`. The catalog scan is capped at 50,000 columns; when the cap is hit `truncated` is `true`, tables past the cut are missing, and the table the cut fell in is dropped rather than returned with only some of its columns — every table returned is complete. Narrow with `table` to see one table past the cap. PK/FK/indexes are not returned yet.

**Mongo:** `schema` is ignored (the database is the namespace) and `table` names one collection. Returns `{ "collections": [{ "database", "name", "type", "indexes": [{ "name", "key", "unique" }] }], "truncated": bool }` from `listCollections` + `listIndexes`; `type` is `collection`, `view`, …, and a view has no indexes.

### `sample_table`

Args: `server`, `database`, `table`, optional `schema`, optional `limit` (default 10, capped), optional `reason`. Returns a small sample. Useful for "what does this data look like" without writing SQL. On Mongo, `table` names a collection and the sample is a limited `find`, one `document` column per row.

**Requires `query_read`, not `schema_read`.** This tool returns row data, so it is authorized exactly like `run_query` and honours the same `require_reason` constraint. A `schema_read` grant covers metadata only (`describe_schema`, `list_databases`).

### `run_query`

Args: `server`, `database`, `sql`, optional `limit`, optional `dry_run`, optional `reason`. Executes under the caller's grant with statement timeout. Returns rows + truncation flag + execution stats, and `rows_affected` for a write. The primary tool.

**Read vs. write is per-grant.** With a `query_read` grant the sql guard accepts only read-only statements (`SELECT` / `EXPLAIN`). A `query_write` grant on the target `(server, database)` additionally lets a single top-level `INSERT` / `UPDATE` / `DELETE` through — **data writes only**. Schema modification (`CREATE` / `ALTER` / `DROP` / `TRUNCATE`), `GRANT` / `REVOKE`, `COPY`, transaction control, and multi-statement bodies are rejected in **both** modes; the gateway never issues DDL. Writes also require the target-DB role to actually hold write privileges — the gateway does not provision them (see [06-permissions](06-permissions.md) and CLAUDE.md non-negotiable #3).

**Two roles per database, one per tier.** A database that accepts writes names a `write_role` (+ `write_password`) next to its read `role`; a `query_write` grant on a database without one fails boot. The access a call runs with is decided per statement: a write-tier caller's `SELECT` still runs as the read `role` inside a read-only transaction, and only a data write runs as `write_role`. The read tier can therefore never reach a write-capable role — the separation is role-level, not parser-level.

**`dry_run: true`** (write tier only) executes the write, reports `rows_affected`, and rolls the transaction back: nothing changes. The response carries `"dry_run": true` and the audit row records outcome `dry_run` with `rows_affected`. `dry_run` on a read statement is `invalid_arguments`; on a write without a `query_write` grant the guard answers `forbidden_sql` first. Writes commit synchronously before the response returns, and every write is audited exactly like a read. Mongo targets remain read-only regardless of grant.

**Read access is enforced by the database too.** A `query_read` call runs in a `READ ONLY` transaction, so even a write-capable target role cannot write through it; the sql guard is the second layer, not the only one. **A write is never cut short:** when a `RETURNING` write produces more rows than the limit (or the byte cap), the gateway stops collecting, drains the rest, commits, and returns the capped rows with `truncated: true` and `rows_affected` — the number of rows the statement actually changed. A write's result always carries `rows_affected`; a read's never does. A read past the cap is cancelled and rolled back (nothing to lose).

**Statement-timeout ceiling:** every query is subject to a hard 30 s ceiling regardless of the per-grant `statement_timeout_ms` value. A grant may set a shorter timeout; it may not exceed 30 s — the gateway clamps it. The timeout is enforced both DB-side (`SET LOCAL statement_timeout`) and by a Tokio guard as belt-and-suspenders. A query that exceeds it returns `timeout`.

**`EXPLAIN ANALYZE` inside `sql` is rejected.** It executes the statement, and through `run_query` it would bypass the per-statement access decision. The sql guard rejects it before the query reaches the DB; the caller receives `forbidden_sql`. Use `explain` with `analyze: true` instead.

**`null` means SQL NULL — always.** A value the gateway cannot render as JSON is never returned as `null`, because an agent acting on the result cannot tell a fabricated null from a real one. Such a cell comes back as `{"unsupported_type": "<pg type>"}` instead, naming the type so the caller can cast it (`SELECT my_col::text`).

**Zero-row results still name their columns — best-effort.** A successful query that matches no rows returns `rows: []`, `truncated: false`, and `columns` populated with the selected column names in their left-to-right order — same shape as a non-empty result. This lets the caller distinguish "your filter matched nothing" from "that table has no such columns" without a second round-trip. Column naming for zero-row Postgres results relies on a best-effort `Describe` after the row stream completes and before the transaction commits; in the rare case that `Describe` fails, the query still succeeds but `columns` comes back as `[]` (`rows: []` and `truncated: false` are unaffected).

Rendering rules for the non-obvious types:

| Postgres type | JSON |
|---|---|
| `numeric` / `decimal` | string, e.g. `"1234.5600"` — never a float, so money keeps full precision |
| `timestamptz` | RFC 3339 string, normalised to UTC |
| `timestamp` / `date` / `time` | ISO-8601 string, no zone invented |
| `uuid` | string |
| `bytea` | Postgres' own `\x`-prefixed hex string |
| `json` / `jsonb` | inlined as JSON |
| `float4` / `float8` NaN, ±infinity | `"NaN"`, `"Infinity"`, `"-Infinity"` — JSON numbers cannot hold them, and `null` would read as SQL NULL |
| `text[]` / `varchar[]`, `int2[]` / `int4[]` / `int8[]`, `uuid[]` | JSON array (elements may be `null`) |
| `interval` | ISO-8601 duration, e.g. `"P1Y2M3DT4H5M6.5S"` |
| `inet` / `cidr` | Postgres text form, e.g. `"10.0.0.1"`, `"10.0.0.0/8"` |
| enums | the label, as a string |
| other arrays, ranges, composites, user-defined | `{"unsupported_type": "…"}` |

### `explain`

Args: `server`, `database`, `sql`, optional `analyze` (default `false`), optional `reason`. Returns `{ "plan", "elapsed_ms" }` from `EXPLAIN (FORMAT JSON)`. Lets the agent estimate cost before running expensive queries. Honours the same `require_reason` constraint as `run_query`.

The statement passes the same guard as `run_query` at the caller's grant: a read needs `query_read`, an `INSERT` / `UPDATE` / `DELETE` needs `query_write` and is planned as the database's `write_role`. Plain `EXPLAIN` never executes the statement, so planning a write changes nothing.

**`analyze: true` executes the statement** for real row counts and timings, so it is accepted for **read statements only** — DML with `analyze` is `forbidden_sql`, whatever the grant. The read runs as the read `role` inside the read-only transaction and under the statement timeout, which is what makes executing it safe.

### `get_query_history`

Args: `server`, `database`, optional `since` (RFC 3339), optional `limit`, optional `cursor`, optional `reason`. Returns *the caller's own* recent queries (request id, SQL, reason, timestamp, duration, row count, rows affected, outcome) for that `(server, database)`, ordered newest-first, one page at a time. Lets the agent recover context across sessions without exposing other users' queries.

**Scoping is the security-critical contract.** The filter is on the SSO-verified identity (`identity.user_sub`) from the session middleware — NEVER on a client-supplied `user` field. The arguments struct uses `#[serde(deny_unknown_fields)]`; any attempt to pass `user` (or any other unknown key) is rejected with JSON-RPC `invalid_params` before any history is read — and the attempt itself is audited as `invalid_arguments`. The `WHERE` clause is `user_sub = $1 AND server_name = $2 AND database_name = $3`, ordered by `(occurred_at, id)` descending; the composite index `audit_calls_history_idx` (migration 0011) covers both.

`limit` defaults to 100 and is clamped to a page ceiling of **1,000**; a hostile `u32::MAX` request is clamped, not honoured. The `truncated` flag reports exactly that clamp: it is `true` when the caller's `limit` exceeded the ceiling and was lowered. It does **not** mean "more entries exist" — that is `next_cursor`.

**Pagination is keyset on `(occurred_at, id)`.** The response carries `next_cursor` — an opaque string, `null` on the last page. Pass it back as `cursor` (with the same `server`, `database`, `since`) for the next older page; pages never overlap, however many new calls land in between. A `cursor` the gateway did not mint is rejected with `invalid_params` (audited `invalid_arguments`).

**Service identities see one run at a time.** When a service-token call carries `x-dbmcp-run-id` ([14-service-tokens](14-service-tokens.md) §Upstream attribution), only rows recorded with that same run id are returned, so agents sharing one token do not read each other's history by default. Without the header a service identity sees all of its rows; the header is ignored for SSO sessions.

Each entry's `sql` is capped at 4,096 bytes (cut on a character boundary); `sql_truncated: true` marks an entry whose statement was cut — here, or at the 64 KiB stored-SQL cap when the row was written ([07-logging-retention](07-logging-retention.md)).

`since` is parsed at the edge as RFC 3339; a malformed value is rejected with `invalid_params` rather than silently dropping the filter.

Response shape: `{ "entries": [{ "request_id", "sql", "sql_truncated", "reason", "occurred_at", "elapsed_ms", "row_count", "rows_affected", "outcome" }], "truncated": bool, "next_cursor": string | null }`.

Requires the `history_read` grant, which is standalone (per [#170](https://github.com/developerz-ai/db-mcp-gateway/issues/170) — `query_read` does not imply it). A caller without an explicit `history_read` grant for `(server, database)` gets `forbidden`. The merged constraints of the matching grants apply as for every other tool: when `require_reason` is set, a call without a non-empty `reason` gets `reason_required` (audited), and the `reason` given is recorded in the audit row. The call itself is audited like any other tool dispatch (`tool = "get_query_history"`, `sql = NULL`).

**Implemented with [#169](https://github.com/developerz-ai/db-mcp-gateway/issues/169).**

### `table_stats`

Args: `server`, `database`, optional `schema` (default `public`), optional `table`, optional `reason`. Requires `schema_read` (statistics are metadata, never row data). Returns `{ "columns", "rows", "truncated", "elapsed_ms" }`, one row per table the read role may `SELECT`: `schema, table, total_bytes, table_bytes, index_bytes, row_estimate, live_rows, dead_rows, seq_scans, index_scans, last_vacuum, last_autovacuum, last_analyze, last_autoanalyze, indexes` — `indexes` a JSON array of `{ name, bytes, scans }`. From `pg_stat_user_tables`, `pg_stat_user_indexes` and `pg_total_relation_size`, read as the read role inside a read-only transaction and the statement timeout; capped at 10,000 tables (`truncated`).

### `db_activity`

Args: `server`, `database`, optional `reason`. Requires `schema_read`. Returns `{ "columns", "rows", "truncated", "elapsed_ms" }` with `pid, request_id, pool, state, wait_event_type, wait_event, running_ms` for each statement the gateway is running on that database **for the caller** — `request_id` is the gateway request the backend serves (the gateway tags its backends via `application_name`), `pool` is `read` / `write`. The adapter only sees the gateway's own roles; the tool then keeps only requests whose intent row ([07-logging-retention](07-logging-retention.md)) carries the caller's identity, so one identity never sees another's activity. No query text: the caller's statements are in `get_query_history`.

### `cancel_query`

Args: `server`, `database`, `request_id`, optional `reason`. Requires `query_read` on that database. Cancels the statement the gateway is running for `request_id` — the id from an error body, the `x-request-id` header, or `db_activity`. **Own identity only:** a `request_id` that is not one of the caller's own on that `(server, database)` answers `forbidden`, exactly like an unknown one, so ids cannot be probed. Returns `{ "cancelled": bool }` — `false` when the request had already finished. The cancelled call answers `cancelled` and writes its own audit row with that outcome; the `cancel_query` call's row records the target `request_id` in `sql`. A malformed `request_id` is `invalid_arguments`.

## Errors

Errors are structured JSON, not free-text strings. Shape: `{ "error": { "category": "<code>", "code": "<detail>" } }`.

| Code | HTTP | When |
|---|---|---|
| `unauthenticated` | 401 | Token missing/expired — agent triggers re-login |
| `expired_session` | 401 | Session outlived its TTL (distinct from `revoked_session`: routine, not a sign-out). Agent triggers re-login |
| `forbidden` | 403 | Authenticated but permission denied for this server/db/action |
| `forbidden_sql` | 403 | SQL rejected before reaching the DB: statement not covered by the grant (a write without `query_write`, or a schema mod / `COPY` / multi-statement in any mode), `EXPLAIN ANALYZE` in `sql` (either spelling, `ANALYZE`/`ANALYSE`, keyword or option form), `explain` with `analyze: true` on a write, Unicode-escaped identifiers (`U&"…"`), or dangerous function (filesystem `pg_read_file`, `lo_*`; session state `set_config`, `pg_advisory_*`; cross-session messages `pg_notify`, `pg_logical_emit_message`; SQL-text executors `query_to_xml*`, `ts_stat`, `ts_rewrite`, `dblink*`; …) |
| `invalid_arguments` | 400 | Arguments rejected: they do not deserialise (missing or mistyped field, unknown key), break the argument edge (any string argument or argument name carrying NUL or another control character — identifiers take none, free text keeps tab/newline/carriage return; an identifier — `server`, `database`, `schema`, `table`, `request_id` — over 128 bytes, `reason` over 1,024, `sql` over 64 KiB (the audit cap, so every statement that runs is stored whole), any other string over 1,024; checked before the intent row, so nothing refused here reaches the target and the audit row stores no part of the refused value), fail a per-tool bound (`limit: 0`, malformed `since` or `cursor`, a `sample_table` name that is not an identifier, `dry_run` on a read, a non-UUID `cancel_query` `request_id`), the tool name contains a control character, the tool name is unknown, `name` is missing, or a service-token call's upstream headers are malformed or missing under `require_upstream` ([14-service-tokens](14-service-tokens.md)). JSON-RPC envelope carries `invalid_params` (-32602); the audit row records `invalid_arguments` — with `server`/`database` NULL when the arguments never parsed, and `tool = "unknown"` for an unknown or missing name (the caller's name, capped at 64 bytes, is in `error_message`) — so every boundary rejection is accountable. |
| `reason_required` | 400 | Policy requires a reason for this call; none provided, or only whitespace |
| `timeout` | 408 | Statement timeout fired (30 s ceiling) |
| `row_limit_exceeded` | 200 | Result truncated at configured cap (flag in response, not an error response) |
| `syntax_error` | 400 | DB rejected the SQL. When the DB gave a SQLSTATE the message carries it and the server's primary message (configured role name redacted), so the agent can fix the query |
| `permission_denied` | 403 | The target role lacks a privilege the statement needs (SQLSTATE `42501`), or a write was attempted inside the read tier's read-only transaction (`25006`); message carries SQLSTATE + server message |
| `undefined_object` | 400 | The statement names a table or column that does not exist (SQLSTATE `42P01` / `42703`); message carries SQLSTATE + server message |
| `unavailable` | 503 | DB unreachable, its credentials rejected, or no pooled connection free within 5 s. Waiting for a connection is not counted against the statement timeout, so a saturated pool is `unavailable`, never `timeout` |
| `rate_limited` | 429 | Calling identity has too many concurrent in-flight requests (per-identity cap). `Retry-After: 1` header is set. |
| `service_overloaded` | 503 | Gateway-wide concurrency ceiling reached. `Retry-After: 1` header is set. |
| `audit_unavailable` | 503 | The audit store refused a write — the intent row before a target call, or the completion row after the tool ran — or the gateway has no audit store. The request is refused; nothing is returned unaudited. The audit row (if the store recovers for the drop-guard retry) records `audit_unavailable` with the tool's own outcome in `error_message`. |
| `unsupported_backend` | 501 | The tool is not offered on the target's engine: `table_stats`, `db_activity` and `cancel_query` on Mongo, and `explain` on Mongo (answered before any SQL parsing or target call) |
| `internal` | 500 | Bug. Has a request ID that matches a server-side log line |

`cancelled` is answered to a call whose statement `cancel_query` stopped. `dry_run` is the audit outcome of a successful `run_query` with `dry_run: true` (the response is a normal result with `"dry_run": true`). Two codes appear only in `audit_calls.outcome`, never in a response: `cancelled` when the client disconnected before the tool finished, and `abandoned` (the gateway stopped between reaching the target and recording the outcome — see [07-logging-retention](07-logging-retention.md) §"Intent and completion").

**Shed requests are not audit rows.** A `429` `rate_limited` or `503` `service_overloaded` answer is a log line and a metric only: under overload the gateway does not add a state-DB write per rejected request. No tool ran and no target was reached, so MUST #2 (every DB call → audit row) is not in play.

Every error includes a `request_id` the user can paste back to ops: the gateway-minted UUID that is also the response's `x-request-id` header, the `request_id` on the server-side log line, and `audit_calls.request_id` — never the client's JSON-RPC `id`.

## Resource safety

Two concurrency budgets protect the gateway. The bearer-gated budget covers `/mcp`, `POST /auth/logout` and the admin API (`/admin/v1/*`):

| Limit | Default | Response when exceeded |
|---|---|---|
| **Global** (process-wide) | 512 concurrent requests | `503` `service_overloaded` |
| **Per-identity** (per SSO `sub` / service account) | 16 concurrent requests; a service account may set its own `max_concurrent_requests` | `429` `rate_limited` |

Both caps are checked *after* authentication. A per-identity permit is held for the full lifetime of the request. The global cap is checked first to keep the per-identity map lookup cheap on a saturated gateway. A cap of `0` is refused at boot.

The unauthenticated OAuth flow routes — `POST /auth/login`, `GET /auth/callback`, `GET /authorize`, `POST /token`, `POST /revoke`, `POST /register` — have their **own, smaller** budget: one eighth of the global cap (64 by default, never below 1). Each of them writes into a size-capped store or drives IdP/DB work, so a flood must be bounded; none carries an identity, and sharing the gated budget would let anonymous traffic (stalled bodies, an `/authorize` flood) take `/mcp` down. Exhausted, these routes answer `503` `service_overloaded`. `GET` on `mcp_path` (a constant `405`), the discovery metadata, `/healthz` and `/readyz` are not gated — probes are trusted infra traffic and discovery documents are static (`/metrics` is on its own listener). `/readyz` answers from a one-second cache and never queues for a state-DB connection: at most one probe runs at a time (concurrent callers get the last result), it takes an idle connection or opens one only when the pool has room, and a pool saturated with request traffic counts as ready.

Every shed response carries `Retry-After: 1`, the body `{"error": {"category", "code"}, "request_id"}`, a `warn` log line with the request id and budget, and increments `requests_shed_total{scope="global"|"identity"|"oauth"}`.

**Time and size bounds.** Every request is bounded end to end; past the timeout the request is dropped (for a tool call: the same path as a client disconnect — query cancelled, audit row `cancelled`) and answered `504`.

| Routes | Timeout | Body limit |
|---|---|---|
| `/mcp`, `/auth/logout` | 75 s — the 30 s statement ceiling + pool acquire + both audit writes + slack | 1 MiB |
| OAuth flow routes | 60 s — covers the 45 s IdP code exchange | 16 KiB |
| Admin API | 30 s | 64 KiB |
| Probes + discovery | 5 s | 1 KiB |

A request body must arrive in full within 10 s, so a slow-loris sender cannot pin a concurrency permit.

The 30 s statement-timeout ceiling (see `run_query` above) is the complementary per-query bound: it limits how long one request can hold its permits.

## What we don't expose

- No DDL tools (`create_table`, `drop_table`, …) — those don't belong in a debugging gateway.
- No DML tools (`insert`, `update`, `delete`) at the protocol layer. If writes are enabled by policy, they go through `run_query` with the role having write grants; the audit log captures the SQL.
- No raw `pg_dump` / `mysqldump` style export. Bulk export is a different product.
- No "run on all databases" — every call is scoped to one DB.
