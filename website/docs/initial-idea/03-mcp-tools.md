# 03 — MCP Tool Surface

The set of tools the gateway exposes to agents. This is the agent-facing contract. Keep it small and boring.

## Design rules

1. **Read-only by default.** A write-capable tool exists only if [06-permissions](06-permissions.md) explicitly enables it for the calling identity.
2. **Every tool accepts `server` + `database`** (except `list_servers` / `list_databases`). The pair fully scopes the call.
3. **`reason` is optional in the protocol but may be required by policy.** If policy requires it and it's absent, the gateway returns a structured error telling the agent to ask the user for one.
4. **Results are size-capped.** `run_query` and `sample_table` accept a caller-supplied `limit`; most-restrictive-wins: the effective row limit is `min(caller.limit, grant.row_limit, gateway-ceiling)`. The **gateway-wide ceiling is 100,000 rows** and applies regardless of what the caller asks for or whether the grant sets `row_limit` — an absent or oversized grant still clamps to the ceiling, never "unbounded". A grant may only tighten below the ceiling; it may not loosen past it. When neither the caller nor the grant names a limit, `run_query` defaults to **1,000 rows** and `sample_table` defaults to **10 rows**. Results are also capped at **32 MiB of decoded values** per call (`exec::MAX_RESULT_BYTES`), whatever the row limit: past it the gateway stops collecting and sets `truncated: true`, exactly as for the row cap. The cap weighs what the gateway holds in memory, not the wire form: every JSON node of a decoded row counts as one whole value (32 bytes) plus the bytes of its strings and keys, so an array of a million small integers weighs 32 MB, not 4. On Postgres a row whose wire form alone is past what is left of the budget is refused before it is decoded (see [Resource safety](#resource-safety) §Memory). Mongo commands get the same row and byte budget; `find` and `aggregate` also carry a server-side limit of `row_limit + 1`. Redis replies get the same row and byte budget; the `SCAN` family also carries a `COUNT` of at most 1,000. Other result-returning tools (`list_servers`, `list_databases`, `describe_schema`, `explain`) do not accept a caller `limit`; they enforce internal caps sized to their output shape.
5. **No tool exposes credentials, connection strings, or hostnames.** Servers and databases are referenced by their config-defined logical name.

## Tools

### `list_servers`

Returns the servers the caller can see — logical name, kind (`postgres`, `mongo`, `redis`), human description. No connection info. The kind is the configured `server.kind`, so a YugabyteDB (YSQL) target, declared `kind: postgres`, reports `postgres`; a Dragonfly, Valkey or KeyDB target reports `redis`. `mysql` / `mssql` never appear: boot refuses them ([08-config](08-config.md)).

### `list_databases`

Args: `server`. Returns databases on that server visible to the caller, with description and tags.

### `describe_schema`

Args: `server`, `database`, optional `schema` (default `public`), optional `table`, optional `reason`. Honours the grant's `require_reason` constraint like every tool that reaches the target: without a non-blank `reason` the call gets `reason_required` (audited) and the catalog is never read. Returns `{ "tables": [{ "schema", "name", "columns": [{ "name", "data_type", "nullable" }] }], "truncated": bool }`. The catalog scan is capped at 50,000 columns; when the cap is hit `truncated` is `true`, tables past the cut are missing, and the table the cut fell in is dropped rather than returned with only some of its columns — every table returned is complete. Narrow with `table` to see one table past the cap. PK/FK/indexes are not returned yet.

**Mongo:** `schema` is ignored (the database is the namespace) and `table` names one collection. Returns `{ "collections": [{ "database", "name", "type", "indexes": [{ "name", "key", "unique" }] }], "truncated": bool }` from `listCollections` + `listIndexes`; `type` is `collection`, `view`, …, and a view has no indexes.

**Redis:** not offered — `unsupported_backend`. A keyspace has no catalog to describe; list keys with `SCAN` (`MATCH`, `TYPE`) and inspect one with `TYPE` through `run_query`.

### `sample_table`

Args: `server`, `database`, `table`, optional `schema`, optional `limit` (default 10, capped), optional `reason`. Returns a small sample. Useful for "what does this data look like" without writing SQL. On Mongo, `table` names a collection and the sample is a limited `find`, one `document` column per row. Not offered on Redis (`unsupported_backend`): there is no table to sample.

**Requires `query_read`, not `schema_read`.** This tool returns row data, so it is authorized exactly like `run_query` and honours the same `require_reason` constraint. A `schema_read` grant covers metadata only (`describe_schema`, `list_databases`).

### `run_query`

Args: `server`, `database`, `sql`, optional `limit`, optional `dry_run`, optional `reason`. Executes under the caller's grant with statement timeout. Returns rows + truncation flag + execution stats, and `rows_affected` for a write. The primary tool.

**`sql` carries the target's own query language.** One argument, three shapes, picked by the server's `kind`:

| `kind` | `sql` carries | Example |
|---|---|---|
| `postgres` (PostgreSQL, YugabyteDB YSQL) | one SQL statement | `SELECT count(*) FROM users` |
| `mongo` | a JSON-encoded command document | `{"find":"users","filter":{"active":true}}` |
| `redis` (Redis, Dragonfly, Valkey, KeyDB) | a JSON array: the command and its arguments | `["HGETALL","user:1"]` |

The rest of this section describes the SQL path; the Mongo rules are in [12-dynamic-permissions](12-dynamic-permissions.md) §"Mongo adapter", the Redis rules under [Redis payload](#redis-payload) below.

**Read vs. write is per-grant.** With a `query_read` grant the sql guard accepts only read-only statements (`SELECT` / `EXPLAIN`). A `query_write` grant on the target `(server, database)` additionally lets a single top-level `INSERT` / `UPDATE` / `DELETE` through — **data writes only**. Schema modification (`CREATE` / `ALTER` / `DROP` / `TRUNCATE`), `GRANT` / `REVOKE`, `COPY`, transaction control, and multi-statement bodies are rejected in **both** modes; the gateway never issues DDL. Writes also require the target-DB role to actually hold write privileges — the gateway does not provision them (see [06-permissions](06-permissions.md) and CLAUDE.md non-negotiable #3).

**Two roles per database, one per tier.** A database that accepts writes names a `write_role` (+ `write_password`) next to its read `role`; a `query_write` grant on a database without one fails boot. The access a call runs with is decided per statement: a write-tier caller's `SELECT` still runs as the read `role` inside a read-only transaction, and only a data write runs as `write_role`. The read tier can therefore never reach a write-capable role — the separation is role-level, not parser-level.

**`dry_run: true`** (write tier only) executes the write, reports `rows_affected`, and rolls the transaction back: nothing changes. The response carries `"dry_run": true` and the audit row records outcome `dry_run` with `rows_affected`. `dry_run` on a read statement is `invalid_arguments`; on a write without a `query_write` grant the guard answers `forbidden_sql` first. Writes commit synchronously before the response returns, and every write is audited exactly like a read. Mongo and Redis targets remain read-only regardless of grant.

**Read access is enforced by the database too.** A `query_read` call runs in a `READ ONLY` transaction, so even a write-capable target role cannot write through it; the sql guard is the second layer, not the only one. **A write is never cut short:** when a `RETURNING` write produces more rows than the limit (or the byte cap), the gateway stops collecting, drains the rest, commits, and returns the capped rows with `truncated: true` and `rows_affected` — the number of rows the statement actually changed. A write's result always carries `rows_affected`; a read's never does. A read past the cap is cancelled and rolled back (nothing to lose).

**Statement-timeout ceiling:** every query is subject to a hard 30 s ceiling regardless of the per-grant `statement_timeout_ms` value. A grant may set a shorter timeout; it may not exceed 30 s — the gateway clamps it. The timeout is enforced both DB-side (`SET LOCAL statement_timeout`) and by a Tokio guard as belt-and-suspenders. A query that exceeds it returns `timeout`.

**`EXPLAIN ANALYZE` inside `sql` is rejected.** It executes the statement, and through `run_query` it would bypass the per-statement access decision. The sql guard rejects it before the query reaches the DB; the caller receives `forbidden_sql`. Use `explain` with `analyze: true` instead.

**The guard refuses what it cannot read the way Postgres does.** It decides on its own parse of `sql`; the target runs Postgres's. So the text is tokenized twice — by the guard's parser and by a scanner following Postgres's lexical rules — and both must put every word, quoted identifier, literal and parameter at the same bytes and agree on which bytes are comments. Anything else is `forbidden_sql`, with a message naming the rewrite: a comment opening directly after an operator character (`1 >-- …` — Postgres ends the operator at `--`; put a space before the comment), string literals separated only by a line break (Postgres joins them, and the continuation keeps the first part's escape rules; join with `||`), Unicode-escaped identifiers (`U&"…"`), and any other disagreement (a backslash in `X'…'`, `1L`, `b"…"`, a `$1$` dollar tag). The price is deliberate: a few legal spellings are refused (`a =-- note`, `'a'⏎'b'`).

**A call needs no parentheses, so names are checked wherever Postgres can resolve one to a call.** Postgres reads `(x).f` and `row.f` as `f(x)` / `f(row)` when no such column exists. The denylist therefore applies to every name in a field-access chain and to the last part of a qualified column reference, not only to `f(…)`. A two-part reference (`t.f`) can only pass `t`'s whole row, so it is held against the families and the exact names whose function takes one row (`http`); an exact name no row can be passed to (`t.pg_notify`, `r.invoke`, `t.setseed`) is an ordinary column there. Three or more parts (`t.col.f` = `f(t.col)`) can pass any value and meet the whole list. Side effect: a *qualified* column whose name falls under a denied family (`l.lo_revenue`) is refused — a family also stands for names not listed, whose signatures are unknown; unqualified (`lo_revenue`) it can only be a column and passes.

**Other sessions' statements are not readable.** Every identity on a `(server, database)` shares one role, so Postgres would show each caller the others' live and recorded SQL. `pg_stat_activity`, `pg_stat_statements`, `pg_prepared_statements`, `pg_stat_monitor`, `yb_terminated_queries`, and the extensions' equivalents (`citus_stat_activity`, `citus_dist_stat_activity`, `citus_lock_waits`, `citus_stat_statements`, `aurora_stat_activity`, `pg_show_plans`, `pg_store_plans`, `pg_qualstats*`) are refused wherever the name is written (table, function or alias), as are the functions beneath them (`pg_stat_get_activity`, `pg_stat_get_backend_*`, `pg_prepared_statement`) and every relation and function in pg_cron's `cron` schema (`cron.*`), plus pg_cron's run log by its bare name (`job_run_details`). A bare `job` is not refused — the name is too common — so **operator requirement:** the target read role has no `USAGE` on schema `cron` (or any other extension schema storing SQL text) and none on its `search_path`; the `REVOKE`s are in [target roles](../deployment/target-roles.md#keep-extension-schemas-that-hold-sql-text-out-of-reach). `pg_stat_statements_info` (eviction count, last reset) shows no statement and stays readable. [`db_activity`](#db_activity) answers "what is running" for the caller's own requests, without query text. The gateway's own `db_activity` / `cancel_query` statements are fixed text and do not pass through the guard.

**Denied functions** (matched on the last name component, case-insensitively, whatever the role may execute): filesystem (`pg_read_file`, `pg_read_binary_file`, `pg_stat_file`, `pg_ls_*`, `pg_current_logfile`, `pg_file_*`, `pg_logdir_ls`, `lo_*`, `loread`, `lowrite`); session and shared state (`set_config`, `setseed`, `pg_advisory_*`, `pg_try_advisory_*`, `pg_stat_reset*`, `pg_stat_statements_reset`); other backends (`pg_cancel_backend`, `pg_terminate_backend`); messages (`pg_notify`, `pg_logical_emit_message`); SQL-text executors (`query_to_xml*`, `cursor_to_xml*`, `table_to_xml*`, `schema_to_xml*`, `database_to_xml*`, `ts_stat`, `ts_rewrite`, `crosstab*`, `connectby`, `xpath_table`, `pgr_*`, `dblink*`); background and scheduled SQL (`pg_background_*`, `schedule`, `schedule_in_database`, `alter_job`, `unschedule`, `cron.*`); network (`http`, `http_get`, `http_post`, `http_put`, `http_patch`, `http_delete`, `http_head`, `http_set_curlopt`, `http_reset_curlopt` — the `http` extension and pg_net —, `invoke` (`aws_lambda`), `query_export_to_s3`, `table_import_from_s3`); replication (`pg_logical_slot_*`, `pg_replication_slot_advance`, `pg_drop_replication_slot`, `pg_create_*`, `pg_copy_*`, `pg_replication_origin_*`). With a write grant, an `UPDATE` of `pg_settings` is refused as `set_config`: its rule calls that function. The target relation decides, not its alias (`UPDATE orders AS pg_settings` passes). `SELECT … INTO` is refused in every spelling, the empty target list (`SELECT INTO t FROM x`) included.

**`null` means SQL NULL — always.** A value the gateway cannot render as JSON is never returned as `null`, because an agent acting on the result cannot tell a fabricated null from a real one. Such a cell comes back as `{"unsupported_type": "<pg type>"}` instead, naming the type so the caller can cast it (`SELECT my_col::text`).

**Zero-row results still name their columns — best-effort.** A successful query that matches no rows returns `rows: []`, `truncated: false`, and `columns` populated with the selected column names in their left-to-right order — same shape as a non-empty result. This lets the caller distinguish "your filter matched nothing" from "that table has no such columns" without a second round-trip. Column naming for zero-row Postgres results relies on a best-effort `Describe` after the row stream completes and before the transaction ends, bounded by what is left of the statement budget and by 1 s at most; if `Describe` fails or runs out of time, the query still succeeds but `columns` comes back as `[]` (`rows: []` and `truncated: false` are unaffected) — a finished read is never turned into an error or a `timeout` by it. **Reads only:** a write that returns no rows (no `RETURNING`, or a `RETURNING` that matched nothing) answers `columns: []`. Nothing runs inside a write's transaction after the statement itself, because a failure there would abort the transaction and the commit would then silently roll the write back. The statement `Describe` prepares is closed before the connection serves another caller (see [05-credentials](05-credentials.md)), so its text is never visible in the next caller's `pg_prepared_statements`.

Rendering rules for the non-obvious types:

| Postgres type | JSON |
|---|---|
| `numeric` / `decimal` | string, e.g. `"1234.5600"` — never a float, so money keeps full precision |
| `timestamptz` | RFC 3339 string, normalised to UTC |
| `timestamp` / `date` / `time` | ISO-8601 string, no zone invented |
| `timestamptz` / `timestamp` / `date` `infinity`, `-infinity` | `"infinity"`, `"-infinity"` |
| a date or timestamp outside years `0000`–`9999` | same shape with a signed year: `"+294276-12-31T23:59:59.999999"`, `"-4712-01-01"` (astronomical year numbering: 1 BC is `0000`) |
| `time` `24:00:00` | `"24:00:00"` |
| `uuid` | string |
| `bytea` | Postgres' own `\x`-prefixed hex string |
| `json` / `jsonb` | inlined as JSON |
| `float4` / `float8` NaN, ±infinity | `"NaN"`, `"Infinity"`, `"-Infinity"` — JSON numbers cannot hold them, and `null` would read as SQL NULL |
| `text[]` / `varchar[]`, `int2[]` / `int4[]` / `int8[]`, `uuid[]` | JSON array (elements may be `null`) |
| `interval` | ISO-8601 duration, e.g. `"P1Y2M3DT4H5M6.5S"` |
| `inet` / `cidr` | Postgres text form, e.g. `"10.0.0.1"`, `"10.0.0.0/8"` |
| enums | the label, as a string |
| other arrays, ranges, composites, user-defined | `{"unsupported_type": "…"}` |

#### Redis payload

`sql` is a JSON array — the argv a Redis client would send — e.g. `["HGETALL","user:1"]` or `["SCAN","0","MATCH","app:user:*","COUNT","200"]`. Elements are strings; a JSON number is accepted and sent as its decimal string.

**Malformed argv is `invalid_arguments`.** A `sql` that is not a JSON array, is empty, or holds an element that is not a string or number (object, array, boolean, `null`) — and a `SCAN`-family call missing its cursor or an option's value, or carrying a `COUNT` that is not a positive integer — is refused at the argument edge with `invalid_arguments` and the message ``"`sql`: <reason>"``, before the intent row and before any network call.

**Deny by default.** The command name (first element, case-insensitive) must be on a read-only allowlist:

| Type | Allowed |
|---|---|
| Strings / keys | `GET` `MGET` `STRLEN` `GETRANGE` `SUBSTR` `GETBIT` `BITCOUNT` `BITPOS` `EXISTS` `TYPE` `TTL` `PTTL` `EXPIRETIME` `PEXPIRETIME` `DBSIZE` |
| Hashes | `HGET` `HMGET` `HGETALL` `HKEYS` `HVALS` `HLEN` `HEXISTS` `HSTRLEN` `HRANDFIELD` `HSCAN` |
| Lists | `LRANGE` `LLEN` `LINDEX` `LPOS` |
| Sets | `SMEMBERS` `SISMEMBER` `SMISMEMBER` `SCARD` `SRANDMEMBER` `SSCAN` `SINTER` `SUNION` `SDIFF` `SINTERCARD` |
| Sorted sets | `ZRANGE` `ZRANGEBYSCORE` `ZRANGEBYLEX` `ZREVRANGE` `ZREVRANGEBYSCORE` `ZREVRANGEBYLEX` `ZSCORE` `ZMSCORE` `ZCARD` `ZCOUNT` `ZLEXCOUNT` `ZRANK` `ZREVRANK` `ZRANDMEMBER` `ZSCAN` |
| Streams | `XRANGE` `XREVRANGE` `XLEN` |
| Keyspace | `SCAN` |

Everything else is `forbidden_sql` before any network call — ``command rejected by gateway: redis command `<NAME>` is not in the read-only allowlist``. That covers every write, and on purpose also `KEYS` (unbounded, blocks the server), `SORT` (can `STORE`), `EVAL*` / `FCALL*` / `FUNCTION` (scripts can write), `MONITOR` and `(P)SUBSCRIBE` (unbounded streams), `CLIENT` / `CONFIG` / `DEBUG` / `INFO` / `OBJECT` / `MEMORY` (server administration and introspection), the blocking commands (`BLPOP` / `BRPOP` / `BLMOVE` / `BZPOPMIN` / …, `WAIT*`), connection state (`SELECT`, `AUTH`, `HELLO`, `MULTI` / `EXEC`) and module commands (`JSON.*`, `FT.*`, …). `ZRANGESTORE` is not on the list, so no allowed command can write. Rejection messages name the command or option, never an argument value.

**Every command is bounded before it is sent.** With *cap* = `row_limit + 1` (the extra one is how `truncated` is detected), the gateway rewrites or prechecks each command that could return an unbounded reply:

| Commands | Bound |
|---|---|
| `LRANGE`, `ZRANGE` index form (incl. `REV`), `ZREVRANGE` | `stop` clamped to `start + cap - 1`; negative indices are first resolved with `LLEN` / `ZCARD` |
| `ZRANGE … BYSCORE` / `BYLEX`, `ZRANGEBYSCORE`, `ZREVRANGEBYSCORE`, `ZRANGEBYLEX`, `ZREVRANGEBYLEX` | a `LIMIT` count that is negative or above *cap* becomes *cap*; no `LIMIT` → `LIMIT 0 cap` appended; a smaller count is kept |
| `XRANGE`, `XREVRANGE` | `COUNT` clamped to *cap*, or appended |
| `LPOS` | `COUNT 0` or above *cap* → *cap*; `MAXLEN` held to 100,000 (injected when absent or `0`) |
| `HRANDFIELD`, `SRANDMEMBER`, `ZRANDMEMBER` | the count's magnitude clamped to *cap*, sign kept; a non-integer count is `invalid_arguments` |
| `HGETALL`, `HKEYS`, `HVALS`, `SMEMBERS` | served by an internal `HSCAN` / `SSCAN` loop (`COUNT 1000`) that stops at *cap* items or the 32 MiB byte budget; duplicates dropped; same output shape. `HGETALL` order is scan order (Redis guarantees none anyway). The ACL user needs `HSCAN` / `SSCAN` (in `+@read`) |
| `SUNION`, `SINTER`, `SDIFF` | `SCARD` precheck (sum / smallest / first set); a possible result above `row_limit` is `forbidden_sql` — ``query rejected by gateway: `SUNION` could return up to N members, past this call's row limit of R; read the sets with SSCAN, or count with SINTERCARD``. `SINTERCARD` returns one integer and is not prechecked (bounded only by the timeout) |
| `GET`, `HGET`, `GETRANGE`, `SUBSTR` | `STRLEN` / `HSTRLEN` precheck; a value over 32 MiB is never fetched — zero rows, `truncated: true` |
| `MGET`, `HMGET` | at most *cap* keys, then only the prefix whose summed length fits 32 MiB; `truncated: true` when anything was dropped |

A precheck and the read are two commands, so a key can grow in between; the client-side timeout is the backstop for that race.

**`SCAN` family options are checked and `COUNT` is clamped.** `MATCH` and `COUNT` are accepted on `SCAN` / `HSCAN` / `SSCAN` / `ZSCAN`; `TYPE` on `SCAN` only. Any other option is `forbidden_sql` (e.g. ``redis command `HSCAN` does not allow option `NOVALUES` `` — `NOVALUES` would drop the values the result shape promises). Every `COUNT` is lowered to at most 1,000, and `COUNT 1000` is appended when absent. Page with the returned `next_cursor` (start at `"0"`; `"0"` again means done).

**Keys are scoped by the target ACL, not a grant** — same rule as tables on Postgres ([06-permissions](06-permissions.md)). The ACL user the gateway logs in as should hold only `+@read` on the key patterns the agent may see. ACL key patterns do **not** filter `SCAN` or `DBSIZE`: a user limited to `~app:*` still sees other key *names* through `SCAN`. The recipe, including `-scan -dbsize` for when key names are sensitive, is in [config-reference §Redis](../deployment/config-reference.md#redis).

**Result shapes.** Every reply becomes the shared `columns` / `rows` shape (the gateway speaks RESP2):

| Reply | `columns` | `rows` |
|---|---|---|
| Scalar (string, integer, nil) | `["value"]` | one row |
| Array (`MGET`, `LRANGE`, `SMEMBERS`, `ZRANGE` without scores, …) | `["value"]` | one row per element; a nested array is one JSON value |
| `HGETALL`, `HRANDFIELD … WITHVALUES` | `["field","value"]` | one row per pair |
| `ZRANGE*` / `ZRANDMEMBER … WITHSCORES` | `["member","score"]` | one row per pair |
| `SCAN` | `["next_cursor","key"]` | one row per key |
| `SSCAN` | `["next_cursor","member"]` | one row per member |
| `HSCAN` | `["next_cursor","field","value"]` | one row per field |
| `ZSCAN` | `["next_cursor","member","score"]` | one row per member |
| `XRANGE` / `XREVRANGE` | `["id","fields"]` | one row per entry; `fields` is a JSON object |

A sorted-set `score` is the server's decimal **text** (`"2.5"`, `"inf"`), not a JSON number — the same no-precision-loss rule as Postgres `numeric`. The `SCAN` family repeats `next_cursor` on every row; an empty page is one row with `next_cursor` set and the item column(s) `null`, so the cursor is never lost. When `row_limit` or the byte budget cuts a `SCAN`-family page, the items past the cap are dropped (`truncated: true`) while `next_cursor` still points past the whole page — narrow `MATCH` or lower `COUNT` rather than relying on the next page to return them. Outside the empty-page row, `null` is Redis' nil reply — a missing key or field. A bulk string that is not valid UTF-8 comes back as `{"base64": "…"}`, never a lossy string; a non-UTF-8 stream field *name* becomes the object key `base64:<encoded>`. `row_limit` and the 32 MiB byte budget apply as on every target, with `truncated: true` when they cut the reply.

**Errors.** A command the server refuses maps to the shared codes: `NOPERM` (the ACL user lacks the command or key) → `permission_denied`; any other error reply (`WRONGTYPE`, `ERR …`) → `syntax_error` carrying the server's code and message with the ACL username replaced by `<role>`; a connection or I/O failure → `unavailable`; a reply the gateway cannot parse → `internal`. Exception: a cluster-topology reply (`MOVED`, `ASK`, `TRYAGAIN`, `CLUSTERDOWN`, `MASTERDOWN`) is about where the data lives or whether the cluster can serve, not about the command — nothing the agent can fix by rewriting it, and `MOVED` / `ASK` carry another node's address. It is `unavailable`, with the server's text dropped; retry later. A connect-time rejection (`WRONGPASS` / `NOAUTH`) is `unavailable` and marks the adapter stale so the next call reconnects with a freshly resolved password ([05-credentials](05-credentials.md)); connect-time server messages are never passed through.

**Timeouts are client-side only.** Redis has no per-command server timeout, so `statement_timeout_ms` (clamped to the 30 s ceiling) is enforced by the gateway's Tokio deadline alone, at exactly the effective timeout. A connection goes back to the pool only after a complete reply or a server error reply; one whose command was cut off by the deadline or a client disconnect, or that hit an I/O error, is **closed**, never reused. The server finishes the command on its own — Redis cannot cancel one in flight — which the allowlist keeps short: no blocking commands, no scripts, no `KEYS`, clamped `SCAN` counts.

### `explain`

Args: `server`, `database`, `sql`, optional `analyze` (default `false`), optional `reason`. Returns `{ "plan", "elapsed_ms" }` from `EXPLAIN (FORMAT JSON)`. Lets the agent estimate cost before running expensive queries. Honours the same `require_reason` constraint as `run_query`.

The statement passes the same guard as `run_query` at the caller's grant: a read needs `query_read`, an `INSERT` / `UPDATE` / `DELETE` needs `query_write` and is planned as the database's `write_role`. Plain `EXPLAIN` never executes the statement, so planning a write changes nothing.

Not offered on Mongo or Redis: `unsupported_backend`, answered before any parsing or target call.

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

Args: `server`, `database`, `request_id`, optional `reason`. Requires `query_read` on that database. Cancels the statement the gateway is running for `request_id` — the id from an error body, the `x-request-id` header, or `db_activity`. **Own identity only:** a `request_id` that is not one of the caller's own on that `(server, database)` answers `forbidden`, exactly like an unknown one, so ids cannot be probed. Returns `{ "cancelled": bool }` — `false` when the request had already finished. The cancelled call answers `cancelled` and writes its own audit row with that outcome; the `cancel_query` call's row records the target `request_id` in `sql`. A malformed `request_id` is `invalid_arguments`. Not offered on Mongo or Redis (`unsupported_backend`). On Redis the answer comes after authz and the `require_reason` check but before the ownership lookup, so it is the same for any `request_id`; a Redis command is bounded by its client-side timeout instead (see [Redis payload](#redis-payload)).

**YugabyteDB.** `cancel_query` uses `pg_cancel_backend` like any Postgres target, and works when `host` names a single tserver. Backend pids and `pg_stat_activity` are node-local and the cancel pool connects to the same `host` as the query pool, so behind a load balancer across tservers the cancel can land on another node: it finds no backend (`{ "cancelled": false }`), the statement runs on until its statement timeout, and a client-disconnect cancel still records `cancelled` in the audit row. The statement timeout is the bound that always holds; point `host` at one tserver.

## Errors

Errors are structured JSON, not free-text strings. Shape: `{ "error": { "category": "<code>", "code": "<detail>" } }`.

| Code | HTTP | When |
|---|---|---|
| `unauthenticated` | 401 | Token missing/expired — agent triggers re-login |
| `expired_session` | 401 | Session outlived its TTL (distinct from `revoked_session`: routine, not a sign-out). Agent triggers re-login |
| `forbidden` | 403 | Authenticated but permission denied for this server/db/action |
| `forbidden_sql` | 403 | SQL rejected before reaching the DB: statement not covered by the grant (a write without `query_write`, or a schema mod / `COPY` / multi-statement in any mode), `EXPLAIN ANALYZE` in `sql` (either spelling, `ANALYZE`/`ANALYSE`, keyword or option form), `explain` with `analyze: true` on a write, text Postgres tokenizes differently from the guard (Unicode-escaped identifiers `U&"…"`, a comment opening inside an operator, string literals split by a line break), a relation showing other sessions' statements (`pg_stat_activity`, `pg_stat_statements`, `pg_prepared_statements`, …), or a denied function, called with parentheses or in attribute notation (filesystem, session state, cross-session messages, SQL-text executors, network, replication — the list is under [`run_query`](#run_query)). On Mongo: a malformed command document, a command or top-level field outside the read-only allowlist, or a denied operator (`$out`, `$merge`, `$function`, `$where`, `$accumulator`). On Redis: a command outside the read-only allowlist, a `SCAN`-family option it does not allow, or a `SUNION` / `SINTER` / `SDIFF` whose `SCARD` precheck exceeds the row limit ([Redis payload](#redis-payload)) |
| `invalid_arguments` | 400 | Arguments rejected: they do not deserialise (missing or mistyped field, unknown key), break the argument edge (any string argument or argument name carrying NUL or another control character — identifiers take none, free text keeps tab/newline/carriage return; an identifier — `server`, `database`, `schema`, `table`, `request_id` — over 128 bytes, `reason` over 1,024, `sql` over 64 KiB (the audit cap, so every statement that runs is stored whole), any other string over 1,024; checked before the intent row, so nothing refused here reaches the target and the audit row stores no part of the refused value), fail a per-tool bound (`limit: 0`, malformed `since` or `cursor`, a `sample_table` name that is not an identifier, `dry_run` on a read, a non-UUID `cancel_query` `request_id`, a malformed Redis argv or a non-integer `*RANDMEMBER` / `HRANDFIELD` count — see [Redis payload](#redis-payload)), the tool name contains a control character, the tool name is unknown, `name` is missing, or a service-token call's upstream headers are malformed or missing under `require_upstream` ([14-service-tokens](14-service-tokens.md)). JSON-RPC envelope carries `invalid_params` (-32602); the audit row records `invalid_arguments` — with `server`/`database` NULL when the arguments never parsed, and `tool = "unknown"` for an unknown or missing name (the caller's name, capped at 64 bytes, is in `error_message`) — so every boundary rejection is accountable. |
| `reason_required` | 400 | Policy requires a reason for this call; none provided, or only whitespace |
| `timeout` | 408 | Statement timeout fired (30 s ceiling). On Redis the gateway's client-side deadline fired (it also covers any precheck) and the connection was closed |
| `syntax_error` | 400 | DB rejected the SQL. When the DB gave a SQLSTATE the message carries it, so the agent can fix the query. The same message is what the audit row and its sinks keep, so it must not carry row data — and Postgres puts row data in a primary message in any position: quoted (`relation "alice@example.com" does not exist`, from a column cast to `regclass`; likewise `regtype`, `regrole`, `regproc`, `regnamespace`, `to_tsquery(col)`, `current_setting(col)`), unquoted (the bytes of an encoding error, the text of a `RAISE EXCEPTION`). So on Postgres the server's sentence is never passed on: the wording is the gateway's, keyed by SQLSTATE (`42P01` → `relation does not exist`; an unlisted code gets its class's wording, an unlisted class `statement rejected by the database`), and the server's text is not read at all — keeping even the server words the submitted SQL also spells would confirm that a row holds that word. One name may follow, taken **from the submitted SQL, by position**: for a parse or analysis diagnostic (SQLSTATE class `42`) that carries an error position into the caller's statement, the identifier the statement holds at that offset, verbatim — the caller's own casing and quoting, qualified name included: `42P01 relation does not exist: Usres`, `42883 function or operator does not exist: nope`, `42601 syntax error: FORM`. Nothing is named when the position is on anything but an identifier (a literal, an operator, a number), when the identifier is longer than 128 characters, or when it is the operand of a cast (`email::regclass`, `CAST(…)`; a column diagnostic, `42702` / `42703`, is exempt) — a cast to a `reg*` type looks its object up from row data. Every other class is raised while the statement runs over data and gets the wording alone: `22P02 invalid input syntax for the target type`, `42P01 relation does not exist` for `col::regclass`, `42501 permission denied` (raised at execution, with no position). A typo'd name is still named; a value read from a row never is, whatever the caller typed. The configured role name is still replaced by `"<role>"`. `DETAIL`, `HINT` and `CONTEXT` are never read. A SQLSTATE of class `28` (a refused login) is never a `syntax_error`: it is `unavailable`, with no server text. On Redis: any server error reply other than `NOPERM` and the cluster replies below (`WRONGTYPE`, `ERR …`), with its code and message and the ACL username replaced by `<role>` |
| `permission_denied` | 403 | The target role lacks a privilege the statement needs (SQLSTATE `42501`), or a write was attempted inside the read tier's read-only transaction (`25006`), or a Redis ACL refusal (`NOPERM`); message carries the SQLSTATE and, on Postgres, the gateway's wording under the `syntax_error` redaction rule: the wording alone, `42501 permission denied` — Postgres reports no statement position for a privilege check, so the object is not named |
| `undefined_object` | 400 | The statement names a table or column that does not exist (SQLSTATE `42P01` / `42703`); message carries the SQLSTATE and the gateway's wording under the `syntax_error` redaction rule (`42703 column does not exist: nope`) |
| `unavailable` | 503 | DB unreachable, its credentials rejected (on any connection the gateway opens — the query pools and the one `cancel_query` uses alike; the server's refusal text names the role and can name the client address, and is never passed on), no pooled connection free within 5 s, or the caller already holding its whole share of the pool for 5 s (see [Resource safety](#resource-safety)). Waiting for a connection is not counted against the statement timeout, so a saturated pool is `unavailable`, never `timeout`. On Redis also a cluster reply about topology rather than the command (`MOVED`, `ASK`, `TRYAGAIN`, `CLUSTERDOWN`, `MASTERDOWN`): the gateway does not follow redirects, and the reply's text — another node's address — is dropped. Redis alike, plus a refused TLS handshake (wrong CA, hostname mismatch — refused before `AUTH` is sent), a connection the server closed while idle, and any I/O error |
| `rate_limited` | 429 | Calling identity has too many concurrent in-flight requests (per-identity cap). `Retry-After: 1` header is set. |
| `service_overloaded` | 503 | Gateway-wide concurrency ceiling reached. `Retry-After: 1` header is set. |
| `audit_unavailable` | 503 | The audit store refused a write — the intent row before a target call, or the completion row after the tool ran — or the gateway has no audit store. The request is refused; nothing is returned unaudited. The audit row (if the store recovers for the drop-guard retry) records `audit_unavailable` with the tool's own outcome in `error_message`. |
| `unsupported_backend` | 501 | The tool is not offered on the target's engine, answered (and audited) before any parsing or target call: `explain`, `table_stats`, `db_activity` and `cancel_query` on Mongo; on Redis those four plus `describe_schema` and `sample_table` |
| `internal` | 500 | Bug. Has a request ID that matches a server-side log line. A tool that panics answers `internal` and its audit row completes as `internal`, not `cancelled`; a panic anywhere else in a request answers HTTP `500` with the JSON-RPC internal-error envelope (`-32603`, `data: {"code": "internal", "request_id"}`). The panic message is never sent to the client |

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

A request body must arrive in full within 10 s, so a slow-loris sender cannot pin a concurrency permit. The OAuth flow routes go further: the body is read in full (≤16 KiB, within 5 s) *before* their concurrency permit is taken, so slow senders cannot hold the OAuth budget at all; a body still incomplete after 5 s is answered `408`, an oversized one `413`, both in the RFC 6749 `{"error": "invalid_request", "error_description"}` shape.

The 30 s statement-timeout ceiling (see `run_query` above) is the complementary per-query bound: it limits how long one request can hold its permits. On Postgres it is enforced DB-side and by the gateway; on Mongo by `maxTimeMS` and the gateway; on Redis by the gateway alone, which closes the connection of any command it cuts off (see [Redis payload](#redis-payload)).

**Per-caller share of a pool.** The per-identity request cap (16) is larger than a database's pool (4 connections by default), so on its own it would let one caller pin every connection of a database with slow queries until the statement timeout. Each adapter therefore also shares its pool out: one caller — SSO `sub` or service account — holds at most `max(1, max_connections − 1)` connections of a pool at a time (per tier on Postgres: the read pool and the write pool are shared out separately). The share is taken before the connection and held as long as it is; a caller at its share waits on itself, for at most 5 s, then gets `unavailable` — it never takes the connection someone else is waiting for. A pool of one connection cannot be shared out and is left whole. Cancels use their own pool and are not counted. Applies to Postgres, Mongo and Redis.

**Memory.** One call's result is bounded by the byte cap above: 32 MiB of decoded values, weighed node by node. What that cap cannot bound is the one row the driver is receiving: the Postgres driver buffers a row whole before the gateway can look at it, and Postgres allows a row of up to 1 GiB (`SELECT repeat('x', 1000000000)`). The gateway never decodes or returns such a row — it is refused from its wire length, the result is `truncated: true`, a read is cancelled — and the buffer is given back when the connection returns to the pool, but for that moment the bytes are held. Rows of 1 MiB or more on the wire are decoded at most two at a time per database, so the copy decoding makes is bounded as well. The limit to size a container for is therefore, per Postgres database, `in-flight queries × (32 MiB + the largest row the role can produce)`, where in-flight queries is at most `pool.max_connections` (twice that with a `write_role`) and no single caller holds more than its share. Keep `max_connections` small on databases whose roles can read very wide rows.

## What we don't expose

- No DDL tools (`create_table`, `drop_table`, …) — those don't belong in a debugging gateway.
- No DML tools (`insert`, `update`, `delete`) at the protocol layer. If writes are enabled by policy, they go through `run_query` with the role having write grants; the audit log captures the SQL.
- No raw `pg_dump` / `mysqldump` style export. Bulk export is a different product.
- No "run on all databases" — every call is scoped to one DB.
