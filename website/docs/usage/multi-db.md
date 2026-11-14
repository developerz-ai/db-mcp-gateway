# Multi-DB targets: Postgres, YugabyteDB, MongoDB, Redis

The gateway dispatches queries to Postgres, MongoDB or Redis targets, picked by `server.kind` in YAML. YugabyteDB (YSQL) speaks the Postgres wire protocol and is declared `kind: postgres`; Dragonfly, Valkey and KeyDB speak RESP and are declared `kind: redis`. Same MCP surface, same authz path, same audit row shape — the agent only has to know which payload shape to send. Spec at [`../initial-idea/12-dynamic-permissions.md`](../initial-idea/12-dynamic-permissions.md) §"`DbAdapter` trait".

Pair with [`first-query.md`](first-query.md) for the Postgres-only quickstart; this page is what *changes* when you add a second target kind.

## Status: what works today

| Target | `kind` | Status |
|---|---|---|
| PostgreSQL | `postgres` | works — reads, opt-in writes, every tool |
| YugabyteDB (YSQL) | `postgres` | works, CI-tested on 2.25.2.0-b359 (own `yugabyte` job, gates publishing; locally `bin/test-yugabyte`) and production-proven. No `NOTIFY`, no large objects; point `host` at one tserver. See [YugabyteDB](#yugabytedb) |
| MongoDB | `mongo` | works, read-only — `find` / `aggregate` / `count` / `distinct` / `listCollections` / `listIndexes`, `describe_schema`, `sample_table` |
| Redis | `redis` | works, read-only — `run_query` with a read-command allowlist. CI-tested |
| Dragonfly | `redis` | works, read-only, same as Redis. CI-tested |
| Valkey, KeyDB | `redis` | expected to work (same RESP protocol and commands); not CI-tested |
| MySQL, MSSQL | `mysql`, `mssql` | not implemented; **rejected at boot** — the gateway refuses to start rather than accepting a config every query would fail |

Tool coverage per target:

| Tool | Postgres / YugabyteDB | MongoDB | Redis |
|---|---|---|---|
| `run_query` | yes (writes with `query_write`) | yes, read-only | yes, read-only |
| `describe_schema` | yes | yes (collections + indexes) | `unsupported_backend` |
| `sample_table` | yes | yes (limited `find`) | `unsupported_backend` |
| `explain` | yes | `unsupported_backend` | `unsupported_backend` |
| `table_stats`, `db_activity`, `cancel_query` | yes | `unsupported_backend` | `unsupported_backend` |
| `get_query_history` | yes | yes | yes |

## What the LLM sees

The MCP `list_servers` tool surfaces every kind with its label:

```text
You:    What databases can I see?

Claude: [calls list_servers]

        You have access to:
        • prod        (postgres) — prod/billing (read-only, reason required)
        • prod-mongo  (mongo)    — prod-mongo/orders, prod-mongo/customers
        • prod-cache  (redis)    — prod-cache/0
```

`run_query` accepts every target. The agent picks the payload shape from the `kind` label:

| Backend | `sql` field carries |
|---|---|
| Postgres, YugabyteDB | a SQL statement, e.g. `SELECT count(*) FROM users` |
| MongoDB | a JSON-encoded command document, e.g. `{"find":"users","filter":{"active":true}}` |
| Redis, Dragonfly | a JSON array — the command and its arguments, e.g. `["HGETALL","user:1"]` |

Same tool, three payload shapes. Modern LLMs pick the right one from the `kind` label in `list_servers`.

## YugabyteDB

A YugabyteDB YSQL endpoint is a Postgres target — declare it `kind: postgres` (YSQL's default port is `5433`, so set `port:`). Everything on the Postgres path applies: the SQL guard, read-only transactions, the write tier, every tool.

```yaml
servers:
  - name: ledger
    kind: postgres
    host: yb-tserver-1.internal    # one tserver, not a load balancer (see Cancellation below)
    port: 5433
    tls: verify_full
    databases:
      - name: ledger
        role: mcp_gateway_ledger_ro  # not `yugabyte`, YSQL's superuser
        password: ${FILE:/run/secrets/ledger-ro-password}
```

Differences from stock Postgres:

- **Connection reset.** Before a pooled connection serves the next caller the gateway runs `RESET ALL; SELECT pg_advisory_unlock_all()`. A YugabyteDB cluster without advisory locks enabled rejects the unlock as `feature_not_supported` (SQLSTATE `0A000`); since 2.0.1 the gateway then runs `RESET ALL` alone and keeps the connection (such a server can hold no advisory lock to leak).
- **Superuser.** The boot check rejects the role `postgres` by name; YSQL's own superuser is `yugabyte`, which the `postgres` kind does not know about. Provision a least-privilege role as on any target.
- **`NOTIFY` is ignored.** YugabyteDB accepts `NOTIFY` but does nothing ("NOTIFY not supported yet and will be ignored", [yugabyte-db#1872](https://github.com/yugabyte/yugabyte-db/issues/1872)). The SQL guard refuses `pg_notify` on every target anyway; only the two integration tests that prove a `pg_notify` side effect would otherwise escape are excluded on YugabyteDB, and the guard's denial stays unit-tested.
- **No large objects.** `lo_from_bytea` and the other `lo_*` functions don't work on YugabyteDB. The guard denies them on every target; one read-only test sub-case that needs them is skipped there.
- **Cancellation behind a load balancer.** The cancel pool connects to the same `host` as the query pool, and YugabyteDB backend pids and `pg_stat_activity` are local to each tserver. If `host` is a load balancer spreading connections across tservers, a cancel (from `cancel_query` or a client disconnect) can land on a different node: the lookup matches nothing, the statement keeps running until its `statement_timeout_ms`, and the audit row still records `cancelled`. **Point `host` at a single tserver for a YugabyteDB target**, and rely on the statement timeout as the hard bound.

**What CI proves.** The `yugabyte` CI job runs the Postgres query-path integration suite against YugabyteDB 2.25.2.0-b359 and gates image publishing: 92 tests pass, 2 are excluded (the `NOTIFY` pair above). Verified there: statement timeout → `timeout`; row cap, truncation and the byte budget; the read-only transaction rejecting writes (SQLSTATE `25006`); the write tier; `pg_cancel_backend` cancelling a running statement (outcome `cancelled`, the backend leaves `active`); and the connection reset keeping the connection through the advisory-lock fallback. Run it locally with `bin/test-yugabyte`; the default `bin/test` does not include YugabyteDB.

## Declaring a mongo target

A mongo server in YAML looks identical to a pg one, with `kind: mongo` and an optional `auth_database` field on the per-database row:

```yaml
servers:
  - name: prod-mongo
    kind: mongo
    host: mongo.prod.internal
    port: 27017
    tls: required
    databases:
      - name: orders
        role: ro_orders
        password: ${ENV:MONGO_RO_ORDERS_PASSWORD}
        # `auth_database` defaults to `name` — the per-db least-privilege
        # pattern. Set this only when the role lives elsewhere (e.g. `admin`
        # for container-bootstrapped users).
        auth_database: orders
```

Set `port:` explicitly — an omitted port defaults to `5432` on every kind except `redis`.

> **Least-privilege role.** The connection still uses a least-privilege mongo role (read-only on the target DB) — defense in depth, same posture as the pg `ro_*` roles. The rejector is the secondary guardrail, not the only one.

## Allowed mongo commands

Six top-level commands pass the rejector:

| Command | Use |
|---|---|
| `find` | Read documents matching a filter |
| `aggregate` | Run a read-only aggregation pipeline |
| `count` | Return a document count |
| `distinct` | Return unique values for a field |
| `listCollections` | List the database's collections |
| `listIndexes` | List one collection's indexes |

Each command also has its own allowlist of top-level fields (shape and read options only — no `$db`, no session or transaction fields, no `writeConcern`). Anything else — `insert`, `update`, `delete`, `findAndModify`, `bulkWrite`, `createIndex`, `drop`, `dropDatabase`, … — is rejected at the gateway with tool error code `forbidden_sql` (mirroring pg's `sql_guard` posture). The mongo wire layer never sees them.

## Blocked mongo operators

Even within an allowed command, five operators are rejected anywhere in the document tree (rejected at any depth — pipeline stage, projection, filter, `$facet` branch, `$lookup` sub-pipeline):

| Operator | Why it's blocked |
|---|---|
| `$out` | Writes the pipeline output to a collection |
| `$merge` | Writes the pipeline output to a collection (mongo's `$out` successor) |
| `$function` | Server-side JS evaluation — arbitrary side effects |
| `$accumulator` | Server-side JS inside `$group` — same risk class as `$function` |
| `$where` | JS predicate evaluation — can have side effects; static analysis of arbitrary JS for purity is impossible, so the conservative choice is reject all |

Pinned by the table-driven tests in `src/exec/mongo/rejector/tests.rs`. A blocked operator returns `forbidden_sql` with the operator name; the *values* in the command are not surfaced in the error message (so a `$where` clause that referenced PII doesn't leak it).

## Mongo result shape

Mongo documents are schemaless; the gateway flattens them into the `(columns, rows)` shape MCP tools share:

| Command | `columns` | `rows` (each row is `[Value]`) |
|---|---|---|
| `find` / `aggregate` | `["document"]` | One row per result document; the cell is the document as JSON |
| `count` | `["count"]` | One row, one cell: the integer count |
| `distinct` | `["value"]` | One row per unique value |

Mongo-specific types render via the **relaxed extended JSON** form — matches what `mongosh` prints:

| BSON | JSON |
|---|---|
| `ObjectId(…)` | `{"$oid":"507f…"}` |
| `Date(…)` | `{"$date":"2026-06-18T12:00:00Z"}` |
| `Decimal128(…)` | `{"$numberDecimal":"123.45"}` |

## Declaring a redis target

`kind: redis` covers Redis, Dragonfly, Valkey and KeyDB. Three things differ from a SQL target:

- **`databases[].name` is the logical DB index** as a plain decimal string — `"0"`, `"1"`, … (`"00"`, `"+1"`, `"-1"` fail boot). Grants address it as `prod-cache/0`. A non-zero index needs `+select` on the ACL user.
- **`role` is an ACL username.** The stock `default` user is refused at boot in any letter case, like `postgres` on Postgres. Create a dedicated read-only ACL user — recipe in [config-reference §Redis](../deployment/config-reference.md#redis).
- **`port` defaults to `6379`.** `auth_database` and `write_role` fail boot. `tls: required` and `verify_full` both verify the certificate.

```yaml
servers:
  - name: prod-cache
    kind: redis
    host: cache.prod.internal
    tls: verify_full
    databases:
      - name: "0"
        role: gateway_ro
        password: ${FILE:/run/secrets/prod-cache-ro-password}
```

The ACL user is also how you scope **keys**: there is no key filter on a grant. `ACL SETUSER gateway_ro … %R~app:* …` lets the gateway read values under `app:*` and nothing else, and Redis enforces it on every command that names a key. It does **not** hide key *names*: `SCAN` still lists every key in the database and `DBSIZE` counts them all. Add `-scan -dbsize` to the ACL user when names are sensitive.

## Allowed redis commands

Deny by default. The command name (the first array element, case-insensitive) must be one of:

| Type | Commands |
|---|---|
| Strings / keys | `GET` `MGET` `STRLEN` `GETRANGE` `SUBSTR` `GETBIT` `BITCOUNT` `BITPOS` `EXISTS` `TYPE` `TTL` `PTTL` `EXPIRETIME` `PEXPIRETIME` `DBSIZE` |
| Hashes | `HGET` `HMGET` `HGETALL` `HKEYS` `HVALS` `HLEN` `HEXISTS` `HSTRLEN` `HRANDFIELD` `HSCAN` |
| Lists | `LRANGE` `LLEN` `LINDEX` `LPOS` |
| Sets | `SMEMBERS` `SISMEMBER` `SMISMEMBER` `SCARD` `SRANDMEMBER` `SSCAN` `SINTER` `SUNION` `SDIFF` `SINTERCARD` |
| Sorted sets | `ZRANGE` `ZRANGEBYSCORE` `ZRANGEBYLEX` `ZREVRANGE` `ZREVRANGEBYSCORE` `ZREVRANGEBYLEX` `ZSCORE` `ZMSCORE` `ZCARD` `ZCOUNT` `ZLEXCOUNT` `ZRANK` `ZREVRANK` `ZRANDMEMBER` `ZSCAN` |
| Streams | `XRANGE` `XREVRANGE` `XLEN` |
| Keyspace | `SCAN` |

Everything else is rejected at the gateway with `forbidden_sql`, before any network call; the message names the command. Notable refusals:

| Refused | Why |
|---|---|
| every write (`SET`, `DEL`, `HSET`, `EXPIRE`, …) | Redis targets are read-only whatever the grant |
| `KEYS` | Walks the whole keyspace in one blocking call — use `SCAN` with `MATCH` |
| `SORT` | Can write (`STORE`) |
| `EVAL*`, `FCALL*`, `FUNCTION` | Scripts and functions can write and run unbounded |
| `MONITOR`, `SUBSCRIBE`, `PSUBSCRIBE` | Unbounded streams, not a query |
| `BLPOP`, `BRPOP`, `BLMOVE`, `BZPOPMIN`, …, `WAIT*` | Block a connection waiting for data |
| `SELECT`, `AUTH`, `HELLO`, `MULTI` / `EXEC` | Change connection state behind the pool's back |
| `CLIENT`, `CONFIG`, `DEBUG`, `INFO`, `OBJECT`, `MEMORY` | Server administration and introspection |
| module commands (`JSON.*`, `FT.*`, …) | Not reviewed; deny by default |

A `sql` that is not a non-empty JSON array of strings (numbers are accepted and sent as their decimal string), or a `SCAN`-family call missing its cursor or an option's value or with a bad `COUNT`, is `invalid_arguments` (``"`sql`: <reason>"``) — refused at the argument edge, before any network call; the audit row records `invalid_arguments`. Error messages name the command or option, never your argument values.

**`SCAN` is clamped.** `SCAN`, `HSCAN`, `SSCAN` and `ZSCAN` accept `MATCH` and `COUNT`; `TYPE` works on `SCAN` only; any other option (e.g. `HSCAN … NOVALUES`) is `forbidden_sql`. `COUNT 1000` is appended when absent, and a larger `COUNT` is lowered to 1,000:

```json
["SCAN", "0", "MATCH", "app:session:*", "TYPE", "hash", "COUNT", "500"]
```

Pass the returned `next_cursor` back as the cursor; `"0"` means the scan is done.

## Redis result shape

| Reply | `columns` | `rows` |
|---|---|---|
| Scalar (string, integer, nil) | `["value"]` | one row |
| Array (`MGET`, `LRANGE`, `SMEMBERS`, …) | `["value"]` | one row per element; nested arrays are one JSON value |
| `HGETALL`, `HRANDFIELD … WITHVALUES` | `["field","value"]` | one row per field |
| `ZRANGE*` / `ZRANDMEMBER … WITHSCORES` | `["member","score"]` | one row per member |
| `SCAN` | `["next_cursor","key"]` | one row per key |
| `SSCAN` | `["next_cursor","member"]` | one row per member |
| `HSCAN` | `["next_cursor","field","value"]` | one row per field |
| `ZSCAN` | `["next_cursor","member","score"]` | one row per member |
| `XRANGE` / `XREVRANGE` | `["id","fields"]` | one row per entry; `fields` is a JSON object |

A `score` is the server's decimal text — `"2.5"`, not `2.5` — so no precision is lost. An empty `SCAN`-family page is one row with `next_cursor` set and the item columns `null`, so the cursor is never lost; when the row cap cuts a page, the keys past the cap are dropped (`truncated: true`) and the next cursor will not return them — lower `COUNT` or narrow `MATCH`. Elsewhere `null` is Redis' nil reply (missing key or field). A value that is not valid UTF-8 comes back as `{"base64": "…"}`; a non-UTF-8 stream field name becomes the key `base64:<encoded>`.

Server errors map to the shared codes: `NOPERM` → `permission_denied`; `WRONGTYPE` and other `ERR …` replies → `syntax_error` (code and message, ACL username shown as `<role>`); connection trouble → `unavailable`.

## Timeout + row cap

Both ride on the grant's `constraints`, whatever the target:

```yaml
permissions:
  - group: analysts
    grants:
      - server: prod-mongo
        database: orders
        action: query_read
        constraints:
          row_limit: 1000
          statement_timeout_ms: 5000
```

| Constraint | Postgres / YugabyteDB | MongoDB | Redis |
|---|---|---|---|
| `statement_timeout_ms` (clamped to 30 s) | `SET LOCAL statement_timeout` + Tokio deadline | `maxTimeMS` on the command (code 50 `MaxTimeMSExpired` → `timeout`) + Tokio deadline | Tokio deadline only, at exactly the effective timeout — Redis has no per-command server timeout. The connection of a command cut off is closed, never reused |
| `row_limit` | Stop collecting at the limit, `truncated: true` | Server-side limit of `row_limit + 1` on `find` / `aggregate`, then stop collecting; `truncated: true` | Reply truncated at the limit, `truncated: true`; `SCAN` `COUNT` ≤ 1,000 |
| 32 MiB result budget | yes | yes | yes |

The Tokio deadline is belt-and-suspenders on Postgres and Mongo — if the server ignores its own cap, the future still completes. On Redis it is the only bound, which is why the allowlist excludes everything that blocks or runs unbounded.

## Cancellation

Agent disconnect → axum drops the dispatch future. What happens to the running operation depends on the target:

| Target | On disconnect |
|---|---|
| Postgres / YugabyteDB | `pg_cancel_backend` on the backend running the statement. YugabyteDB: only reliable when `host` is a single tserver — see [YugabyteDB](#yugabytedb) |
| MongoDB | Best-effort `currentOp` + `killOp`, only when the role holds the `inprog` + `killop` privileges — see [config-reference §Mongo](../deployment/config-reference.md#mongo). Otherwise the operation runs until it finishes or hits `maxTimeMS` |
| Redis | No cancel exists in the protocol. The connection is closed; the server finishes the command, which the allowlist keeps short |

On every target the audit row still lands: the drop-guard in `audit_dispatch` spawns a detached task that writes `outcome = "cancelled"` with `error_message = "client disconnected before completion"` even though the parent future died. Pinned by `tests/it_db/audit_dispatch_cancellation_real_db.rs` (and `mongo_cancel_killop_real_db.rs` for Mongo).

## Audit row shape

Same envelope on every target. Per-target fields:

| Target | `db_type` | `sql` for `run_query` |
|---|---|---|
| Postgres | `postgres` | the SQL statement |
| YugabyteDB | `postgres` (it is a `kind: postgres` server) | the SQL statement |
| MongoDB | `mongo` | the command document as JSON text |
| Redis, Dragonfly | `redis` | the argv as a JSON array, e.g. `["HGETALL","user:1"]` |

`sql` is the string the agent sent, stored verbatim (up to the 64 KiB cap). There is no redaction policy on any target ([spec 07](../initial-idea/07-logging-retention.md)).

```sql
-- "Show me all redis activity in the last hour"
SELECT occurred_at, user_email, tool, server_name, database_name, sql, outcome
  FROM audit_calls
 WHERE db_type = 'redis'
   AND occurred_at > now() - interval '1 hour'
 ORDER BY occurred_at DESC;
```

To tell a YugabyteDB server from a Postgres one in the audit log, filter on `server_name`.

## Gotchas

### `kind: mongo` but my role lives in `admin`

Container-bootstrapped mongo deployments (the `MONGO_INITDB_ROOT_*` env pattern) create the root user inside the `admin` database. The gateway's default `auth_database` (= the target DB name) won't authenticate. Set:

```yaml
auth_database: admin
```

on the affected database. Boot rejects `auth_database: ""` or whitespace — set to a real value or omit the field.

### My write command is rejected even though my role can write

The Mongo and Redis rejectors run **before** any wire call, so a role or ACL user with write privileges still can't issue `insert` / `update` / `SET` / `DEL` through the gateway, and a `query_write` grant does not change that. This is intentional: gateway-side enforcement on top of the least-privilege role is the spec 12 defense-in-depth posture. Writes on these targets are out of scope ([spec 10](../initial-idea/10-non-goals.md)).

### `$where` with no side effects is still blocked

Yes — we reject all `$where`. Static analysis of arbitrary JS for purity is impossible, so the conservative choice is "all of it." Use `$expr` with read-only operators (`$gt`, `$eq`, etc.) instead — those compile to safe BSON and aren't on the deny list.

### `KEYS app:*` is rejected

Use `["SCAN","0","MATCH","app:*"]` and follow `next_cursor`. `KEYS` blocks the server for the whole keyspace walk; `SCAN` does it in bounded steps.

### Redis says `NOPERM`

The call answers `permission_denied`: the ACL user lacks that command or key pattern. That is the ACL doing its job — the gateway forwarded an allowed command and Redis refused it for this user. Widen the ACL (`%R~pattern`) if the agent should see those keys.
