# Multi-DB targets: Postgres + MongoDB

The gateway dispatches queries to either Postgres or MongoDB targets, picked by `server.kind` in YAML. Same MCP surface, same authz path, same audit row shape — the agent doesn't have to know which backend is on the other side. Spec at [`../initial-idea/12-dynamic-permissions.md`](../initial-idea/12-dynamic-permissions.md) §"Query target".

Pair with [`first-query.md`](first-query.md) for the Postgres-only quickstart; this page is what *changes* when you add mongo as a second target kind.

## Status: what works today

| Capability | Status |
|---|---|
| Postgres query targets (#4) | works |
| MongoDB scaffold + read-only rejector (#57) | works |
| MongoDB query execution: `find` / `aggregate` / `count` / `distinct` (#58) | works |
| `maxTimeMS` injection for statement timeout (#58) | works |
| Cancellation: drop the cursor → mongo kills server-side (#58) | works |
| `outcome = "cancelled"` audit row on agent disconnect (#58) | works |
| MySQL or MSSQL query targets | not implemented; `server.kind: mysql\|mssql` aborts at first dispatch with a typed `UnsupportedAdapter` error |

## Declaring a mongo target

A mongo server in YAML looks identical to a pg one, with `kind: mongo` and an extra `auth_database` field on the per-database row:

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
        # pattern spec 12 §237 recommends. Set this only when the role
        # lives elsewhere (e.g. `admin` for container-bootstrapped users).
        auth_database: orders
```

> **Least-privilege role.** The connection still uses a least-privilege mongo role (read-only on the target DB) — defense in depth, same posture as the pg `ro_*` roles. The rejector is the secondary guardrail, not the only one.

## What the LLM sees

The MCP `list_servers` tool surfaces both kinds with the backend label:

```text
You:    What databases can I see?

Claude: [calls list_servers]

        You have access to:
        • prod        (postgres) — prod/billing (read-only, reason required)
        • prod-mongo  (mongo)    — prod-mongo/orders, prod-mongo/customers
```

`run_query` accepts both pg and mongo targets. The agent picks the right shape based on `server.kind`:

| Backend | `sql` field carries |
|---|---|
| Postgres | a SQL statement, e.g. `SELECT count(*) FROM users` |
| MongoDB | a JSON-encoded BSON command, e.g. `{"find":"users","filter":{"active":true}}` |

Same tool, two payload shapes. The agent has to know which one to send — modern LLMs handle this from the `kind` label in `list_servers`.

## Allowed mongo commands

Only four top-level commands pass the rejector:

| Command | Use |
|---|---|
| `find` | Read documents matching a filter |
| `aggregate` | Run a read-only aggregation pipeline |
| `count` | Return a document count |
| `distinct` | Return unique values for a field |

Anything else — `insert`, `update`, `delete`, `findAndModify`, `bulkWrite`, `createIndex`, `drop`, `dropDatabase`, … — is rejected at the gateway with tool error code `forbidden_sql` (mirroring pg's `sql_guard` posture). The mongo wire layer never sees them.

## Blocked operators

Even within an allowed command, four operators are rejected anywhere in the document tree (rejected at any depth — pipeline stage, projection, filter, `$facet` branch, `$lookup` sub-pipeline):

| Operator | Why it's blocked |
|---|---|
| `$out` | Writes the pipeline output to a collection |
| `$merge` | Writes the pipeline output to a collection (mongo's `$out` successor) |
| `$function` | Server-side JS evaluation — arbitrary side effects |
| `$where` | JS predicate evaluation — can have side effects; static analysis of arbitrary JS for purity is impossible, so the conservative choice is reject all |

Pinned by `src/exec/mongo/rejector.rs` table-driven tests. A blocked operator returns `Forbidden` with the operator name; the *values* in the command are not surfaced in the error message (so a `$where` clause that referenced PII doesn't leak it).

## Result shape

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

## Timeout + row cap

Both ride on the grant's `constraints`:

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

| Constraint | Mongo translation |
|---|---|
| `statement_timeout_ms` | Added to the command document as `maxTimeMS` before dispatch. Mongo's wire code 50 (`MaxTimeMSExpired`) maps back to the typed `Timeout` tool error. |
| `row_limit` | The cursor stops draining at this count; mongo's `getMore` loop is never asked for the over-budget batch. `truncated = true` flag in the result tells the agent more documents existed. |

Belt-and-suspenders: the gateway also wraps the call in a Tokio-side deadline. If mongo ignores `maxTimeMS` the future still completes — same posture as the pg `SET LOCAL statement_timeout` + Tokio timeout pairing.

## Cancellation

Agent disconnect → axum drops the dispatch future → mongo cursor drops → mongo kills the operation server-side. CLAUDE.md *§Cancellation safety* contract:

- A pending cursor doesn't pin a connection forever.
- The audit row still lands. The drop-guard in `audit_dispatch` spawns a detached task that writes `outcome = "cancelled"` with `error_message = "client disconnected before completion"` even though the parent future died.

Pinned by `tests/audit_dispatch_cancellation_real_db.rs`.

## Audit row shape

Same envelope as pg. Two mongo-specific fields:

- `db_type = "mongo"` (column added in migration 0007).
- `sql` carries the BSON command as JSON text — the same string the agent sent. Future redaction policy (spec 07 §"SQL capture") will apply equivalently to both backends; today the full command is stored.

```sql
-- "Show me all mongo activity in the last hour"
SELECT occurred_at, user_email, tool, server_name, database_name, sql, outcome
  FROM audit_calls
 WHERE db_type = 'mongo'
   AND occurred_at > now() - interval '1 hour'
 ORDER BY occurred_at DESC;
```

The partial index on `db_type IS NOT NULL` keeps this query cheap on installs that mix both backends.

## Gotchas

### `kind: mongo` but my role lives in `admin`

Container-bootstrapped mongo deployments (the `MONGO_INITDB_ROOT_*` env pattern) create the root user inside the `admin` database. The gateway's default `auth_database` (= the target DB name) won't authenticate. Set:

```yaml
auth_database: admin
```

on the affected database. Boot rejects `auth_database: ""` or whitespace — set to a real value or omit the field.

### My write command is rejected even though my role can write

The rejector runs **before** any wire call to mongo, so a role with write privileges still can't issue `insert` / `update` / `delete` through the gateway. This is intentional: gateway-side enforcement on top of the least-privilege role is the spec 12 §"Defense in depth" posture. Write support for mongo lifts the rejector, which is out of scope today (spec 12 §"Out of scope").

### `$where` with no side effects is still blocked

Yes — we reject all `$where`. Static analysis of arbitrary JS for purity is impossible, so the conservative choice is "all of it." Use `$expr` with read-only operators (`$gt`, `$eq`, etc.) instead — those compile to safe BSON and aren't on the deny list.
