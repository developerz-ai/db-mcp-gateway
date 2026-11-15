# 06 — Permissions

## Model

Permissions are **grants** that attach a **group** to a **(server, database, action)** with optional **constraints**.

```
group  ⨯  (server, database)  ⨯  action  ⨯  constraints  →  allowed
```

| Piece | Meaning |
|---|---|
| **Group** | An SSO group claim (e.g. `backend-engineers`, `oncall`, `data-platform`). Synced from IdP. |
| **Server / database** | Logical names from the config — never raw hosts. On a `redis` server the database is the numeric logical DB index (`prod-cache/0`). |
| **Action** | `schema_read`, `query_read`, `query_write`, `history_read`. |
| **Constraint** | Per-grant overrides: `require_reason`, `row_limit`, `statement_timeout_ms`. A business-hours `time_window` is roadmap ([11](11-roadmap.md)). |

A request is allowed iff *some* grant matches. Denies are not explicit — absence of a matching grant denies.

**Table and schema scoping belongs to the target-DB role, not to a grant.** There is no `allowed_schemas` / `denied_tables` constraint: a SQL parser cannot see through views, functions or `search_path`, so a gateway-side table list would be a promise it cannot keep. Grant the database role exactly the tables it may read (`GRANT SELECT ON …`); that is the boundary the database itself enforces for every statement. A Redis target is the same posture in a different shape: key scoping belongs to the ACL user the gateway logs in as (below), not to a grant — grant fields stay `(server, database, action)` plus `require_reason` / `row_limit` / `statement_timeout_ms`, and there is no redis-specific `key_pattern` / `allowed_keys` constraint to grow one. The adapter's deny-by-default read-only allowlist ([03](03-mcp-tools.md#redis-payload)) is the gateway-side layer above the ACL, and the two fail closed together: neither can be spent by the other.

That is also how you scope **keys**: `ACL SETUSER gateway_ro on >… resetkeys %R~app:* resetchannels -@all +@read -keys` grants read-only access to the *values* under `app:*` and nothing else, and Redis enforces it on every command that names a key. ACL key patterns do **not** filter `SCAN` or `DBSIZE`: that user still sees other key *names* through `SCAN` (verified on Redis and Dragonfly). When key names are sensitive, add `-scan -dbsize`; a non-zero DB index also needs `+select`. Recipe and each part explained in [config-reference §Redis](../deployment/config-reference.md#redis). On Mongo, the role's per-database (or per-collection) privileges play the same part.

## Actions in detail

| Action | What it unlocks |
|---|---|
| `schema_read` | `list_databases`, `describe_schema`, `table_stats`, `db_activity` (own requests only) |
| `query_read` | `run_query` with read-only enforcement, `explain` (incl. `analyze: true` on reads), `sample_table` (size-capped), `cancel_query` (own requests only) |
| `query_write` | `run_query` data writes (single `INSERT` / `UPDATE` / `DELETE`, optionally `dry_run`) and `explain` of them, run as the database's `write_role` — which must exist in config and hold write privileges. Postgres only. Mongo and Redis targets have no write path: `write_role` on them fails boot, so a YAML `query_write` grant matching one fails boot, and a DB-backed one is refused with `forbidden` |
| `history_read` | Read your *own* query history via the `get_query_history` tool ([#169](https://github.com/developerz-ai/db-mcp-gateway/issues/169)). Scoping is on the SSO-verified identity, never a client-supplied user field. Admin-only history access remains via the state DB. |

`query_read` implies `schema_read`. `query_write` implies `query_read`.

**Read-only is enforced by the target database, not only by the gateway's parser.** Every read — including a `query_write` caller's `SELECT` — connects as the database's read `role` inside a `READ ONLY` transaction; only a data write under `query_write` connects as `write_role`. Two tiers can therefore share one `servers:` entry, and the read tier never reaches a write-capable role; the SQL guard and its function denylist are the layers behind it. **Zero is not a constraint value:** a `statement_timeout_ms` or `row_limit` of `0` is rejected by config validation and the admin API, and the exec layer clamps the timeout to at least 1 ms as belt and braces (Postgres reads `statement_timeout = 0` as "no limit").

## Worked examples

**Backend engineer on staging:** full query, schema-read on prod.
```yaml
- group: backend-engineers
  grants:
    - server: staging
      database: "*"
      action: query_read
    - server: prod
      database: "*"
      action: schema_read
```

**Oncall with audited prod access:** query on prod, but reason required and short timeouts.
```yaml
- group: oncall
  grants:
    - server: prod
      database: "*"
      action: query_read
      constraints:
        require_reason: true
        statement_timeout_ms: 5000
        row_limit: 1000
```

**Data platform with writes to a single sandbox DB** (the `sandbox` database declares `write_role` + `write_password` next to its read `role` — a `query_write` grant on a database without them fails boot):
```yaml
- group: data-platform
  grants:
    - server: analytics
      database: sandbox
      action: query_write
      constraints:
        require_reason: true
```

**New hires:** no entry → no access. The default is *nothing*.

**Shared-cluster rollout (issue `#19`).** Rule: rollout stays contract-only and scan-friendly.

| Item | Value |
|---|---|
| Deployable config | `config/permissions.yml` |
| IdP groups | `devs`, `devops`, `cto` |
| v1 action scope | `query_read` only |
| Shared constraints | `statement_timeout_ms: 30000`, `row_limit: 10000` |
| Deferred scope | Per-dev DB ownership (requires IdP group-per-app mapping) |

## Evaluation

For a request `(user, groups, server, db, action)`:

1. Resolve groups from the session.
2. Collect every grant matching one of the user's groups and the target `(server, db)`, plus the subject's DB-backed grants ([12](12-dynamic-permissions.md)) — none for a `service:<name>` identity, whose authority is exactly its YAML group. A `database: "*"` grant matches every database the config declares on that server.
3. If no grant has an action that includes the requested one → `forbidden`. `history_read` is outside the `query_write ⊇ query_read ⊇ schema_read` chain: it neither grants nor is granted by any of them.
4. Merge constraints across matching grants: take the **most restrictive** value for each (lowest `row_limit`, lowest `statement_timeout_ms`, `require_reason` = true wins). Zero is a bound, the tightest one — never "unset".
5. Apply constraints to the call.

Most-restrictive merging means you can't accidentally upgrade your access by being in two groups. The decision depends only on the *set* of matching grants, never their order (`src/authz/resolver_proptests.rs`).

## Hot reload

Permission changes land via PR → merge → operator runs `kill -HUP` on the gateway (or rolling restart). The reload swaps the YAML grants atomically or not at all and invalidates every cached grant, so the next call evaluates against the new file — see [08-config §Hot reload](08-config.md#hot-reload) for what a reload can and cannot change (the admin API's mount, group and known-server list are fixed at boot). Group memberships still come from the session's IdP snapshot until next login (matches [04-auth-sso](04-auth-sso.md)).

## Admin operations

There is no in-band admin UI. Operator actions are CLI subcommands of the gateway binary, run inside the container, against the state DB:

- `gateway admin revoke-session <user_email>`
- `gateway admin list-active-sessions`
- `gateway admin replay-audit <query>` (for compliance investigations)

Admin commands authenticate via a separate mechanism (Unix socket / shell access), not SSO — they're for whoever has prod shell access.
