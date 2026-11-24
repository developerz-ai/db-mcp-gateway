# 06 — Permissions

## Model

Permissions are **grants** that attach a **subject** — a **group**, or one **user** — to a **(server, database, action)** with optional **constraints**.

```
subject  ⨯  (server, database)  ⨯  action  ⨯  constraints  →  allowed
```

| Piece | Meaning |
|---|---|
| **Group** | An SSO group claim (e.g. `backend-engineers`, `oncall`, `data-platform`). Synced from IdP. A `permissions:` block names it with `group:`. |
| **User** | One SSO subject (`user: <sub>`), for the grant that fits one person and no group. Matches only an SSO session with exactly that `sub` — never a service token (whose authority is exactly its one YAML group, [14](14-service-tokens.md)). A block names exactly one of `group:` / `user:`. |
| **Server / database** | Logical names from the config — never raw hosts. On a `redis` server the database is the numeric logical DB index (`prod-cache/0`). |
| **Action** | `schema_read`, `query_read`, `query_write`, `history_read`. |
| **Constraint** | Per-grant overrides: `require_reason`, `row_limit`, `statement_timeout_ms`. A grant may name a `profile:` from top-level `constraint_profiles:`; the profile is merged into the grant's own values most-restrictively at parse time, so a profile can tighten a grant, never loosen it. A business-hours `time_window` is roadmap ([11](11-roadmap.md)). |
| **`except:`** | On a `database: "*"` grant only: databases the wildcard does not cover. Each entry must name a declared database (boot error otherwise). |
| **Expiry** | DB-backed grants may carry `expires_at` ([12](12-dynamic-permissions.md)); from that instant on (inclusive) evaluation ignores the grant. YAML grants never expire. |

A request is allowed iff *some* grant matches. Denies are not explicit — absence of a matching grant denies.

**Table and schema scoping belongs to the target-DB role, not to a grant.** There is no `allowed_schemas` / `denied_tables` constraint: a SQL parser cannot see through views, functions or `search_path`, so a gateway-side table list would be a promise it cannot keep. Grant the database role exactly the tables it may read (`GRANT SELECT ON …`); that is the boundary the database itself enforces for every statement.

The same holds for keys on a Redis target: there is no `allowed_keys` constraint. Scope the ACL user the gateway logs in as — `ACL SETUSER gateway_ro on >… resetkeys %R~app:* resetchannels -@all +@read -keys` grants read-only access to the *values* under `app:*` and nothing else, and Redis enforces it on every command that names a key. ACL key patterns do **not** filter `SCAN` or `DBSIZE`: that user still sees other key *names* through `SCAN` (verified on Redis and Dragonfly). When key names are sensitive, add `-scan -dbsize`; a non-zero DB index also needs `+select`. Recipe and each part explained in [config-reference §Redis](../deployment/config-reference.md#redis). On Mongo, the role's per-database (or per-collection) privileges play the same part.

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
2. Collect every grant the caller holds on the target `(server, db)`: the YAML grants of each of the user's groups and of a `user:` block naming the caller's SSO `sub`, plus the subject's live, unexpired DB-backed grants ([12](12-dynamic-permissions.md)) — none of the last two for a `service:<name>` identity, whose authority is exactly its YAML group. A `database: "*"` grant matches every database the config declares on that server, minus its `except:` list.
3. Keep only the grants whose action **includes the requested action** (`query_write ⊇ query_read ⊇ schema_read`; a grant includes its own action). These are the *matching* grants. None left → `forbidden`. `history_read` is outside the chain: it neither grants nor is granted by any of them.
4. Merge constraints across the matching grants, and only those: take the **most restrictive** value for each (lowest `row_limit`, lowest `statement_timeout_ms`, `require_reason` = true wins). Zero is a bound, the tightest one — never "unset". The merge scope is therefore the requested action, not the caller's whole grant set:
   - a grant that does not include the requested action contributes nothing. A `query_read` grant's `row_limit` or `require_reason` never binds a `query_write` call — cap the write grant itself;
   - the inclusion runs one way. A `query_write` grant includes `query_read`, so it is a matching grant for a read and its constraints do merge into that read (and into a `schema_read` call).
5. Apply constraints to the call.

Grants are a union, constraints a per-action merge. Being in a second group can widen access: its grants add every action and target they cover — a `query_write` grant in one group gives the write the other group lacks, bound only by the constraints of the grants that match the write (step 4). What a second group cannot do is loosen a call another grant already matches: its constraints join that call's merge and the tighter value wins, so an unconstrained grant never lifts another group's `row_limit` on the same action. A `user:` grant behaves the same: it can add an action the user's groups lack, but where it and a group grant both match, the tighter value wins (`src/authz/subject_proptests.rs`). The decision depends only on the *set* of matching grants, never their order (`src/authz/resolver_proptests.rs`); the action scope of the merge is pinned by `src/authz/action_scope_proptests.rs`. `POST /admin/v1/explain` answers "why allowed / denied" from this same evaluation (`authz::matching_grants`), not a re-implementation.

## Hot reload

Permission changes land via PR → merge → operator runs `kill -HUP` on the gateway (or rolling restart). The reload swaps the YAML grants atomically or not at all and invalidates every cached grant, so the next call evaluates against the new file — see [08-config §Hot reload](08-config.md#hot-reload) for what a reload can and cannot change (the admin API's mount, group and known-server list are fixed at boot). Group memberships still come from the session's IdP snapshot until next login (matches [04-auth-sso](04-auth-sso.md)).

## Admin operations

There is no in-band admin UI. **Planned, not built:** the CLI below is scheduled in plan 101 slice 08 (operator tooling); the binary ships no subcommands today. Until it lands, revoke sessions with the audited admin API (`POST /admin/v1/users/:id/revoke-sessions`, [admin-api.md](../deployment/admin-api.md)) or SQL against the state DB, and read audit history from `audit_calls` directly. The planned operator actions are CLI subcommands of the gateway binary, run inside the container, against the state DB:

- `gateway admin revoke-session <user_email>`
- `gateway admin list-active-sessions`
- `gateway admin replay-audit <query>` (for compliance investigations)

Admin commands authenticate via a separate mechanism (Unix socket / shell access), not SSO — they're for whoever has prod shell access.
