# 12 — Dynamic permissions + multi-DB targets

> Status: spec. Tracks issue #46. Locks the surface before #47–#60 land code.

## Why

The shipped design (see [06-permissions](06-permissions.md), [08-config](08-config.md)) puts all grants in YAML in git, reviewed by PR, hot-reloaded on SIGHUP. That works for one install run by the team that owns the repo. It does not work for external deployers who never touch our git history and need their *own* audit trail for who-granted-what.

Sebby's direction (2026-06-10 / 2026-06-11): keep YAML as the simple path. Add a second path — an **SSO-gated admin API** writing into the state DB — for installs that need runtime permissions management. No UI; that non-negotiable stands.

Same direction also asks for multi-database query targets (Postgres + MongoDB initially), dispatched by `db_type` on the grant.

## What changes

| Area | Before | After |
|---|---|---|
| Permission source | YAML only | YAML **or** DB-backed, via the same authz engine |
| Permission write audit | Git history (review trail in the PR) | Git history **or** synchronous `permissions_audit` row |
| Permission management | PR | PR **or** `POST /admin/v1/*` (SSO-gated to an admin group) |
| Query target | Postgres only | Postgres **or** MongoDB, dispatched on `db_type` |
| Permission storage backend | n/a | Postgres first; MySQL as a second backend behind the same trait |

## Two sources, one engine

A request `(user, groups, server, db, action)` resolves grants from:

1. **YAML** — same shape as today ([06-permissions](06-permissions.md)).
2. **DB** — rows in the state DB, loaded by `(user_id, database_id)`.

The resolver concatenates both grant sets and hands them to the existing constraint-merge engine. Most-restrictive value wins, unchanged — see [06-permissions §Evaluation](06-permissions.md). YAML and DB are interchangeable inputs. There is no priority order between them; the merge is symmetric.

```
                       ┌──────────────────┐
                       │   YAML grants    │
                       └────────┬─────────┘
                                │
   (user, groups,               ▼
   server, db, action) ──▶  ┌──────────┐  ──▶  ┌──────────────────┐  ──▶ allow + constraints
                            │ resolver │       │ constraint-merge │
                            └──────────┘       └──────────────────┘
                                ▲
                       ┌────────┴─────────┐
                       │   DB grants      │
                       └──────────────────┘
```

### Why merge symmetrically (not "DB overrides YAML")

If DB overrides YAML, an attacker who compromises the admin API can *widen* a grant — the YAML's intent is silently lost. With symmetric merge under most-restrictive, the worst an admin-API attacker can do is *narrow* access (denial of service) or add grants the YAML didn't have. The YAML still floors what its existing grants allow. Defense in depth.

The same logic justifies *not* having a `priority` field on grants. A grant either applies or it doesn't; the merge step picks the safest combination. No precedence game.

## Storage backends

Postgres first. MySQL is a second backend behind the same `PermissionsRepo` trait. **No MongoDB** for the permissions store — it'd add a third schema dialect for no gain (we already have pg, are adding mysql, and mongo's flexible schema is a liability for an authz store where the schema is the contract).

Config switch:

```yaml
permissions:
  yaml: config/permissions.yml      # optional, can be empty/absent
  store:
    driver: pg                       # pg | mysql
    dsn: env:PERMISSIONS_DB_DSN
```

If `store` is absent, the gateway runs YAML-only and the admin API is disabled. This is the path the dogfood install keeps using.

**The MySQL store is read-only-provisioned.** The gateway only reads it; the operator fills it with their own tooling. Boot rejects `driver: mysql` together with `admin.enabled: true`, so there is no audited write path to MySQL and none is planned — the `permissions_audit` table its `0002` migration created stays unwritten. With no admin commit there is no cross-replica notification either: a change made in MySQL is honoured within `PERMISSIONS_CACHE_TTL_SECONDS` (clamped to ≤ 300 s). Identity and routing columns (`user_sub`, `server`, `db_name`) use the case- and accent-sensitive `utf8mb4_0900_as_cs` collation (`migrations-mysql/0004`), so `Alice` and `alice` are two subjects, as they are in Postgres.

**`db_type` names the target engine** a `permissions_databases` row registers — `postgres`, `mysql` or `mongo` (`migrations/0013`, `migrations-mysql/0005`) — not the store the row lives in.

## `permissions_audit` table

Mirrors the query audit invariant from non-negotiable #4: synchronous, write fails → request fails. No best-effort audit, ever, including for permissions changes.

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `ts` | timestamptz | server time |
| `actor_id` | uuid | the acting admin's `permissions_users.id`; deliberately not a foreign key, so an append-only audit row outlives any cleanup of the row it names |
| `actor_email` | text | denormalized for forensics; mirrors query audit |
| `action` | text | `create` \| `update` \| `delete` |
| `target_type` | text | `user` \| `database` \| `grant` |
| `target_id` | uuid | row id of the changed entity |
| `before` | jsonb | full row before, or `null` for `create` |
| `after` | jsonb | full row after, or `null` for `delete` |
| `request_id` | text | matches the request id in [07-logging-retention](07-logging-retention.md) |

**Never logged**: target-DB connection strings, role passwords, role secrets. `before`/`after` redact any field that could carry a secret — same rule as query audit (non-negotiable #1).

Indexes: `(ts)`, `(actor_id, ts)`, `(target_type, target_id, ts)`.

Retention: the hourly audit pruner deletes `permissions_audit` rows whose `ts` is older than `AUDIT_RETENTION_DAYS` (default 90), with the same cutoff, batching and advisory lock as query audit ([07 §Retention pruning](07-logging-retention.md#retention-pruning)). A change trail needed longer than that must be exported before it ages out. The MySQL store's table is never written by the gateway and is not pruned.

## Admin API

Surface: `/admin/v1/{users,databases,grants}`. SSO-gated to a configured admin group. No UI ever.

```yaml
admin:
  enabled: true                    # default false
  group: db-mcp-gateway-admins     # SSO group claim required
```

If `admin.enabled` is false, the entire `/admin/*` route is `404`. Belt-and-suspenders for installs that want YAML-only.

### Endpoints

All endpoints require a valid SSO JWT with the admin group claim. Every write commits a `permissions_audit` row **before** the response goes out.

**List endpoints are paginated.** `GET /admin/v1/{users,databases,grants}` accept `?limit=` and `?offset=`. `limit` defaults to **100** and is clamped to a maximum of **1000** — an oversized ask is clamped, not rejected, matching how the gateway treats every other caller-supplied bound. A non-numeric value is a client mistake and returns `invalid_request` (400). Ordering is stable and total (`created_at, id` for users and grants; `(server, db_name)` for databases), so a walk over a *stable* dataset returns rows in deterministic order and visits each one exactly once. Concurrent inserts, deletes, or updates between page requests can shift rows in or out of a later `offset` window — this is offset-pagination semantics, not a snapshot. Callers that need snapshot guarantees should either walk the pages inside a single admin batch (no writes in-flight) or fall back to a full re-read on the tail. Without pagination an install's entire permissions table loaded into memory and serialized into one response.

Pagination deliberately does *not* apply to the resolver's read: `authz::loader` loads a subject's complete live grant set in **one query** (live user ⋈ live grants ⟕ live databases, keyed on `user_sub`), and a windowed read would silently drop authority. A specific grant whose database is soft-deleted drops inside that query.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/admin/v1/users` | Register a user (SSO subject + email + cached groups). A `service:*` subject is rejected (400) — a service token's authority is its YAML group only ([14](14-service-tokens.md)) |
| `GET` | `/admin/v1/users` | List users |
| `GET` | `/admin/v1/users/:id` | Fetch one user |
| `PATCH` | `/admin/v1/users/:id` | Update (e.g. refresh group cache) |
| `DELETE` | `/admin/v1/users/:id` | Soft-delete; its live grants are revoked in the same transaction, one `delete` audit row per grant |
| `POST` | `/admin/v1/users/:id/revoke-sessions` | Revoke every live session and delete every refresh chain of the user's `user_sub`; their bearers are `401` on the next call. One `permissions_audit` row (`update` on the user, payload `{user_sub, live_sessions, refresh_tokens}` before → zeros after) in the revoke's transaction; session-cache tombstones only after commit. Returns `{revoked_sessions, revoked_refresh_tokens}` |
| `POST` | `/admin/v1/databases` | Register a logical `(server, db_name, db_type)` |
| `GET` | `/admin/v1/databases` | List |
| `GET` | `/admin/v1/databases/:id` | Fetch one |
| `PATCH` | `/admin/v1/databases/:id` | Update (rename, change type — both audited) |
| `DELETE` | `/admin/v1/databases/:id` | Soft-delete; its specific grants are revoked in the same transaction, one `delete` audit row per grant (wildcards name the server and stay) |
| `POST` | `/admin/v1/grants` | Create a grant |
| `GET` | `/admin/v1/grants` | List, filterable by user / database |
| `GET` | `/admin/v1/grants/:id` | Fetch one |
| `PATCH` | `/admin/v1/grants/:id` | Update action and/or constraints — constraints merge per key (see §PATCH merges per key) |
| `DELETE` | `/admin/v1/grants/:id` | Revoke |

### What the API never returns

- Connection strings.
- Role passwords or secrets.
- Other users' SSO tokens or session state.
- Audit rows for other organizations (single-tenant assumption — see [02-architecture](02-architecture.md)).

The `databases` endpoints register a *logical* db reference; the connection string for that db still lives in YAML/secrets and is loaded by the gateway at boot. The admin API can't accept a DSN field. This keeps non-negotiable #1 intact even if the admin DB is compromised: there is no credential on the DB side to leak.

### Request shapes

`POST /admin/v1/grants`:

```json
{
  "user_id": "uuid-of-user",
  "database_id": "uuid-of-database",
  "db_name_wildcard": false,
  "action": "query_read",
  "constraints": {
    "row_limit": 1000,
    "statement_timeout_ms": 5000,
    "require_reason": true
  }
}
```

`db_name_wildcard: true` + `database_id: null` + `server` is the `db_name = "*"` form (see §Wildcard). `server` must name a server the gateway config declares; `"*"` or an undeclared name is `invalid_request` (400).

### Validation + error semantics

The grants handlers validate at the API layer **before** the DB CHECKs would catch it, so client-correctable mistakes surface as stable `invalid_request` (400) rather than `internal` (500):

| Rule | Trigger | Response |
|---|---|---|
| XOR target | both, neither, or mismatched `database_id` / `(server, db_name_wildcard: true)` | `invalid_request` (400) at handler, never reaches DB CHECK |
| Action parse | unknown action string | `invalid_request` (400) before any SQL runs |
| Dead reference | `user_id` or `database_id` missing or soft-deleted — checked by the insert itself (`INSERT … SELECT … WHERE deleted_at IS NULL`, both rows held `FOR SHARE` until commit) | `invalid_request` (400), stable `invalid grant reference` message; DB error text never echoed (non-negotiable #1) |
| Wildcard server | `server` is `"*"` or not declared in config | `invalid_request` (400) |
| Zero bound | `constraints.row_limit` or `constraints.statement_timeout_ms` is `0` on POST, or set to `0` by PATCH (a zero would disable the bound, not tighten it) | `invalid_request` (400); nothing written |
| Stale precondition | PATCH `expected_updated_at` differs from the locked row's `updated_at` | `conflict` (409); nothing written |
| Deadlock / serialization abort (`40P01` / `40001`) | concurrent admin writes Postgres had to abort | `conflict` (409); safe to retry |
| CHECK violation (`23514`) | belt-and-suspenders for a future migration adding a CHECK the handler doesn't pre-validate | `invalid_request` (400) |
| UNIQUE violation (`23505`) | on `/databases`: registering a `(server, db_name)` pair that already exists, or PATCHing one onto another | `invalid_request` (400), message names the pair from the caller's own input; DB error text never echoed |
| Anything else | pool exhaustion, encoder bug, audit failure | `internal` (500), body carries `request_id` only; underlying error stays in gateway logs |

The `(server, db_name)` UNIQUE index is partial (`WHERE deleted_at IS NULL`), so a soft-deleted pair does not occupy it — the same pair can be registered again after a DELETE.

### Locked writes

Every admin mutation runs one shape (`src/transport/admin/audited_tx.rs`): begin → upsert the acting admin's `permissions_users` row → lock the target row (`SELECT … FOR UPDATE`) → mutate → write `permissions_audit` → queue `NOTIFY` → commit → invalidate this replica's cache. Locking the actor row first gives every admin write one lock order; a mutation of the actor's own user row skips the actor upsert (that row plays both parts). Because the target is locked before `before` is read, concurrent writes serialise and the audit chain is continuous: `after[n] == before[n+1]`. PATCH bodies may carry `expected_updated_at` (the value last read); a mismatch is 409.

### PATCH merges per key

`constraints` on `PATCH /admin/v1/grants/:id` is a per-key patch onto the stored object, never a replacement: an absent key keeps its value, `null` clears it (`require_reason` clears to `false`), a value sets it. A PATCH naming only `row_limit` therefore keeps `require_reason` and `statement_timeout_ms` — no admin call can loosen a constraint it did not name. Proven by `src/authz/patch_proptests.rs`.

### PATCH cannot change the target

`PATCH /admin/v1/grants/:id` accepts `action`, `constraints` and `expected_updated_at` only. The XOR target (`Specific` vs `Wildcard`) is the grant's identity — re-targeting is DELETE + POST. Bodies carrying `database_id` / `server` / `db_name_wildcard` are rejected at the parse layer (`deny_unknown_fields` → 400).

### Cache invalidation

The resolver caches each subject's DB grant set (`PermissionsCache`, keyed on `user_sub`). A cold miss is one store query; concurrent misses for one subject share it (single flight); a load overtaken by an invalidation of that subject is not cached (per-subject revision) and is retried at most three times; expired idle entries are swept on insert.

An admin commit both drops this replica's affected entries and, inside the same transaction, `NOTIFY`s channel `dbmcp_permissions`; every replica's listener applies it on commit and never on rollback. The listener keeps running through the shutdown drain, so requests still in flight on a stopping replica see revokes until they finish. A listener that loses its connection reconnects with backoff and flushes everything on reconnect, since notifications sent meanwhile are lost. The bound on a revoke reaching every replica is therefore the notification latency, or the reconnect delay after a dropped listener — the TTL (`PERMISSIONS_CACHE_TTL_SECONDS`, default 60 s, clamped ≤ 300 s) bounds only what nothing announces, such as a MySQL store edited outside the gateway.

| Surface | Scope | Why |
|---|---|---|
| `/admin/v1/grants` (POST/PATCH/DELETE) | The grant's user | A grant only ever affects the one user it targets. |
| `/admin/v1/users` (POST/PATCH/DELETE) | The mutated row's `user_sub` | A group change flips constraint-merge results; a re-POST of an existing subject is an upsert and changes it too; a soft-delete (and its grant cascade) must stop landing decisions immediately. |
| `/admin/v1/databases` (PATCH/DELETE) | Every subject | A rename or soft-delete changes what every specific grant on the row resolves to. |
| `/admin/v1/databases` (POST) | None | A new row has no grants, and wildcards resolve against config databases, never these rows. |

| Rule | Behavior |
|---|---|
| Post-commit | Local invalidation runs **after** commit, so a concurrent reader cannot re-warm with the pre-commit state; the `NOTIFY` is transactional for the same reason. |
| Detached from the request | Local invalidation runs on a `tokio::spawn`ed task (`PermissionsCache::spawn_apply`), so a client disconnect between commit and invalidate cannot strand a stale entry. |
| `user_sub`-keyed | Grants reference users by row id; the handler resolves `user_sub` inside the transaction. |
| Service identities | A `service:<name>` identity never reads the store — its authority is exactly its YAML group, so a DB grant seeded for it is inert. |
| YAML-only installs | No resolver cache → invalidation is a no-op. |

## Wildcard grants

`db_name = "*"` is a per-grant flag for "applies to every database the gateway **config** declares on `server`" — not every `permissions_databases` row registered for it. Registering or deleting a database row never changes what a wildcard covers; changing the config's databases does. Intended for dev/superuser grants; the audience Sebby flagged as "us devs and other like us".

### Rules

1. Explicit denies *always* beat wildcard allows. (We don't have explicit denies today; absence is the deny — see [06-permissions §Evaluation](06-permissions.md). Wildcards do not change this.)
2. A wildcard grant never widens permissions on a database the user has a more-specific grant on — the per-database grant's constraints intersect with the wildcard's, most-restrictive wins.
3. Wildcards still go through the same constraint engine. A wildcard `row_limit: 100` does not become unlimited just because it matches every db; it caps every db.

Tested with proptest in #55. The property: for any pair of `(wildcard_grant, specific_grant)` on overlapping databases, the merged result is never more permissive than the specific grant alone.

### Reserved `"*"` sentinel on `/admin/v1/databases`

`"*"` is *only* meaningful as the wildcard marker on grants (`grant.server == "*"` / `grant.database == "*"`, expressed on the API as `db_name_wildcard: true` + `database_id: null`). A `permissions_databases` row whose `server` or `db_name` is literally `"*"` would let every `Specific`-target grant pointing at it silently behave as a wildcard — an authz escalation an admin registering a database `"*"` would not expect or intend.

To keep the sentinel from ever reaching the store, `POST` and `PATCH` on `/admin/v1/databases` reject any request where the trimmed `server` or `db_name` equals `"*"`:

| Body field | Value (after `trim()`) | Response |
|---|---|---|
| `server` | `"*"` | `400 invalid_request`, message names the field and points at the wildcard-grant alternative |
| `db_name` | `"*"` | Same |
| Either | whitespace-only | `400 invalid_request`, `<field> must be non-empty` |
| Either | any other string containing `*` (e.g. `prod-*-shard`) | Accepted — only the bare sentinel is magic to the evaluator |

The rejection runs before any INSERT/UPDATE against `permissions_databases`, so a rejected request leaves the store and `permissions_audit` unchanged (verified end-to-end in `tests/it_db/admin_databases_e2e.rs`).

### Declared servers only on `/admin/v1/databases`

`POST` and `PATCH` on `/admin/v1/databases` (a `PATCH` only when it sets `server`) require the trimmed `server` to name a server declared in the gateway's **boot** config — the same set a wildcard grant's `server` is checked against; a SIGHUP reload does not change it. An undeclared server is `400 invalid_request` (`server must name a server declared in the gateway config`). A row on an undeclared server would otherwise sit dormant until a later config change silently armed every specific grant on it. Like the sentinel check, the refusal happens before the transaction opens, so no `permissions_databases` row and no `permissions_audit` entry is written (verified in `tests/it_db/transport_wave2_admin_databases.rs`).

The supported way to grant access to every database on a server is `db_name_wildcard: true` + `database_id: null` on `POST /admin/v1/grants` (see [Request shapes](#request-shapes) above), *not* a `permissions_databases` row literally named `"*"`.

## `DbAdapter` trait

Polymorphic query execution. CLAUDE.md convention: trait when the second impl arrives. Mongo is that second impl, so it lands now.

```rust
#[async_trait]
pub trait DbAdapter: Send + Sync {
    /// Identifies the backend kind for dispatch and audit.
    fn kind(&self) -> DbKind;

    /// Execute a query under the merged constraint set.
    /// Cancellation safety: drop = cancel the backend operation.
    async fn execute(
        &self,
        request: ExecRequest,
        constraints: &Constraints,
    ) -> Result<ExecResult, ExecError>;

    /// Liveness check for the per-DB pool.
    async fn health(&self) -> Result<(), ExecError>;
}

pub enum DbKind {
    Postgres,
    Mongo,
}
```

`ExecRequest` carries the raw query (SQL for pg, BSON command for mongo), the user identity, and the request id. The adapter is responsible for backend-specific read-only enforcement before any I/O.

### Postgres adapter

Existing pg execution moves behind `DbAdapter` with no behavior change. Read-only enforcement stays at the role level (per-DB `ro_*` roles in the target DB) + statement classification at the gateway. See [05-credentials](05-credentials.md).

**One role per tier.** A database that accepts writes declares `write_role` + `write_password` beside its read `role`, and the adapter keeps two pools keyed `(server, database, read|write)`. Every read — a `query_write` caller's `SELECT` included — runs as `role` in a `READ ONLY` transaction; only a data write under `query_write` runs as `write_role`. A YAML `query_write` grant whose databases (wildcards expanded against the configured ones) lack a `write_role` fails boot ([08-config](08-config.md)); a DB-backed `query_write` grant on such a database is refused at request time with `forbidden`. The read tier never reaches a write-capable role.

Introspection (`table_stats`, `db_activity`, `cancel_query` — [03](03-mcp-tools.md)) runs on the read pool. The adapter tags every backend with the gateway `request_id` through `application_name`, which is how `db_activity` names requests and `cancel_query` finds one; the tool, not the adapter, checks that the request is the caller's own.

### Mongo adapter

Read-only enforcement is the interesting part. Mongo doesn't have a single "READ ONLY" role flag we can rely on the same way as a Postgres role; some "read" commands can write (`$out`, `$merge` in aggregation pipelines, `$function` server-side JS with side effects). The adapter rejects:

- Any aggregation pipeline containing `$out`, `$merge`, `$function`, or `$where` with non-pure JS.
- Any command outside the allowed set: `find`, `aggregate`, `count`, `countDocuments`, `distinct`, `estimatedDocumentCount`, `listCollections`, `listIndexes`.
- Write commands explicitly: `insert`, `update`, `delete`, `findAndModify`, `bulkWrite`, `createIndex`, `drop`.
- Any top-level key outside the command's own allow-list (`src/exec/mongo/rejector/mod.rs`, `allowed_fields`). The lists hold shape and read options only (`filter`, `sort`, `projection`, `pipeline`, `cursor`, `limit`, `collation`, …), so no `$`-prefixed key (`$db` would re-target the command at another database, `$readPreference` re-routes it), no session or transaction field (`lsid`, `txnNumber`, `autocommit`, `startTransaction`), no `writeConcern`, and no cursor-lifetime knob (`tailable`, `awaitData`, `noCursorTimeout`) reaches the driver. Before this, a `$db` key was forwarded and the server (8.0) refused the duplicate `$db` itself — safe by the server's grace, not the gateway's.

The connection still uses a least-privilege mongo role (read-only on the target DB) — defense in depth, same posture as the pg `ro_*` roles.

`describe_schema` and `sample_table` work on Mongo too: `describe_schema` is `listCollections` + `listIndexes` (collections with their indexes; `schema` is ignored, `table` names one collection) and `sample_table` is a `find` with the sample limit. Mongo writes stay out of scope ([10](10-non-goals.md)); `write_role` on a Mongo database fails boot.

Timeouts via `maxTimeMS`. Row caps via a server-side limit of `row_limit + 1` (`find` `limit`/`batchSize`, a trailing `$limit` stage on `aggregate`) plus the gateway's row and byte budget at the adapter. A reply missing its documented field, or a document that cannot be rendered, is a typed error — never a fabricated `null`. Cancellation: `killOp` on client disconnect, best-effort and requires an opt-in privilege — see [config-reference.md §Mongo](../deployment/config-reference.md#mongo) for the full contract (`statement_timeout_ms` is the guaranteed bound either way, same as pg's belt-and-suspenders `tokio::time::timeout`).

Audit row shape matches pg's: same envelope (`request_id`, `user`, `server`, `database`, `outcome`, `duration_ms`), payload carries `db_kind: "mongo"` and the BSON command with sensitive values redacted by the same rules as SQL parameter redaction in [07-logging-retention](07-logging-retention.md).

## Phasing

| Phase | Issues | Ship outcome |
|---|---|---|
| Design | #46 (this doc) | Surface locked |
| Storage | #47, #48 | State DB has permission tables; pg repo works |
| Resolver | #49, #50 | DB grants flow through the existing authz engine |
| Audit | #51 | `permissions_audit` table + sync writer |
| Admin API | #52, #53, #54 | CRUD endpoints, SSO-gated, audited |
| Wildcard | #55 | `db_name = "*"` |
| Multi-DB | #56, #57, #58 | `DbAdapter` trait, mongo adapter, mongo queries |
| Backends | #59 | MySQL permission store |
| Docs | #60 | Operator + developer docs |

Each phase is independently shippable. The gateway stays YAML-only and pg-only until the relevant phase is complete. No flag-flip surprise.

## Open questions

1. **Admin bootstrap.** How does the first admin get created when `admin.enabled: true` is first turned on and no users exist? Proposal: a one-shot CLI subcommand (`gateway admin bootstrap <sso-email>`) inserts the first user with the admin group, runs against the state DB directly, audits to `permissions_audit` with `actor_id = NULL` and `request_id = "bootstrap"`.
2. **API versioning.** `/admin/v1/*` — bake `v1` into the URL now to avoid future churn. Confirmed default.
3. **YAML ↔ DB import/export.** Out of scope for this milestone. Operators can write a one-off script against the public CRUD if they need to migrate. Revisit if the ask is real.
4. **Mongo write grants.** Out of scope. `query_write` for mongo would mean lifting the rejector for `$out`/`$merge` etc; that's a future spec doc, not this one.

## See also

- [01-overview](01-overview.md) — synchronous audit invariant
- [02-architecture](02-architecture.md) — layers and process model
- [05-credentials](05-credentials.md) — target-DB roles and DSN resolution
- [06-permissions](06-permissions.md) — grant model and evaluation
- [07-logging-retention](07-logging-retention.md) — audit shape and redaction
- [08-config](08-config.md) — YAML schema and hot reload
