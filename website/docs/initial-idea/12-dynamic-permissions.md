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

## `permissions_audit` table

Mirrors the query audit invariant from non-negotiable #4: synchronous, write fails → request fails. No best-effort audit, ever, including for permissions changes.

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `ts` | timestamptz | server time |
| `actor_id` | uuid | the admin who made the change (SSO subject) |
| `actor_email` | text | denormalized for forensics; mirrors query audit |
| `action` | text | `create` \| `update` \| `delete` |
| `target_type` | text | `user` \| `database` \| `grant` |
| `target_id` | uuid | row id of the changed entity |
| `before` | jsonb | full row before, or `null` for `create` |
| `after` | jsonb | full row after, or `null` for `delete` |
| `request_id` | text | matches the request id in [07-logging-retention](07-logging-retention.md) |

**Never logged**: target-DB connection strings, role passwords, role secrets. `before`/`after` redact any field that could carry a secret — same rule as query audit (non-negotiable #1).

Indexes: `(ts)`, `(actor_id, ts)`, `(target_type, target_id, ts)`.

Retention follows the same pruner pattern as query audit. Permission changes are typically lower volume than queries, so hot-window retention can be longer (90+ days) without strain.

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

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/admin/v1/users` | Register a user (SSO subject + email + cached groups) |
| `GET` | `/admin/v1/users` | List users |
| `GET` | `/admin/v1/users/:id` | Fetch one user |
| `PATCH` | `/admin/v1/users/:id` | Update (e.g. refresh group cache) |
| `DELETE` | `/admin/v1/users/:id` | Soft-delete; existing grants cascade to revoked |
| `POST` | `/admin/v1/databases` | Register a logical `(server, db_name, db_type)` |
| `GET` | `/admin/v1/databases` | List |
| `GET` | `/admin/v1/databases/:id` | Fetch one |
| `PATCH` | `/admin/v1/databases/:id` | Update (rename, change type — both audited) |
| `DELETE` | `/admin/v1/databases/:id` | Remove; grants on it cascade-revoke |
| `POST` | `/admin/v1/grants` | Create a grant |
| `GET` | `/admin/v1/grants` | List, filterable by user / database |
| `GET` | `/admin/v1/grants/:id` | Fetch one |
| `PATCH` | `/admin/v1/grants/:id` | Update constraints, action set |
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

`db_name_wildcard: true` + `database_id: null` is the `db_name = "*"` form (see §Wildcard).

### Validation + error semantics

The grants handlers validate at the API layer **before** the DB CHECKs would catch it, so client-correctable mistakes surface as stable `invalid_request` (400) rather than `internal` (500):

| Rule | Trigger | Response |
|---|---|---|
| XOR target | both, neither, or mismatched `database_id` / `(server, db_name_wildcard: true)` | `invalid_request` (400) at handler, never reaches DB CHECK |
| Action parse | unknown action string | `invalid_request` (400) before any SQL runs |
| FK violation (`23503`) | `user_id` or `database_id` missing / soft-deleted | `invalid_request` (400), stable `invalid grant reference` message; DB error text never echoed (non-negotiable #1) |
| CHECK violation (`23514`) | belt-and-suspenders for a future migration adding a CHECK the handler doesn't pre-validate | `invalid_request` (400) |
| UNIQUE violation (`23505`) | on `/databases`: registering a `(server, db_name)` pair that already exists, or PATCHing one onto another | `invalid_request` (400), message names the pair from the caller's own input; DB error text never echoed |
| Anything else | pool exhaustion, encoder bug, audit failure | `internal` (500), body carries `request_id` only; underlying error stays in gateway logs |

The `(server, db_name)` UNIQUE index is partial (`WHERE deleted_at IS NULL`), so a soft-deleted pair does not occupy it — the same pair can be registered again after a DELETE.

### PATCH cannot change the target

`PATCH /admin/v1/grants/:id` accepts `action` and `constraints` only. The XOR target (`Specific` vs `Wildcard`) is the grant's identity — re-targeting is DELETE + POST. Bodies carrying `database_id` / `server` / `db_name_wildcard` are rejected at the parse layer (`deny_unknown_fields` → 400).

### Cache invalidation

The resolver caches `(user, server, db) → grants` per session. Admin API writes call `PermissionsCache::spawn_invalidate` (per-user) or `PermissionsCache::spawn_invalidate_all` (full flush) after the data + audit tx commits. Both launch a detached `tokio::spawn`ed task that runs the invalidation off the request future, so a client disconnect between commit and invalidate can't leave a stale entry live until TTL. The next tool call recomputes. No restart needed. Cache TTL is also short (default 60s) so a missed invalidation self-heals.

Every admin surface that can change a grant's meaning invalidates on a successful commit — not just `/admin/v1/grants`:

| Surface | Scope | Why |
|---|---|---|
| `/admin/v1/grants` (POST/PATCH/DELETE) | Per-user (`PermissionsCache::spawn_invalidate`) | A grant only ever affects the one user it targets. |
| `/admin/v1/users` (PATCH/DELETE) | Per-user, keyed on the mutated row's `user_sub` | A group change flips constraint-merge results; a soft-delete must stop landing decisions for the deleted principal immediately, not after TTL. `create` skips invalidation — a fresh row has no existing cache entry. |
| `/admin/v1/databases` (POST/PATCH/DELETE) | Full flush (`PermissionsCache::spawn_invalidate_all`) | A `permissions_databases` row change can shift what a `(server, db_name)` wildcard grant resolves to for *any* user — narrower per-user invalidation is not sufficient. |

Implementation notes every handler honors:

| Rule | Behavior |
|---|---|
| Post-commit, fire-and-forget | Hook fires **after** the data + audit tx commits. Pre-commit lets a concurrent reader re-warm with the still-stale grant; post-commit guarantees the next re-warm sees the new state. |
| Detached from the request | `spawn_invalidate` / `spawn_invalidate_all` run the invalidation on a `tokio::spawn`ed task, not awaited inline on the request future. A client disconnect between the tx commit and the invalidate call must not leave a stale entry live until TTL — the detached task owns its inputs and runs to completion regardless of what happens to the request. |
| `user_sub`-keyed (user/grant paths) | Cache key is the SSO subject; grants reference users by row id. Handler resolves `user_sub` through the same tx (lookup sees the same DB state the audit row records) before spawning the invalidation. |
| YAML-only installs | No state DB → resolver cache absent → invalidation is a no-op. TTL is the safety net. |

## Wildcard grants

`db_name = "*"` is a per-grant flag for "applies to every database registered for `server`". Intended for dev/superuser grants; the audience Sebby flagged as "us devs and other like us".

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

The rejection runs before any INSERT/UPDATE against `permissions_databases`, so a rejected request leaves the store and `permissions_audit` unchanged (verified end-to-end in `tests/admin_databases_e2e.rs`).

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

### Mongo adapter

Read-only enforcement is the interesting part. Mongo doesn't have a single "READ ONLY" role flag we can rely on the same way as a Postgres role; some "read" commands can write (`$out`, `$merge` in aggregation pipelines, `$function` server-side JS with side effects). The adapter rejects:

- Any aggregation pipeline containing `$out`, `$merge`, `$function`, or `$where` with non-pure JS.
- Any command outside the allowed set: `find`, `aggregate`, `count`, `countDocuments`, `distinct`, `estimatedDocumentCount`, `listCollections`, `listIndexes`.
- Write commands explicitly: `insert`, `update`, `delete`, `findAndModify`, `bulkWrite`, `createIndex`, `drop`.

The connection still uses a least-privilege mongo role (read-only on the target DB) — defense in depth, same posture as the pg `ro_*` roles.

Timeouts via `maxTimeMS`. Row caps via cursor batch limit + total-rows enforcement at the adapter. Cancellation: `killOp` on client disconnect, best-effort and requires an opt-in privilege — see [config-reference.md §Mongo](../deployment/config-reference.md#mongo) for the full contract (`statement_timeout_ms` is the guaranteed bound either way, same as pg's belt-and-suspenders `tokio::time::timeout`).

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
