# Admin API

Reference for `/admin/v1/*` — the SSO-gated, audited HTTP surface for managing users, target databases, and grants without editing YAML. Pair with the spec at [`../initial-idea/12-dynamic-permissions.md`](../initial-idea/12-dynamic-permissions.md) for the *why*.

The admin API is **off by default**. Setting `admin.enabled: true` in YAML opens it; the entire `/admin/*` path stays 404 otherwise. CLAUDE.md non-negotiable #5: the only ways to manage permissions are this API and reviewed YAML.

## Status: what works today

| Capability | Status |
|---|---|
| Users CRUD (#52) | works |
| Databases CRUD (#53) | works |
| Grants CRUD with XOR target + wildcard (#54) | works |
| Synchronous `permissions_audit` writes (#51) | works |
| Cache invalidation on grant change | works |
| Pg backend (default) | works |
| Mysql backend | **resolver path only** — boot rejects `permissions_store.driver: mysql` + `admin.enabled: true` until a transactional `PermissionsRepo` shape lands. Operators on mysql today use YAML grants or pre-populate the tables directly. |

## Enabling the surface

Add an `admin` block to the YAML the gateway loads:

```yaml
admin:
  enabled: true
  group: db-admins   # SSO group claim that authorizes /admin/v1/*
```

`group` must be non-empty when `enabled: true`. An empty string aborts boot rather than silently letting every authenticated user in.

Routes mount only when both `permissions_repo` and `state_db` are present in the runtime state. If either is missing at startup the gateway refuses to boot — no half-loaded admin surface.

## Auth flow

Same OIDC path as the MCP surface — see [`../usage/first-query.md`](../usage/first-query.md). Every admin request needs:

1. **Bearer session token** in `Authorization: Bearer …` (issued by `/auth/login` → `/auth/callback`). 401 without it.
2. **Membership in `admin.group`** carried on the SSO identity's `groups` claim. 403 without it. The check fires on every call; group membership is read from the live JWT, not cached.

On a successful admin call the gateway upserts the caller into `permissions_users` (idempotent) and stamps every write with their `user_id` + `user_email` in `permissions_audit`.

## Audit guarantees

Every mutating call (POST/PATCH/DELETE) writes a `permissions_audit` row in the **same transaction** as the data change. If the audit insert fails the data write rolls back too — there is no best-effort audit (CLAUDE.md non-negotiable #4).

Audit shape (one row per write):

| Field | Source |
|---|---|
| `actor_id`, `actor_email` | The calling admin's `permissions_users` row |
| `action` | `create` / `update` / `delete` |
| `target_type` | `user` / `database` / `grant` |
| `target_id` | The row being touched |
| `before` | Pre-write snapshot JSON. `NULL` on `create`. |
| `after` | Post-write snapshot JSON. `NULL` on `delete`. |
| `request_id` | Threaded from the HTTP request for join-back to operator dashboards |
| `ts` | Server-side, assigned at write time (not monotonic — ordering uses `(ts, id)` as the tie-breaker). |

Query examples (run as the state DB superuser):

```sql
-- "What did this admin touch in the last hour?"
SELECT ts, action, target_type, target_id
  FROM permissions_audit
 WHERE actor_email = 'alice@example.com'
   AND ts > now() - interval '1 hour'
 ORDER BY ts, id;

-- "Who last edited this grant?"
SELECT ts, actor_email, action, before, after
  FROM permissions_audit
 WHERE target_type = 'grant' AND target_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
 ORDER BY ts DESC, id DESC LIMIT 5;
```

## Endpoints

All paths are under `/admin/v1`. Request and response bodies are JSON. `Content-Type: application/json` is required on POST/PATCH.

### Users

`POST /admin/v1/users` — upsert by `user_sub` (the SSO subject claim).

```json
{
  "user_sub": "8f2b…|alice",
  "user_email": "alice@example.com",
  "groups": ["engineers"]
}
```

Response: the full `PermissionsUser` row. Upsert is idempotent on the *live* row — soft-deleted history stays as audit trail.

`GET /admin/v1/users` — list live users, oldest first.

`GET /admin/v1/users/:id` — one user by id. 404 if missing or soft-deleted.

`PATCH /admin/v1/users/:id` — partial update. Fields not in the body stay unchanged.

```json
{ "user_email": "alice.new@example.com", "groups": ["engineers", "oncall"] }
```

`DELETE /admin/v1/users/:id` — soft delete. Sets `deleted_at`; subsequent live lookups return 404. The row stays in the table as audit trail.

### Databases

`POST /admin/v1/databases` — register a logical target the resolver can attach grants to.

```json
{ "server": "prod", "db_name": "billing", "db_type": "postgres" }
```

`db_type` is `postgres` or `mysql` only — mongo is intentionally absent from the permissions store (spec 12 §"Storage backends"). Mongo *query* targets exist as a separate axis; see [`../usage/multi-db.md`](../usage/multi-db.md).

This row carries only the routing key — **no DSN, no role, no password**. CLAUDE.md non-negotiable #1: connection details stay in YAML / secret backends, never in the admin API.

DSN field names (`connection_string`, `dsn`, `password`, `role`) are rejected with HTTP 400 at parse time via `#[serde(deny_unknown_fields)]`. Pinned by `tests/admin_databases_e2e.rs`.

`GET /admin/v1/databases` — list live databases.

`GET /admin/v1/databases/:id` — by id. 404 if missing.

`PATCH /admin/v1/databases/:id` — partial update. Same DSN-rejection rules.

`DELETE /admin/v1/databases/:id` — soft delete.

### Grants

`POST /admin/v1/grants` — attach a grant to a user. Spec 12 §"Wildcards": targets are XOR — a specific database row OR a server-level wildcard, not both.

Specific target:

```json
{
  "user_id": "uuid-of-the-user",
  "database_id": "uuid-of-the-database",
  "action": "query_read",
  "constraints": { "row_limit": 1000, "statement_timeout_ms": 5000 }
}
```

Wildcard target:

```json
{
  "user_id": "uuid-of-the-user",
  "server": "prod",
  "db_name_wildcard": true,
  "action": "schema_read",
  "constraints": {}
}
```

Bodies that mix `database_id` and `server` (or set neither) return 400 with a stable `invalid_request` code. The pg storage layer has a matching CHECK constraint as defense-in-depth — pinned by `xor_target_violations_are_rejected` in the e2e suite.

Foreign-key violations (`user_id` or `database_id` not in the tables) and CHECK violations from the storage layer surface as 400 `invalid_request`, not 500. CodeRabbit added this mapping in #54.

`action` is one of `schema_read`, `query_read`, `query_write`, `history_read`. Spec 06 §Actions: `query_write` ⊇ `query_read` ⊇ `schema_read`. `history_read` is orthogonal.

`GET /admin/v1/grants?user_id=…&database_id=…` — list live grants, optional filters. Either filter alone, both, or neither. `database_id` filter matches only `Specific` grants — wildcards have no `database_id` so they're never "for" a single database in this filter's sense.

`GET /admin/v1/grants/:id` — by id.

`PATCH /admin/v1/grants/:id` — partial update of `action` / `constraints`. **The target is the grant's identity and is NOT mutable** — re-target via DELETE + POST. Bodies that carry `database_id` / `server` / `db_name_wildcard` are rejected at parse time.

`DELETE /admin/v1/grants/:id` — revoke. Sets `revoked_at`; the cache invalidates for the affected user post-commit (`tests/admin_grants_e2e.rs::live_grant_change_invalidates_cache_for_user`).

## End-to-end: first user + first grant

The acceptance test for these docs — Sebby (or any deployer) can stand up a fresh install and add a user + grant from this page alone.

```bash
# 0. Sign in once to mint a session token. Browser flow; copy the token from
#    Claude Code's keychain or your IdP's debug page.
export TOK=eyJhbGc…

# 1. Register the user (idempotent by SSO sub).
curl -sX POST https://gw/admin/v1/users \
  -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"user_sub":"8f2b…|alice","user_email":"alice@example.com","groups":["engineers"]}' \
  | jq .id
# → "uuid-of-the-user"
USER_ID=…

# 2. Register the target database (logical row only — no DSN).
curl -sX POST https://gw/admin/v1/databases \
  -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"server":"prod","db_name":"billing","db_type":"postgres"}' \
  | jq .id
DB_ID=…

# 3. Grant query_read with a 1k row cap.
curl -sX POST https://gw/admin/v1/grants \
  -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{
        "user_id":"'"$USER_ID"'",
        "database_id":"'"$DB_ID"'",
        "action":"query_read",
        "constraints":{"row_limit":1000}
      }'
# → 201 + grant row. The cache invalidates for $USER_ID before this returns.
```

Alice can now `list_servers` from Claude Code and see `prod/billing`.

## Storage backend

Default is pg — the permissions tables live in the same state DB as `audit_calls` and `sessions`. To split them off:

```yaml
permissions_store:
  driver: pg     # default; same DB as state DB
  # OR
  driver: mysql  # opens a separate pool via PERMISSIONS_DB_DSN env at startup
```

DSN is **not** in YAML — read from the `PERMISSIONS_DB_DSN` env var at boot. Same pattern as `STATE_DB_URL`. Keeping connection strings out of YAML keeps them out of the committed config and out of boot-trace logs.

> **Mysql + admin is rejected at boot.** The admin handlers use pg's `RETURNING` + `JSONB` via `sqlx::Transaction<'_, Postgres>` and haven't been ported. A `permissions_store.driver: mysql` + `admin.enabled: true` combo aborts startup with a message pointing at the deferred follow-up. Use `driver: pg` to enable the admin API, or run mysql with YAML grants only.

## Operator queries

The spec calls out these as the queries operators want to run; both work today:

```sql
-- "Show me the timeline of all permission changes"
SELECT ts, actor_email, action, target_type, target_id
  FROM permissions_audit
 ORDER BY ts DESC, id DESC LIMIT 100;

-- "What permissions does this user have right now?"
SELECT g.action,
       d.server, d.db_name,
       g.server AS wildcard_server,
       g.constraints
  FROM permissions_grants g
  LEFT JOIN permissions_databases d ON d.id = g.database_id
 WHERE g.user_id = $1 AND g.revoked_at IS NULL;
```
