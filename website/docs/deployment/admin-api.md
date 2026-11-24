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
| Grant `expires_at` (expired grants listed `expired: true`, ignored by evaluation) | works |
| Batch apply — many grant upserts/deletes, one audited transaction | works |
| `explain` — why a call is allowed or denied | works |
| Effective-permissions export + diff (YAML ∪ DB) | works |
| `audit/calls` NDJSON stream | works |
| OpenAPI 3.1 document at `GET /admin/v1/openapi.json` | works |
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

Every admin request needs:

1. **A gateway session token** in `Authorization: Bearer …`. This is a JWT the *gateway* signs, not a token from your IdP: an IdP access or ID token is rejected with `401`. Two ways to get one:
   - `POST /auth/login` returns `{ "login_url", "state" }`. Open `login_url` in a browser and sign in; the IdP redirects to `/auth/callback`, which answers `{ "session_token": "eyJ…", "expires_in_seconds": 28800 }`. Copy `session_token`.
   - The access token an MCP client obtained through the gateway's OAuth bridge (`/authorize` → `/token`) is the same kind of session JWT, so it works too.

   Service tokens (`dbmcp_svc_…`) never reach the admin API: boot refuses a service account mapped to the admin group.
2. **Membership in `admin.group`** in the session's groups. `403 forbidden` without it. Groups are a snapshot taken from the ID token **at login** and stored with the session; they are not re-read from the IdP. Adding someone to the admin group takes effect at their next login; removing them takes effect when their session ends or is revoked ([revoke-sessions](#revoke-a-users-sessions)).
3. **A fresh enough session**, when `admin.session_max_age_secs` is set. A session issued longer ago than that (or with an `issued_at` in the future) gets `403 session_too_old`; sign in again. This bounds how long a removed admin keeps admin access.

On a successful **mutating** call the gateway locks the caller's `permissions_users` row inside the same transaction — inserting it from the session's `sub`, email and groups only if absent — and stamps the write with their `user_id` + `user_email` in `permissions_audit`. An existing row is never rewritten by the caller's own admin calls: its email and groups change only through an audited users write, so its `before`/`after` chain stays continuous and its `updated_at` never moves under another admin's `expected_updated_at`. A read changes no grant and writes no `permissions_audit` row, but it is not write-free: `explain`, `permissions/export`, `permissions/diff` and `audit/calls` each commit one `audit_calls` row before answering ([audit guarantees](#audit-guarantees)). The other `GET`s write nothing.

Every admin response, success or error, carries `Cache-Control: no-store`: the bodies name subjects, emails and grant sets.

## Errors

Every error body has one shape, and carries the gateway-minted request id. Correlate an error by that id in the gateway's logs: a failed write rolls back with its audit row, so a `permissions_audit.request_id` match exists only for a mutation that committed (and an audited read's `audit_calls` row for the read endpoints).

```json
{ "error": { "code": "conflict", "message": "row changed since expected_updated_at; re-read and retry", "request_id": "…" } }
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `invalid_request` | Malformed body, path id or query string; validation failure; FK/CHECK violation |
| 401 | `unauthorized` | No or invalid gateway session token |
| 403 | `forbidden` | Caller not in `admin.group` |
| 403 | `session_too_old` | Session older than `admin.session_max_age_secs` |
| 404 | `not_found` | Missing or soft-deleted row. (With the admin API off, every `/admin/*` path is a plain `404` with no body.) |
| 409 | `conflict` | `expected_updated_at` mismatch, or the database aborted the write to break a deadlock / serialization conflict. Re-read and retry |
| 413 | `payload_too_large` | Body past the route's byte bound: 1 MiB for `grants/batch`, 16 MiB for `permissions/diff`, 64 KiB for every other route |
| 503 | `audit_unavailable` | An audited read (`explain`, `permissions/export`, `permissions/diff`, `audit/calls`) could not write its `audit_calls` row; nothing was returned. Retry once the state DB recovers |
| 500 | `internal` | Anything else, including a failed audit write; the body never carries the cause |

## Pagination

`GET` on `/users`, `/databases` and `/grants` takes `?limit=&offset=`. `limit` defaults to `100` and is clamped to `1..=1000`; `offset` defaults to `0`. The body is a bare JSON array — no total, no cursor. Advance `offset` by the number of rows received, and stop when a page comes back shorter than the **clamped** limit (`min(limit, 1000)`): a `limit=2000` request returns at most 1000 rows, and a full 1000-row page is not the end. Order is stable: users and grants by `(created_at, id)`, databases by `(server, db_name)`.

## Optimistic concurrency

Every `PATCH` body accepts an optional `expected_updated_at` — the `updated_at` you read (RFC 3339). If the row changed since, the write is refused with `409 conflict` and nothing is written. Omit it for last-writer-wins.

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

Reads that disclose grants or audit history — `explain`, `permissions/export`, `permissions/diff`, `audit/calls` — write one `audit_calls` row each (`tool` = `admin.explain`, `admin.permissions_export`, `admin.permissions_diff`, `admin.audit_calls`; the admin as `user_sub`) **before** the response goes out. An `admin.audit_calls` row's `params` holds what was asked — `user`, `server`, `db`, `tool`, `outcome`, `since`, `until`, `limit` and `include_sql` — so a read that disclosed statements and bound values is told apart from a metadata-only one. If it cannot be written the read fails with `503 audit_unavailable`. A request refused as invalid reads nothing and writes no row.

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

All paths are under `/admin/v1`. Request and response bodies are JSON (except the NDJSON audit stream). `Content-Type: application/json` is required on POST/PATCH. The machine-readable contract is `GET /admin/v1/openapi.json` (OpenAPI 3.1, admin-gated like every other route); a test holds it equal to the mounted routes.

### Users

`POST /admin/v1/users` — upsert by `user_sub` (the SSO subject claim).

```json
{
  "user_sub": "8f2b…|alice",
  "user_email": "alice@example.com",
  "groups": ["engineers"]
}
```

Response: the user row (`id`, `user_sub`, `user_email`, `groups`, `created_at`, `updated_at`) — `201` when created, `200` when an existing live row was updated. Upsert is idempotent on the *live* row — soft-deleted rows stay until the retention pruner hard-deletes them `AUDIT_RETENTION_DAYS` after deletion.

`GET /admin/v1/users` — list live users, oldest first.

`GET /admin/v1/users/:id` — one user by id. 404 if missing or soft-deleted.

`PATCH /admin/v1/users/:id` — partial update. Fields not in the body stay unchanged.

```json
{ "user_email": "alice.new@example.com", "groups": ["engineers", "oncall"], "expected_updated_at": "2026-11-23T10:15:02.123456Z" }
```

At least one of `user_email` / `groups` must be set.

Bounds on `POST` and `PATCH` (trimmed; violations are `400 invalid_request`): `user_sub` at most 255 bytes (the OIDC `sub` limit), `user_email` at most 254 bytes, `groups` at most 256 entries of at most 255 bytes each. A `user_sub` starting with `service:` — in any letter case — is refused: that namespace belongs to YAML service accounts.

`POST /admin/v1/users/:id/revoke-sessions` — see [below](#revoke-a-users-sessions).

`DELETE /admin/v1/users/:id` — soft delete, `204`. Sets `deleted_at` and revokes the user's grants; subsequent live lookups return 404. The row is hard-deleted `AUDIT_RETENTION_DAYS` (default 90) after `deleted_at`; `permissions_audit` keeps the change on the same horizon.

### Databases

`POST /admin/v1/databases` — register a logical target the resolver can attach grants to.

```json
{ "server": "prod", "db_name": "billing", "db_type": "postgres" }
```

`server` must name a server declared in the gateway config (the boot snapshot; a reload does not change the set), the same rule a wildcard grant obeys — a row on an undeclared server would sit dormant until a later config change silently armed it. For the same reason `db_name` must name a database the **live** config declares on that server: a reload that adds a database makes it registrable at once, and one that drops it refuses new registrations of it. `db_type` names the target engine: `postgres`, `mysql` or `mongo` (spec 12 §"Storage backends"; migrations `0013` / `migrations-mysql/0005`). Don't confuse it with the permissions *store* backend, which is postgres or mysql only — a mongo target is registered here like any other. Either violation is `400 invalid_request`, and a refused create or `PATCH` writes no row and no `permissions_audit` entry.

This row carries only the routing key — **no DSN, no role, no password**. CLAUDE.md non-negotiable #1: connection details stay in YAML / secret backends, never in the admin API.

DSN field names (`connection_string`, `dsn`, `password`, `role`) are rejected with HTTP 400 at parse time via `#[serde(deny_unknown_fields)]`. Pinned by `tests/it_db/admin_databases_e2e.rs`.

`GET /admin/v1/databases` — list live databases.

`GET /admin/v1/databases/:id` — by id. 404 if missing.

`PATCH /admin/v1/databases/:id` — partial update. Same DSN-rejection and declared-server rules, and the resulting `(server, db_name)` pair must be declared in the live config.

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

Foreign-key violations (`user_id` or `database_id` not in the tables) and CHECK violations from the storage layer surface as 400 `invalid_request`, not 500.

`action` is one of `schema_read`, `query_read`, `query_write`, `history_read`. Spec 06 §Actions: `query_write` ⊇ `query_read` ⊇ `schema_read`. `history_read` is orthogonal.

`GET /admin/v1/grants?user_id=…&database_id=…` — list live grants, optional filters. Either filter alone, both, or neither. `database_id` filter matches only `Specific` grants — wildcards have no `database_id` so they're never "for" a single database in this filter's sense.

`GET /admin/v1/grants/:id` — by id.

`PATCH /admin/v1/grants/:id` — partial update of `action` / `constraints` / `expires_at`. **The target is the grant's identity and is NOT mutable** — re-target via DELETE + POST. Bodies that carry `database_id` / `server` / `db_name_wildcard` are rejected at parse time.

**Expiry.** `POST` (and `PATCH`) take an optional `"expires_at": "2026-12-31T00:00:00Z"`, which must be in the future; `PATCH` with `"expires_at": null` removes it. From that instant on the grant no longer authorizes anything, but it stays a live row: `GET` responses keep showing it with `"expired": true` (and `expires_at`) until you `DELETE` it. YAML grants never expire.

`DELETE /admin/v1/grants/:id` — revoke. Sets `revoked_at`; the cache invalidates for the affected user post-commit (`tests/it_db/admin_grants_e2e.rs::live_grant_change_invalidates_cache_for_user`).

`POST /admin/v1/grants/batch` — apply up to 500 changes in **one** transaction, all or nothing. The body may be up to 1 MiB (500 maximal changes take about 310 KiB pretty-printed); past that it is `413 payload_too_large`:

```json
{ "changes": [
  { "op": "upsert", "user_id": "…", "server": "prod", "db_name_wildcard": true,
    "action": "query_read", "constraints": { "row_limit": 500 }, "expires_at": "2026-12-31T00:00:00Z" },
  { "op": "delete", "id": "uuid-of-a-grant" }
] }
```

An `upsert` carries the `POST /admin/v1/grants` fields and is keyed by `(user_id, target, action)`: an existing live grant with that key gets the given `constraints` and `expires_at` (replaced, not merged), otherwise a grant is created. Response: `{"results": [{"index", "op": "created" | "updated" | "unchanged" | "deleted", "id", "grant"?}]}`. Each applied change writes its own `permissions_audit` row; an `unchanged` upsert writes nothing. Any failing change (message prefixed `changes[<i>]: `) rolls back the whole batch, audit rows included.

### Explain

`POST /admin/v1/explain` — why a call would be allowed or denied, from the same evaluation every tool call runs:

```json
{ "user": "okta|00u123", "server": "prod", "database": "app", "action": "query_read" }
```

Exactly one of `user` (SSO subject) or `group`. With `user`, `groups` (optional) overrides the group claims assumed; by default the groups cached on the user's `permissions_users` row are used. Response: `decision` (`allow` / `deny`), merged `constraints` (or `null`), `matched` (each grant with `source: yaml` + its `subject`, or `source: db` + `grant_id`), `expired` (DB grants that would match but for their expiry), `groups`, `groups_source`, and `target_declared` (whether the config declares that database at all). Explain never reads a live session, so for a `user` it is a simulation: `groups_source` is `stored` (the last-login snapshot on `permissions_users`), `none` (the user has no `permissions_users` row: no snapshot, so no groups) or `assumed` (the `groups` you sent), and a session whose current IdP claims differ can be decided differently; `group` for a group question.

### Export and diff

`GET /admin/v1/permissions/export` — every grant evaluation can use, YAML ∪ DB, as `{"generated_at", "grants": [{source, subject, server, database, action, constraints, except?, profile?, expires_at?, expired?, grant_id?}]}`. DB grants appear with `subject: {"user": "<sub>"}`. The read writes its `audit_calls` row (`admin.permissions_export`) before answering.

`POST /admin/v1/permissions/diff` — post a desired document in the same shape (an edited export works; export-only keys are ignored) and get `{add, remove, change, unchanged}` against the effective permissions, keyed by `(subject, server, database, action)`. Read-only: no grant changes — its one write is its own `audit_calls` row (`admin.permissions_diff`), committed before the answer. Export and diff share one size contract: diff takes a body of up to 16 MiB, whatever its grant count, so an export — unedited or edited — posts back while it fits 16 MiB. A store whose export passes 16 MiB has no scoped comparison yet.

### Audit calls

`GET /admin/v1/audit/calls?user=&server=&db=&tool=&outcome=&since=&until=&limit=&include_sql=` — `audit_calls` rows as NDJSON (`Content-Type: application/x-ndjson`), newest first. `user` matches `user_sub` or `user_email`; `since` is inclusive, `until` exclusive (RFC 3339); `outcome` must be a spec 03 code; `limit` defaults to 1000 and is clamped to 1–10 000. The statement text and its bound parameters (`sql`, `sql_truncated`, `params`) are included only with `include_sql=true`. The read writes its own `audit_calls` row (`admin.audit_calls`, the filters in `params`) before the first line. If the stream breaks after it started, the last line is `{"error": {"code": "internal", …}}`. Rows are read in batches of up to 200 rows or 1 MiB of encoded lines, with no state-DB connection held while the client reads, so a stalled reader pins nothing and holds a few MiB at most.

```bash
curl -sN -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$GATEWAY/admin/v1/audit/calls?user=alice@example.com&outcome=forbidden&limit=50"
```

## End-to-end: first user + first grant

The acceptance test for these docs — any deployer can stand up a fresh install and add a user + grant from this page alone.

```bash
# 0. Mint a gateway session token (not an IdP token). Open login_url in a
#    browser, sign in as a member of admin.group, copy session_token from the
#    JSON /auth/callback shows.
curl -sX POST https://gw/auth/login | jq -r .login_url
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

## Revoke a user's sessions

`POST /admin/v1/users/:id/revoke-sessions` (no body) — the operator kill switch for one subject. In one audited transaction it revokes every live session of that user's `user_sub` (`sessions.revoked_at`) and deletes every refresh chain, so no client can refresh back in.

```json
{ "revoked_sessions": 2, "revoked_refresh_tokens": 3 }
```

The `permissions_audit` row is an `update` of the user, with `before`/`after` carrying `live_sessions` and `refresh_tokens`. Grants are untouched — the user can sign in again, and that new session gets whatever their groups and grants allow then. Deleting the user's permissions-store row does not keep them out on its own: a YAML `permissions:` grant naming their `user:` or one of their groups still matches their next session. To keep them out, revoke their sessions **and** remove every grant that applies to them — store grants, YAML grants (by PR) and their IdP group memberships — or disable their sign-in at the IdP. The replica that served the call stops honouring the sessions at once; other replicas within `SESSION_CACHE_TTL_SECONDS` (default 30 s).

## Storage backend

Default is pg — the permissions tables live in the same state DB as `audit_calls` and `sessions`. To split them off:

Pick exactly one `driver`:

```yaml
permissions_store:
  driver: pg     # default; same DB as state DB
```

```yaml
permissions_store:
  driver: mysql  # opens a separate pool via PERMISSIONS_DB_DSN env at startup
```

```yaml
permissions_store:
  driver: none   # YAML-only: no permissions store at all
```

DSN is **not** in YAML — read from the `PERMISSIONS_DB_DSN` env var at boot. Same pattern as `STATE_DB_URL`. Keeping connection strings out of YAML keeps them out of the committed config and out of boot-trace logs.

`driver: none` runs YAML-only: grants come from `permissions:` alone and no store is ever read. It also refuses `admin.enabled: true` at boot — the admin API edits a store that install does not have.

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
