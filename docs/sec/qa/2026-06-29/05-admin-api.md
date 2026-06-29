# 05 — Admin API (SSO-gated permissions management)

Scope: `src/transport/admin/{mod,middleware,error,users}.rs`, `admin/databases/*`, `admin/grants/*`.

This surface is well-built. **No confirmed High/Critical vulnerability.** All mutations are parameterized, synchronously audited in-transaction, DTOs reject credential-bearing fields, and responses carry no credential columns. Findings are Low / hardening, plus a doc discrepancy.

---

## ADM1 — Read GETs upsert `permissions_users` outside an audit transaction — **Low (authz impact needs verification)**

**File:** `src/transport/admin/middleware.rs:111-113`

```rust
let user = match state
    .repo
    .upsert_user(&identity.user_sub, &identity.user_email, &identity.groups)
    .await
```

Every admin request — **including read-only GETs** — upserts the caller's `permissions_users` row (email + groups) via the pool-backed repo, outside any `permissions_audit` transaction. This mutates a permissions table while escaping the synchronous-audit guarantee (non-negotiables #4/#5).

Impact is bounded: authz group matching uses the **live JWT groups**, not the stored column (`authz/effective.rs:44`). The stored `groups` column is effectively denormalized/informational, so this write cannot grant or escalate authority — hence Low, not a privilege issue.

**Verify:** confirm no code path reads `permissions_users.groups` for an authorization decision (current grep: only `effective.rs` matches groups, and it uses `identity.groups`). If any resolver ever consults the stored column, this rises to a real audit gap.

**Fix:** either (a) document this sync-from-SSO write as an explicit non-audited exception in the spec, or (b) skip the upsert on read-only methods and fold it into the audited tx on writes (the actor row is only needed as an audit FK on mutations).

---

## ADM2 — Stale admin privilege from session-cached groups — **Low (revocation behavior needs verification)**

**File:** `src/transport/admin/middleware.rs:92`

```rust
if !identity.groups.iter().any(|g| g == &state.admin_group) {
```

`identity.groups` comes from the OIDC `groups` claim captured at login and stored in the session row (`auth/oidc.rs:192-202`). Removing a user from the admin group in the IdP does not revoke admin access until the gateway session expires (8h default) or is explicitly revoked. Standard session staleness, but worth an explicit operator note given the privilege level. (Compounds with [A3](02-authentication.md) — cross-replica revocation.)

**Fix / verify:** document that admin de-provisioning requires session revocation (confirm the denylist path covers it), shorten admin session TTL, or re-validate the admin group against a fresh token rather than the cached session for `/admin/*`.

---

## Doc discrepancy — admin/databases does NOT store credentials — Informational

CLAUDE.md states "Gateway adds DB connections (stores credentials) via admin/databases." The implementation does **not** — `permissions_databases` stores only `(server, db_name, db_type)` (`databases/sql.rs:20-31`); host/port/password live in YAML/secrets and pools are keyed by YAML server name (`exec/pg.rs:114-121`, `exec/mod.rs:71-89`). The implementation is the safer design. Update the CLAUDE.md/spec line so reviewers don't assume a credential-storage path exists here (and don't add one).

---

## Benign-but-surprising behavior — noted, no fix

`POST`/`PATCH /admin/v1/users` accept an arbitrary `groups` array (`users.rs:71-85`), so an admin can write `groups: ["<admin-group>"]` onto any user row. Because authz/admin checks use the **live JWT groups**, not the stored column (ADM1), this does **not** escalate privilege — the stored value is cosmetic today. If that ever changes, revisit ADM1 and this note together.

---

## Out-of-scope follow-up (cross-references authz cache)

Confirm every admin mutation that affects a user's effective grants calls the matching cache `invalidate`/`invalidate_all` — including `permissions_databases` mutations that change wildcard-grant meaning. The authz loader trusts this (see [06](06-authorization.md), needs-verification).

---

## Controls verified correct (no action)

- **AuthZ layering is sound and fail-closed.** Every admin route is behind both `bearer_auth` and `require_admin_group`. In `transport/mod.rs:100-104` the admin router is wrapped with `bearer_auth` *outermost* (runs first, injects `Identity`), then `require_admin_group` reads it; no `Identity` ⇒ 401 (`middleware.rs:74-90`). All admin routes attach via `route_layer` on the merged router — none escapes the layer. `admin.enabled=false` unmounts the whole surface (`mod.rs:76-105`). No open registration / first-user / env bypass.
- **No SQL injection.** Every query in `users.rs`, `databases/sql.rs`, `grants/sql.rs` uses sqlx bind params (`$1..$n`); no user input interpolated into SQL. The only `format!`s build error messages, not SQL.
- **No credential storage / no SSRF** (see doc discrepancy above). DTOs `deny_unknown_fields` (`databases/dto.rs:46,55`) reject `dsn`/`connection_string`/`password`/`role` at parse time; `DatabaseResponse` has no credential columns. An admin-created `server` string matching no YAML server simply fails to connect — it cannot point the gateway at `169.254.169.254` or a `file://` DSN.
- **Synchronous audit honored.** Every create/update/delete on users/databases/grants opens a tx, writes the data + the `permissions_audit` row through the *same* tx, commits — audit failure rolls back (`users.rs:99-138`, `databases/mod.rs:82-108`, `grants/mod.rs:90-122`, and patch/delete identically).
- **No credential/PII leak in errors/logs.** `internal()` helpers log only `stage` + `error_type` + `request_id`, never `%err` (`users.rs:436-445`, `databases/validation.rs:52-60`, `grants/validation.rs:108-117`); `AdminError` bodies are hand-written, secret-free (`error.rs:102-112`).
- **CSRF N/A** — bearer-token auth in the `Authorization` header, not cookies.
- **IDOR N/A** — single-tenant by design; admins legitimately act on all entities.
- **Write grants are by design, not a violation.** `parse_action` (`grants/validation.rs:62-70`) accepts `query_write` — the *explicit per-grant opt-in* non-negotiable #3 requires. The gateway still never provisions write privileges on the target-DB role (operator's role config). Keep this distinction in mind during review.
