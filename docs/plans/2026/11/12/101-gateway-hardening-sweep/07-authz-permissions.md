# 07 — Authz and permissions store

> Part of [`overview.md`](overview.md). Depends on: 02, 03 (`0013`, mysql `0004`/`0005`). **`(security review required)`** — `src/authz/`, admin write path + `permissions_audit`. Reviewers look for: constraint loosening, bypass of the YAML-only service contract, audit `before` drift.

## Files to change

- `src/transport/admin/grants/mod.rs:183`, `grants/validation.rs:68`, `grants/sql.rs:69`, `grants/dto.rs:53` — PATCH replaces the whole constraints object.
- `src/transport/admin/users/handlers.rs:24-97` — `create` accepts `service:` subjects; upsert path never invalidates the cache.
- `src/authz/cache.rs:83-127,171` — per-process, no single-flight, global revision, unbounded retry, no expiry sweep.
- `src/authz/loader.rs:39-51,65` — three sequential queries incl. full `permissions_databases` read; wildcard ignores registration.
- `src/transport/admin/grants/validation.rs:39-47` — wildcard server unvalidated (`"*"` accepted).
- `grants/sql.rs:15,44`, `users/tx.rs:23,88`, `databases/sql.rs:33` — unlocked read-before-write; no soft-delete liveness check; no cascade.
- `src/state/permissions/mod.rs:27` (`DbType`), `databases/validation.rs` `parse_db_type`.
- `src/state/permissions/pg.rs:366-420` vs `grants/sql.rs:115`, `users/tx.rs:102`, `databases/sql.rs:87` — three copies of the row mappers; repo write methods have no production caller.
- `src/transport/admin/middleware.rs:207` `tx_upsert_actor`.
- `src/config/yaml.rs:418` — group name stored untrimmed.
- `src/tools/get_query_history.rs:283-293` — merged constraints discarded.

## Steps

1. **PATCH merges.** `UpdateGrantRequest.constraints` becomes a patch DTO (`Option<Option<_>>` per key: absent = keep, `null` = clear, value = set). Apply with a per-key merge, not `COALESCE` on the whole object.
2. **Service identities are YAML-only.** Introduce `enum IdentityKind { Sso, Service }` on `Identity` (replaces the `service:` string prefix test); `load_or_empty` skips the DB for `Service`; `users::create` rejects the `service:` prefix with 400.
3. **Wildcard.** Reject `"*"` and unknown servers in `parse_grant_target` (thread the server list into `GrantsState`). Decide spec 12:201 — recommended: wildcard = every database in config for that server (current behaviour); fix the spec and the comment at `databases/mod.rs:137`.
4. **Locked writes.** `SELECT … FOR UPDATE` in the three `tx_get_*` helpers; optional `expected_updated_at` precondition → 409. `tx_upsert_actor` runs first in the transaction to give a fixed lock order.
5. **Delete semantics.** User/database soft-delete revokes dependent grants in the same transaction with one `permissions_audit` row each; `tx_create_grant` uses `INSERT … SELECT … WHERE deleted_at IS NULL` → 400 otherwise.
6. **One-query loader.** New repo method: grants ⋈ users ⟕ databases `WHERE user_sub = $1` — one round trip, no full scan. Per-key revision (not global), bounded retry, single-flight per subject, expired-entry sweep on insert.
7. **Cross-replica invalidation.** Postgres store: `LISTEN/NOTIFY` on admin commit → `invalidate`. MySQL store: clamp TTL and document the bound. Clamp `PERMISSIONS_CACHE_TTL_SECONDS` ≤ 300 (`src/config/mod.rs:235-243`). Add the missing `spawn_invalidate` after the upsert in `users::create`.
8. **One SQL home.** Move admin SQL + row mappers out of `src/transport/admin/*/sql.rs` into `src/state/permissions/` as transactional methods taking `&mut Transaction` (audited by construction); delete the unaudited write methods from the `PermissionsRepo` trait, or gate them `#[cfg(test)]`.
9. **`db_type`.** Add `mongo` (0013/0005) and make `DbType` describe target kind only.
10. **MySQL store.** Document as read-only-provisioned (no audited write path — boot already rejects mysql + admin, `src/config/yaml.rs:348-360`); drop the unwritten MySQL `permissions_audit` table or leave it with a comment — pick one.
11. Small: trim `permission.group` on load; `history_read` honours `require_reason` (or spec 03 says it does not); add the `actor_id` FK or fix the comment (`migrations/0005:21`).
12. Spec: `12-dynamic-permissions.md` (PATCH, wildcard, cascade, line 187 invalidation, replica bound, MySQL, `db_type`), `14-service-tokens.md:81-85`, `06-permissions.md`.

## Tests

- `tests/admin_grants_e2e.rs`: PATCH only `row_limit` keeps `require_reason`; `"*"` server → 400; grant on soft-deleted user → 400; concurrent PATCHes give a continuous audit chain (`after[n] == before[n+1]`).
- `tests/admin_users_e2e.rs`: POST on an existing user invalidates cached authz; delete cascades with audit rows.
- `tests/service_tokens_e2e.rs`: seeded DB grant for `service:<name>` → `forbidden` + audit row `outcome: forbidden`.
- `tests/permissions_resolver_real_db.rs`: query count on miss is 1; two caches on one repo converge after a revoke.
- Proptests (`src/authz/*_proptests.rs`): PATCH/JSON round-trip, grant-order independence, zero rejection, `HistoryRead` disjointness, loader drops soft-deleted databases.
- `bin/test`, `bin/lint`.

## Done when

- No admin call can loosen a constraint it did not name.
- A service token's effective grants are exactly its YAML group.
- A revoke is honoured on every replica within the documented bound.
