# 06 — Authorization (grant evaluation & constraint merge)

Scope: `src/authz/{mod,effective,cache,loader}.rs` + proptests, with supporting types in `config/schema.rs` and boot validation in `config/yaml.rs`.

**No Critical, High, or Medium authorization vulnerability found.** The engine is fail-closed, the constraint merge is provably most-restrictive, wildcards match exactly (no over-matching), write actions are correctly gated, and the cache invalidation race is handled. Findings below are Low/informational and none are exploitable in the current call graph.

---

## AZ1 — Empty-string `group` name accepted at boot — **Low**

**File:** `src/config/yaml.rs:269-276` (and `schema.rs:88-97` accepts any `String` for `Grant.server/database/group`).

Grant `server`/`database` strings are protected: boot validation rejects YAML grants on unknown (non-`*`) servers/databases (`yaml.rs:277-292`), and `find_server_db` requires the target to exist in config — so `server: ""` fails to load and `grant_applies` never sees an attacker-controlled target. The only un-guarded field is `permission.group`: an empty group name is accepted (`yaml.rs:269-276` only checks duplicates). This is not an escalation — it merely grants that block to identities carrying an empty group claim — but it is sloppy.

**Fix (cheap hardening):** reject empty/whitespace `group` (and, defensively, `server`/`database`) at boot.

---

## Low / informational (by design, no code change)

- **Cache staleness window equals TTL for out-of-band DB writes.** `cache.rs:74-107`. Revocation is immediate only when the admin API calls `invalidate`/`invalidate_all`. A grant revoked by a *direct* DB mutation (batch tool, manual SQL) is served from cache up to the TTL. Documented as intended safety-net behavior (`cache.rs:8-11`). Already-returned `Arc<Vec<Grant>>` snapshots also mean an in-flight request uses pre-revoke grants. Operators should know: bypass the admin API ⇒ up to TTL of stale authz.
- **`grant_applies` does not re-check database existence** (`mod.rs:85-89`), unlike `grant_can_see` (`mod.rs:75-81`). Safe because every tool pre-resolves the target through `find_server_db` (`run_query.rs:200-208`), which returns config-canonical names — `evaluate` never sees raw client input. Keep this invariant ("callers must resolve targets against config first") in mind for any future tool calling `evaluate` directly.

---

## Needs verification (out of this scope)

- **Admin-API path for DB grants** (`GrantTarget::Wildcard { server }`, `loader.rs:65`): the loader trusts that the admin API validated `server` and that `invalidate`/`invalidate_all` is called after *every* write affecting effective grants — including `permissions_databases` mutations that change wildcard meaning (`cache.rs:119-127`). Those guarantees live in the admin endpoints and `src/state/permissions/*`. Confirm each mutation calls the matching invalidation (cross-ref [05](05-admin-api.md)).

---

## Controls verified correct (no action)

- **Write gating is sound.** `Action::includes` (`schema.rs:129-138`) only lets a `QueryWrite` grant satisfy a `QueryWrite` request; no read-tier grant (`SchemaRead`/`QueryRead`) can cover a write; `HistoryRead` is isolated. Non-negotiable #3 holds at the authz layer.

  ```rust
  (QueryWrite, _) => matches!(requested, QueryWrite | QueryRead | SchemaRead),
  (QueryRead, QueryRead | SchemaRead) => true,
  (SchemaRead, SchemaRead) => true,
  (HistoryRead, HistoryRead) => true,
  _ => false,
  ```

- **Constraint merge is most-restrictive, always.** `merge`/`min_option` (`mod.rs:97-111`): `require_reason` ORs (true wins), `row_limit`/`statement_timeout_ms` take the min, `Some` always beats `None`. Proven commutative, associative, identity-respecting, monotonically narrowing by proptests (`mod.rs:392-449`, `effective_proptests.rs`). No arithmetic ⇒ no overflow.
- **No default-allow.** `evaluate_effective` (`effective.rs:52-64`) starts `merged_some = false`, flips only on a real match; absence ⇒ `Decision::Deny` (`empty_match_denies`).
- **Wildcards do not over-match.** `grant_applies` (`mod.rs:85-89`) is `grant.server == "*" || grant.server == server` — literal `*` or exact case-sensitive equality. No prefix/substring/path-traversal matching. Wildcard expands the target only, never the action.
- **Group union cannot escalate.** YAML grants are group-filtered (`effective.rs:42-46`); more groups add grants but most-restrictive merge prevents any upgrade. No deny token by design (spec 12), so "deny overrides allow" is correctly N/A.
- **Symmetric YAML⊕DB; DB grants additive only.** Both sources chain into one merge with no priority (`effective.rs:54-57`); DB grants can only add an allow or tighten constraints, never relax.
- **Cache fail-closed + race handled.** Load errors propagate as deny (`run_query.rs:87-95` returns `internal`, never falls through to YAML-only). The revision counter forces a reload retry if invalidation occurs during an in-flight load (`cache.rs:84-95`); write-lock double-check prevents inserting stale data. Cache key is `user_sub` — no cross-user collision. Soft-deleted DB rows drop at load time (`loader.rs:57-64`), so a recreated `(server, db)` doesn't inherit stale grants.
