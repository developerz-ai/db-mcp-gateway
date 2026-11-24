# 02 — Security patch (2.3.1)

> Part of [`overview.md`](overview.md). Depends on: 01. Label: `security review required`.
> Done: #377 (fix + four review rounds), #380, `v2.3.1`, advisory GHSA-j6xv-c57r-59rw. Reviewers: guard/DB divergence, credential or row data in errors, missing audit rows, timeout/row-cap bypass.

## Files to change

| ID | Sev | Where | Change |
|---|---|---|---|
| SEC-1 **V** | high | `src/exec/sql_guard/lexical.rs:14`, `sql_guard/mod.rs:142`, `src/exec/pg/mod.rs:238` | Extend `check_lexical`: refuse every token shape the two lexers read differently. `reset_on_release` also resets role and session authorization |
| SEC-2 **V** | high | `src/exec/sql_guard/visitor.rs:146` | `pre_visit_expr`: run `check_denied_name` on every name-bearing node that Postgres can resolve to a call, not only `Expr::Function` |
| SEC-3 **V** | high | `src/exec/pg/decode/mod.rs:144` | Decode date/time from raw integers with checked arithmetic; out-of-range and special values render as text. Add a catch-panic layer in `src/transport/mod.rs` → 500 + `internal` + completed audit row |
| SEC-4 **V** | high | `src/exec/pg/run.rs:184`, `src/exec/budget.rs:54` | Charge raw wire length (`try_get_raw().as_bytes()`) before decode; charge `size_of::<Value>()` per node; document memory limit; bound concurrent in-flight decode per adapter |
| SEC-5 **V** | med | `src/exec/pg/run.rs:208` | No persistent statement for the zero-row describe. Fold with 03-E1 |
| SEC-6 | med | `visitor.rs:155` | Deny relations/functions exposing other sessions (H9) |
| SEC-7 | med | `visitor.rs:34` | Add missing families |
| SEC-8 | med | `src/exec/pg/introspect.rs:88`, `pg/error.rs:16` | Acquire via `AcquireFailure`; SQLSTATE class 28 never becomes `Rejected`; mark adapter stale |
| SEC-9 **V** | high | `src/auth/oauth/client_registry.rs:174-203`, `src/transport/oauth/authorize.rs:117`, `src/state/oauth/clients.rs:78` | `lookup` read-only; promote only after a verified IdP login; adopted rows start on the unused TTL. Spec 04 already says this; flip test `first_authorize_promotes_the_client_to_the_long_ttl` |
| SEC-10 **P** | high | `src/auth/oauth/grants.rs:82,153`, `src/transport/admin/users/revoke.rs:52` | Per-subject `pg_advisory_xact_lock` in mint, rotate, both revoke paths. Reproducing concurrent test first |
| SEC-11 **P** | med | `src/transport/{mod.rs:101,limit.rs:42,bounds.rs:21}` | OAuth router: buffer body ≤16 KiB with a short deadline before taking the permit |
| SEC-12 **V** | med | `src/exec/pool_sizing.rs:20`, adapter acquire | Per-identity semaphore per adapter, `max(1, pool_max - 1)`, before acquire |
| SEC-13 | low | `client_registry.rs:196`, `clients.rs:56` | `lookup -> Result<Option<_>>`; adopt uses `DO NOTHING` on a live row |
| SEC-14 | low | `src/exec/pg/error.rs:29`, `src/exec/redis/error.rs:29` | Audit/sinks keep SQLSTATE + redacted text; redirect-type Redis errors → `Unavailable` |
| SEC-15 **V** | med | `src/config/reload.rs:63`, `src/exec/registry.rs:93` | Slot stores config fingerprint; mismatch = miss |

## Steps
1. Owner drafts the advisory (H1). Coordinator keeps branch names and PR text neutral ("exec: guard hardening").
2. Failing real-DB test per row, then fix. SEC-1: differential test — corpus run through the guard **and** Postgres, asserting the function set Postgres executes equals the set the guard saw.
3. Extend `sql_guard` proptest: an accepted statement re-parses to one read-shaped statement; token-mutation fuzz over comments, strings, operators.
4. Yugabyte suite: every new refusal and the reset statement (`bin/test-yugabyte`).
5. `chore(release)` 2.3.1 alone; tag; release notes generic until the owner publishes the advisory.
6. After release (H2): `pg_query` second parser in its own PR; agreement required on statement count, kinds, function names.

## Tests
- `tests/it_db/sql_guard_*.rs`, `exec_run_query.rs`, `oauth_lifecycle_real_db.rs`, `admin_users_e2e.rs`, `adapter_registry_concurrency.rs`, `config_reload.rs`. Every refusal asserts an audit row (`forbidden_sql`).

## Done when
- All rows closed, each with a test red on `ad833b7`; spec 03 §guard and 04 updated; 2.3.1 images on both registries.


## Outcome
- Every row closed with a test; most fail on `ad833b7`. Review rounds added: position-based error naming (no server text), per-generation registry retirement, registry advisory lock, unconfirmed-mint handling, `DISCARD SEQUENCES/TEMP`, extension denylists.
- Not done: H2 (`pg_query` second parser) — next plan candidate.
