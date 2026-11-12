# 13 — Test suite: gaps, flakiness, gates

> Part of [`overview.md`](overview.md). Depends on: 02 step 1 (shared harness). Runs alongside 04–12; each of those slices lists its own tests — this slice covers what belongs to none of them.

## Files to change

- `tests/describe_schema_real_db.rs:85,143`, `tests/sample_table_real_db.rs`, `tests/explain_real_db.rs` — re-type the tool's SQL instead of calling the tool; cannot catch drift.
- `tests/auth_e2e.rs:188,221,248`, `tests/oauth_bridge_e2e.rs:193,252,832`, `tests/transport.rs:14-15` — `tools/call` with no audit-row assertion.
- `tests/json_logging.rs:43-70,126+`, `tests/metrics_endpoint.rs:30` — tautological (emit the line / bump the counter themselves).
- `tests/cancellation_real_db.rs:91,124,154,178,269,291,344,418`, `tests/audit_dispatch_cancellation_real_db.rs:362,424`, `tests/adapter_registry_concurrency.rs:124`, `tests/tls_reload.rs:106,145,166`, `tests/run_query_e2e.rs:917,960,1000`, `tests/session_cache_real_db.rs:159` — fixed sleeps as synchronisation.
- `tests/run_query_e2e.rs:905-1019` — `rate_limited`/`service_overloaded` tested on a synthetic router, not the real `/mcp` route.
- `src/exec/sql_guard.rs:1004-1040`, `src/exec/mongo/rejector.rs` — proptests draw from fixed lists; rejector has none.
- `src/authz/mod.rs:395-434`, `effective_proptests.rs:152-244` — missing properties.

## Steps

1. **Tools tested through the tool.** `list_databases` gets its first behavioural test; `describe_schema`, `sample_table`, `explain` real-DB tests call the tool entry point and assert the audit row, success and `forbidden`.
2. **Audit assertion everywhere.** Every `tools/call` in `tests/` asserts a row via `common::audit::assert_audit_outcome`. Add a guard test that greps `tests/` for `tools/call` without it (cheap, catches regressions of CLAUDE.md §Testing).
3. **Error-code golden.** New `tests/error_codes_e2e.rs`, table-driven from the code list in `website/docs/initial-idea/03-mcp-tools.md`: for each code assert the JSON-RPC body shape and the audit `outcome`. Currently unasserted end to end: `syntax_error`, `unavailable`, `invalid_arguments` (sample_table identifiers), `reason_required` (`run_query`, `explain`), `forbidden_sql` via Mongo, `internal`/`permissions_cache_load_failed`, audit-write failure, `rate_limited`/`service_overloaded` on the real route. Reconcile spec 03:81 (error shape) and the never-emitted `row_limit_exceeded` (spec 03:91) — fix code or spec.
4. **De-flake.** Replace fixed sleeps with poll-until-deadline (pattern at `tests/audit_dispatch_cancellation_real_db.rs:62,93`); per-test marker comments instead of distinct `pg_sleep(31/32/33)` literals (pattern at `tests/exec_run_query.rs:269`); drop the redundant static mutex in `tests/client_registry_real_db.rs:25,50-52`.
5. **Real behaviour, not echoes.** `json_logging` and `metrics_endpoint` drive a real dispatch and capture output.
6. **Properties.** Add: `merge(a,a) == a`; grant-order permutation invariance through `evaluate_effective`; adding a group never turns Allow into Deny; `effective_row_limit`/`effective_timeout_ms` ≤ `min(grant, ceiling)` for any caller input; a `query_write` grant cannot dodge a tighter `query_read` cap (`src/tools/run_query.rs:139-142`); `query_read` never satisfies `QueryWrite`.
7. **Generative guard tests.** Grammar-based SQL generator (comments, casing, nesting, CTE-wrapped writes, dollar-quoting, string-embedded SQL) asserting *accepted ⇒ single read statement* (or single DML under `ReadWrite`). Arbitrary-BSON generator for the rejector asserting *accepted ⇒ no denied operator at any depth*. Optional `cargo-fuzz` targets under `fuzz/`, run on a schedule, not per PR.
8. **Multi-replica.** New `tests/two_replicas_real_db.rs`: two gateway instances on one state DB — permissions revoke propagation (07), refresh-rotation race (one winner), pruner double-run (10), session revoke (08). `PendingFlows`/`AuthCodes` are in-process (`src/main.rs:214-215`), so `/authorize` on A + `/token` on B fails: either move them to the state DB or document "sticky sessions or one replica for login" in `09-deployment.md`. Both clusters run one replica today — document now, move later.
9. **Isolation regression.** Extend `tests/adapter_registry_concurrency.rs`: N parallel `run_query` on DB A while DB B hangs; assert A's p99 stays under a bound (CLAUDE.md "a slow query on DB A must never block DB B").
10. **Load gate.** Wire `benchmarks/harness` into a scheduled workflow (not per PR) that fails on a regression against a stored baseline — numbers from 01 and 06.
11. **Thin layers.** Direct tests for `update_user`/`update_grant` in both permission stores; `src/exec/pg/{decode,truncate}.rs` unit tests.

## Tests

- This slice is tests. Run `bin/test` three times in a row locally and in CI once the de-flake lands; zero failures.
- `bin/lint`.

## Done when

- Every stable client code in spec 03 has an end-to-end assertion on body and audit row.
- No `sleep` used as synchronisation in `tests/`.
- The guard proptests generate inputs, not replay a list.
