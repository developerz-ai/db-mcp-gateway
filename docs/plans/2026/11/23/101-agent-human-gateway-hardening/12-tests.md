# 12 — Tests

> Part of [`overview.md`](overview.md). Depends on: 03–06 for the new surfaces.

## Steps
1. `[lints.clippy]` deny `unwrap_used`, `expect_used`, `panic` outside tests (current `src/` is clean); evaluate `indexing_slicing`. Decide `anyhow` in `src/startup/` (rule says `main.rs` only; used in `boot.rs`, `serve.rs`, `metrics.rs`, `logging.rs`).
2. HTTP e2e + audit row for PG `syntax_error`, `undefined_object`, `permission_denied`; `unavailable`, `internal`; `rate_limited` body + `Retry-After`.
3. `admin.session_max_age_secs` from YAML → `session_too_old`; audit-failure rollback for admin databases and grants; `pool.min_connections` / `idle_timeout_s`; Redis `sweep_idle`.
4. `audit_assertion_guard` per test function, not per file.
5. Property/fuzz: Redis rejector/rewriter (COUNT never above cap), Mongo rejector (denied op at any depth), JSON-RPC bytes, YAML (planted secret never echoed), `sentry_scrub`, `redact_role`.
6. Replace fixed sleeps: `run_query_e2e.rs:915,956`, `adapter_registry_concurrency.rs:130,177`, `service_account_concurrency_e2e.rs:98,157`, `redis_timeout_real_db.rs:87,136`, `sql_guard_unicode_escape.rs:56`, `exec_run_query.rs:791` → poll `pg_stat_activity` / semaphore state.
7. Dedup: `common::mcp::call_tool`, one `BufWriter`, one `MockIdp`, one config builder.
8. Weekly advisory coverage job (`cargo llvm-cov nextest`), no threshold.

## Done when
- Every stable code and config key has a behaviour test; nextest flake count 0 over 30 runs at 4 threads (09-C10).
