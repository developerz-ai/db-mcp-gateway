# tests/ — testing rules

Binding for every test, here and in `src/` unit modules, on top of the root [`CLAUDE.md`](../CLAUDE.md). Run them through `bin/test` (queued), never raw `cargo test` against the DB suites.

One binary per group dir: `it_db/` (real DBs, never a mocked target DB), `it_offline/` (no Docker; `bin/test --unit` runs it), `it_global/` (process-global installs). Standalone `*.rs` files are doc and drift guards (`brief_rows.rs`, `doc_drift.rs`, `claude_md_drift.rs`, `deploy_catalogue.rs`). `tests/bin/*.test.sh` test the `bin/` scripts and CI gate.

| Kind | Rule |
|---|---|
| Unit + property | Pure logic (authz evaluation, config validation, SQL rewriting), no real DB. Authz constraint-merge (`proptest`): most restrictive value wins, always. |
| Integration | Gateway booted against real Postgres (CI service container). Real MCP requests over HTTP. |
| Audit | Every integration test that hits a tool asserts an audit row exists. Tool failed authz → audit row with `outcome: forbidden`. Enforced by `it_offline::audit_assertion_guard`. |
| Isolation | Every `tests/it_db/` test declares `#[serial_test::serial(world)]` (table-wide side effect: reaper/pruner/GC sweep, cap seeding, global counts) or `#[serial_test::parallel(world)]` — the suites share one process under `cargo test`. Enforced by `it_offline::isolation_guard`. After adding or removing a `serial(world)`, run `bin/regen-serial`. |
| Panics | Tests may `unwrap`/`expect`/`panic`: a test binary's root file opens with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`, since `[lints.clippy]` denies them for shipped code. |
