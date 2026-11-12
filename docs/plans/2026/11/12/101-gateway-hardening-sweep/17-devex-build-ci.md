# 17 — Dev experience, build speed, CI/CD

> Part of [`overview.md`](overview.md). Depends on: none — independent track, start any time; step 2 is cheaper after 02 step 1 (shared test harness). No security label unless a workflow's secrets or the release path change.

Faster edit–test loop locally (16 cores idle during link), cheaper and shorter CI, same gates.

## Files to change

- `Cargo.toml` — `tokio = { features = ["full"] }`; `[profile.dev]`/`[profile.release]`; no test profile tuning.
- `.cargo/` — only `audit.toml`; no `config.toml` (default linker, no aliases).
- `tests/*.rs` — 43 top-level integration files = 43 separately linked test binaries.
- `bin/test:81`, `bin/ci` (280 lines), `bin/lint`, `bin/check`, `bin/setup`.
- `.github/workflows/ci.yml:60-98` (clippy: `cargo clean -p`, dev + release passes, 50 min timeout), `:100-194` (test: cold build, 50 min), `:296-365` (image build per arch), `release.yml`.
- `Dockerfile` — `cargo install cargo-chef` in the image build; base images tag-pinned.
- `rust-toolchain.toml`.

## Steps

1. **Measure first.** Record in the PR: `cargo build --timings` (cold + after touching `src/lib.rs`), `cargo test --no-run` wall time, full `bin/test` wall time, and the last ten `ci.yml` run durations per job (`gh run list` / `gh run view --json jobs`). Every later step states its before/after.
2. **One integration-test binary.** Move `tests/*.rs` to `tests/it/*.rs` modules under a single `tests/it/main.rs` (keep any test that needs its own process — e.g. the SIGHUP/`raise` tests in `tls_reload.rs`, global-recorder tests in `metrics_endpoint.rs` — as separate binaries). One link instead of ~43. `bin/test --test <name>` becomes a name filter; update `CLAUDE.md` §Commands and the `verify-change` skill text.
3. **cargo-nextest.** Add `.config/nextest.toml`: process-per-test isolation, test groups with `max-threads = 1` replacing `#[serial]` for the tests sharing a global table, a `ci` profile with retries = 0 and JUnit output, slow-test timeouts. `bin/test` uses nextest when installed (`bin/setup` installs it), doctests still via `cargo test --doc`. Uses all cores safely because isolation is per process.
4. **Linker.** `.cargo/config.toml`: `mold` (or `lld`) via `clang` for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, behind a check so a machine without it still builds (document in `bin/setup`, install there). Add to the machine via the `pc` repo module per the global rule, not ad hoc.
5. **Profiles.** `[profile.dev]` keeps `line-tables-only`; add `[profile.test]` inheriting dev; a `[profile.ci]` (inherits dev, `debug = false`, `incremental = false`) for CI builds. Trim `tokio` features to what is used (`rt-multi-thread`, `macros`, `net`, `time`, `signal`, `sync`, `io-util`, `fs` as needed). Check `cargo tree -d` for duplicate major versions and `cargo machete`/`cargo udeps` for unused deps; any lock change follows CLAUDE.md §Dependency graph (re-resolve narrowly, sqlx pin untouched).
6. **CI: build once, check twice.** Today clippy and test each compile the graph cold. Fix the root cause of the `cargo clean -p db-mcp-gateway` workaround (stale depfiles restored from a `main` cache — key `Swatinem/rust-cache` on job + lockfile hash + toolchain, `save-if` only on `main`), so PR runs restore a warm dependency cache. Use the `ci` profile in both jobs. Keep the release-cfg clippy pass but share its cache key.
7. **CI: shape.** `fmt`, `audit`, `secret-scan` stay tiny and parallel. Split `test` with nextest partitioning (`--partition hash:N/M`) only if step 1 shows test *run* time (not build) dominates. Path filters: docs-only changes (`website/**`, `docs/**`, `*.md`) skip clippy/test/build but still run the docs guards. Lower `timeout-minutes` to ~2× the measured p95 after the fixes.
8. **Image build.** Replace `cargo install cargo-chef` with the pinned prebuilt `cargo-chef` binary (or a pinned chef base image by digest); BuildKit cache mounts for `~/.cargo/registry` and `target`; keep `type=gha` cache with `mode=max`; digest-pin both base images (also in 10). Keep the native arm64 runner (no QEMU). Do not cancel `main` builds (existing rule: Image Updater pins the short SHA).
9. **Local gate speed.** `bin/check --changed`-style fast path: fmt + clippy on the workspace, nextest filtered to tests affected by the diff (module-path heuristic), full `bin/ci` unchanged. Optional pre-commit hook, off by default, never `--no-verify`-bait: it must finish in seconds or it is not installed.
10. **Dev stack.** `bin/dev up` waits on health checks only for services the selected tests need (`bin/test --pg-only` skips MySQL/Mongo containers); tmpfs data dirs for the test databases in `docker-compose.dev.yml` (faster, disposable).
11. **Scheduled jobs (cheap, off the PR path).** Weekly: `cargo audit` on `main`, fuzz targets (13), the load gate (13 step 10), `cargo update --dry-run` report. Public repo → GitHub-hosted runners stay (org rule).
12. Docs: `CLAUDE.md` §Commands/§CI, `CONTRIBUTING`/README dev section, `bin/setup` prerequisites.

## Tests

- `bin/ci` green before and after each step; `bin/check-scrub-features` still passes (profile/feature changes can alter the shipping graph — that script is the guard).
- Test count identical before/after step 2 (`cargo nextest list | wc -l` vs the old `cargo test -- --list`).
- `cargo audit` clean; `cargo tree -i libsqlite3-sys` still empty and no `patch not used` warning.
- `docker build -t db-mcp-gateway:dev .` produces a working image (`/healthz`).

## Done when

- Measured, recorded reductions in: incremental `cargo test --no-run`, full local `bin/test`, PR CI wall time, image build time.
- Same gates as today: fmt, clippy `-D warnings` (dev + release cfg), full test suite on real Postgres/MySQL/Mongo, audit, secret-scan.
- No workflow loses SHA-pinned actions, `concurrency` groups or `timeout-minutes`.
