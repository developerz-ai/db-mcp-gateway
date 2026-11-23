# 09 — CI/CD

> Part of [`overview.md`](overview.md). Depends on: 01. Workflow edits by the coordinator.

Measured (110 runs): PR p50/p95 159/424 s; `test` 147 warm (run ~87, compile ~28), 440 cold; `public-tree` up to 387 s to scan text; cache 8.6 of 10 GB, 48 % node; main → image ~230 s. Cold dependency PRs = rust-cache discarding entries > 7 d old on a prefix hit (`cleanTargetDir(checkTimestamp)`), not eviction.

## Steps

| ID | Wave | Change | Saves |
|---|---|---|---|
| C1 | a | `public-tree` → `python3 -I` script + ported `fires_on_*` tests; pre-check in `bin/ci` | 33–380 s, 463 MB |
| C2 | a | Cache key with ISO week + scheduled warm run before Monday Dependabot | ~290 s per dep PR |
| C3 | a | `test` and `yugabyte` share one key (`ci`), only `test` saves | 451 MB |
| C4 | a | Node: `actions/cache` + restore-keys, save on main only; drop rust-cache in `weekly.yml:86` | ~40 s, ~4.5 GB |
| C5 | a | `.dockerignore` allowlist | 104–157 s on ~1/7 main pushes |
| C6 | a | One clippy graph for both lints (`--profile ci`, debug-assertions off) — prove it still catches cfg drift | ~100 s cold |
| C7 (H8) | a | `audit` blocking only on lock/config change; daily audit → issue; pin cargo-audit | unblocks merges |
| C8 | a | `image-check` PR job (path-filtered, no push); `msrv` job on `Cargo.*` | first red on PR, not main |
| C9 | b | Six sleeping tests → injectable timeouts (`adapter_registry_concurrency`, `redis_timeout`, `exec_run_query`, `secret_refs`); touches `src/exec` → label | ~40 s |
| C10 | b | `it_db` group to 4 threads; 32 `serial(world)` tests `threads-required = num-test-threads`; `isolation_guard` keeps the list in step; one-week soak | with C9: 87 → ~30 s |
| C11 | b | Release: `preflight` requires ancestor of `origin/main`; drop the untested no-CI fallback; probe both registries; version tags on both before `:latest` | integrity |
| C12 | b | `sbom: true`, `actions/attest-build-provenance`, cosign keyless, weekly image scan, CodeQL | supply chain |
| C13 | b | `release-smoke`: boot with a state DB, `/healthz` 200, `/mcp` 401; both registries | |
| C14 | b | `load-gate` out of `weekly`, 2-of-3; digest-pin compose images; docs-only main pushes skip Rust | ~700 runner-s |
| C15 | a | Dependabot security group for `/website` (`applies-to: security-updates`); website gate = `npm ci && build`, not `bin/check` | ends 1-PR-per-package |
| C16 | owner | SET-1..SET-5 | |

Not now: sccache, nextest archive, single build job (warm compile is 28 s).

Target PR graph: `changes → {lint, test, yugabyte, image-check?, msrv?}` + `static` + `audit` + `website?` → `gate` (only required check).

## Done when
- Overview timing targets over 20 runs; `.github/CLAUDE.md` (secrets list, pin claim, authority) corrected.
