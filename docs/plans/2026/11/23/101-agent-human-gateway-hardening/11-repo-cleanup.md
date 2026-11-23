# 11 — Repo cleanup

> Part of [`overview.md`](overview.md). Depends on: 01. Outward actions (close/delete) need the owner's go; commands below are ready to run.

## PRs and issues

| Item | Disposition |
|---|---|
| #373 cargo-minor | Merge after 01; mongodb 3.10 raises MSRV → H7 first (`rust-version`, `README.md:15`, `CLAUDE.md` Stack). Verify in the release notes |
| #374 / #375 axum-server 0.9 | One test compile error: `tests/it_offline/tls_reload.rs:81` (`from_tcp_rustls` returns `Result`). #375 shows an automated run in progress — check before pushing. Merge, then close #375 |
| #372 `.mcp.json` | Close: `tests/public_tree.rs:330` forbids it by design; stop the writer (SET-6) |
| sqlx 0.9 wip branch `origin/dz/clear-rustsec-2023-0071-…` | Finish (never compiled; call sites wrapped, stub + lock done). Rebase, MSRV 1.94.1, stale text `CONTRIBUTING.md:228,273`, `.cargo/audit.toml`, skill `:52`; `bin/ci`; removes the only audit ignore. Land **after** 02 (shares `exec/pg/run.rs`). Label |
| #218 archive/capture, #222 glama | H10 |
| New issues to file | axum 0.8; toolchain 1.96 → current (`rust-toolchain.toml` + Dockerfile + blueprint together) |

## Branches, stash, labels
- Delete with #372: `developerz/mcp-codegraph`. Local: `git branch -d chore/typescript-7` (merged), `git stash drop` (only `tmp/` ignore), `rmdir .claude/worktrees`.
- Labels delete: `claudetm`, `triage/auto`, `area/frontend`, `area/ai`, `documentation`. Keep `afk/hitl/ready` (pipeline reads them). Count usage first (search API was rate-limited).

## Files

| Path | Action |
|---|---|
| `.claude/hooks/__pycache__`, `.github/scripts/__pycache__` (3 tracked `.pyc`) | `git rm --cached`, ignore `__pycache__/` |
| `audit.toml` | Delete; `.cargo/audit.toml` is the one read. Fix `CONTRIBUTING.md:228`, skill `verify-change:53` |
| `.dz/briefs/health.md` | Identical to `.dz/schedules/health.md`, and the test guards the unused copy. Delete, repoint `tests/brief_rows.rs:1,19`, `ci.yml:33` |
| `.dz/README.md` + seven references to missing `.dz/briefs/{release-due,security-release}.md` | Repoint to `.dz/schedules/` |
| `.gitignore` | Dedupe; drop dead entries; add `tmp/` |
| `benchmarks/results/{postgres,mongo,instances4}.json` (1.3 MB) | gzip, update refs |
| `docs/sec/qa/2026-06-29` | Keep (22/22 fixed); add "paths as of" note, list in `docs/README.md` |
| `.coderabbit.yaml`, `.devin/`, `glama.json` | H10 |
| Dead API | `authz::evaluate`, `RefreshTokens::insert_rotated`, `TlsConfig::is_enabled`, `is_read_only`, `ConfigFile::load_yaml_str` → `#[cfg(test)]` or delete; `audit/pruner.rs:159` no-op test delete |
| `src/auth/config.rs:4` | Comment cites a closed issue |
| `src/exec/adapter.rs` (304) | Move tests out. 300-LOC rule: exempt `benchmarks/`, `tests/` or split |

## Done when
- 0 unexplained PRs/branches/stashes; `cargo audit` with no ignore; broken-path scan clean.
