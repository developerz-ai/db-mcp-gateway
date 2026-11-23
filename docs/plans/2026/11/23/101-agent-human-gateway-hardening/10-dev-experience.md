# 10 — Dev experience

> Part of [`overview.md`](overview.md). Depends on: 01; 07-P1 (shares the dev IdP).

## Files to change

| ID | Change |
|---|---|
| X1 | `bin/run`: `bin/dev up state-db target-db` + committed `config/dev.yaml` + env + `cargo run`; replaces the long `CLAUDE.md` line. Gitignore root `config.yml` |
| X2 | Compose profile `idp` (Dex, static user + group) on the port `OIDC_ISSUER` already points at (nothing listens today); `bin/seed`; `bin/mcp-call <tool> <json>` with a minted service token |
| X3 | Hooks: pre-commit = fmt + scans (< 5 s); pre-push = clippy + unit; full `bin/check` on demand/CI (hook today compiles three graphs + starts six containers, 18–48 min cold). Comment in `.githooks/pre-commit` claims CI runs `bin/check`; it does not |
| X4 | `bin/test --unit` (`--lib --bins`, `it_offline`) without Docker |
| X5 | `bin/setup`: non-Debian skip (`:16`), log file + tail on failure, prebuilt nextest, cargo-audit, opt-in `core.hooksPath` |
| X6 | `.env.example`: Redis/Dragonfly/Yugabyte; comment `TARGET_DB_URL` so `TARGET_DB_PORT` wins |
| X7 | `bacon.toml`, documented optional mold config, devcontainer on the compose stack |
| X8 | `CLAUDE.md` < 10 KB: §CI → `.github/CLAUDE.md`, §Dependency graph → `third_party/CLAUDE.md`. Facts told once; a test pins drifting ones (service count 6 not 4, latest migration 0021/0006, required checks) |
| X9 | Agent docs stale: `.claude/skills/{stack,state-migrations,verify-change}`, `.claude/agents/{audit-log,query-exec}.md`, `.claude/commands/planx.md`, `bin/dev:3`, `CONTRIBUTING.md:257`, `.dz/pipeline/agent-pipeline.json` (yugabyte) |

## Tests
- `tests/bin/` script per new `bin/` entry; CI `scripts` job (01) runs them.

## Done when
- Clone → `bin/setup && bin/run` → `bin/mcp-call run_query` works; unit loop needs no Docker; commit hook < 10 s.
