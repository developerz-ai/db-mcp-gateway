# bin/ — the rest of the commands

The everyday commands and the concurrency rules are in the root [`CLAUDE.md`](../CLAUDE.md); this file names every other script, so each `bin/` script is listed exactly once across the two (`tests/claude_md_drift.rs` checks it). `lib/` holds sourced helpers, not commands.

`bin/test` details: runs cargo-nextest when installed, else `cargo test`; several filters are fine and need no `--` (`bin/test --test it_db run_query_e2e:: explain_e2e::`). `bin/check` runs 2 build jobs by default (`CARGO_BUILD_JOBS=$(nproc) bin/check` on a dedicated box). `bin/snapshot-check <files…> [-- <cmd>]` builds HEAD plus your files in its own target dir; `-- <cmd>` overrides the default clippy + unit tests, `--slot` runs it beside another agent. `bin/fmt --changed` formats the `.rs` files changed vs `origin/main` plus untracked ones. `bin/run` uses the dev stack and the committed `config/dev.yaml`. `bin/setup --hooks` enables `.githooks/` (pre-commit fmt + scans; pre-push clippy + unit).

## Commands

| Task | Command |
|---|---|
| Postgres query-path suite against YugabyteDB (starts `state-db` + `target-yugabyte`, nextest profile `yugabyte`) | `bin/test-yugabyte` |
| Regenerate nextest's run-alone list after adding/removing `#[serial_test::serial(world)]` | `bin/regen-serial` |
| Regenerate the SQL guard's parse-tree schema after bumping `pg_query` (`--check` reports drift) | `bin/regen-pg-tree` |
| Validate `deploy/` (promtool, helm lint, kubeconform; Docker only) | `bin/check-deploy` |
| Assert scrubber regex features in the shipping graph | `bin/check-scrub-features` |
| Scan the git index for service tokens (contents, file names, symlink targets; CI and the pre-commit hook run it); `--staged` for the index only | `bin/secret-scan` |
| Mint a static service bearer token | `bin/mint-service-token <name>` |
| Seed the demo `shop` DB on the dev target | `bin/seed` |
| One MCP tool call as the dev service token (`--list` for tools) | `bin/mcp-call <tool> '<json>'` |
| One-command demo (Docker only, no Rust) | `cd examples/demo && docker compose up -d` |
| Build release image locally | `docker build -t db-mcp-gateway:dev .` |
