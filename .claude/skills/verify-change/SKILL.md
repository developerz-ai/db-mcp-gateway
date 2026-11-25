---
description: Prove a change in developerz-ai/db-mcp-gateway before committing or opening a pull request — the repo's own install, run and check commands. Use before every commit.
applies: [rust]
---

# Verify a change in developerz-ai/db-mcp-gateway

> House skill — written from this repo’s own detected commands and
> owned by this repository's maintainers. Correct it in place; setup never overwrites a skill that exists.

## Use the bin/ wrappers, not raw cargo

Every check below has a `bin/` wrapper. The compiling and testing ones queue
(`bin/lib/queue.sh`): a repo-local `heavy` lock serialises compiles, a `db`
lock lets one suite at a time touch the shared dev databases, and the outer
full-suite runs (`bin/check`, full `bin/test`, `bin/test-yugabyte`) also
queue under the machine-wide `heavy` ledger when it is on PATH. A raw
`cargo test` against `tests/it_db/` skips the `db` lock and races whatever
else is using the same Postgres/MySQL/Mongo/Redis — never run one.
`DBMCP_NO_QUEUE=1` opts out, for a dedicated box only.

## Narrowest proof first, the full gate once

| Step | Command | What it proves |
|------|---------|----------------|
| install | `bin/setup` (`--hooks` also sets `core.hooksPath .githooks`) | host prerequisites, cargo-nextest + cargo-audit at CI's versions, `cargo fetch --locked`, the eight default dev services healthy; log in `target/setup.log` |
| format | `bin/fmt` | rewrites; `bin/lint` only checks |
| unit loop | `bin/test --unit` | lib + bin unit tests and `tests/it_offline` — no Docker, no database |
| one DB suite | `bin/test --test it_db <module>::` | that module against the real dev stack (target DB never mocked) |
| lint | `bin/lint` | fmt-check, clippy `-D warnings` on all targets and on the release cfg, `bin/check-scrub-features` |
| Yugabyte | `bin/test-yugabyte` | the Postgres query-path suite against YugabyteDB (profile `yugabyte`); only when the Postgres exec path changed |
| the gate | `bin/check` | preflight, then `bin/ci`: the orchestration regression, the public-tree guard, lint + the SHA-pin scan, `bin/test` (full suite), `cargo audit`, the tracked-token scan, the doc-anchor guard and Pages parity |

Run `bin/check` once, at the end, in the background with its output in a
file; it is minutes long. CI does not invoke it: `.github/workflows/ci.yml`
configures its jobs independently and `bin/ci` mirrors them. The mapping is
`CONTRIBUTING.md#local-quality-gate-matrix`. The git hooks are the fast
subset: pre-commit = fmt + staged token scan, pre-push = clippy +
`bin/test --unit`.

`bin/test` (full, or with `--test it_db …`) runs
`docker compose -f docker-compose.dev.yml up -d --wait` before cargo, so the
eight default services (`state-db`, `target-db`, `target-pool-db`,
`target-pooler`, `permissions-mysql`, `target-mongo`, `target-redis`,
`target-dragonfly`) must be healthy. A stack
that never became healthy returns 75 without invoking cargo and names each
unhealthy service. Test arguments are forwarded unchanged (cargo-nextest when
installed, else `cargo test`).

The audit ignore set is empty: `.cargo/audit.toml` — the one config
cargo-audit reads — ignores nothing, and a new ignore is a reviewed change. Website dependencies
(`cd website && npm ci`) are the one thing `bin/setup` does not install;
without them the Pages job reports `NOT RUN`.

Registry login, image pushes, releases and Pages deployment are CI-only steps,
not local validation.

## Rules

- Run every command from the repo root — the scripts `cd` there themselves.
- `bin/check` red is not a pull request. Fix the cause, never silence the gate.
- Changed a dependency? Re-run `bin/setup` before `bin/check`, or you are proving a stale tree.
- Add the test that fails first, then the fix — a green run that never went red proves nothing.

## Exit codes `bin/check` must use

A coding box runs this gate before it commits, and it has to tell a FAILING change
from a gate it could not run — otherwise correct work is thrown away as if it were
red. Exit 1 cannot carry that difference, so one code is reserved:

| Exit | Means | What the platform does |
|------|-------|------------------------|
| 0 | every job that ran passed; any job that did not run is named in the summary | commit it |
| 75 | a REQUIRED resource is unreachable (cargo/rustc/rustfmt/clippy, cc, make, grep, the Docker CLI/daemon/Compose, a dev stack that never became healthy) — it refused to grade | refuse the commit, and blame the environment, never the change |
| any other non-zero | the gate ran and the change is red | refuse the commit, and blame the change |

- Guard the REQUIRED preconditions FIRST and `exit 75` when one is unmet. `exit 1`
  there tells the platform your change is broken when it is your environment that is.
- A job whose own toolchain is absent (python3 for the public-tree guard;
  cargo-audit; Node 20+/npm + installed website dependencies) is not an environment blocker: report
  `NOT RUN: <job> - <reason> (<how to enable it>)` and keep grading. A job that
  runs and fails keeps its own non-zero code — never turn a red job into a skip.
- Every job that did not run is named in the output and repeated in the final
  summary, which then reads
  `✓ Local quality checks passed for the gates that ran (no publishing or deployment)`
  instead of claiming a full pass.
