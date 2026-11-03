---
description: Prove a change in developerz-ai/db-mcp-gateway before committing or opening a pull request — the repo's own install, run and check commands. Use before every commit.
applies: [rust]
---

# Verify a change in developerz-ai/db-mcp-gateway

> House skill — established by dz-runner setup mode from this repo’s own
> detected commands. Correct it in place; setup never overwrites a skill that exists.

## The one gate

`bin/check` is the local gate and delegates to `bin/ci`. CI does not invoke it:
`.github/workflows/ci.yml` independently configures fmt, SHA-pin validation, both
clippy configurations, scrub-feature validation, all-target/all-feature tests,
dependency audit and tracked-token scan with its regex regression. The local gate
runs equivalent quality checks plus isolated shell orchestration regressions.

The gate also runs the Pages-parity job — website typecheck, production build
and the post-build sensitive-asset denylist from `.github/workflows/pages.yml` —
whenever the site toolchain is present (Node 20+, npm, installed website
dependencies). When that toolchain is absent, that one job is reported `NOT RUN`
and the gate still grades everything else. Pages retains its existing path
filters; CI stays the authority for the audit and Pages jobs. See
`CONTRIBUTING.md#local-quality-gate-matrix` for the mapping. Local success does
not guarantee CI publishing or deployment success.

Prepare Rust (rustc, rustfmt and clippy), a C compiler (`cc`), `make`, Git,
Bash, GNU grep with PCRE, standard shell utilities, Docker Compose and a
running Docker daemon. These are REQUIRED: a missing one returns 75, because
the gate cannot grade anything at all.

Two toolchains are GATE-SCOPED — each belongs to exactly one job: cargo-audit
(the audit job) and Node 20+/npm plus the installed website dependencies (the
Pages job). When one is absent, that job reports
`NOT RUN: <job> - <reason> (<how to enable it>)` and the gate keeps grading
every other job. The skip is printed and repeated in the final summary; it is
never silent.

`bin/check` installs nothing. The local audit command is CI's exact command,
`cargo audit --ignore RUSTSEC-2023-0071`; the ignore set is unchanged (only
`RUSTSEC-2023-0071`, justified in `.cargo/audit.toml` and `audit.toml`).
`bin/setup` alone is insufficient: it does not install cargo-audit or website
dependencies. Prepare both separately to have every job run.

`bin/test` always runs `docker compose -f docker-compose.dev.yml up -d --wait`
before cargo, including when the state DB is already running. All four services
(`state-db`, `target-db`, `permissions-mysql`, `target-mongo`) must be healthy.
A stack that never became healthy returns 75 without invoking cargo, and the
report names every unhealthy service with its state and health. 75 is reserved
for an unreachable resource or a confirmed health failure: a malformed compose
file or any other compose command failure keeps its own exit status, so the
platform blames the change and not the box. Test arguments are forwarded
unchanged.

Registry login, image/manifest pushes, release publication, artifact upload and
Pages deployment are separate credentialed CI-only steps, not local validation.
CI cache cleanup is also deliberately not reproduced locally.

| Step | Command | What it is |
|------|---------|------------|
| install | `bin/setup` | export PATH="$HOME/.cargo/bin:$PATH" && (dpkg -s build-essential openssl curl >/dev/null 2>&1 \|\| (sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends build-essential openssl curl)) && cargo fetch --locked && docker compose -f docker-compose.dev.yml up -d --wait |
| run | `bin/dev` | cd "$(dirname "$0")/.."; c="docker compose -f docker-compose.dev.yml"; case "${1:-up}" in up) $c up -d --wait;; down) $c down;; logs) shift; $c logs -f "$@";; psql) case "${2:-state}" in state) $c exec -T state-db psql -U "${STATE_DB_USER:-gateway}" "${@:3}";; target) $c exec -T target-db psql -U "${TARGET_DB_USER:-app}" "${@:3}";; esac;; esac — on developerz.ai runs, start it with code_bash_background when you need a running stack |
| prove | `bin/check` | cd "$(dirname "$0")/.." && export PATH="$HOME/.cargo/bin:$PATH" && bin/ci |

## Rules

- Run every command from the repo root — the scripts `cd` there themselves.
- `bin/check` red is not a pull request. Fix the cause, never silence the gate.

## Exit codes `bin/check` must use

A coding box runs this gate before it commits, and it has to tell a FAILING change
from a gate it could not run — otherwise correct work is thrown away as if it were
red. Exit 1 cannot carry that difference, so one code is reserved:

| Exit | Means | What the platform does |
|------|-------|------------------------|
| 0 | every job that ran passed; any job that did not run is named in the summary | commit it |
| 75 | a REQUIRED resource is unreachable (cargo/rustc/rustfmt/clippy, cc, make, git, grep without PCRE, the Docker CLI/daemon/Compose, a dev stack that never became healthy) — it refused to grade | refuse the commit, and blame the environment, never the change |
| any other non-zero | the gate ran and the change is red | refuse the commit, and blame the change |

- Guard the REQUIRED preconditions FIRST and `exit 75` when one is unmet. `exit 1`
  there tells the platform your change is broken when it is your environment that is.
- A job whose own toolchain is absent is not an environment blocker: report
  `NOT RUN: <job> - <reason> (<how to enable it>)` and keep grading. A job that
  runs and fails keeps its own non-zero code — never turn a red job into a skip.
- Every job that did not run is named in the output and repeated in the final
  summary, which then reads
  `✓ Local quality checks passed for the gates that ran (no publishing or deployment)`
  instead of claiming a full pass. A gate that stops early names the jobs it
  never reached the same way: each gets a `NOT RUN: <job> - <reason>` notice
  and an entry in the final list.
- Changed a dependency? Re-run `bin/setup` before `bin/check`, or you are proving a stale tree.
- Add the test that fails first, then the fix — a green run that never went red proves nothing.
