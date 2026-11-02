---
description: Prove a change in developerz-ai/db-mcp-gateway before committing or opening a pull request — the repo's own install, run and check commands. Use before every commit.
applies: [rust]
---

# Verify a change in developerz-ai/db-mcp-gateway

> House skill — established by dz-runner setup mode from this repo’s own
> detected commands. Correct it in place; setup never overwrites a skill that exists.

## The one gate

`bin/check` is the gate. CI runs it and the pre-commit hook runs it, so a change that
passes it locally passes everywhere.

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
| 0 | the change passes | commit it |
| 75 | a resource the gate NEEDS is unreachable (a database, a service, a credential) — it refused to grade | refuse the commit, and blame the environment, never the change |
| any other non-zero | the gate ran and the change is red | refuse the commit, and blame the change |

- Guard preconditions FIRST and `exit 75` when one is unmet. `exit 1` there tells the
  platform your change is broken when it is your environment that is.
- Changed a dependency? Re-run `bin/setup` before `bin/check`, or you are proving a stale tree.
- Add the test that fails first, then the fix — a green run that never went red proves nothing.
