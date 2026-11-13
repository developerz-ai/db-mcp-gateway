# AI-first scorecard

> Written by the developerz.ai maintainer agent. Each onboarding run rewrites this file whole; the latest run wins, and the same card is stored on the platform.

- Run: `run_68c92316ab2940838d24f0b18f66eca2`
- Computed: 2026-11-02T04:22:52.930Z
- Proof: **proved** — every command ran green at head.
- Score: 13 of 15 items ok

## `policy` — ok

- .dz/maintainer/maintainer.yml already present, left alone
- .dz/maintainer/reviewer.md established

## `brain` — ok

- CLAUDE.md already present, left alone

## `roster` — ok

- .claude/agents/audit-log.md established
- .claude/agents/authz-permissions.md established
- .claude/agents/mcp-transport.md established
- .claude/agents/query-exec.md established

## `skills` — ok

- .claude/skills/verify-change/SKILL.md established
- .claude/skills/stack/SKILL.md established
- .claude/skills/state-migrations/SKILL.md established

## `scripts` — ok

- bin/setup established
- bin/dev repaired
- bin/check established
- down: ./bin/dev down (bin_dev)
- ./bin/setup exited 0 at head (2.5s)

## `wiring` — ok

- .mcp.json established

## `commands` — ok

- .claude/commands already present, left alone

## `access` — gap

- landed 2 of 27 asked: SENTRY_ACCESS_TOKEN, SENTRY_HOST
- still missing: STATE_DB_URL, STATE_DB_USER, STATE_DB_PASSWORD, STATE_DB_NAME, STATE_DB_PORT, TARGET_DB_URL, TARGET_DB_USER, TARGET_DB_PASSWORD, TARGET_DB_NAME, TARGET_DB_PORT, PERMISSIONS_DB_DSN, PERMISSIONS_MYSQL_PASSWORD, TARGET_MONGO_PASSWORD, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OID…

## `layout` — gap

- migration to the house layout filed as tasks
- apps/db-mcp-gateway: 22 move(s) planned as one task

## `smoke_test` — ok

- tests/run_query_e2e.rs in the repository
- run by ./bin/check exited 0 at head (47.2s)

## `env_example` — ok

- .env.example already present, left alone

## `agents_md` — ok

- AGENTS.md established

## `per_workspace_brains` — ok

- single-package repository: 0 workspaces
- CLAUDE.md already present, left alone

## `docs_readme` — ok

- docs/README.md established

## `gate_proved` — ok

- ./bin/check exited 0 at head (47.2s)
