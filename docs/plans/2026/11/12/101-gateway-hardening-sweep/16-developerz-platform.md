# 16 — developerz.ai platform: give agents the gateway

> Part of [`overview.md`](overview.md). Depends on: 14 and/or 15 (tokens exist and are live). **Repo: `/home/superuser/workspace/developerz-ai/developerz.ai`** (TypeScript, Bun) — follow its `CLAUDE.md`/`AGENTS.md`: `bun run verify`, one PR in flight, runtime changes owe a `## Live test`. Refs below were read on branch `feat/one-year-logins`; re-check line numbers on `main`. Paths relative to that repo.

Today nothing connects the two: no credential, no `.mcp.json` entry, no box-side mount. The platform only files a suggestion issue.

## Files to change

- `packages/domain/src/entities/tool-service.ts:111-119,281` — `ToolServiceMcp` is `stdio` only; descriptors are `UI_DEBUGGER`, `SENTRY_MCP`.
- `apps/worker/src/dispatch/vault-resolver.ts:311-345` — tool-service secrets sealed per account, no origin/role filter.
- `apps/runner/src/modes/worker/obs-read.ts:54,112-127` + `apps/worker/src/fleet/obs-read.ts:177-179` — the precedent: origin-gated `extraTools`, proxied by the mothership, box never holds URL or credential.
- `apps/runner/src/modes/worker/devops/capabilities.ts:1-20`, `apps/runner/src/harness/mode-narrowing.ts` — devops capability list; mode narrowing seam.
- `packages/domain/src/value-objects/agent-roster.ts:22-36,66-68,121,140` — agent ids, origin → mode.
- `apps/worker/src/consumers/mcp-provision.ts:134,303,655,690` + tests; `apps/runner/src/modes/setup/base/services.ts:170-186`, `base/capabilities.test.ts:160-210` — the suggestion-only path and the test pinning "gateway is not a tool service".
- `apps/runner/src/modes/worker/outcome.ts:157-176,388`, `packages/domain/src/value-objects/ops-approval.ts:45-63` — production `ops_action` gate (no minter exists).
- `docs/plans/2026/10/25/101-maintenance-one-way-doors/01-prod-data-gateway.md`, `docs/plans/2026/11/04/101-dz-usefulness-master-plan/11-prod-debugging.md` + its `status.yml:78-81`, `docs/standards/org-hardening.md:97-102`, `docs/idea/devops-watch.md:127-130`, `docs/spaces/kb/developerz-ai/db-mcp-gateway.md`.

## Steps

1. **Integration kind.** Account-level integration `tool_service:db-mcp-gateway` holding: gateway URL, a **read** token and an optional **write** token (per connected gateway — an account may have more than one: `db.developerz.ai`, `db-mcp.miamibeachstart.com`). Sealed like existing tool services; audited as `tool_service.deliver`.
2. **Mount = mothership proxy, not a box credential.** Follow `obs-read`: tools `db.list_servers`, `db.list_databases`, `db.describe_schema`, `db.sample_table`, `db.explain`, `db.query`, `db.table_stats`, `db.activity`, `db.history` are `extraTools` on the box; each call goes to the mothership, which holds the token and calls the gateway's MCP endpoint. The box never sees URL or token (consistent with `apps/runner/docs/tool-service-keys.md` and with the gateway's MUST #1 one hop further out).
3. **Tier selection on the mothership.** Origin `devops` → write token and the additional tool `db.write` (maps to `run_query` under `query_write`; `reason` required; `dry_run` exposed). Every other origin (`coder`, `reviewer`, `ci_fixer`, `scout`, `planner`, `sentry`, …) → read token, no `db.write`. The origin is re-checked server-side exactly as `OBS_ORIGINS` is (`apps/worker/src/fleet/obs-read.ts:177-179`); the box cannot ask for the other tier.
4. **Attribution.** The proxy sets `x-dbmcp-run-id` (dz run/task id) and `x-dbmcp-on-behalf-of` (the human or automation that originated the task) on every call (12 step 2) and stores the gateway's `x-request-id` on the platform's own `tool_call` audit row — one id joins the two audit trails.
5. **Write gating.** Platform doctrine: humans never approve; a destructive step runs behind a verified backup (`CLAUDE.md` non-negotiables). So: `db.write` on a production-tagged target requires a `dry_run` result in the same run first (rows-affected shown to the model), a `reason`, and — above a configurable rows-affected threshold — the verified-backup precondition, else it is refused and surfaced as a `decision_needed` blocker. No `OpsApproval` minter is added by this plan.
6. **Limits.** Per-run call budget and result-size cap on the proxy so one agent cannot burn the account's gateway concurrency bucket (12 step 3 sets the gateway side).
7. **Provisioner.** `mcp-provision` stops filing the "consider adding db-mcp-gateway" issue for accounts that have the integration; `suggestDbGateway` and the capability test (`capabilities.test.ts:195-200`) are updated — the gateway is still not a *box* tool service, it is a proxied one; say so in the test name.
8. **Human + Claude Code path stays SSO.** No change: people connect Claude Code straight to the gateway with their own identity (`infrastructure/docs/db-mcp-gateway/connect.md`). Service tokens are for the platform only.
9. **Supersede old decisions.** `01-prod-data-gateway.md` decided scout-only, read-only, "never proposes a gateway permission change" and a box-side `.mcp.json` mount; mark that slice `superseded` in its `status.yml` with a pointer here, and update step 7 of `11-prod-debugging.md`. Refresh the KB digest (says 1.1.1, read-only) and `org-hardening.md` § Database access.

## Tests

- Unit (fakes, as the existing provisioner tests): tier selection by origin; non-devops origin requesting `db.write` is refused server-side; headers set; token never appears in any box-bound payload (assert on the serialized dispatch); budget enforced.
- Integration against a locally booted gateway (`../db-mcp-gateway`, `bin/dev up` + `cargo run`): read tier SELECT ok / UPDATE forbidden; devops tier dry-run then write; gateway audit row carries run id and requester; platform `tool_call` row carries the gateway request id.
- `bun run verify`. `## Live test` on the closing issue: one coder task and one devops task against each connected gateway, with the audit rows from both sides quoted.

## Done when

- A coding agent can explore and query; a devops agent can also write; neither box ever holds a gateway credential.
- Every gateway audit row from the platform names the run and the requester, and joins to a platform audit row by request id.
- The two older plans no longer contradict what shipped.
