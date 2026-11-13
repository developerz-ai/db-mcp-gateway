# 16 — The platform: give agents the gateway

> Part of [`overview.md`](overview.md). Depends on: 14 and/or 15 (tokens exist and are live). **Repo: the agent platform's repo** — follow its own rules: its verify command, one PR in flight, runtime changes owe a `## Live test`.

Today nothing connects the two: no credential, no MCP config entry, no mount on the agent machine. The platform only files a suggestion issue.

## What to change

- The tool-service entity — MCP tool services are `stdio` only.
- The per-account secret resolver — tool-service secrets sealed per account, no origin/role filter.
- The precedent: the platform's existing origin-gated privileged tools, proxied by its control plane so the agent machine never holds a URL or credential.
- The devops capability list and the mode-narrowing seam; the agent roster (agent ids, origin → mode).
- The MCP provisioner's suggestion-only path and the test pinning "gateway is not a tool service".
- The production `ops_action` gate (no minter exists).
- The platform's older gateway plan and KB entries, which contradict this one.

## Steps

1. **Integration kind.** Account-level integration `tool_service:db-mcp-gateway` holding: gateway URL, a **read** token and an optional **write** token (per connected gateway — an account may have more than one). Sealed like existing tool services; audited as `tool_service.deliver`.
2. **Mount = control-plane proxy, not a machine credential.** Follow the precedent: tools `db.list_servers`, `db.list_databases`, `db.describe_schema`, `db.sample_table`, `db.explain`, `db.query`, `db.table_stats`, `db.activity`, `db.history` are extra tools on the agent machine; each call goes to the control plane, which holds the token and calls the gateway's MCP endpoint. The agent machine never sees URL or token (the gateway's MUST #1, one hop further out).
3. **Tier selection on the control plane.** Origin `devops` → write token and the additional tool `db.write` (maps to `run_query` under `query_write`; `reason` required; `dry_run` exposed). Every other origin (`coder`, `reviewer`, `ci_fixer`, `scout`, `planner`, …) → read token, no `db.write`. The origin is re-checked server-side exactly as the precedent's origin allowlist is; the agent cannot ask for the other tier.
4. **Attribution.** The proxy sets `x-dbmcp-run-id` (run/task id) and `x-dbmcp-on-behalf-of` (the human or automation that originated the task) on every call (12 step 2) and stores the gateway's `x-request-id` on the platform's own `tool_call` audit row — one id joins the two audit trails.
5. **Write gating.** Platform doctrine: humans never approve; a destructive step runs behind a verified backup. So: `db.write` on a production-tagged target requires a `dry_run` result in the same run first (rows-affected shown to the model), a `reason`, and — above a configurable rows-affected threshold — the verified-backup precondition, else it is refused and surfaced as a `decision_needed` blocker. No approval minter is added by this plan.
6. **Limits.** Per-run call budget and result-size cap on the proxy so one agent cannot burn the account's gateway concurrency bucket (12 step 3 sets the gateway side).
7. **Provisioner.** It stops filing the "consider adding db-mcp-gateway" issue for accounts that have the integration; the suggestion and its capability test are updated — the gateway is still not a tool service on the agent machine, it is a proxied one; say so in the test name.
8. **Human + Claude Code path stays SSO.** No change: people connect Claude Code straight to the gateway with their own identity. Service tokens are for the platform only.
9. **Supersede old decisions.** The older plan decided scout-only, read-only, "never proposes a gateway permission change" and a machine-side MCP config mount; mark it `superseded` with a pointer here. Refresh the KB digest (says 1.1.1, read-only) and the database-access section of the hardening standard.

## Tests

- Unit (fakes, as the existing provisioner tests): tier selection by origin; non-devops origin requesting `db.write` is refused server-side; headers set; token never appears in any agent-bound payload (assert on the serialized dispatch); budget enforced.
- Integration against a locally booted gateway (`bin/dev up` + `cargo run` in this repo): read tier SELECT ok / UPDATE forbidden; devops tier dry-run then write; gateway audit row carries run id and requester; platform `tool_call` row carries the gateway request id.
- The platform's verify command. `## Live test` on the closing issue: one coder task and one devops task against each connected gateway, with the audit rows from both sides quoted.

## Done when

- A coding agent can explore and query; a devops agent can also write; no agent machine ever holds a gateway credential.
- Every gateway audit row from the platform names the run and the requester, and joins to a platform audit row by request id.
- The older plans no longer contradict what shipped.
