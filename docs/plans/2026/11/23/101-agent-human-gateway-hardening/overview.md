# Gateway hardening + agent/human UX

## Goal
Make the gateway great for agents (fewer failed calls, self-explaining limits) and humans (first query in minutes, operable, honest docs), after a patch release and the correctness fixes from a sweep of `ad833b7` (v2.3.0). Includes CI/CD, dev experience, repo cleanup.

## Context
- Stack: `CLAUDE.md` §Stack. Layers: one reason to change each.
- Non-negotiables touched: #1 (02, 05), #2 (04, 06), #3 (02, 03), #4 (05), #5 (08). None weakened.
- `security review required`: 02, 03, 04, 05, 06 (new tool, row caps), parts of 08, 11 (sqlx), 12 only if `src/` moves.
- Agent friction to fix: failed call retried blind (no hint, position or limit in the error), discovery-only call chains, retried timeouts. Baseline aggregates are in the owner's private notes; slice 06 targets exactly these.
- Evidence level per row: **V** = re-read by the coordinator or executed; **R** = read by one agent; **P** = plausible, reproducing test first. Line refs are `ad833b7`; re-verify before trusting.

## Public-tree rules for this plan
- `SET-n` rows and slice 02: detail lives in the owner's private notes (ask the owner), not here.
- Deployment and consumer-platform slices exist in their own repositories; nothing about them here.

## Plan files (execute in order)
1. [`01-unblock-main.md`](01-unblock-main.md) — audit red, local gate red on clean main, fail-open CI gate.
2. [`02-security-patch.md`](02-security-patch.md) — patch release 2.3.1 (detail private).
3. [`03-exec-correctness.md`](03-exec-correctness.md) — wrong values, lost writes, pools, fairness, cancel.
4. [`04-auth-transport.md`](04-auth-transport.md) — OAuth, sessions, admin API, cache bugs.
5. [`05-audit-state.md`](05-audit-state.md) — audit completeness, sinks, listener, state pool.
6. [`06-agent-surface.md`](06-agent-surface.md) — MCP surface: instructions, errors, limits, describe v2, `whoami`.
7. [`07-docs-onboarding.md`](07-docs-onboarding.md) — wrong client URL, broken compose, one-command demo, doc accuracy + drift test.
8. [`08-operator-tooling.md`](08-operator-tooling.md) — `--check`, CLI, metrics, alerts, HA login state, chart.
9. [`09-ci-cd.md`](09-ci-cd.md) — gate job, caches, speed, release integrity.
10. [`10-dev-experience.md`](10-dev-experience.md) — `bin/run`, dev IdP, hooks, setup, agent docs.
11. [`11-repo-cleanup.md`](11-repo-cleanup.md) — PRs, issues, branches, labels, clutter, deps, sqlx 0.9.
12. [`12-tests.md`](12-tests.md) — lints, property tests, missing e2e, flake removal.

## Waves (one PR in flight; ≤4 agents per wave, file sets disjoint)

| Wave | Slices | Agents and file sets |
|---|---|---|
| 0 | 01 | 1 agent; `Cargo.lock`, `.github/workflows/{pages,ci}.yml` applied by coordinator |
| 1 | 02 | private slice → release 2.3.1 |
| 2 | 11a + 09a | deps and cleanup (no `src/` overlap except sqlx); CI gate/caches |
| 3 | 03 | A `exec/pg/`; B `exec/{mongo,redis}/`; C `exec/{registry,adapter,pool_sizing}.rs` + `src/config/` |
| 4 | 04 + 05 | A `auth/`, `transport/oauth/`; B `transport/admin/`, `state/permissions/`, `authz/`; C `audit/`, `state/audit/`; D `startup/`, `transport/{probes,mcp_handler}.rs` |
| 5 | 06 | PR sequence in the slice; additive first, breaking rows grouped in one minor/major per the human decision |
| 6 | 07 + 10 | A `website/docs/`, `README.md`; B `examples/`, compose; C `bin/`; D `.claude/`, `CLAUDE.md` text (coordinator applies) |
| 7 | 08 | A CLI `src/main.rs` + new `src/cli/`; B `startup/metrics*`, exec metrics; C `deploy/` (rules, dashboard, chart); D HA login state (`state/`, `auth/oauth/`) |
| 8 | 12 + 09b | tests, speed, remaining CI |

Docs-only PRs of slice 07 (P0 first) may land any time after wave 0, between waves, when no open PR touches the same file.

## Done when
- `audit`, `bin/check` and every workflow on `main` green; `pages` 0 lost deploys over 20 pushes.
- Slice 02 done; 2.3.1 published.
- A fresh machine with Docker only: one command → a query result through the gateway, no IdP built by hand.
- Documented `claude mcp add` command works verbatim.
- Agent metrics two weeks after a release with slice 06: `run_query` error rate and 60 s-retry share halved, discovery calls per run halved (owner re-runs the private aggregates).
- Warm code PR ≤ 100 s, dependency PR ≤ 200 s, Actions cache ≤ 5 GB, one required check.
- 0 open PRs/issues without a disposition; no stale branch; roadmap and non-goals match the code.
- `bin/lint` clean, `bin/test` green; audit rows asserted for each tool path incl. `forbidden`.

## Risks / open questions — human rows (never decided silently)

| # | Question | Recommendation |
|---|---|---|
| H1 | Disclosure process for slice 02 | Owner; private |
| H2 | Follow-up to slice 02 | Owner; private |
| H3 | Constraints merge per action (code) or per (server, db) (spec 06 step 2–4) | Keep code, fix spec: per-action is what lets read and write grants carry different caps. Security call |
| H4 | `permissions_store` absent: YAML-only (spec 12) or always consult (code) | Add explicit YAML-only mode, default unchanged until 3.0 |
| H5 | Argument errors `-32602` → `isError` result; `run_query` default limit 1000 → 100 | Both breaking for clients: ship together in 3.0, additive rows now |
| H6 | `whoami`/effective-access tool reveals caller's own grants | Yes; own grants only, audited |
| H7 | MSRV 1.88 → 1.94.1 (mongodb 3.10, sqlx 0.9 need it) | Yes; removes the only audit ignore |
| H8 | Audit red on advisory blocks every PR vs only lock-changing PRs | Block only lock changes + daily scheduled audit that opens an issue |
| H9 | Compatibility call in slice 02 | Owner; private |
| H10 | #218 archive/capture policies; `glama.json`; `.coderabbit.yaml`; `.devin/` | Roadmap "not planned"; do glama sign-in; delete the other two if uninstalled |
| H11 | MySQL query target; masking; JIT expiring grants; image signing | Next-plan candidates, in that order of evaluator impact: signing (S), expiry (M), MySQL (L), masking (L) |
| H12 | `SET-n` repository settings | Owner applies; needs admin scope |
