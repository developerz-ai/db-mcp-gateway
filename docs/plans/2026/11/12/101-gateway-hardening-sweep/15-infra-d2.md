# 15 — Deployment: cluster D2

> Part of [`overview.md`](overview.md). Depends on: a gateway release containing 05, 10, 11, 12. **Repo: D2's infrastructure repo** — follow its own rules: GitOps only, **one stack per PR**, secrets never in argv or git, its `bin/check` is the gate.

Starting point is the inverse of 14: everything is read-write. One shared service account and three operator groups share `query_write` on `"*"/"*"`; every database is wired to `mcp_gateway_rw`; the RO role exists and is unused. Work here **narrows**.

## What to change

- The gateway config overlay — a Postgres server (5 DBs, two of them financial) and a Yugabyte server (1 DB); full-RW grants; `require_reason: false`, 10 000 rows.
- The Deployment — 1 replica, 100m/256Mi, 512Mi limit, no Reloader, TCP liveness.
- The NetworkPolicy — ingress from the tunnel only.
- The stack manifest — secret key list; `log_retention_days: 365` vs `AUDIT_RETENTION_DAYS=90` in the Deployment.
- The stack's SQL files — RO and RW roles, applied by hand.
- The stack's contract tests — pin eight secret keys, exactly one service account, full-RW grants, the RW role on a financial database.
- The stack README and the secret-rotation runbook.
- Observability — nothing for the gateway.

## Steps (each bullet group = one PR, in this order)

1. **Right-size + observe.** Requests/limits from 01; `terminationGracePeriodSeconds ≥ 75`; ServiceMonitor on the internal metrics port + NetworkPolicy ingress from Prometheus; alerts and a dashboard on the series in 11 (writes, audit failures, shed, pruner). Reconcile retention: one value in the stack manifest and the Deployment.
2. **Secrets first.** Add the coding and devops service tokens to the gateway secret with the repo's secret-apply verb **before** the config PR. Update every place the secrets contract test pins the key list, and the test itself (count wording included). Name the record file in the rotation runbook.
3. **Re-wire roles.** In the gateway config: `role: mcp_gateway_ro` (with the existing RO password refs) and `write_role: mcp_gateway_rw` on each database (12 step 1). Reads from every identity now run as RO with `default_transaction_read_only` on.
4. **Narrow grants.** `svc-coding`: `query_read` everywhere. `svc-devops`: `query_write`, `require_reason: true`, lower `row_limit`/`statement_timeout_ms`, `require_upstream: true`. **Owner decision** (overview §Risks): whether the two financial databases stay writable by agents at all — recommended: read-only for agents, write for named operators only. Operator email groups keep their grants but gain `require_reason: true`. Update the access contract test to pin the new shape (two accounts, coding tier read-only, financial-database policy).
5. **Retire the shared account.** After 16 has switched the platform to the two new tokens and one clean day of audit rows shows no calls from the old account, remove it and its secret key. Removing it earlier breaks the running platform.
6. **RW role scope.** The RW SQL grants DML on all tables with default privileges for future tables. If step 4 makes a database agent-read-only, drop that database from the RW grant and add a revoke file; applied with the repo's SQL verb, in its own PR.
7. **Other agent platforms.** If another platform's agents also connect, they get their own account (read tier by default), never a shared token — one token per platform keeps revocation and the concurrency bucket separate.
8. **Reload.** No Reloader here: after a ConfigMap/Secret change, SIGHUP (once 10 ships) or a rollout via a config-hash annotation in the overlay. Add the annotation so GitOps, not a manual restart, applies config.
9. Yugabyte: verify in a scratch database that read-only transactions, `pg_cancel_backend` by `application_name`, and DML through `mcp_gateway_rw` behave like Postgres (the gateway pins one node); record the result in the stack README.

## Tests

- The repo's `bin/check` (typecheck, lint, tests incl. both contract tests, manifest render).
- Live test per PR, recorded in the PR body: coding token — SELECT ok, UPDATE → `forbidden`, `SELECT current_user` = `mcp_gateway_ro`; devops token — UPDATE on a scratch row ok with reason + run id in the audit row; financial databases per the decision; `/metrics` unreachable through the public hostname.
- Rollback: revert the config PR; the old shared account still works until step 5.

## Done when

- No agent identity reads through a write-capable role.
- The full-RW-on-everything grant is gone; what replaced it is pinned by the contract tests.
- The gateway has alerts and a dashboard in this cluster.

## Note

The platform's cluster agent holds cluster-admin in this cluster by owner ruling, so it can read the gateway secret and reach every database directly. Gateway tiers bound what agents do *through the gateway*; they are not a containment boundary for that agent here. Not changed by this plan.
