# 15 — Deployment: tesote cluster

> Part of [`overview.md`](overview.md). Depends on: a gateway release containing 05, 10, 11, 12. **Repo: `/home/superuser/workspace/tesote/infrastructure`** — follow its `CLAUDE.md`: GitOps only, **one stack per PR**, secrets never in argv or git, `bin/check` is the gate. Paths below are relative to that repo.

Starting point is the inverse of 14: everything is read-write. One service account (`developerz` → `svc-developerz`) and three operator groups share `query_write` on `"*"/"*"`; every database is wired to `mcp_gateway_rw`; the RO role exists and is unused. Work here **narrows**.

## Files to change

- `stacks/db-mcp-gateway/k8s/overlays/production/gateway-config.yaml:22-52,63-97` — servers `pg-production` (5 DBs incl. `bank_integrations_production`, `gringotts_production`) and `yugabyte` (`tesote_ai`); `*full_rw_grants`; `require_reason: false`, 10 000 rows.
- `stacks/db-mcp-gateway/k8s/base/deployment.yaml:15-22,53-100` — 1 replica, 100m/256Mi, 512Mi limit, no reloader, liveness TCP.
- `stacks/db-mcp-gateway/k8s/base/networkpolicy.yaml:17-60` — ingress from cloudflared only.
- `stacks/db-mcp-gateway/stack.yml:60-78,98-114` — secret key list; `log_retention_days: 365` vs `AUDIT_RETENTION_DAYS=90` (`deployment.yaml:70-71`).
- `stacks/db-mcp-gateway/sql/01..06` — RO and RW roles, applied by hand.
- `stacks/db-mcp-gateway/__tests__/secrets-contract.test.ts:28-37`, `__tests__/developerz-access.test.ts:27-49` — pin eight secret keys, exactly one service account, full-RW grants, RW role on `bank_integrations_production`.
- `stacks/db-mcp-gateway/README.md:83-113`, `docs/runbooks/rotate-secrets.md:22-31`.
- `platform/observability/**` — nothing for the gateway.

## Steps (each bullet group = one PR, in this order)

1. **Right-size + observe.** Requests/limits from 01; `terminationGracePeriodSeconds ≥ 75`; ServiceMonitor on the internal metrics port + NetworkPolicy ingress from Prometheus; alerts and a dashboard on the series in 11 (writes, audit failures, shed, pruner). Reconcile retention: one value in `stack.yml` and the deployment.
2. **Secrets first.** Add `DZ_DEVOPS_SERVICE_TOKEN`, `DZ_CODING_SERVICE_TOKEN` to `db-mcp-gateway-secrets` via `bin/k8s/secret-apply.sh … KEY=@/path` **before** the config PR. Update the key list in the four places the contract test pins (`stack.yml` `secrets[]`, README Secrets step, `deployment.yaml:73-76` comment, overlay `kustomization.yaml:10-14` comment) and `secrets-contract.test.ts` (count wording included). Name the record file in `rotate-secrets.md`.
3. **Re-wire roles.** In `gateway-config.yaml`: `role: mcp_gateway_ro` (with the existing `*_RO_PASSWORD` refs) and `write_role: mcp_gateway_rw` on each database (12 step 1). Reads from every identity now run as RO with `default_transaction_read_only` on (`sql/01:14-26`).
4. **Narrow grants.** `svc-dz-coding`: `query_read` everywhere. `svc-dz-devops`: `query_write`, `require_reason: true`, lower `row_limit`/`statement_timeout_ms`, `require_upstream: true`. **Owner decision** (overview §Risks): whether `bank_integrations_production` and `gringotts_production` stay writable by agents at all — recommended: read-only for agents, write for named operators only. Operator email groups keep their grants but gain `require_reason: true`. Update `developerz-access.test.ts` to pin the new shape (two accounts, coding tier read-only, bank/gringotts policy).
5. **Retire `developerz`.** After 16 has switched the platform to the two new tokens and one clean day of audit rows shows no `service:developerz` calls, remove the account and its secret key. Removing it earlier breaks the running platform.
6. **RW role scope.** `sql/04`–`06` grant DML on all tables with default privileges for future tables. If step 4 makes a database agent-read-only, drop that database from `sql/05` and add a revoke file; applied with `bun scripts/db/sql.ts` per the README, in its own PR.
7. **tesote.ai agents.** If tesote.ai's own agents (not dz) also connect, they get their own account (`tesote-ai` → `svc-tesote-ai`, read tier by default), never a shared token — one token per platform keeps revocation and the concurrency bucket separate.
8. **Reload.** No Reloader here: after a ConfigMap/Secret change, SIGHUP (once 10 ships) or a rollout via a config-hash annotation in the overlay. Add the annotation so GitOps, not a manual restart, applies config.
9. Yugabyte: verify in a scratch database that read-only transactions, `pg_cancel_backend` by `application_name`, and DML through `mcp_gateway_rw` behave like Postgres (the gateway pins one node at `100.64.0.9:5433`); record the result in the stack README.

## Tests

- `bin/check` (typecheck, lint, `bun test` incl. both contract tests, `bun scripts/k8s/render.ts`).
- Live test per PR, recorded in the PR body: coding token — SELECT ok, UPDATE → `forbidden`, `SELECT current_user` = `mcp_gateway_ro`; devops token — UPDATE on a scratch row ok with reason + run id in the audit row; bank/gringotts per the decision; `/metrics` unreachable through the Cloudflare hostname.
- Rollback: revert the config PR; the old `developerz` account still works until step 5.

## Done when

- No agent identity reads through a write-capable role.
- The full-RW-on-everything grant is gone; what replaced it is pinned by the contract tests.
- The gateway has alerts and a dashboard in this cluster.

## Note

dz-agent holds cluster-admin in this cluster by owner ruling (`CLAUDE.md:23`, `platform/dz-agent/README.md`), so it can read `db-mcp-gateway-secrets` and reach every database directly. Gateway tiers bound what agents do *through the gateway*; they are not a containment boundary for dz-agent here. Not changed by this plan.
