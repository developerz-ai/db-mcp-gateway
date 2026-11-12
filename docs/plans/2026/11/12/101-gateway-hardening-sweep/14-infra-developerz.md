# 14 — Deployment: developerz-ai cluster

> Part of [`overview.md`](overview.md). Depends on: a gateway release containing 05, 10, 11, 12. **Repo: `/home/superuser/workspace/developerz-ai/infrastructure`** — follow its `AGENTS.md`: draft PRs, **one stack per PR**, GitOps only (no `kubectl apply`), every deploying PR owes a `## Live test`. Paths below are relative to that repo.

Starting point: read-only, no `service_accounts:`, no RW roles, pgcat in the path, Image Updater tracking `main`.

## Files to change

- `stacks/apps/db-mcp-gateway/manifests/configmap-gateway-yaml.yml:21-110` — one server `worker-db` via pgcat; groups `devs`/`devops`/`cto`, all `query_read`.
- `stacks/apps/db-mcp-gateway/manifests/deployment.yml:13-24,74,105-147,166-184` — 1 replica, 100m/256Mi req, 512Mi limit, no PDB.
- `stacks/apps/db-mcp-gateway/manifests/kustomization.yml:21-28` — stale comment claiming RW roles exist.
- `stacks/apps/db-mcp-gateway/README.md` — stale (GHCR, `/mcp`-only ingress, direct primary).
- `stacks/stateful/postgres-instance/manifests/cluster.yml:177-231` — RO managed roles only; `multi-ai-router-ro-grant-job.yml` is the grant pattern.
- `stacks/stateful/pgcat/manifests/configmap.yml:78-113,233-249` — session pools, `pool_size` 10.
- `stacks/platform/observability/alert-rules/manifests/prometheusrule.yml:849-869`, `grafana/dashboards/db-mcp-gateway.json`, `stacks/apps/db-mcp-gateway/manifests/servicemonitor.yml:45-54`.
- `docs/db-mcp-gateway/connect.md`.

## Steps (each bullet group = one PR, in this order)

1. **Right-size from measurement.** Apply 01's numbers to `deployment.yml` requests/limits (write the measurement and the condition that would prove it wrong next to the value — repo rule), add a PDB, set `terminationGracePeriodSeconds ≥ 75`, set `RUST_LOG`/`METRICS_BIND`. Move the ServiceMonitor to the internal metrics port.
2. **RW roles (postgres-instance stack).** Managed roles `mcp_gateway_<db>_rw` for the app DBs only (`discord_server`, `legaldiligencemedellin`, `multi_ai_router`); `zitadel` and `vaultwarden` stay read-only. One PostSync grant Job per DB, modelled on `multi-ai-router-ro-grant-job.yml`: run as DB owner, one transaction, DML + sequences, no DDL, revoke the sensitive tables. First check the live cluster for leftover `mcp_gateway_*_rw` roles from the reverted July rollout (#630–#633) — a removed CNPG managed role is not dropped.
3. **Secrets, sealed with real ciphertext.** One sealed basic-auth secret per RW role (single-secret pattern of `multi-ai-router-ro`), reflected to `db-mcp-gateway` and `pgcat`; one sealed secret holding the two service tokens (`bin/mint-service-token` in the gateway repo). The July outage was a config referencing keys that were never sealed — this PR merges and syncs **before** step 5.
4. **pgcat.** Add the RW users to the write pools (`min_pool_size = 0`, so bad credentials cannot crash pgcat for every tenant). Size `pool_size` against the gateway's per-DB pool config (06) for read + write + cancel pools. Verify in the dev stack that `SET TRANSACTION READ ONLY`, `SET LOCAL statement_timeout`, `application_name` and `pg_cancel_backend` behave through a session-mode pool; if any does not, the gateway connects to Postgres directly for writes.
5. **Gateway config.** In `configmap-gateway-yaml.yml`: `write_role` + `write_password` on the three app databases (12 step 1); groups `svc-dz-coding` (`query_read`, all five DBs) and `svc-dz-devops` (`query_write` on the three app DBs, `require_reason: true`, tight `row_limit`/`statement_timeout_ms`); `service_accounts: dz-coding, dz-devops` with `require_upstream: true` and a per-account concurrency cap; human `devops` group keeps `query_read` unless the owner opts it into `query_write`. Dry-boot the config locally (`cargo run -- --config …`) before merging.
6. **Alerts + dashboard.** `tool_calls{access="write"}` rate and by-outcome panels; alerts on `audit_write_failures_total`, `audit_abandoned_total`, `requests_shed_total`, pruner last-success age, write-rate anomaly. Replace the Loki-only blind spot noted at `prometheusrule.yml:849-857`.
7. **Docs.** Refresh the stack README and the `kustomization.yml` comment; `connect.md` gains a headless section; new runbook: mint, rotate (`-next` name changes the audit identity for the overlap — say so), revoke (config PR + SIGHUP once 10 ships; Reloader rolls the pod today).
8. **NetworkPolicy** for the namespace (none today): ingress from Traefik + Prometheus, egress to pgcat/Postgres/DNS/IdP.

## Tests

- `bin/check --changed`, `bun scripts/ci/render-stacks.ts`, `kubectl kustomize stacks/apps/db-mcp-gateway/manifests` — render output noted in each PR body.
- `## Live test` per PR: after step 5 — `dz-coding` token: `run_query` SELECT ok, UPDATE → `forbidden`; `dz-devops` token: UPDATE on a scratch row ok with `rows_affected`, on `zitadel` → `forbidden`; audit rows carry run id; `SELECT current_user` under each tier shows the RO vs RW role.
- Rollback: revert the config PR; roles and secrets are inert without it.

## Done when

- Two service accounts live, tiers enforced at the role level, every write visible in one dashboard panel and one alert.
- Requests/limits carry a measurement, not a guess.
- README and comments describe the deployment that is running.
