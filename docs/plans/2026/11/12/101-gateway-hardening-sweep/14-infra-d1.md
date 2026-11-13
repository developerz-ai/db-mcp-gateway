# 14 — Deployment: cluster D1

> Part of [`overview.md`](overview.md). Depends on: a gateway release containing 05, 10, 11, 12. **Repo: D1's infrastructure repo** — follow its own rules: draft PRs, **one stack per PR**, GitOps only (no `kubectl apply`), every deploying PR owes a `## Live test`.

Starting point: read-only, no `service_accounts:`, no RW roles, pgcat in the path, an image updater tracking `main`.

## What to change

- The gateway's config ConfigMap — one server via pgcat; groups `devs`/`devops`/`cto`, all `query_read`.
- The Deployment — 1 replica, 100m/256Mi request, 512Mi limit, no PDB.
- The stack's kustomization comment (claims RW roles exist) and README (stale registry, ingress and DB route).
- The Postgres cluster's managed roles (RO only today) and its existing read-only grant Job, the pattern for write roles.
- pgcat's pool config — session pools, `pool_size` 10.
- The gateway alert rules, dashboard and ServiceMonitor; the human connect guide.

## Steps (each bullet group = one PR, in this order)

1. **Right-size from measurement.** Apply 01's numbers to the Deployment's requests/limits (write the measurement and the condition that would prove it wrong next to the value), add a PDB, set `terminationGracePeriodSeconds ≥ 75`, set `RUST_LOG`/`METRICS_BIND`. Move the ServiceMonitor to the internal metrics port.
2. **RW roles.** Managed roles `mcp_gateway_<db>_rw` for the app DBs only; the IdP and password-vault databases stay read-only. One PostSync grant Job per DB, modelled on the read-only grant Job: run as DB owner, one transaction, DML + sequences, no DDL, revoke the sensitive tables. First check the live cluster for leftover `mcp_gateway_*_rw` roles from the reverted July rollout — a removed managed role is not dropped.
3. **Secrets, sealed with real ciphertext.** One sealed basic-auth secret per RW role, reflected to the gateway and pgcat namespaces; one sealed secret holding the two service tokens (`bin/mint-service-token` in this repo). The July outage was a config referencing keys that were never sealed — this PR merges and syncs **before** step 5.
4. **pgcat.** Add the RW users to the write pools (`min_pool_size = 0`, so bad credentials cannot crash pgcat for every tenant). Size `pool_size` against the gateway's per-DB pool config (06) for read + write + cancel pools. Verify in the dev stack that `SET TRANSACTION READ ONLY`, `SET LOCAL statement_timeout`, `application_name` and `pg_cancel_backend` behave through a session-mode pool; if any does not, the gateway connects to Postgres directly for writes.
5. **Gateway config.** `write_role` + `write_password` on the app databases (12 step 1); groups `svc-coding` (`query_read`, every DB) and `svc-devops` (`query_write` on the app DBs, `require_reason: true`, tight `row_limit`/`statement_timeout_ms`); `service_accounts: coding, devops` with `require_upstream: true` and a per-account concurrency cap; human `devops` group keeps `query_read` unless the owner opts it into `query_write`. Dry-boot the config locally (`cargo run -- --config …`) before merging.
6. **Alerts + dashboard.** `tool_calls{access="write"}` rate and by-outcome panels; alerts on `audit_write_failures_total`, `audit_abandoned_total`, `requests_shed_total`, pruner last-success age, write-rate anomaly. Replace the Loki-only blind spot in the existing gateway alert rules.
7. **Docs.** Refresh the stack README and the kustomization comment; the connect guide gains a headless section; new runbook: mint, rotate (`-next` name changes the audit identity for the overlap — say so), revoke (config PR + SIGHUP once 10 ships; Reloader rolls the pod today).
8. **NetworkPolicy** for the namespace (none today): ingress from the ingress controller + Prometheus, egress to pgcat/Postgres/DNS/IdP.

## Tests

- The infra repo's own check and render commands, and `kubectl kustomize` of the stack — render output noted in each PR body.
- `## Live test` per PR: after step 5 — coding token: `run_query` SELECT ok, UPDATE → `forbidden`; devops token: UPDATE on a scratch row ok with `rows_affected`, on the IdP database → `forbidden`; audit rows carry run id; `SELECT current_user` under each tier shows the RO vs RW role.
- Rollback: revert the config PR; roles and secrets are inert without it.

## Done when

- Two service accounts live, tiers enforced at the role level, every write visible in one dashboard panel and one alert.
- Requests/limits carry a measurement, not a guess.
- README and comments describe the deployment that is running.
