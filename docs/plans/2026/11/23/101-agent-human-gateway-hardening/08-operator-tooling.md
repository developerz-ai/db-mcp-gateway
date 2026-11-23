# 08 — Operator tooling

> Part of [`overview.md`](overview.md). Depends on: 04, 05. Label where noted (*).

## Files to change

| ID | Pri | What | Where |
|---|---|---|---|
| O1 | 1 | `--check` (parse, validate, `--no-secrets`, report **all** errors, connection-budget print, inert-constraint and unknown-env warnings), `--healthcheck` self-probe, published JSON Schema | `src/main.rs:22`, `config/yaml/{mod.rs:164,validate.rs:19}`, new `src/cli/` |
| O2 | 1 | Better errors: field names from schema only; secret errors name server/db/tier; aggregate; trim newline on `${ENV}` like `${FILE}` | `config/yaml/error.rs:39,130`, `config/secret.rs` |
| O3 | 1 | Gauges die after 1 h (`pool_size` is set once at open) and pruner gauge sits on the same boundary | `startup/metrics.rs:25-51`, `pg/tier.rs:116`, `startup/background.rs:25` |
| O4 | 1 | Counters pre-registered at 0; `server`/`db`/cause labels on calls and duration; real pool metrics (in-use, idle, waiters, acquire) for all adapters + state; `build_info`, cert `not_after`, reload time/hash, reaper last-success, login failures by code | `startup/metrics.rs`, `audit_dispatch/mod.rs:135,207`, `exec/*` |
| O5 | 1 | `deploy/`: Prometheus rules, Grafana dashboard, runbook per alert/outcome; test pins the metric catalogue to source | new |
| O6 * | 1 | Persist login flows, consents, auth codes in the state DB → HA without sticky routes | `startup/boot.rs:103`, `auth/oauth/{pending_flows.rs:65,auth_codes.rs}`; `migrations/0022_oauth_flows.sql` (hashed ids, TTL index, GC); code reads only after migration; spec 02 §HA, 09 |
| O7 * | 2 | Reload without a signal: poll config, `${FILE}` refs, TLS PEMs | `startup/mod.rs:82`, `config/reload.rs` |
| O8 * | 2 | Opt-in per-database degrade on unresolved secret; opt-in target preflight `target_up{}`; service tokens stay fail-closed | `config/yaml/mod.rs:215`, `exec/registry.rs` |
| O9 * | 2 | CLI over the existing audited API: `login` (loopback OAuth), `grants`, `sessions revoke`, `audit query/export`, `mint-service-token` in the image | `src/cli/` |
| O10 * | 2 | Admin API: OpenAPI doc, `POST /admin/v1/explain` (why denied), grants `expires_at`, batch apply, YAML∪DB export/diff, `GET /admin/v1/audit/calls` NDJSON (reads audited) | `transport/admin/`, `authz/effective.rs`, migration for `expires_at` (pg + mysql) |
| O11 | 2 | Helm chart / kustomize base: grace ≥ 130 s, native `sleep` preStop, HTTPS probes, startupProbe, restricted securityContext, NetworkPolicy, ServiceMonitor | `deploy/`, spec 09, 11 |
| O12 | 3 | `roles` generator + `doctor` (print-only SQL; live privilege diff: superuser, writable read role, missing tables). MUST #3 | `config/yaml/roles.rs:19` |
| O13 | 3 | Config ergonomics: `Database.connect_name`, server-level defaults, `databases: [..]`, named constraint profiles, `except:`, `user:` subjects (*) | `config/schema/`, `exec/pg/config.rs:33` |
| O14 | 3 | `/healthz`+`/readyz` on the internal listener; cancel-pool size config; per-grant write rate limit (*) ; device flow RFC 8628 (*) | `startup/metrics.rs:100`, `pg/mod.rs:79`, `transport/oauth/` |

## Tests
- O1 golden output; O3/O4 scrape test past the idle window (paused time); O6 two-replica login e2e; O10 audit rows per route.

## Done when
- Operator validates a config in CI without secrets, sees pool saturation per database, runs two replicas without sticky sessions.
