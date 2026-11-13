# Gateway hardening + agent power sweep

## Goal

Make `db-mcp-gateway` correct, secure, efficient and more capable for its three audiences — humans and Claude Code (SSO), and headless agent platforms on service tokens in two tiers: **coding = read**, **devops = read + write** — and roll that out through the platform and both deployments. Source: nine code/architecture sweeps of this repo, a map of the three deployment and platform repos, and a read-only measurement of both production clusters, D1 and D2 (2026-11-12).

## Context

- **Stack.** Rust 2024, tokio, axum, sqlx 0.8 (Postgres + MySQL), mongodb 3.7, hand-rolled JSON-RPC over HTTP+SSE, serde-saphyr YAML validated at boot, Postgres state store. Gateway v1.6.0 in both clusters, one replica each.
- **Non-negotiables touched — all five.** The plan tightens them; it relaxes none:

| MUST | Gap found | Fixed in |
|---|---|---|
| 1 Credentials never leave | Scrubber misses bare service tokens, bearer headers, JSON-form passwords; target TLS unverified | 11, 10 |
| 2 Every call → audit row | Row written only after the target commit; lost on crash/shutdown; `sample_table`/`describe_schema` do not record the table; rejected calls leave no row | 04 |
| 3 Read-only by default | Parser is the only read-only gate (transaction is read-write); session state leaks across pooled connections; a truncated write is rolled back but reported as success | 05, 12 |
| 4 Synchronous audit | Single-phase, not the two-phase the spec claims; audit failure after the query ran; outcome differs from what the client saw | 04 |
| 5 Permissions by YAML or audited API | PATCH silently loosens constraints; service identities can receive in-band grants; YAML hot reload does not exist | 07, 10 |

- **Four repos.** This repo (01–13, 17), D1's infrastructure repo (14), D2's infrastructure repo (15), the platform's repo (16). Slices 14–16 follow the target repo's own rules (draft PRs, one stack per PR, GitOps only, `## Live test`).
- **Load reality (01).** D1 had 0 tool calls in 64 h; D2 ~9/day. Performance work is proven with `benchmarks/`, not production; resources are over-provisioned ~25–30×.
- **Reference patterns.**
  - `tests/tls_reload.rs` — shape for the SIGHUP config-reload test.
  - `tests/audit_dispatch_cancellation_real_db.rs:62,93` — poll-until-deadline instead of sleeps.
  - `tests/permissions_indexes_mysql.rs` — EXPLAIN-asserting index tests.
  - `src/transport/admin/users/handlers.rs:37-89` — data change + `permissions_audit` in one transaction.
  - `src/state/permissions/mysql/` — per-entity file split to mirror for `pg/`.
  - The platform's existing origin-gated privileged tools, proxied by its control plane — the shape for 16.
  - D1's existing read-only role-grant Job — the pattern for 14's write roles.
- **`(security review required)`**: slices 02 (steps 3–6), 04, 05, 06, 07, 08, 09 (auth/OAuth steps), 10, 11, 12. Reviewers look for: credentials in errors/logs, missing audit rows, authz bypass via constraint-merge edges, SQL injection / timeout bypass.

## Plan files (execute in order)

1. [`01-live-baseline.md`](01-live-baseline.md) — measured production numbers + benchmark baseline; every sizing decision cites it.
2. [`02-refactor-foundations.md`](02-refactor-foundations.md) — behaviour-preserving: shared test harness, outcome enum, tool context, SQL into `src/state/`, auth state into `src/auth/`, adapter trait, file splits (23 files > 300 LOC).
3. [`03-state-migrations.md`](03-state-migrations.md) — all state-DB migrations and their ordering vs the code that reads them.
4. [`04-audit-integrity.md`](04-audit-integrity.md) — intent row + reaper, shutdown drain, honest outcomes, record what was read, history pagination, sinks.
5. [`05-exec-safety.md`](05-exec-safety.md) — read-only transactions, connection reset, write-truncation fix, denylist, identity-checked cancel, byte cap, Mongo key allowlist.
6. [`06-exec-efficiency.md`](06-exec-efficiency.md) — config-sized lazy pools, eviction + password rotation, per-column decoder, actionable errors, single serialisation.
7. [`07-authz-permissions.md`](07-authz-permissions.md) — PATCH merge, service identities YAML-only, wildcard validation, locked admin writes, one-query loader, cross-replica invalidation.
8. [`08-auth-sessions.md`](08-auth-sessions.md) — 5xx vs 401, revoke-all + admin revoke, atomic refresh rotation, cache tombstones, session GC, JWKS.
9. [`09-transport.md`](09-transport.md) — separate budget for unauthenticated routes, timeouts, registration bounds, one request id, SSE, JSON-RPC error mapping.
10. [`10-config-reload-shutdown.md`](10-config-reload-shutdown.md) — real hot reload, shutdown drain, state-pool split, batched pruner, validation, verified target TLS, idle cost.
11. [`11-observability-scrubber.md`](11-observability-scrubber.md) — scrubber gaps, metric catalogue (writes, audit failures, shed), `/metrics` off the public listener.
12. [`12-agent-power.md`](12-agent-power.md) — per-database write role, upstream attribution, per-account limits, `rows_affected`/dry-run, `EXPLAIN ANALYZE` (read-only), `table_stats`/`db_activity`/`cancel_query`, Mongo introspection.
13. [`13-tests.md`](13-tests.md) — coverage holes, error-code golden, de-flake, properties, generative guard tests, two-replica tests, load gate.
14. [`14-infra-d1.md`](14-infra-d1.md) — D1: right-size, RW roles + sealed secrets, pgcat, two service accounts, alerts.
15. [`15-infra-d2.md`](15-infra-d2.md) — D2: wire the idle RO role, narrow the full-RW grant, two service accounts, metrics + alerts.
16. [`16-platform.md`](16-platform.md) — the platform: control-plane-proxied gateway tools, tier by origin, attribution headers, write gating.
17. [`17-devex-build-ci.md`](17-devex-build-ci.md) — one test binary, nextest, fast linker, warm CI cache, faster image build. **Independent track — may start first.**

**Ordering rules.** 01 → 02 → 03 are prerequisites. 04–11 may run in parallel after 02 (disjoint layers; 05 before 06; 04 before 09–11). 12 needs 04–07 and 10. A gateway release containing 05, 10, 11, 12 gates 14 and 15; in each infra repo secrets and roles merge **before** the config that references them. 16 goes last. 13 and 17 run alongside from the start. No worktrees — parallel agents work in the one checkout on disjoint files.

## Done when

- `bin/lint` clean, `bin/test` green three runs in a row, `bin/ci` green; no file in `src/` over 300 LOC; no `sqlx::query` outside `src/state/`.
- Audit: every tool path asserts a row in tests — success, `forbidden` on failed authz, `invalid_arguments`, `cancelled`, `abandoned`; killing the gateway mid-write leaves a reaped intent row; shutdown under load loses none.
- Read-only: a read grant cannot write even on a write-capable role; no session state survives a pooled connection; a write is never rolled back and reported as success.
- Tiers: a coding-tier token runs as the RO role and cannot write; a devops-tier token writes with reason, run id and `rows_affected` in the audit row — proven by live tests in both clusters.
- Reload: a merged YAML permission or service-account change takes effect on SIGHUP, atomically or not at all.
- Every spec file touched (`website/docs/initial-idea/02`–`08`, `12`, `14`), `CLAUDE.md` and `website/docs/{usage,deployment}/` describe what shipped, in the same PRs.
- Recorded before/after numbers: benchmark throughput and peak RSS (06), PR CI wall time and local `bin/test` time (17), pod requests vs measured usage (14, 15).
- Platform agents reach both gateways with no credential on any agent machine; older plans there marked superseded.

## Risks / open questions

Owner decisions (the plan states a recommendation; the executor must not guess past it):

| Decision | Recommendation | Where |
|---|---|---|
| DDL / migrations, multi-statement transactions, Mongo writes through the gateway | **Not planned** — spec 03 and spec 10 name them non-goals; "more power" is DML + introspection + attribution. Reopen only with a spec change | 12 step 11 |
| Which D1 databases are agent-writable | App DBs only; the IdP and password-vault databases stay read-only | 14 step 2 |
| Agent writes to D2's two financial databases (D2 grants them today) | Read-only for agents; write for named operators with `require_reason` | 15 step 4 |
| Intent row for every call or writes only | Every target-DB call; revisit if the benchmark shows the extra insert matters | 04 step 2 |
| Wildcard grant = config databases or registered databases | Config databases (current behaviour); fix spec 12 | 07 step 3 |
| MySQL permissions store | Read-only-provisioned; document, do not build an audited write path now | 07 step 10 |
| Human `devops` SSO group gets `query_write` | Not by default | 14 step 5 |

Risks to watch:

- **Upstream attribution is claimed, not verified.** `x-dbmcp-run-id` / `on-behalf-of` come from the token holder; the audit subject stays `service:<name>`. Never use them for authz.
- **Service-token exception (CLAUDE.md NEVER table).** 12 must preserve its four properties: synchronous audit as `service:<name>`, YAML-only configuration, one non-admin group, no in-band mint/revoke.
- **pgcat (D1).** Read-only transactions, `SET LOCAL`, `application_name` and cancel through a session-mode pool are unverified for writes; verify before 14 step 5 or connect directly.
- **Repeat of the July D1 outage** — config referencing an unsealed secret key crash-looped the gateway. Secrets first, dry-boot the config.
- **D2 tiers are not containment for the platform's cluster agent** — it is cluster-admin there by owner ruling.
- **Single replica + in-process login state.** A second replica needs 13 step 8 first.
- **Index drops** rest on no-traffic evidence; re-measure under load (01 finding 9).
- **Lock changes** (17 step 5, any dependency edit): `Cargo.lock` is what ships — re-resolve narrowly, sqlx pin and the `sqlx-sqlite` stub untouched, `bin/check-scrub-features` green.
- **D1 rolled during the inspection** from a ConfigMap change of unknown origin (01 finding 10) — identify it before editing that stack.
- Unverified dependency-internal claims to confirm while implementing: axum-server drops handler futures at the drain deadline; `metrics-exporter-prometheus` 0.18 upkeep; Mongo `$db` override; Yugabyte cancel/read-only parity.
