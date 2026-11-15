# 11 — Roadmap

Phased plan from skeleton to a deployable gateway. Each phase is mergeable independently and leaves the previous phase still working. Order is best-guess; phases 2 onward will shuffle once usage informs priorities.

## Phase 0 — Skeleton ✅ done (v0.1.0)

- Repo bootstrapped, CI green on an empty Rust workspace.
- Docs in `docs/initial-idea/` describe the target.
- CLAUDE.md spells out architecture, conventions, non-negotiables.
- License, README, .gitignore, Cargo workspace, basic GitHub Actions.

## Phase 1 — MCP transport + auth bones ✅ done (v0.1.0)

- HTTP+SSE listener (hand-rolled JSON-RPC; no stable MCP SDK at the time).
- OIDC login flow, JWT verification, in-memory session cache.
- A single working tool: `list_servers` (returns config contents minus secrets).
- State DB with sessions table; migrations on startup.
- End-to-end test: agent connects, completes mock-OIDC login, calls `list_servers`.
- **v0.2.0 addition:** MCP OAuth bridge (discovery, PKCE S256, authorization-code flow, refresh tokens) for agents that drive the OAuth dance without a browser.

## Phase 2 — First real DB tools ✅ done (v0.1.0)

- Per-database Postgres connection pool with statement timeout + row cap.
- `list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain`.
- Permission evaluation pipeline (groups × server × db × action).
- Audit log table + synchronous write on every tool call.
- Manual smoke test against a local Postgres.

## Phase 3 — Production readiness ✅ done (v0.1.1)

- TLS by default, cert reload on SIGHUP.
- `/healthz`, `/readyz`, `/metrics`.
- Structured logging.
- Secrets references: `${ENV}`, Vault, AWS SM, GCP SM.
- Config validation with friendly errors at startup.
- Docker image build + push pipeline.

## Phase 4 — Audit retention + archive (partial — see note)

- Hot retention pruner background task. **Done.**
- Streaming sinks (`logging.stream` in YAML): `stdout` and `syslog` **done**
  (#218) — `stdout` emits the full audit row as a `target: "audit_stream"`
  tracing event; `syslog` sends the same row as an RFC 5424 message over
  UDP, fire-and-forget. `otlp` remains unimplemented; the config parser
  rejects it.
- S3 / GCS / Azure Blob archive exporter. Not started.
- SQL capture policies (`full` / `redacted` / `metadata_only`). Not started.

## Phase 5 — Beyond Postgres (partial — see note)

- MongoDB adapter ✅ done (v0.2.0) — `DbAdapter` trait implemented; run_query wired; describe_schema (collections + indexes) and sample_table added in plan 101. Mongo stays read-only.
- Redis target ✅ shipped for the RESP family — `kind: redis` serves Redis 8, Valkey and Dragonfly (Redis and Dragonfly in CI, `redis:8.4-alpine` / `target-dragonfly` in the dev stack). `run_query` dispatches the JSON argv of one command through a deny-by-default read-only allowlist checked before any network I/O; replies are bounded by `row_limit` and the 32 MiB budget with `SCAN` `COUNT` clamped, `statement_timeout_ms` is enforced client-side with a cut-off connection closed rather than reused, and the connection is built from structured parts (host, port, ACL user, password, DB index) — never a URL. Key scoping is the target ACL user's `~` patterns; `role: default` is refused at boot; there is no write tier ([10](10-non-goals.md)). Remaining work: no `describe_schema` / `sample_table` / `explain` / `table_stats` / `db_activity` / `cancel_query` (all answer `unsupported_backend`), and KeyDB is not CI-tested.
- YugabyteDB (YSQL) ✅ tested as a `kind: postgres` target — prod-proven on 2.25.2.0-b359, and since 2.0.1 the connection reset falls back to `RESET ALL` alone when the server has no advisory locks. A dedicated CI job (`yugabyte`, gating image publishing; locally `bin/test-yugabyte`) runs the Postgres query-path integration suite against it: 92 pass, 2 excluded because YugabyteDB ignores `NOTIFY` (yugabyte-db#1872; the guard's denial of `pg_notify` stays unit-tested), and one large-object sub-case is skipped. Cancellation needs `host` to name a single tserver, not a load balancer ([03](03-mcp-tools.md#cancel_query)).
- MySQL adapter — **deferred post-1.0**. Config parses and validates, but dispatch returns `UnsupportedAdapter` at boot. See [note below](#mysql--mssql--deferred).
- MSSQL adapter — **deferred post-1.0**. Same status as MySQL.
- BigQuery adapter — not started.
- Snowflake adapter — not started.

Each adapter implements the `DbAdapter` trait ([12](12-dynamic-permissions.md#dbadapter-trait)) — `execute`, `describe_schema`, `sample`, `explain`, `table_stats`, `db_activity`, `cancel_request`, `is_stale`; a tool the engine cannot serve answers `unsupported_backend`. Audit + permissions are engine-agnostic.

### MySQL / MSSQL — deferred

Config schema accepts `kind: mysql` and `kind: mssql`, but as of v1.0.0 the dispatcher rejects these at boot with a typed `UnsupportedAdapter` error rather than silently failing at query time. Full adapter implementation is planned but has no committed timeline. The driver crates (`sqlx` MySQL, `tiberius`) are not yet in `Cargo.toml`.

## Phase 6 — Reason capture + policy hooks ✅ done (v0.2.0)

- `require_reason` enforcement end-to-end (tool returns `reason_required` error; agent prompts user; retries with reason).
- Per-grant constraints: `row_limit`, `statement_timeout_ms` and `require_reason` are wired; `time_window` (business hours only) is still to come. `allowed_schemas` / `denied_tables` are dropped — table scoping is the target-DB role's job ([06](06-permissions.md)).
- Dynamic permissions admin API — SSO-gated `/admin/*` endpoints for grant CRUD; all mutations audited synchronously to `permissions_audit`. See [12-dynamic-permissions](12-dynamic-permissions.md).

## Phase 7 — HA + multi-replica

- Two-replica deploys behind a load balancer.
- Session storage already in state DB → mostly free.
- Leader election for the retention pruner (don't run twice).
- Documented runbook for rolling restarts.

## Phase 8 — Operator ergonomics

- `gateway admin …` subcommands (revoke session, list active sessions, replay audit query).
- Helm chart with cert-manager integration.
- Example `docker-compose` repo polished.
- Provisioning SQL bundled and templated per engine.

## Phase 9 — Write mode

- `query_write` action with explicit per-grant opt-in ✅ — runs as a separate `write_role` per database; reads of the same caller stay on the read role.
- `rows_affected` in the response and `audit_calls.rows_affected` ✅; `dry_run` (execute, report, roll back; audited `dry_run`) ✅; `explain` of DML under `query_write` ✅; `tool_calls{access="write"}` ✅.
- Mandatory reason capture — available per grant (`require_reason`), not forced for writes.
- Optional pre-write review step — **not planned**: an in-band approval UI conflicts with MUST #5 ([10](10-non-goals.md)).

## Phase 10 — Agent power (plan 101, slice 12) ✅

- Upstream attribution for service tokens: `x-dbmcp-run-id` / `x-dbmcp-on-behalf-of` → `audit_calls.upstream_run_id` / `upstream_actor` (claimed, unverified); `require_upstream` per account ([14](14-service-tokens.md)).
- Per-account `max_concurrent_requests`; `get_query_history` filtered by run id for service identities.
- `explain` with `analyze: true` for reads; introspection tools `table_stats`, `db_activity`, `cancel_query` ([03](03-mcp-tools.md)).
- Mongo `describe_schema` (collections + indexes) and `sample_table` (`find` + limit).

## Later, maybe never

- Kubernetes operator (vs. plain Helm).
- SCIM for direct group sync (vs. OIDC claims).
- Browser-based audit log viewer (resists the temptation — see [10-non-goals](10-non-goals.md); this would be operator-only, not user-facing).
- Per-query approval workflow (write mode, sensitive tables).
- Query cost estimation + budget caps per user/group.

## Anti-roadmap

Things explicitly *not* on the roadmap, even with infinite time:

- SaaS hosted version.
- Customer dashboards.
- Natural-language-to-SQL inside the gateway.
- Multi-tenancy on one install.

See [10-non-goals](10-non-goals.md) for the reasoning.
