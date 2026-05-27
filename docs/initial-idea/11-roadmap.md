# 11 — Roadmap

Phased plan from skeleton to a deployable gateway. Each phase is mergeable independently and leaves the previous phase still working. Order is best-guess; phases 2 onward will shuffle once usage informs priorities.

## Phase 0 — Skeleton (this commit)

- Repo bootstrapped, CI green on an empty Rust workspace.
- Docs in `docs/initial-idea/` describe the target.
- CLAUDE.md spells out architecture, conventions, non-negotiables.
- License, README, .gitignore, Cargo workspace, basic GitHub Actions.

## Phase 1 — MCP transport + auth bones

- HTTP+SSE listener using the MCP server SDK (or hand-rolled JSON-RPC if SDK isn't ready).
- OIDC login flow, JWT verification, in-memory session cache.
- A single working tool: `list_servers` (returns config contents minus secrets).
- State DB with sessions table; migrations on startup.
- End-to-end test: agent connects, completes mock-OIDC login, calls `list_servers`.

## Phase 2 — First real DB tools

- Per-database Postgres connection pool with statement timeout + row cap.
- `list_databases`, `describe_schema`, `sample_table`, `run_query`, `explain`.
- Permission evaluation pipeline (groups × server × db × action).
- Audit log table + synchronous write on every tool call.
- Manual smoke test against a local Postgres.

## Phase 3 — Production readiness

- TLS by default, cert reload on SIGHUP.
- `/healthz`, `/readyz`, `/metrics`.
- Structured logging.
- Secrets references: `${ENV}`, Vault, AWS SM, GCP SM.
- Config validation with friendly errors at startup.
- Docker image build + push pipeline.

## Phase 4 — Audit retention + archive

- Hot retention pruner background task.
- S3 / GCS / Azure Blob archive exporter.
- SQL capture policies (`full` / `redacted` / `metadata_only`).
- Optional OTLP / syslog / stdout streaming sinks.

## Phase 5 — Beyond Postgres

- MySQL adapter.
- MSSQL adapter.
- BigQuery adapter (read-only is native here).
- Snowflake adapter.

Each adapter implements a small `DbAdapter` trait — pool, describe-schema, run-query, explain. Audit + permissions are engine-agnostic.

## Phase 6 — Reason capture + policy hooks

- `require_reason` enforcement end-to-end (tool returns `reason_required` error; agent prompts user; retries with reason).
- Per-grant constraints fully wired (`row_limit`, `statement_timeout_ms`, `allowed_schemas`, `denied_tables`, `time_window`).

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

- `query_write` action with explicit per-grant opt-in.
- Mandatory reason capture.
- Distinct audit log surfacing for writes.
- Optional pre-write review step (queued + approved by another user) — *maybe*; revisit when a customer actually asks.

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
