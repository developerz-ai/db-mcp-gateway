# 12 — Agent power: tiers, attribution, tools

> Part of [`overview.md`](overview.md). Depends on: 03 (`0014`), 04, 05, 06, 07, 10. **`(security review required)`** — new MCP tools, write path, service-token auth, config schema. Reviewers look for: a read tier reaching a write role, missing audit rows on new tools, unverified upstream identity treated as verified.

Three audiences: **humans + Claude Code** (SSO session), **headless agents** (agent platforms — service tokens), in two tiers: read (coding agents) and read+write (devops agents). More power is delivered inside the five non-negotiables, not around them.

## Files to change

- `src/config/schema.rs:80-94,147-181` — `Database` has one `role`; constraints are three keys; `ServiceAccount` has no limits.
- `src/exec/pg/config.rs:25`, `src/exec/mod.rs:90-128` — one pool per `(server, database)`.
- `src/auth/service_token.rs:162`, `src/transport/mod.rs:293-299`, `src/tools/audit_dispatch/types.rs:53-79` — identity and request context; only `reason` and `agent_client` carry caller context.
- `src/transport/limit.rs:36-41` — 16 per identity, constant.
- `src/exec/adapter.rs:76-81` — `ExecResult` has no rows-affected.
- `src/tools/explain.rs:154` — always `is_read_only`.
- `src/tools/mod.rs:161-237` — seven tools.
- `src/exec/mongo/rejector.rs:36` — four commands.
- `website/docs/initial-idea/{03,06,10,11,12,14}-*.md`, `website/docs/usage/`.

## Steps

1. **Separate write role per database.** `Database.write_role` + `write_password` (optional). Reads always use `role` in a read-only transaction (05); `Access::ReadWrite` uses a second pool keyed `(server, database, write)`. A `query_write` grant on a database without `write_role` fails boot validation. Result: the read tier can never reach a write-capable role, and the two tiers share one `servers:` entry — no duplicate-server workaround. Behaviour change (pre-v1, no shim): deployments that wired the RW role as `role` move it (15).
2. **Upstream attribution for service identities.** Headers `x-dbmcp-run-id` and `x-dbmcp-on-behalf-of` on service-token requests → `audit_calls.upstream_run_id` / `upstream_actor` (0014) and the dispatch span. Length/charset-capped, stored as *claimed* (unverified) and documented as such; ignored for SSO sessions, whose identity is verified. `service_accounts[].require_upstream: true` rejects calls without them (`invalid_arguments`). The audit subject stays `service:<name>` (CLAUDE.md NEVER table — the four preserved properties are untouched).
3. **Per-account limits.** `service_accounts[].max_concurrent_requests` (default 16) so a fleet behind one token is not capped at 16; global cap unchanged. `get_query_history` for a service identity filters by `upstream_run_id` when supplied, so agents sharing a token do not read each other's history by default.
4. **Write ergonomics.** `ExecResult.rows_affected` → response + `audit_calls.rows_affected`; `explain` accepts DML under a `query_write` grant (plain `EXPLAIN` does not execute); `tool_calls{access="write"}` (11). Optional `run_query` arg `dry_run: true` under a write grant: execute, report `rows_affected`, roll back, audit as `outcome: dry_run`.
5. **`explain` with `analyze: true`** — read statements only, inside the read-only transaction and the statement timeout. Spec 03 currently forbids ANALYZE because it executes; the read-only transaction is what makes it safe. Spec change required.
6. **Introspection tools** (each: `schema_read`, audited, read-only transaction, row/byte capped, no superuser):

| Tool | Returns | Notes |
|---|---|---|
| `table_stats` | size, row estimate, index sizes + scan counts, last vacuum/analyze, dead tuples | `pg_stat_user_tables`, `pg_stat_user_indexes`, `pg_total_relation_size` |
| `db_activity` | running queries of the gateway's own role: pid, state, duration, wait event, gateway request id | `pg_stat_activity` filtered to `current_user`; query text only for the caller's own requests |
| `cancel_query` | cancels a query by gateway `request_id` | only the caller's own identity; uses the `application_name` tag from 05 step 6; needs `query_read` on that database |

7. **Mongo parity.** `listCollections`, `listIndexes`; `sample_table` via `find` + limit; `describe_schema` via collection + index listing; top-level key allowlist from 05. Mongo writes stay out of scope (spec 12).
8. **Constraints.** Spec 06 lists `allowed_schemas`, `denied_tables`, `time_window`; code has none. Table-level scoping belongs to the target-DB role (a parser cannot see through views and functions): **remove** `allowed_schemas`/`denied_tables` from the spec, point to role grants. `time_window` stays roadmap.
9. **Result usability.** Arrays/intervals/enums/NaN (06); actionable SQLSTATE errors (06); byte cap + `truncated` (05); `x-request-id` everywhere (09).
10. **Docs.** `website/docs/usage/`: connect guides for Claude Code (SSO) and headless agents (service token + the two headers), tier table, write semantics. `website/docs/deployment/`: provisioning RO + RW roles (the gateway never does it — MUST #3), service-token mint/rotate.
11. **Explicitly not planned** (collide with stated non-goals; listed in overview §Risks as owner decisions): DDL/migrations through the gateway (spec 03, spec 10), multi-statement/explicit transactions, in-band approval UI (MUST #5), Mongo writes, in-band token mint.

## Tests

- `tests/run_query_e2e.rs`: read call on a database with `write_role` runs as `role` (`SELECT current_user`); write runs as `write_role`; `query_write` without `write_role` fails boot; `rows_affected` in response and audit; `dry_run` leaves no change and audits `dry_run`.
- `tests/service_tokens_e2e.rs`: upstream headers land in the audit row; `require_upstream` rejects without them (audit row `invalid_arguments`); headers ignored for an SSO session; per-account cap honoured; history filtered by run id.
- New `tests/introspection_tools_real_db.rs`: `table_stats`, `db_activity`, `cancel_query` — own-identity only, forbidden → audit `outcome: forbidden`, cancel produces the victim's `cancelled` row.
- `tests/explain_e2e.rs`: `analyze: true` on SELECT works, on DML → `forbidden_sql`; EXPLAIN of DML needs `query_write`.
- `tests/mongo_query_real_db.rs`: `listCollections`, sampling, schema.
- `tests/tool_dispatch_coverage.rs` covers every new tool. `bin/test`, `bin/lint`.

## Done when

- A coding-tier token provably cannot write (role-level, not parser-level); a devops-tier token can, with `rows_affected`, reason and run id on every row.
- Every new tool has an audit row on success, forbidden and invalid arguments.
- Specs 03, 06, 12, 14 and the usage docs describe exactly what shipped.
