# 06 — Agent surface

> Part of [`overview.md`](overview.md). Depends on: 03, 05-U1. `security review required` for M6–M11. Public API: update spec 03 + `usage/` in each PR.

Current: `2025-06-18` only, ten static tools, no `instructions`, annotations, `structuredContent`; text-JSON results; `src/mcp/{protocol.rs,tool_list.rs}`.

## PR sequence

**PR1 — additive, S each**

| ID | Change | Where |
|---|---|---|
| M1 | `initialize.instructions`: logical names, call order, payload per kind (SQL / Mongo JSON / Redis argv), limits, `reason`, what to do on each code | `protocol.rs:31` |
| M2 | Tool text: payload shapes, defaults/ceilings (1000 rows, 100 000, 32 MiB, 30 s), tools per kind; fix `db_activity` false claim | `tool_list.rs:104,173` |
| M3 | `title`, `annotations` (`readOnlyHint` on the seven pure reads; not `run_query`/`explain`/`cancel_query`) | `protocol.rs:80` |
| M4 | Error body adds `retryable`, `hint`, `write: not_applied\|unknown\|applied`, `limit`, `elapsed_ms`; keep `code/message/request_id` | `audit_dispatch/outcome.rs:18`, `run_query.rs:199` |
| M5 | `forbidden`: same text for unknown and denied + "see list_servers / list_databases"; timeout message carries the value and points at `explain` | `target.rs:52`, `run_query.rs:29` |

**PR2 — errors that fix the next call**

| ID | Change | Where |
|---|---|---|
| M6 | Pass PG `POSITION` + `HINT` (role-redacted; never `DETAIL`) | `pg/error.rs:29`, `rejection.rs:37` |
| M7 | 42703/42P01: attach near-miss column/table names the caller may already describe | `describe` catalog path |
| M8 | Mongo code + `errmsg` redacted; malformed JSON → `invalid_arguments`; guard parse error carries line/col | `mongo/dispatch.rs:160`, `mongo/rejector/mod.rs:129`, `sql_guard` |

**PR3 — discovery in one call**

| ID | Change | Where |
|---|---|---|
| M9 | `list_databases.server` optional = all visible; `list_servers` inlines databases | `tool_list.rs:33`, `list_*.rs` |
| M10 | Per database: `actions`, `require_reason`, effective `row_limit`, `statement_timeout_ms`, `writes`, supported tools, kind; engine version cached from pool connect (no extra target call) | `authz/effective.rs`, `list_databases.rs:36` |
| M11 (H6) | `whoami`: identity, groups, session expiry, own grants. Audited, no target call | new tool |

**PR4 — results sized for a context window**

| ID | Change | Where |
|---|---|---|
| M12 | `truncated_by: limit\|grant_row_limit\|byte_cap`, effective `row_limit`, keyset guidance text | `run_query.rs:53`, `budget.rs`, `adapter.rs` `ExecResult` |
| M13 | Caller `max_bytes` (min-wins), per-cell cap with marker; `sample_table` column list | `budget.rs:17` |
| M14 | Column types beside names | `tabular.rs` |
| M15 | Concurrency budget headers; 429/503 as JSON-RPC error with `data.retry_after_s` (keep status + header) | `limit.rs:191` |

**PR5 — schema v2**: `describe_schema` `detail: names|columns|full`, `search`, schema list when empty; real types (`format_type`, enum labels, arrays), PK/FK/indexes with columns, comments, row estimate, relation kind; Mongo field inference from a bounded sample under `query_read`. `exec/pg/catalog.rs`, `tools/describe_schema/`. Bind values only. `ident.rs:12`: allow Mongo names with `-`/`.`.

**PR6 — power**: bind `params` (`exec/query.rs:25`; params stored in the audit row → migration), `explain` summary (cost, rows, seq scans), history `sql_sha256` + filter (per identity).

**3.0 (H5)**: `-32602` → `isError` with `request_id`; default limit 100; `structuredContent`/`outputSchema` for small-shape tools; accept `2025-11-25`.

Skip: resources, prompts, sampling, elicitation, tasks, SSE, `listChanged`.

## Tests
- Snapshot test of `tools/list` + `initialize`. e2e per code asserting body fields + audit row. Golden "agent walk" test: list → describe → typo → fix → truncated → timeout → forbidden.

## Done when
- Spec 03 §Errors matches reality (today it documents an HTTP shape that does not exist, `row_limit_exceeded`, `tags`); overview agent metrics hit.
