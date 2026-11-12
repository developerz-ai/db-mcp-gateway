# 04 — Audit integrity

> Part of [`overview.md`](overview.md). Depends on: 02, 03 (`0010`, `0011`). **`(security review required)`** — audit write path. Reviewers look for: any success path with no committed row, audit failure downgraded to a log, credentials/PII in rows.

Closes the gap between MUST #2/#4 and the code: the audit row is written once, **after** the target query commits.

## Files to change

- `src/tools/audit_dispatch/mod.rs:235,292` — `work.await` runs before `audit::log`; no row exists while the query runs. Add intent write before `work`.
- `src/tools/audit_dispatch/mod.rs:144` — fallback/cancelled row is a detached `tokio::spawn` in `Drop`; lost at shutdown (`src/main.rs:281,66`).
- `src/tools/audit_dispatch/mod.rs:243,327-334` — row says `success` when the client got `timeout`/`internal` because the audit write failed.
- `src/tools/audit_dispatch/mod.rs:105,222` — `outcome: String::new()` sentinel; `:211,271` `AuditRow` built twice.
- `src/tools/audit_dispatch/mod.rs:309`, `src/audit/mod.rs:91` — failure cause never logged.
- `src/tools/sample_table.rs:86-89`, `src/tools/describe_schema.rs:95` — `sql: None`; the table read is not recorded.
- `src/tools/mod.rs:116-125,249` + each tool's argument parse — rejected calls return before `audit_dispatch`.
- `src/audit/mod.rs:234-260` — history query: uncapped, swallowed decode errors (`:253,256-260,109`).
- `src/tools/get_query_history.rs:89-93` — `limit` up to 100 000.
- `src/audit/stream.rs:104,125-200` — syslog UDP: oversize rows dropped, DNS + socket per row.
- New `src/audit/reaper.rs`, `src/audit/drain.rs`.

## Steps

1. **Outcome type.** Replace scattered `&'static str` outcome literals and the empty-string sentinel with one `enum Outcome` in `src/audit/` (`Success`, `Forbidden`, `ForbiddenSql`, `InvalidArguments`, `Timeout`, `Cancelled`, `Abandoned`, `AuditUnavailable`, …) with `as_code()`. Stable codes stay as documented in `website/docs/initial-idea/03-mcp-tools.md`.
2. **Intent row.** Before any call that reaches a target DB, insert into `audit_call_intents`; failure → refuse dispatch with `audit_unavailable` (new stable code). After `work`, write the `audit_calls` completion row as today. Applies to reads and writes — decide after 01 whether the measured audit-insert latency justifies writes-only; record the decision in spec 07.
3. **Reaper.** `src/audit/reaper.rs`: under `pg_try_advisory_lock`, insert `audit_calls` rows with `outcome: abandoned` for intents older than `drain + statement ceiling + audit timeout` that have no completion; spawned from `src/startup.rs` beside the pruner.
4. **Drain.** `src/audit/drain.rs`: a `tokio_util::task::TaskTracker` in `AppState`; every detached audit/cancel/sink spawn (`audit_dispatch/mod.rs:144`, `src/exec/pg/cancel.rs:50`, `src/audit/stream.rs:128`, `src/authz/cache.rs:147,160`) goes through it. `main` closes and awaits it with a bound after `serve()` returns (wired in 10). Counter `audit_fallback_failures_total`.
5. **Client-visible outcome.** On audit-write failure the guard row records the code the client saw; the tool's own outcome moves to `error_message`. `tool_calls` metric follows the same value.
6. **Record what was read.** `sample_table`/`describe_schema` build the generated SQL (or validated `schema.table`) before the header and set `header.sql`; fix the false comments at `sample_table.rs:87` and `audit_dispatch/types.rs:33`.
7. **Rejected calls.** Route argument-deserialisation failures and unknown tool names through `audit_dispatch` with `invalid_arguments` and null server/database. 429/503 shed: log line + metric only (no state-DB write under overload) — state this carve-out in spec 03.
8. **History.** Ceiling ~1000 with keyset pagination on `(occurred_at, id)`; truncate `sql` in responses; cap stored `sql` bytes with `sql_truncated` (0014); propagate decode errors with `?` — no fabricated `Utc::now()`.
9. **Syslog sink.** Truncate to a safe datagram size with a marker; cache resolved address + socket; rate-limit the error log; `audit_stream_dropped_total`. Implement `sql_capture` (spec 07) or delete it from the spec — pick one, no half state.
10. Log `state::connect_error_class(&source)` (credential-free) on audit failure.
11. Spec: `07-logging-retention.md` (intent/completion/reaper, caps, sinks), `03-mcp-tools.md` (`audit_unavailable`, history pagination, shed carve-out), `02-architecture.md` two-phase wording, `CLAUDE.md` "Audit before response" row.

## Tests

- `tests/audit_dispatch_cancellation_real_db.rs`: state pool closed after work starts → intent row exists, reaper writes `abandoned`; abort dispatch then drain → `cancelled` row present; audit failure → row outcome equals client code.
- `tests/sample_table_real_db.rs`, `tests/describe_schema_real_db.rs`: `audit_calls.sql` contains the table.
- `tests/tool_dispatch_coverage.rs`: malformed args and unknown tool leave `invalid_arguments` rows.
- `tests/get_query_history_real_db.rs`: `limit: 100000` clamped; oversized SQL truncated; keyset page 2 has no overlap.
- `tests/audit_stream_real_db.rs`: 100 KB SQL row still delivers a truncated datagram.
- `bin/test`, `bin/lint`.

## Done when

- Killing the gateway between target commit and completion write leaves an intent row that the reaper turns into `abandoned`.
- No detached audit task outlives `main` un-awaited.
- Every tool path, including rejected ones, asserts an audit row in tests.
