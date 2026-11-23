# 05 — Audit and state

> Part of [`overview.md`](overview.md). Depends on: 02. Label: `security review required`.

## Files to change

| ID | Sev | Where | Defect → fix |
|---|---|---|---|
| U1 **V** | med | `src/tools/audit_dispatch/mod.rs:141-173` | Completion insert fails after a committed write → "request rejected"; agent retries, double write. Append `WRITE_MAY_HAVE_COMMITTED` / structured `write` field (06-M4) |
| U2 **R** | med | `src/audit/reaper.rs:104`, `state/audit/intents.rs:145` | `abandoned` rows never reach sinks. `RETURNING` + `StreamSinks::send` |
| U3 **R** | low | `src/audit/stream/mod.rs:88` | stdout sink lacks `upstream_actor`, `upstream_run_id`, `rows_affected`, `sql_truncated`. Field-parity test against `AuditRow` |
| U4 **R** | low | `startup/boot.rs` `spawn_permissions_listener`, `config/env.rs:99` | Listener holds a request-pool conn; `STATE_DB_POOL_SIZE=1` deadlocks. Background pool (3) or ≥2 |
| U5 **R** | low | `list_servers.rs`, `list_databases.rs` | Success rows have NULL `elapsed_ms` |
| U6 **R** | med | `src/exec/pg/error.rs:95`, `startup/logging.rs:37` | Target-error log lines carry no request_id/server/tool (span output off). Put fields on the event |
| U7 **R** | med | `startup/boot.rs:30`, `state/mod.rs:48` | Single 5 s state-DB attempt then exit. Retry, not-ready meanwhile |
| U8 | med | `migrations/0002`, `0005` | Append-only by convention. Document split roles (runtime INSERT/SELECT, pruner DELETE); optional hash chain = separate design |
| U9 | med | `src/audit/stream/syslog.rs` | UDP only, stdout drops on full queue. TCP/TLS syslog |
| U10 | low | spec 07 | `sql` stored verbatim; capture policy never shipped (#218). Say so, or H10 |

## State migration
- None for U1–U7. U8 hash chain (if chosen): new `migrations/0022_*` additive, nullable; code reads after.

## Tests
- Integrity tests assert the write-message; reaper → sink e2e; parity test.

## Done when
- Every audit row reaches every sink with every field; spec 07 + `deployment/logging.md` match `src/audit/outcome.rs:56`.
