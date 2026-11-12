# 05 — Exec safety

> Part of [`overview.md`](overview.md). Depends on: 02, 04 (outcome enum). **`(security review required)`** — SQL execution. Reviewers look for: read-only bypass, timeout bypass, cross-user connection state, credentials in errors.

Today the parser (`src/exec/sql_guard.rs`) is the only read-only gate, and pooled connections carry state between users.

## Files to change

- `src/exec/adapter.rs:46,76-81` — `ExecQuery`/`ExecResult`: no access mode, no rows-affected; `effective_timeout_ms(Some(0)) == 0`.
- `src/exec/pg/mod.rs:178` — `pool.begin()` opens a read-write transaction for every call.
- `src/exec/pg/mod.rs:253-262`, `src/exec/pg/truncate.rs:33` — truncation rolls back even for DML, response says success.
- `src/exec/pg/mod.rs:100-111` — no reset on release; `:215` persistent prepared statements for ad-hoc SQL.
- `src/exec/pg/mod.rs:209-230`, `src/exec/mongo/mod.rs:236-245` — no byte budget.
- `src/exec/pg/cancel.rs:50-58`, `src/exec/pg/mod.rs:67` — late cancel can hit a reused backend PID.
- `src/exec/sql_guard.rs:91-98` — `DENIED_FUNCTIONS` has six names; `:166` accepts `ExplainTable`.
- `src/exec/mongo/rejector.rs:75-86` — top-level command keys not allowlisted.
- `src/config/yaml.rs` validate + `src/transport/admin/grants/validation.rs` — zero constraints accepted.

## Steps

1. **Access mode on the query.** Add `access: Access` (`ReadOnly | ReadWrite`) to `ExecQuery`; `run_query` passes what authz decided (`src/tools/run_query.rs:164-173`); `explain`, `sample_table`, `describe_schema`, `list_databases` always `ReadOnly`.
2. **Read-only transaction.** For `ReadOnly`, first statement is `SET TRANSACTION READ ONLY` (alongside `SET LOCAL statement_timeout`). The guard becomes the second layer, not the only one.
3. **Write truncation.** For `ReadWrite` DML with `RETURNING` past `row_limit`: stop collecting, keep draining, **commit**, return capped rows + `truncated: true` + `rows_affected`. Never report success after a rollback. Reads keep `cancel_and_rollback`.
4. **Connection reset.** `PoolOptions::after_release`: `RESET ALL; SELECT pg_advisory_unlock_all()`; on failure discard the connection. Set `.persistent(false)` on ad-hoc user SQL so reset and cache do not fight. No `DISCARD ALL`.
5. **Denylist.** Add `set_config`, `pg_advisory_lock*`/`pg_try_advisory_lock*`, `pg_cancel_backend`, `pg_terminate_backend`, `query_to_xml*`, `cursor_to_xml`, `table_to_xml`, `database_to_xml`, `dblink*`, `pg_ls_*dir`, `pg_current_logfile`, `lo_*`/`lowrite`. Reject `Statement::ExplainTable`. Module doc: denylist is layer three behind DB role and read-only transaction.
6. **Identity-checked cancel.** `SET LOCAL application_name = '<request uuid>'` per transaction; cancel with `SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE pid = $1 AND application_name = $2`. Same tag is reused by `cancel_query` in 12.
7. **Byte budget.** Gateway constant next to the row ceiling (`src/tools/mod.rs:72`), e.g. 32 MiB of decoded `Value` per result; on overflow set `truncated`, take the step-3 path by access mode. Same budget in the Mongo cursor loop.
8. **Zero constraints.** `NonZeroU32` for `statement_timeout_ms` and `row_limit` at both edges (YAML validate, admin DTO); `effective_timeout_ms` clamps `.max(1)` as belt and braces.
9. **Mongo.** Per-command allowlist of top-level keys; reject any top-level `$…`, `lsid`, `txnNumber`, `autocommit`, `startTransaction`. Verify the `$db` behaviour against a second database in the dev stack before and after.
10. **Pool-acquire vs timeout.** Acquire outside the statement budget so a saturated pool returns `unavailable`, not `timeout` (`src/exec/pg/mod.rs:148-151`, spec 02:79).
11. Spec: `03-mcp-tools.md` (byte cap, write truncation, `rows_affected`), `05-credentials.md`, `06-permissions.md` (read-only transaction, zero rule), `12-dynamic-permissions.md` (Mongo key policy).

## Tests

- `tests/exec_run_query.rs`: 1-connection pool — `set_config('search_path',…)` in call 1 is gone in call 2; advisory lock released; wide rows truncate at the byte budget and the connection is reusable; `nextval`/`lo_from_bytea` under a read grant fail with no side effect.
- `tests/run_query_e2e.rs`: `UPDATE … RETURNING *` over the limit → DB state, response and audit row agree; `pg_terminate_backend` → `forbidden_sql` + audit row.
- `tests/cancellation_real_db.rs`: saturate the cancel pool, drop N futures, next query on the same pool succeeds.
- `src/exec/sql_guard.rs` unit tests: each denied family in projection, FROM and CTE position. Add `proptest`/fuzz target for the guard (13).
- `tests/mongo_query_real_db.rs`: `$db` pointing at a second database is rejected.
- `bin/test`, `bin/lint`.

## Done when

- A read grant cannot cause a write on a write-capable role (proven against the dev role, which is write-capable).
- No session state survives a connection's return to the pool.
- A write is never rolled back and reported as success.
