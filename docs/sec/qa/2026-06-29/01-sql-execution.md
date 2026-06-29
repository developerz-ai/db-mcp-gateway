# 01 — SQL Execution & MCP Tools (Query Path)

Scope: `src/exec/{mod,adapter,pg,sql_guard}.rs`, `src/exec/mongo/{mod,rejector}.rs`, `src/tools/*`.

This layer carries the highest-severity findings. The three High findings all defeat `sql_guard`, the AST-level read-only guard whose stated purpose (module doc, `sql_guard.rs:1-4`) is: *"if a DBA accidentally grants write privileges to the `*_ro` role, the gateway still refuses to send a write query."* They matter precisely when the target-DB role is over-privileged — i.e. when the primary defense has already failed.

---

## S1 — Writable CTE bypasses the read-only guard — **High**

**File:** `src/exec/sql_guard.rs:83-92`

```rust
fn check_query(query: &Query) -> Result<(), GuardError> {
    if !query.locks.is_empty() {
        return Err(GuardError::Locking);
    }
    Ok(())
}
```

`check_query` inspects **only** `query.locks`. It never walks `query.with` (the CTE list) or `query.body`. A data-modifying CTE parses (sqlparser 0.52.0, Postgres dialect) as a single `Statement::Query`, so it passes `check_statement` → `check_query` → `Ok`.

Verified allowed:
- `WITH x AS (INSERT INTO users VALUES (1) RETURNING id) SELECT * FROM x`
- `WITH x AS (UPDATE users SET a=1 RETURNING id) SELECT * FROM x`

(`DELETE` inside a CTE happens to be a parse error in 0.52, so that one variant is incidentally rejected — do not rely on it.)

**Exploit (via `run_query`):**
```sql
WITH x AS (INSERT INTO users(id,is_admin) VALUES (999,true) RETURNING id) SELECT * FROM x
```
If the `*_ro` role can write, this executes the INSERT. The guard — the layer designed for exactly this misconfiguration — does not stop it.

**Fix:** Recurse the whole `Query`. Reject any `SetExpr::Insert(_) | SetExpr::Update(_)` (and `Delete` once the parser supports it) found in `query.body` **or** in each `query.with.cte_tables[].query`. Walk set-operation arms and subqueries. Permit only `SetExpr::Select | SetExpr::Query | SetExpr::SetOperation | SetExpr::Values | SetExpr::Table`. Add regression tests mirroring the exploit strings above.

---

## S2 — `SELECT … INTO` bypasses the read-only guard — **High**

**File:** `src/exec/sql_guard.rs:83-92`

`Select` carries `into: Option<SelectInto>`; `check_query` never inspects it. Verified allowed: `SELECT * INTO new_table FROM users`. In Postgres this is DDL — it materializes a new table.

**Exploit (via `run_query`):** `SELECT * INTO exfil_copy FROM secrets`

**Fix:** In the same query-tree walk (S1), reject any `Select` whose `into.is_some()`.

---

## S3 — `EXPLAIN ANALYZE` executes; combined with S1 runs writes — **High**

**File:** `src/exec/sql_guard.rs:54`

```rust
Statement::Explain { statement, .. } => check_statement(statement),
```

The guard recurses into the EXPLAIN target but ignores the `analyze` flag. `EXPLAIN ANALYZE SELECT …` is intentionally allowed (test at `sql_guard.rs:143`), but `EXPLAIN ANALYZE` **executes** the plan. Combined with S1:

Verified allowed: `EXPLAIN ANALYZE WITH x AS (INSERT INTO users VALUES (1) RETURNING id) SELECT * FROM x` — parsed as `Statement::Explain`, recursed, `Ok`. `run_query` sends it verbatim and ANALYZE executes the INSERT.

The `explain` tool itself wraps with `EXPLAIN (FORMAT JSON)` (no ANALYZE), so it is safe — this is a **`run_query`** problem: `run_query` lets the caller supply `EXPLAIN ANALYZE …` directly.

**Fix:** Once S1/S2 are fixed the write is blocked at the CTE/INTO level regardless of EXPLAIN. Additionally consider rejecting `EXPLAIN ANALYZE` outright in the guard (match `analyze: true` in `Statement::Explain`), since ANALYZE side-effects are the documented worry and plain `EXPLAIN` is the safe form.

---

## S4 — No statement-timeout floor → unbounded query pins a pool connection (DoS) — **Medium**

**File:** `src/exec/pg.rs:91-99`, `:172-177`

```rust
} else {
    // `None` is the spec-06 "no constraint from this side" ...
    run_query_inner(&self.pool, &query).await
}
```

When the merged grant's `statement_timeout_ms` is `None`, there is **neither** a `tokio::time::timeout` **nor** a `SET LOCAL statement_timeout`. The row cap doesn't help: it bounds rows *returned*, not a query that blocks before yielding any.

**Exploit:** A grant with no `statement_timeout_ms` + `run_query` with `SELECT pg_sleep(1e9)` (or a heavy cartesian join). The streaming `.next().await` blocks indefinitely; each call pins one of `DEFAULT_POOL_MAX_CONNECTIONS = 5` connections. Five such calls starve every other user of that `(server, database)` — violating "one noisy user must not starve others."

**Fix:** Apply a gateway-wide default `statement_timeout` floor (the `pg.rs` comment nominates `authz::effective` as its home). At minimum, always wrap `run_query_inner` in a `tokio::time::timeout` using a configured ceiling even when the grant declined to set one.

---

## S5 — Client disconnect does not `pg_cancel_backend`; query continues server-side — **Medium**

**Files:** `src/exec/pg.rs:168-212`; inaccurate claim at `src/tools/audit_dispatch.rs:100-102`

The audit guard comment asserts *"`mongodb::Cursor` and `sqlx::Transaction` both kill their backend operation on drop."* For an in-flight long-running Postgres query this is not accurate — dropping the sqlx stream/transaction does not send a Postgres `CancelRequest`. The backend continues until it next writes to the (closed) socket or until `statement_timeout` fires. There is no `pg_cancel_backend` call anywhere in `src/exec/`. So on disconnect the real bound is `statement_timeout`, which per S4 may be `None` (unbounded).

The audit-row `outcome: cancelled` path works (`CancelledAuditGuard`); the **server-side query cancellation** the spec requires (CLAUDE.md: "Agent disconnect → … `pg_cancel_backend`") does not.

**Fix:** On future-drop, actively cancel — capture the backend PID (`SELECT pg_backend_pid()` on the held connection, or use sqlx's connection cancel handle) and issue `pg_cancel_backend(pid)` from a detached task, mirroring the detached audit write. Fix the comment in `audit_dispatch.rs`.

---

## S6 — Mongo rejector misses `$accumulator` (server-side JS) — **Medium**

**File:** `src/exec/mongo/rejector.rs:48`

```rust
const DENIED_OPERATORS: &[&str] = &["$out", "$merge", "$function", "$where"];
```

The deny list blocks `$function` and `$where` JS, but **`$accumulator`** — an aggregation operator that runs arbitrary server-side JavaScript — is not listed. It is valid inside an allowed `aggregate` command, which the executor dispatches.

**Exploit:**
```json
{"aggregate":"users","pipeline":[{"$group":{"_id":null,"x":{"$accumulator":{
  "init":"function(){...}","accumulate":"function(){...}","accumulateArgs":[],
  "merge":"function(){...}","lang":"js"}}}}],"cursor":{}}
```
Passes the rejector (`$accumulator` not denied, command is `aggregate`) and executes server-side JS — the same risk class `$function`/`$where` were added to close.

**Fix:** Add `$accumulator` to `DENIED_OPERATORS`. Strongly consider switching to an **allow-list** of operators, or at minimum enumerate every JS-capable operator for the supported server versions. The deny-list approach is one new server operator away from the next bypass.

---

## S7 — `pg_read_file` / `lo_export` pass the guard (function-blind) — **Low**

**File:** `src/exec/sql_guard.rs` (statement-level only)

Verified allowed: `SELECT pg_read_file('/etc/passwd')`. The guard is read-only at the *statement* level and does not inspect called functions. These require elevated server roles (`pg_read_server_files`, superuser), so a correctly least-privileged `*_ro` role blocks them at the DB. Defense-in-depth limitation, not an independent vuln — but if the read-only role is over-privileged (the same precondition as S1–S3), they are reachable. Consider a function denylist if you want the guard to be a true second layer here.

---

## Needs verification

- **Mongo `maxTimeMS` vs cumulative `getMore`** (`src/exec/mongo/mod.rs:130-171`): unlike the pg path, `MongoAdapter::execute` has no outer Tokio deadline and relies solely on injected `maxTimeMS`, which may not bound cumulative time across `getMore` round-trips when draining a large cursor. Verify mongo driver 3.7 semantics; if confirmed, wrap the drain in a `tokio::time::timeout`. (The module header doc "ships no execution" is stale — find/aggregate/count/distinct are live.)
- **Row cap bounds row count, not bytes** (`pg.rs:179-200`, `mongo/mod.rs:157-164`): a single huge row/document (`SELECT repeat('x', 1e9)`, multi-MB jsonb) is fully decoded into memory. With timeout `None` (S4) there's no bound at all. Likely acceptable for v1; consider an accumulated-byte ceiling. Not an injection issue.

---

## Controls verified correct (no action)

- **`describe_schema`** (`describe_schema.rs:207-219`): schema/table passed as bind params `$1`/`$2` into `information_schema.columns`. No identifier interpolation.
- **`sample_table`** (`sample_table.rs:189-198`): `is_safe_identifier` enforces `^[A-Za-z_][A-Za-z0-9_]*$` before interpolating into `"schema"."table"`; forbids `"`, `.`, `;`, whitespace, non-ASCII, so double-quote wrapping can't be escaped. `LIMIT` is a gateway-produced `u32`. No SQL injection.
- **Multi-statement `;` stacking**: rejected by statement-count check (`sql_guard.rs:42-46`).
- **`SELECT … FOR UPDATE/SHARE`**: rejected via `query.locks` (`sql_guard.rs:88`).
- **`COPY`, DDL, GRANT/REVOKE, transaction control, `SET`, `CALL`/`DO`**: rejected (`sql_guard.rs:58-79` + catch-all).
- **Row cap applied during streaming**, not after full materialization (`pg.rs:190-200`); `truncated` flag set correctly.
- **`SET LOCAL statement_timeout`** uses a `u32`, no interpolation (`pg.rs:172-176`); plus Tokio timeout when a timeout is set.
- **Mongo command allow-list + first-key selection**: `serde_json` built with `preserve_order` (Cargo.toml:34) so rejector and executor agree on the wire-first key; executor wires only `find/aggregate/count/distinct` (second allow-list), so even a rejector mismatch can't dispatch a write command. `$out`/`$merge`/`$function`/`$where` denied at any tree depth.
- **Audit-before-response chokepoint** and **cancelled-audit-row guard** (`audit_dispatch.rs`): audit write failure aborts the response; dropped futures still write `outcome: cancelled` via detached spawn. (Only the *server-side* cancellation claim is wrong — see S5.)
- **Credential redaction**: `PgAdapter`/`MongoAdapter` `Debug` and `ExecError::Display` carry no DSN/password; `list_servers`/`list_databases` use credential-free view types.
