# 06 — Exec efficiency and pools

> Part of [`overview.md`](overview.md). Depends on: 01 (measured pool/latency numbers), 05. **`(security review required)`** — SQL execution, credential loading.

Per-DB pools sized by config (CLAUDE.md convention, not true today), lazy and evictable; cheaper row decoding; useful errors.

## Files to change

- `src/exec/pg/mod.rs:57-58,67,101` — pool hard-coded 5 + 2 cancel; `src/config/schema.rs:80` `Database` has no pool field.
- `src/exec/mod.rs:90-128` — `OnceCell` slot never evicted; password baked into `PgConnectOptions` (`src/exec/pg/mod.rs:97-113`).
- `src/exec/pg/decode.rs:45-128` — per-cell type probing, `type_name.to_string()` per cell, NaN/±Inf → `null`.
- `src/exec/pg/decode.rs:18-30`, `src/exec/pg/mod.rs:105,111,178`, `src/exec/mongo/mod.rs:357`, `src/tools/audit_dispatch/outcome.rs:98-114` — target errors discarded, no log, everything is `syntax_error`.
- `src/exec/mongo/mod.rs:100-107,271,342` — no selection/connect timeout; row cap not pushed into the command; fabricated nulls.
- `src/tools/describe_schema.rs:65-68,196-202,230-232,254` — truncation invisible; `unwrap_or("")` shape.
- `src/exec/adapter.rs` — `DbAdapter::health`/`kind` unused, `ExecError::NotImplemented` never built.
- `src/transport/jsonrpc.rs:119-142`, `src/tools/audit_dispatch/outcome.rs:35-45` — result materialised ~4 times.

## Steps

1. **Pool config.** `Database.pool: { max_connections, min_connections, idle_timeout_s }` (optional, validated non-zero); server-level default; plumb into `PgAdapter::open` and the Mongo client options. `min_connections` default 0 — pools stay lazy: opened on first use, idle connections closed. Defaults come from 01, not from the current constants.
2. **Eviction.** `AdapterRegistry::evict(key)`; call it on auth failure at acquire (SQLSTATE `28P01`/`28000`) so the next call re-resolves the secret, and from config reload (10). Old pool closes after in-flight work. Covers the cancel pool and Mongo. Fixes the false "rotation works" claim at `src/config/secret.rs:8-10`.
3. **Negative cache for dead targets.** A failed pool open is cached for a short interval (a few seconds) so each request does not spend ~10 s retrying while holding a global permit; log `connect_error_class` once per interval.
4. **Decoder.** Build a per-column decoder once from `row.columns()` type info, dispatch by match per cell. Non-finite floats → strings (`"NaN"`, `"Infinity"`). Add `text[]`/`int[]`/`uuid[]`, `interval`, `inet`, enums (as text).
5. **Errors agents can act on.** For `sqlx::Error::Database` only: return SQLSTATE + the server's primary message; map `42501` → `permission_denied`, `42P01`/`42703` → `undefined_object` (new stable codes in spec 03); everything else stays opaque. `tracing::warn!` with SQLSTATE and error variant name (never `Display` of a connect error) at each discard point.
6. **Mongo.** `server_selection_timeout` + `connect_timeout`; inject `batchSize`/`limit` = `row_limit + 1`; missing `n` or BSON failure → typed error, not `Value::Null`.
7. **`describe_schema`.** Add `truncated` to `DescribeSchemaResult`, drop the trailing partial table; fix the `if let Some(_table)` binding.
8. **Single serialisation.** `Response.result` as `Box<RawValue>` (or generic) so a tool result is serialised once; keep wire shape byte-identical (golden test).
9. **Health.** Either wire `DbAdapter::health` into `/readyz` per spec 02:71 (non-blocking, cached ~1 s) or delete `health`, `kind`, `ExecError::NotImplemented` and fix the spec. Prefer delete — `/readyz` must not depend on target DBs.
10. Spec: `08-config.md` (`pool:`), `05-credentials.md` (rotation), `03-mcp-tools.md` (codes, NaN, arrays, `describe_schema.truncated`), `02-architecture.md` (health, pool sizing), `CLAUDE.md` Per-DB pools row if wording changes.

## Tests

- `tests/adapter_registry_concurrency.rs`: evict + reopen under concurrent callers; configured size honoured (`pool.size()` never exceeds it).
- `tests/secret_refs.rs`: open pool, `ALTER ROLE … PASSWORD`, rewrite the file, kill backends → next query succeeds.
- `tests/exec_run_query.rs`: `SELECT 'NaN'::float8, 'Infinity'::float4` not null; arrays decode; undefined column returns SQLSTATE + message; `tests/json_logging.rs` sees the warn line.
- `tests/mongo_timeout_real_db.rs`: unreachable host fails within the selection timeout.
- `src/transport/jsonrpc.rs` unit: wire-shape parity before/after `RawValue`.
- Benchmark: `benchmarks/` harness before/after on a 100k-row × 20-column result — record throughput and peak RSS in the PR.
- `bin/test`, `bin/lint`.

## Done when

- Pool size is a config value per `(server, database)`; an idle gateway holds zero target connections.
- Password rotation needs no restart.
- Peak RSS for the benchmark result drops versus the 01 baseline; number recorded.
