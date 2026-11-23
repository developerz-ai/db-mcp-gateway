# 03 — Exec correctness

> Part of [`overview.md`](overview.md). Depends on: 02 (same files). Label: `security review required`.

## Files to change

| ID | Sev | Where | Defect → fix |
|---|---|---|---|
| E1 **V** | med | `src/exec/pg/run.rs:90-109,208` | Describe runs inside the write tx and its error is swallowed; an aborted tx then `COMMIT`s as rollback while the client and audit say `success`. Skip describe for `Access::ReadWrite`; for reads make it budgeted and never turn a finished read into `timeout` |
| E2 **R** | med | `src/exec/pg/tier.rs:130`, `pg/mod.rs:145`, `pg/methods.rs:76,87` | Write-tier cancel/activity looks only at this process's pool; cross-replica cancel answers "already finished". Always query the write tier's `cancel_pool` |
| E3 **V** | med | `src/exec/registry.rs:110-124` | Waiters on a dead target each re-run the open (5, 10, 15 s…). Recheck `failed_at` inside the init closure; assert total wall time for N waiters |
| E4 **R** | med | `src/exec/mongo/bson_json.rs:19` | Non-finite doubles → fabricated `null`. Canonical ExtJSON |
| E5 **R** | med | `src/exec/pg/decode/mod.rs:134` | `json/jsonb` numbers lose precision via f64. `RawValue` (feature already on, `Cargo.toml:59`) |
| E6 **R** | low | `decode/mod.rs:142,152` | `numeric` scale rounded to 4 / sci notation; NaN/Infinity → unsupported; `24:00:00` → `00:00:00`. Use `dscale`, plain string, special cases |
| E7 **R** | low | `decode/mod.rs:111` | `"char"`, `oid`, `reg*`, `name[]`, `bool[]`, `float8[]`, `numeric[]`, `timestamptz[]`, `timetz`, `tsvector`, `xml`, `money` unsupported → `pg_class` unusable. Add |
| E8 **R** | low | `src/exec/mongo/dispatch.rs:178`, `redis/error.rs:29`, `pg/error.rs:26` | Mislabels: Mongo 13 → `permission_denied`; Redis `LOADING/BUSY/MASTERDOWN/CLUSTERDOWN` → `unavailable`; 40001/40P01/25P03 → not `syntax_error`. A new code = public API (spec 03) |
| E9 **R** | low | `src/exec/mongo/mod.rs` `execute` | Pool wait counted in the statement budget; saturated pool reads as `timeout` |
| E10 **R** | low | `src/exec/redis/pool.rs:87` | No liveness check on idle conns. PING if idle > few s, or reconnect once (reads idempotent) |
| E11 **R** | low | `src/exec/pg/mod.rs:121,156` | Broken write credential fails/evicts the read tier. Lazy resolve, per-tier staleness (contract `tier.rs:73`) |
| E12 **P** | low | `src/exec/pg/truncate.rs` | Rollback failure after truncation: prove the connection is discarded, not reused |
| E13 **R** | low | `src/tools/run_query.rs:151`, `sample_table.rs:148` | `limit: 0` not rejected, spec 03:200 says `invalid_arguments` |

## Steps
1. E1 first (data-integrity lie), E3, E2; then decode rows as one PR; Mongo/Redis as another.
2. Spec 03 (type rendering table, codes) in the same PR.

## Tests
- Real PG/YB/Mongo/Redis/Dragonfly. Decode: round-trip table test per type, incl. specials. E1: inject describe failure on a write. E2: extend `two_replicas_real_db.rs`.

## Done when
- No result path can return a wrong value silently; unsupported types documented and marked.
