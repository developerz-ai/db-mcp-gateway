# 01 — Live baseline (measured 2026-11-12 15:27–15:32 UTC)

> Part of [`overview.md`](overview.md). Depends on: none. Read-only measurement of both production deployments; the numbers every sizing decision in 06, 10, 14, 15 must cite. Re-measure after 16 puts agent traffic on the gateway.

D1 = the first production cluster, D2 = the second, each run by its own infrastructure repo. Both run gateway v1.6.0, one replica.

## What was measured

| | D1 | D2 |
|---|---|---|
| Image | `sha-ef713d2` (DOCR, Image Updater) | v1.6.0 by digest |
| Pod memory | 8 Mi (2d15h old) – 18 Mi (fresh) | 19 Mi now; 30-day max 19.6 Mi, 7-day avg 10.6 Mi |
| Pod CPU | 1m | 1m; 7-day avg 0.18m, 5-min peak 0.44m |
| Requests / limits | 100m / 256 Mi; limit 512 Mi; no CPU limit | same |
| Node | memory **requests 92 %** committed, limits 309 % | requests 45 %, limits 131 % |
| Restarts / OOM | 0 | 0 in 30 d |
| PDB / HPA | none / none | `minAvailable: 0` (no-op) / none |
| Tool dispatches | **0 in 64 h of logs**; 0 audit inserts and 0 target-role statements since 2026-10-06 | 104 in 11.9 d, 3 users, ≤ 24/day |
| State DB size | 9.0 MB (`audit_calls` 68 rows) | 9.8 MB |
| State connections | 2 idle via pgcat (pool 10) | 1 idle, 7-day max 2 |
| Log level / volume | `info,db_mcp_gateway=debug`; 119 lines/h, 99.9 % two GC messages | `info`; 1.4 lines/h |
| App metrics scraped | ServiceMonitor exists; no read-only query verb | **not scraped at all** |
| TLS in pod | on (8443) | `TLS_DISABLED=true` (plain HTTP behind the tunnel) |

D2 `run_query` (79 calls): p50 13 ms, p95 100 ms, max 6 089 ms (two calls > 5 s — target-query time). Outcomes: 64 success, 8 `syntax_error`, 6 `forbidden`, 1 `forbidden_sql`. Targets: the Yugabyte database 42, two Postgres app databases 17 and 4.

D1 state-DB statements for role `gateway` since 2026-10-06: `SELECT 1` (readyz) 641 501 calls; `DELETE FROM oauth_refresh_tokens WHERE expires_at <= now()` 106 937 calls as a seq scan (index never used); audit pruner DELETE 898 calls. No audit INSERT and no session query in the window.

## Findings that change the plan

| # | Finding | Kind | Consequence |
|---|---|---|---|
| 1 | Neither gateway has meaningful load; D1 has none | measured | Production cannot rank performance work. Priority is correctness, security, agent power and adoption (16); throughput/memory claims in 05/06 are proven with `benchmarks/`, not prod |
| 2 | Memory request is ~25–30× usage, on a D1 node 92 % committed on memory requests | measured | 14/15 step 1: lower the **request** (it is what costs); keep headroom in the limit until agent load is measured |
| 3 | Idle chatter is the whole workload: readyz hits the state DB every 5 s, refresh-token GC runs a DELETE every 30 s | measured | 09 step 11 (cache readyz), 10 step 10 (GC interval, log level) |
| 4 | D2: a state-DB DNS failure made the single pod unready for ~1 h (165 readyz warnings, 2026-10-31) | measured / outage length inferred | Readiness = state DB reachable, with one replica, is an outage amplifier. 10 step 3 + deployment docs; two replicas need 13 step 8 first |
| 5 | D2 runs `TLS_DISABLED=true` | measured | SIGHUP currently kills that process (`src/main.rs:284-321`) — 10 step 1 is a prerequisite for any reload-based workflow there |
| 6 | D2: 11 % of `run_query` calls are syntax errors, all reported as one opaque code | measured | 06 step 5 (SQLSTATE + message) is the highest-value agent-ergonomics fix |
| 7 | D2: one `audit pruner run failed`; state connections killed by an admin command three times, pool recovered | measured | 10 step 4 metrics; nothing alerts today |
| 8 | D2 has no gateway metrics, alerts or dashboard | measured | 15 step 1 |
| 9 | D1: 20 of 26 state-DB indexes never scanned, incl. `audit_calls` pkey | measured, weak (no traffic) | Do **not** drop on this evidence; 03 `0011`/`0015` drops wait for a re-measure under load |
| 10 | D1 Deployment rolled at 15:28:29Z (Reloader, gateway ConfigMap changed) during the inspection | measured; cause not identified | Not caused by the read-only inspection. Confirm who changed the ConfigMap before 14 |
| 11 | D1 `sessions`: reltuples 55, live 0, never analyzed | measured | 08 step 6 (GC) + autovacuum will fix; no action alone |

## Not measured

- D1: tool latency, audit-write latency, 7-day memory max (no read-only metrics verb); min/max `audit_calls.occurred_at` (`stats_reader` lacks permission — not escalated); pgcat pool counters.
- D2: any table-level state-DB detail and target-side statements — every DB verb in that repo runs as superuser; no `stats_reader` equivalent. Add one (role with `pg_read_all_stats` only) as part of 15 step 1 so the next baseline can be taken.

## Steps (for the executor)

1. Before sizing anything in 06/10/14/15, re-read this table; if agent traffic has started, re-measure with the same read-only verbs each infrastructure repo provides (pod status, logs, top, state-DB stats as `stats_reader`, Prometheus queries). No secret values. Note: the stats and Prometheus verbs use `kubectl exec` internally.
2. Capture a local benchmark baseline with `benchmarks/harness` (throughput, p50/p95/p99, peak RSS for a 100k × 20 result, state-DB round trips per call) on `main` before 04–06 land; store the numbers in this file.
3. Append each re-measurement as a dated table; never overwrite.

## Done when

- Every resource, pool-size and index decision in the plan cites a row here or a benchmark number.
- A post-rollout measurement (agent traffic present) is appended.

## Re-measurement 2026-11-13 (post-rollout, agent traffic present)

D1 on 2.0.3 (`sha-75ac3ab`), D2 on 2.0.3. Agent traffic: the platform's `db_*` tools (slice 16 live test), the coding / devops service accounts, slice 14/15 live tests. Read-only: Prometheus queries over 24 h, pod status, gateway history.

| Metric (D1, 24 h) | Value | Note |
|---|---|---|
| `query_duration_seconds` p50 / p95 | 15.8 ms / 45.4 ms | through pgcat |
| `audit_write_duration_seconds` p95 | 24.6 ms | two-phase (intent + completion) |
| Peak working set per pod | 20.0 MB | limit-sizing evidence for 14 step 1 (64Mi request holds) |
| Peak CPU (5 m rate) | 1 mcore | 20m request holds |
| `audit_abandoned_total`, `requests_shed_total` | 0 / 0 | no abandoned calls, no shedding |
| Restarts | 0 | after every 2.0.x roll |

`tool_calls` increases are understated: counters reset on each of the day's ~10 pod rolls.

| Check (D2) | Result |
|---|---|
| Yugabyte reset fix (2.0.1) | 0 `connection reset failed` warnings; Yugabyte read pool steady at 4 connections over 72 calls |
| 2.0.3 roll | migrations 15 + 16 applied, 0 restarts, 0 WARN/ERROR over 5 min |
| Attribution | every platform call carries `upstream_run_id` = task id; the platform's own audit row stores the gateway request id, which joins gateway audit rows |

### Benchmark baseline (step 2)

Captured after 04–06 landed (2.0.2, `1ff42f5`), not before — the dev box's target port was unavailable. CI load gate, `ubuntu-latest`, 4 vCPU, concurrency 8, 2000 requests/shape; full file `benchmarks/baselines/ci-ubuntu-latest-postgres.json` (#305).

| Shape | Direct p50 / p95 | Gateway p50 / p95 / p99 | Gateway req/s | Peak RSS |
|---|---|---|---|---|
| point_lookup | 1.0 / 1.6 ms | 5.5 / 8.2 / 9.7 ms | 1381 | 26 MiB |
| range_scan (2000 rows) | 3.5 / 5.1 ms | 9.3 / 13.9 / 18.3 ms | 764 | 28 MiB |
| aggregate | 11.7 / 19.1 ms | 16.5 / 24.2 / 28.6 ms | — | — |

Gateway overhead ≈ 4.5–6 ms p50 per call (auth + authz + two audit writes + JSON). Pre-hardening comparison is not available; future runs compare against this file.
