# 01 — Live baseline (measured 2026-11-12 15:27–15:32 UTC)

> Part of [`overview.md`](overview.md). Depends on: none. Read-only measurement of both production deployments; the numbers every sizing decision in 06, 10, 14, 15 must cite. Re-measure after 16 puts agent traffic on the gateway.

D1 = developerz-ai (`db.developerz.ai`), D2 = tesote (`db-mcp.miamibeachstart.com`). Both run gateway v1.6.0, one replica.

## What was measured

| | D1 | D2 |
|---|---|---|
| Image | `sha-ef713d2` (DOCR, Image Updater) | v1.6.0 by digest |
| Pod memory | 8 Mi (2d15h old) – 18 Mi (fresh) | 19 Mi now; 30-day max 19.6 Mi, 7-day avg 10.6 Mi |
| Pod CPU | 1m | 1m; 7-day avg 0.18m, 5-min peak 0.44m |
| Requests / limits | 100m / 256 Mi; limit 512 Mi; no CPU limit | same |
| Node | worker-1: memory **requests 92 %** committed, limits 309 % | worker-7: requests 45 %, limits 131 % |
| Restarts / OOM | 0 | 0 in 30 d |
| PDB / HPA | none / none | `minAvailable: 0` (no-op) / none |
| Tool dispatches | **0 in 64 h of logs**; 0 audit inserts and 0 target-role statements since 2026-10-06 | 104 in 11.9 d, 3 users, ≤ 24/day |
| State DB size | 9.0 MB (`audit_calls` 68 rows) | 9.8 MB |
| State connections | 2 idle via pgcat (pool 10) | 1 idle, 7-day max 2 |
| Log level / volume | `info,db_mcp_gateway=debug`; 119 lines/h, 99.9 % two GC messages | `info`; 1.4 lines/h |
| App metrics scraped | ServiceMonitor exists; no read-only query verb | **not scraped at all** |
| TLS in pod | on (8443) | `TLS_DISABLED=true` (plain HTTP behind the tunnel) |

D2 `run_query` (79 calls): p50 13 ms, p95 100 ms, max 6 089 ms (two calls > 5 s — target-query time). Outcomes: 64 success, 8 `syntax_error`, 6 `forbidden`, 1 `forbidden_sql`. Targets: yugabyte/`tesote_ai` 42, `equipo_production` 17, `sales_production` 4.

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
| 10 | D1 Deployment rolled at 15:28:29Z (Reloader, ConfigMap `db-mcp-gateway-config` changed) during the inspection | measured; cause not identified | Not caused by the read-only inspection. Confirm who changed the ConfigMap before 14 |
| 11 | D1 `sessions`: reltuples 55, live 0, never analyzed | measured | 08 step 6 (GC) + autovacuum will fix; no action alone |

## Not measured

- D1: tool latency, audit-write latency, 7-day memory max (no read-only metrics verb); min/max `audit_calls.occurred_at` (`stats_reader` lacks permission — not escalated); pgcat pool counters.
- D2: any table-level state-DB detail and target-side statements — every DB verb in that repo runs as superuser; no `stats_reader` equivalent. Add one (role with `pg_read_all_stats` only) as part of 15 step 1 so the next baseline can be taken.

## Steps (for the executor)

1. Before sizing anything in 06/10/14/15, re-read this table; if agent traffic has started, re-measure with the same commands: D1 `bun scripts/k8s/pods.ts`, `bun scripts/k8s/logs.ts`, `bun scripts/db/stats.ts`; D2 `bin/k8s/kubectl.sh get|describe|top|logs`, `bun scripts/observability/query.ts`. Read-only verbs only; no secret values. Note: `stats.ts` and `query.ts` use `kubectl exec` internally (psql as `stats_reader`; an HTTP GET to Prometheus).
2. Capture a local benchmark baseline with `benchmarks/harness` (throughput, p50/p95/p99, peak RSS for a 100k × 20 result, state-DB round trips per call) on `main` before 04–06 land; store the numbers in this file.
3. Append each re-measurement as a dated table; never overwrite.

## Done when

- Every resource, pool-size and index decision in the plan cites a row here or a benchmark number.
- A post-rollout measurement (agent traffic present) is appended.
