# Benchmark run report

Invocation log for the committed evidence in this directory: `postgres.json`,
`mongo.json`, `instances4.json`. One section per `gateway_overhead.sh`
invocation — the exact command, its exit status, and the harness's complete
captured output verbatim: stderr warnings included, nothing trimmed, nothing
retried away. The published page built on these artifacts is
[website/docs/benchmarks.md](../../website/docs/benchmarks.md); the method and
its countermeasures are documented in [benchmarks/README.md](../README.md).

Captured output was kept in gitignored scratch (`tmp/dz/*.log`) and is
reproduced here in full. Only this file and the three JSON artifacts are
committed. The `EXIT=` line each capture command appended to its log is not
part of the harness output and appears below only as the recorded exit
status. Every number in the JSONs was written by the harness; no figure
anywhere in this directory was hand-edited.

## Host, toolchain, revision

Identical for every invocation below (each JSON carries it in its
`environment` object):

| | |
|---|---|
| CPU | 8 × Intel(R) Xeon(R) CPU E5-2630L v3 @ 1.80GHz, KVM |
| Memory | 31.3 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS / 6.8.0-147-generic |
| CPU steal since boot | 10.43% – 10.46% across attempts — a shared host |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v1.6.0 |
| Revision | `230d04bb0eada97adaa2a7f6c08e687c52b18a23`, working tree **dirty** |

**Dirty-tree caveat.** The working tree was dirty during every run, so the
harness recorded the **base commit** `230d04bb0ea…` with `git_dirty: true`.
That hash identifies the code the release gateway binary was built from only
up to the uncommitted delta. The uncommitted delta was documentation and
evidence files only — nothing under `src/` or `benchmarks/harness/` — so the
measured binary corresponds to the base commit's gateway code.

## Invocation 1 — postgres overhead + MySQL boot-rejection → `postgres.json`

- Command (run from the repository root):
  `./benchmarks/gateway_overhead.sh --mysql-rejection --out benchmarks/results/postgres.json`
- Workload: harness defaults — 2000 measured requests per path per shape,
  concurrency 8, 200 warmup discarded, 1 gateway instance, backend
  `postgres`, database `app`
- Exit status: **0**
- Captured 2026-11-04; gateway booted 18:41:15Z
- Warnings (all reproduced verbatim below): 10.43% CPU steal since boot;
  dirty working tree; baseline drift above 5% on **all three shapes**
  (109.7%, 17.6%, 20.9%) → every delta row in this run is marked
  `Trustworthy: no`
- MySQL boot-rejection verdict: **PASS** (own report section, not a
  performance figure)
- Artifact: [postgres.json](postgres.json)

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-04T18:41:15.641027Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway"}
-- measuring (backend=postgres queries=2000 concurrent=8 warmup=200 instances=1)
seeding 50000 rows…
WARNING: 10.43% CPU steal since boot — this host shares cycles with other tenants and its percentiles describe them too.
WARNING: working tree is dirty; the recorded commit does not identify this run
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 5.564ms
  gateway…      p50 43.978ms
  direct (2/2)… p50 11.671ms
  WARNING: baseline drifted 109.7% between runs — the host did not hold still, treat this shape's delta as indicative only
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 53.106ms
  gateway…      p50 149.959ms
  direct (2/2)… p50 43.760ms
  WARNING: baseline drifted 17.6% between runs — the host did not hold still, treat this shape's delta as indicative only
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… p50 83.471ms
  gateway…      p50 151.536ms
  direct (2/2)… p50 66.049ms
  WARNING: baseline drifted 20.9% between runs — the host did not hold still, treat this shape's delta as indicative only
── mysql rejection ──
  boot rejected: true, runtime backstop: true, verdict: PASS
### Environment

| | |
|---|---|
| CPU | 8 × Intel(R) Xeon(R) CPU E5-2630L v3 @ 1.80GHz |
| Virtualization | kvm |
| CPU steal since boot | 10.4344% |
| Memory | 31.3 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS / 6.8.0-147-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v1.6.0 @ `230d04bb0ead` (dirty) |
| Backend measured | postgres |

Load generator, gateway and database all run on this one host — see the caveat below.

### Effective configuration

The configuration this run actually applied, so the numbers above can be interpreted without the command line. The row cap is the one the harness requested per shape; the gateway clamps it against the grant's own `row_limit` and its ceiling, so a shape capped below both is never truncated.

| | |
|---|---|
| Backend | postgres |
| Server | `target` |
| Database | `app` |
| Direct baseline database | `app` |
| Direct baseline target | `localhost:5434` |
| Concurrency | 8 |
| Requests per phase | 2000 |
| Warmup requests | 200 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `point_lookup` | 10 |
| Row cap — `range_scan` | 2000 |
| Row cap — `aggregate` | 10 |

### Latency

Every row: same postgres query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 5.56ms | 13.19ms | 18.47ms | 2000 |
| | **gateway** | **43.98ms** | **121.56ms** | **159.28ms** | 2000 |
| SELECT 1000 rows over an indexed range | direct | 53.11ms | 118.36ms | 161.18ms | 2000 |
| | **gateway** | **149.96ms** | **285.79ms** | **365.15ms** | 2000 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 83.47ms | 205.67ms | 273.76ms | 2000 |
| | **gateway** | **151.54ms** | **274.68ms** | **334.25ms** | 2000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| SELECT one row by primary key | +38.41ms | +108.37ms | +140.81ms | 7.90× | 109.7% | **no** |
| SELECT 1000 rows over an indexed range | +96.85ms | +167.42ms | +203.98ms | 2.82× | 17.6% | **no** |
| COUNT + SUM aggregate over 50k rows, one row returned | +68.07ms | +69.01ms | +60.49ms | 1.82× | 20.9% | **no** |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 1231 | — | — | — |
| | **gateway** | **150** | 26.1 MiB | 7.11 | 16 |
| SELECT 1000 rows over an indexed range | direct | 134 | — | — | — |
| | **gateway** | **49** | 30.7 MiB | 47.32 | 47 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 83 | — | — | — |
| | **gateway** | **50** | 30.9 MiB | 11.10 | 44 |

### MySQL query-target rejection

MySQL is **not** a query target in this gateway. This section records the verification of that fact — it is not a latency measurement and is deliberately kept out of the tables above.

| Check | Result |
|---|---|
| Boot-time rejection of `kind: mysql` | **rejected** |
| Runtime backstop maps to the stable `internal` code | **ok** |
| Rejection message | `invalid config: server `mysql-target` has kind `Mysql`, which has no query adapter yet (supported kinds: postgres, mongo)` |

### Not measured

- absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and the database, so the throughput reported above is what the whole box managed, not what the gateway alone can serve
- horizontal scaling as a scaling law — adding gateway instances to a host that is already saturated measures contention, not scaling; the scaling section above is labelled as such and needs a separate load host to become a scaling result
- multi-host or multi-region behaviour — one host, one set of cores, one database
- write-path overhead — both targets are read-only here (the postgres role is read-only and the mongo adapter runs a read-only rejector), so a write grant's overhead is not covered
- TLS termination cost — the bench gateway runs with TLS disabled

raw results → benchmarks/results/postgres.json
```

## Invocation 2 — mongo overhead → `mongo.json`

- Command (run from the repository root):
  `./benchmarks/gateway_overhead.sh --backend mongo --out benchmarks/results/mongo.json`
- Workload: same defaults as invocation 1, backend `mongo` against the dev
  stack's `target-mongo` (localhost:27018, database `app`); shapes
  `mongo_point_find`, `mongo_range_find`, `mongo_aggregate` over 50,000
  seeded documents
- Exit status: **0**
- Captured 2026-11-04; gateway booted 18:44:38Z
- Warnings (reproduced verbatim below): 10.44% CPU steal since boot; dirty
  working tree; baseline drift above 5% on **all three shapes** (30.3%,
  16.0%, 38.8%) → every delta row in this run is marked `Trustworthy: no`.
  The `mongo_aggregate` gateway deltas are *negative* (the gateway measured
  faster than the second baseline); with a 38.8% drift between the two
  baselines that is the host moving, not a gateway speedup
- Artifact: [mongo.json](mongo.json)

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Mongo
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-04T18:44:38.988390Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway"}
-- measuring (backend=mongo queries=2000 concurrent=8 warmup=200 instances=1)
seeding 50000 documents…
WARNING: 10.44% CPU steal since boot — this host shares cycles with other tenants and its percentiles describe them too.
WARNING: working tree is dirty; the recorded commit does not identify this run
── mongo_point_find ── mongo find by _id, one document returned
  direct (1/2)… p50 7.101ms
  gateway…      p50 30.383ms
  direct (2/2)… p50 4.950ms
  WARNING: baseline drifted 30.3% between runs — the host did not hold still, treat this shape's delta as indicative only
── mongo_range_find ── mongo find over the indexed _id range, 1000 documents
  direct (1/2)… p50 32.636ms
  gateway…      p50 69.124ms
  direct (2/2)… p50 27.427ms
  WARNING: baseline drifted 16.0% between runs — the host did not hold still, treat this shape's delta as indicative only
── mongo_aggregate ── mongo $match + $group aggregate, one document returned
  direct (1/2)… p50 563.307ms
  gateway…      p50 533.573ms
  direct (2/2)… p50 781.981ms
  WARNING: baseline drifted 38.8% between runs — the host did not hold still, treat this shape's delta as indicative only
### Environment

| | |
|---|---|
| CPU | 8 × Intel(R) Xeon(R) CPU E5-2630L v3 @ 1.80GHz |
| Virtualization | kvm |
| CPU steal since boot | 10.4406% |
| Memory | 31.3 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS / 6.8.0-147-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v1.6.0 @ `230d04bb0ead` (dirty) |
| Backend measured | mongo |

Load generator, gateway and database all run on this one host — see the caveat below.

### Effective configuration

The configuration this run actually applied, so the numbers above can be interpreted without the command line. The row cap is the one the harness requested per shape; the gateway clamps it against the grant's own `row_limit` and its ceiling, so a shape capped below both is never truncated.

| | |
|---|---|
| Backend | mongo |
| Server | `mongo` |
| Database | `app` |
| Direct baseline database | `app` |
| Direct baseline target | `localhost:27018` |
| Concurrency | 8 |
| Requests per phase | 2000 |
| Warmup requests | 200 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `mongo_point_find` | 10 |
| Row cap — `mongo_range_find` | 2000 |
| Row cap — `mongo_aggregate` | 10 |

### Latency

Every row: same mongo query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| mongo find by _id, one document returned | direct | 7.10ms | 33.24ms | 49.56ms | 2000 |
| | **gateway** | **30.38ms** | **72.45ms** | **93.09ms** | 2000 |
| mongo find over the indexed _id range, 1000 documents | direct | 32.64ms | 70.28ms | 89.09ms | 2000 |
| | **gateway** | **69.12ms** | **150.71ms** | **189.49ms** | 2000 |
| mongo $match + $group aggregate, one document returned | direct | 563.31ms | 965.68ms | 1151.74ms | 2000 |
| | **gateway** | **533.57ms** | **907.54ms** | **1090.62ms** | 2000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| mongo find by _id, one document returned | +23.28ms | +39.20ms | +43.53ms | 4.28× | 30.3% | **no** |
| mongo find over the indexed _id range, 1000 documents | +36.49ms | +80.43ms | +100.41ms | 2.12× | 16.0% | **no** |
| mongo $match + $group aggregate, one document returned | -29.73ms | -58.14ms | -61.12ms | 0.95× | 38.8% | **no** |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| mongo find by _id, one document returned | direct | 738 | — | — | — |
| | **gateway** | **229** | 26.4 MiB | 3.80 | 10 |
| mongo find over the indexed _id range, 1000 documents | direct | 221 | — | — | — |
| | **gateway** | **95** | 34.0 MiB | 21.57 | 24 |
| mongo $match + $group aggregate, one document returned | direct | 14 | — | — | — |
| | **gateway** | **14** | 33.6 MiB | 5.38 | 155 |

### Not measured

- absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and the database, so the throughput reported above is what the whole box managed, not what the gateway alone can serve
- horizontal scaling as a scaling law — adding gateway instances to a host that is already saturated measures contention, not scaling; the scaling section above is labelled as such and needs a separate load host to become a scaling result
- multi-host or multi-region behaviour — one host, one set of cores, one database
- write-path overhead — both targets are read-only here (the postgres role is read-only and the mongo adapter runs a read-only rejector), so a write grant's overhead is not covered
- TLS termination cost — the bench gateway runs with TLS disabled

raw results → benchmarks/results/mongo.json
```

## Invocation 3 — four gateway instances → `instances4.json`

### Attempt 1 — infrastructure failure, no artifact written

- Command (run from the repository root):
  `./benchmarks/gateway_overhead.sh --instances 4 --out benchmarks/results/instances4.json`
- Workload: same defaults as invocation 1 with four gateway processes on
  `127.0.0.1:8899`–`:8902`
- Exit status: **none — terminated (SIGTERM) mid-run**. The session driving
  the run was killed during the `aggregate` phase; the harness's EXIT trap
  tore down the gateways it had booted and no result JSON was written. No
  number from this attempt is published anywhere; the attempt is recorded
  here because failures are part of the evidence, and because the successful
  invocation below is a retry of it.
- Captured 2026-11-04; gateways booted 18:55:05Z, terminated ~18:56

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
-- booting gateway on 127.0.0.1:8900
-- booting gateway on 127.0.0.1:8901
-- booting gateway on 127.0.0.1:8902
{"timestamp":"2026-11-04T18:55:05.225828Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8901","target":"db_mcp_gateway"}
{"timestamp":"2026-11-04T18:55:05.266643Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8902","target":"db_mcp_gateway"}
{"timestamp":"2026-11-04T18:55:05.274945Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8900","target":"db_mcp_gateway"}
{"timestamp":"2026-11-04T18:55:05.335974Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway"}
-- measuring (backend=postgres queries=2000 concurrent=8 warmup=200 instances=4)
seeding 50000 rows…
WARNING: 10.45% CPU steal since boot — this host shares cycles with other tenants and its percentiles describe them too.
WARNING: working tree is dirty; the recorded commit does not identify this run
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 13.034ms
  gateway…      p50 56.557ms
  direct (2/2)… p50 18.374ms
  WARNING: baseline drifted 41.0% between runs — the host did not hold still, treat this shape's delta as indicative only
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 34.274ms
  gateway…      p50 111.150ms
  direct (2/2)… p50 22.595ms
  WARNING: baseline drifted 34.1% between runs — the host did not hold still, treat this shape's delta as indicative only
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… Terminated
```

### Attempt 2 — retry after the failure above, same command

- Command: unchanged —
  `./benchmarks/gateway_overhead.sh --instances 4 --out benchmarks/results/instances4.json`
- Exit status: **0**
- Captured 2026-11-04; gateways booted 19:05:03Z
- Warnings (reproduced verbatim below): 10.46% CPU steal since boot; dirty
  working tree; baseline drift 35.3% (`point_lookup`) and 79.8%
  (`range_scan`) → those delta rows are marked `Trustworthy: no`;
  `aggregate` drifted 3.2% and is the one `Trustworthy: yes` row in this
  whole evidence set
- Artifact: [instances4.json](instances4.json)

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
-- booting gateway on 127.0.0.1:8900
-- booting gateway on 127.0.0.1:8901
-- booting gateway on 127.0.0.1:8902
{"timestamp":"2026-11-04T19:05:03.639193Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway"}
{"timestamp":"2026-11-04T19:05:03.726835Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8901","target":"db_mcp_gateway"}
{"timestamp":"2026-11-04T19:05:03.758453Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8902","target":"db_mcp_gateway"}
{"timestamp":"2026-11-04T19:05:03.834171Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8900","target":"db_mcp_gateway"}
-- measuring (backend=postgres queries=2000 concurrent=8 warmup=200 instances=4)
seeding 50000 rows…
WARNING: 10.46% CPU steal since boot — this host shares cycles with other tenants and its percentiles describe them too.
WARNING: working tree is dirty; the recorded commit does not identify this run
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 11.484ms
  gateway…      p50 34.500ms
  direct (2/2)… p50 15.538ms
  WARNING: baseline drifted 35.3% between runs — the host did not hold still, treat this shape's delta as indicative only
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 13.526ms
  gateway…      p50 86.439ms
  direct (2/2)… p50 24.321ms
  WARNING: baseline drifted 79.8% between runs — the host did not hold still, treat this shape's delta as indicative only
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… p50 44.250ms
  gateway…      p50 60.645ms
  direct (2/2)… p50 45.660ms
── horizontal scaling ── 4 instance(s) on one host
  1 instance(s): http://127.0.0.1:8899/mcp
  2 instance(s): http://127.0.0.1:8899/mcp, http://127.0.0.1:8900/mcp
  3 instance(s): http://127.0.0.1:8899/mcp, http://127.0.0.1:8900/mcp, http://127.0.0.1:8901/mcp
  4 instance(s): http://127.0.0.1:8899/mcp, http://127.0.0.1:8900/mcp, http://127.0.0.1:8901/mcp, http://127.0.0.1:8902/mcp
  driving: http://127.0.0.1:8899, http://127.0.0.1:8900, http://127.0.0.1:8901, http://127.0.0.1:8902
  1 instance(s): 177 req/s, p50 42.69ms
  2 instance(s): 240 req/s, p50 27.46ms
  3 instance(s): 221 req/s, p50 30.97ms
  4 instance(s): 195 req/s, p50 36.65ms
  (contention on a single shared host — the load generator, the gateway instances and the database share the same cores, so this is not a scaling law)
### Environment

| | |
|---|---|
| CPU | 8 × Intel(R) Xeon(R) CPU E5-2630L v3 @ 1.80GHz |
| Virtualization | kvm |
| CPU steal since boot | 10.4591% |
| Memory | 31.3 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS / 6.8.0-147-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v1.6.0 @ `230d04bb0ead` (dirty) |
| Backend measured | postgres |

Load generator, gateway and database all run on this one host — see the caveat below.

### Effective configuration

The configuration this run actually applied, so the numbers above can be interpreted without the command line. The row cap is the one the harness requested per shape; the gateway clamps it against the grant's own `row_limit` and its ceiling, so a shape capped below both is never truncated.

| | |
|---|---|
| Backend | postgres |
| Server | `target` |
| Database | `app` |
| Direct baseline database | `app` |
| Direct baseline target | `localhost:5434` |
| Concurrency | 8 |
| Requests per phase | 2000 |
| Warmup requests | 200 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `point_lookup` | 10 |
| Row cap — `range_scan` | 2000 |
| Row cap — `aggregate` | 10 |

### Latency

Every row: same postgres query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 11.48ms | 33.34ms | 45.79ms | 2000 |
| | **gateway** | **34.50ms** | **76.86ms** | **184.83ms** | 2000 |
| SELECT 1000 rows over an indexed range | direct | 13.53ms | 27.67ms | 36.24ms | 2000 |
| | **gateway** | **86.44ms** | **180.35ms** | **225.93ms** | 2000 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 44.25ms | 89.88ms | 121.01ms | 2000 |
| | **gateway** | **60.65ms** | **151.41ms** | **186.18ms** | 2000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| SELECT one row by primary key | +23.02ms | +43.52ms | +139.04ms | 3.00× | 35.3% | **no** |
| SELECT 1000 rows over an indexed range | +72.91ms | +152.68ms | +189.68ms | 6.39× | 79.8% | **no** |
| COUNT + SUM aggregate over 50k rows, one row returned | +16.40ms | +61.53ms | +65.17ms | 1.37× | 3.2% | yes |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 569 | — | — | — |
| | **gateway** | **198** | 83.5 MiB | 5.51 | 11 |
| SELECT 1000 rows over an indexed range | direct | 524 | — | — | — |
| | **gateway** | **82** | 87.8 MiB | 33.05 | 28 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 164 | — | — | — |
| | **gateway** | **108** | 88.1 MiB | 7.31 | 22 |

### Horizontal scaling

> **contention on a single shared host — the load generator, the gateway instances and the database share the same cores, so this is not a scaling law** — these rows do not publish a scaling law.

| Instances | URLs used | req/s | p50 | p95 | p99 | errors |
|---|---|---|---|---|---|---|
| 1 | 1 | 177 | 42.69ms | 82.92ms | 108.98ms | 0 |
| 2 | 2 | 240 | 27.46ms | 74.46ms | 105.74ms | 0 |
| 3 | 3 | 221 | 30.97ms | 75.48ms | 96.47ms | 0 |
| 4 | 4 | 195 | 36.65ms | 84.61ms | 114.15ms | 0 |

### Not measured

- absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and the database, so the throughput reported above is what the whole box managed, not what the gateway alone can serve
- horizontal scaling as a scaling law — adding gateway instances to a host that is already saturated measures contention, not scaling; the scaling section above is labelled as such and needs a separate load host to become a scaling result
- multi-host or multi-region behaviour — one host, one set of cores, one database
- write-path overhead — both targets are read-only here (the postgres role is read-only and the mongo adapter runs a read-only rejector), so a write grant's overhead is not covered
- TLS termination cost — the bench gateway runs with TLS disabled

raw results → benchmarks/results/instances4.json
```

## Credentials

No credential, connection string, service token or password appears in any
block above or in any artifact in this directory. The runner mints a service
bearer token per invocation and passes it to the gateway and harness in the
environment only (`SERVICE_TOKEN_BENCH`) — never as a command-line argument,
never printed, never written to disk. Before this file was written, all
captured logs and all three JSON artifacts were scanned for the
service-token pattern (`dbmcp_svc_` followed by 64 hex characters): zero
matches. The dev credentials the bench configs hold are the ones already
public in `docker-compose.dev.yml`.

## Limitations

Read before quoting any number from this directory:

- **Shared host.** Load generator, gateway(s), state database and target
  database all ran on the same 8 vCPU KVM guest, which reported 10.43–10.46%
  CPU steal since boot during every attempt. The percentiles describe the
  neighbours too.
- **Drift.** The harness re-runs the baseline after the gateway phase and
  marks a row `Trustworthy: no` when the two baselines disagree by more than
  5%. Eight of the nine overhead rows measured here are marked **no**
  (drift 16.0% – 109.7%); only the `aggregate` row of invocation 3 (3.2%)
  passed the guard. Those rows are published as measured, with their
  marking — not dropped, not averaged away.
- **Contention, not scaling.** The `--instances 4` run measures how the load
  generator, four gateway processes and the database divide one host's
  cores. It is labelled as contention in the JSON, the Markdown output and
  the published page. A scaling result needs a separate load host.
- **Not measured at all:** absolute throughput ceilings, write-path overhead
  (bench grants are read-only), MySQL query behaviour (no mysql adapter —
  only the boot-time rejection is verified), multi-host or multi-region
  behaviour, TLS termination cost (bench gateway runs with TLS disabled).

Every run is reproducible with the commands recorded above; the harness
prints a Markdown report and writes a JSON file carrying the workload
definition, effective configuration, revision and raw per-request samples,
so any published percentile can be re-derived rather than taken on trust.
