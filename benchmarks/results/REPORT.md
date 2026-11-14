# Benchmark run report

Invocation log for the committed evidence in this directory. Invocations
1–3 (shared KVM host, 2026-11-04) produced `postgres.json`, `mongo.json` and
`instances4.json`; invocations 4–9 (bare-metal workstation, 2026-11-14,
appended at the end under "Quiet-host runs") produced `postgres-quiet.json`,
`mongo-quiet.json`, `instances4-quiet.json` and `postgres-write-quiet.json` (committed as `.json.gz`).
The host table, dirty-tree caveat, credentials and limitations sections
directly below describe invocations 1–3. One section per `gateway_overhead.sh`
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
  faster than the first baseline); with a 38.8% drift between the two
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

---

# Quiet-host runs — 2026-11-14

Invocations 4–9 below re-ran the harness on a different host from invocations
1–3: a bare-metal workstation with no hypervisor and zero CPU steal. Each was
wrapped in a capture script that snapshotted `/proc/loadavg` and the `cpu`
line of `/proc/stat` (whose 8th column is steal) immediately before and after,
took the dev-DB lock, and logged stdout+stderr verbatim. The `--out` path
pointed at a session scratch directory, shown below as `<scratch>/`; the
published files are byte-for-byte copies of those outputs under the names
given per invocation. Nothing else in the captures is altered.

## Host, toolchain, revision

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor (8 cores / 16 threads), bare metal |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| CPU frequency | `amd-pstate-epp` driver, `powersave` governor, `balance_performance` EPP — not pinned |
| CPU steal since boot | 0.0000% in every artifact; steal column 0 in every before/after snapshot |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 |
| Revision | `4639295bb23b…` — clean tree for invocations 4–7; **dirty** for 8–9 (see below) |

**Not an isolated box.** The workstation ran a desktop session (browser,
editor, chat client, other agent sessions) during every run — roughly 5–10%
of total CPU in `top` between runs, on 16 hardware threads. No hypervisor
steal, but not a dedicated benchmark machine either. Load generator,
gateway(s), state DB and target DBs all ran on this one host.

**Dirty tree for invocations 8–9.** During those runs the working tree held
(a) this change's harness edits under `benchmarks/` (the per-instance
`METRICS_BIND`, the `postgres-write` backend and its bench-config server) and
(b) uncommitted CI/workflow/deployment-doc edits made concurrently by
another session (`.dockerignore`, `.github/workflows/*`, `bin/ci`,
`website/docs/deployment/releasing.md`, `website/docs/initial-idea/09-deployment.md`).
Neither touches `src/`, so the release gateway binary measured is the
`4639295` gateway code.

**State DB note.** Every gateway boot logged `schema was migrated by a newer
gateway release; running on it as a rollback` (applied 19, known 18): the
shared dev state DB had been migrated by a newer build from another branch.
The gateway ran on it as designed; the warning is reproduced in each capture.

## Invocation 4 — exploratory postgres run, harness defaults — not published

- Command (repository root): `./benchmarks/gateway_overhead.sh --mysql-rejection --out <scratch>/pg-default.json`
- Exit status: **0**; wall time 247s (includes the cargo build step)
- Host before 2026-11-14T03:32:43Z: loadavg `1.56 7.67 5.32`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:36:50Z: loadavg `9.71 10.65 7.29`, `/proc/stat` steal column `0`

First run on this host, started right after a cold release build. Its `range_scan` row drifted 33.6%. Recorded because it ran; its figures are not quoted on the published page.

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-14T03:36:33.904545Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:36:33.904563Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:36:33.972249Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:36:34.000258Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway::startup::serve"}
-- measuring (backend=postgres queries=2000 concurrent=8 warmup=200 instances=1)
seeding 50000 rows…
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 0.605ms
  gateway…      p50 6.285ms
  direct (2/2)… p50 0.621ms
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 2.405ms
  gateway…      p50 8.221ms
  direct (2/2)… p50 1.597ms
  WARNING: baseline drifted 33.6% between runs — the host did not hold still, treat this shape's delta as indicative only
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… p50 5.613ms
  gateway…      p50 13.103ms
  direct (2/2)… p50 5.581ms
── mysql rejection ──
  boot rejected: true, runtime backstop: true, verdict: PASS
### Environment

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor |
| Virtualization | unknown |
| CPU steal since boot | 0.0000% |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 @ `4639295bb23b` |
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
| SELECT one row by primary key | direct | 0.61ms | 0.98ms | 1.38ms | 2000 |
| | **gateway** | **6.29ms** | **16.71ms** | **21.36ms** | 2000 |
| SELECT 1000 rows over an indexed range | direct | 2.41ms | 4.20ms | 5.14ms | 2000 |
| | **gateway** | **8.22ms** | **22.80ms** | **33.81ms** | 2000 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 5.61ms | 6.31ms | 7.82ms | 2000 |
| | **gateway** | **13.10ms** | **26.60ms** | **34.15ms** | 2000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| SELECT one row by primary key | +5.68ms | +15.73ms | +19.98ms | 10.38× | 2.6% | yes |
| SELECT 1000 rows over an indexed range | +5.82ms | +18.60ms | +28.67ms | 3.42× | 33.6% | **no** |
| COUNT + SUM aggregate over 50k rows, one row returned | +7.49ms | +20.29ms | +26.34ms | 2.33× | 0.6% | yes |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 12268 | — | — | — |
| | **gateway** | **1042** | 28.6 MiB | 1.21 | 3 |
| SELECT 1000 rows over an indexed range | direct | 3066 | — | — | — |
| | **gateway** | **765** | 34.0 MiB | 2.20 | 3 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 1538 | — | — | — |
| | **gateway** | **529** | 34.4 MiB | 1.14 | 5 |

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

raw results → <scratch>/pg-default.json
```

## Invocation 5 — exploratory postgres re-run, harness defaults — not published

- Command (repository root): `./benchmarks/gateway_overhead.sh --mysql-rejection --out <scratch>/pg-default-2.json`
- Exit status: **0**; wall time 12s (includes the cargo build step)
- Host before 2026-11-14T03:37:36Z: loadavg `5.24 9.37 7.01`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:37:48Z: loadavg `5.10 9.12 6.97`, `/proc/stat` steal column `0`

Same command, build already cached. Baselines still drifted 16–18% on two shapes. Per-shape phases at the default 2000 requests last well under two seconds for the direct path, so a sub-second wobble in the host moves a sub-millisecond p50 by more than 5%. Decision taken after this run, before the next: measure every published shape at `--queries 20000 --warmup 2000` (10× longer phases), one run each, and publish whatever comes out.

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-14T03:37:37.089160Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:37:37.089466Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:37:37.099439Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:37:37.105528Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway::startup::serve"}
-- measuring (backend=postgres queries=2000 concurrent=8 warmup=200 instances=1)
seeding 50000 rows…
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 0.396ms
  gateway…      p50 4.927ms
  direct (2/2)… p50 0.391ms
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 0.962ms
  gateway…      p50 6.340ms
  direct (2/2)… p50 1.130ms
  WARNING: baseline drifted 17.5% between runs — the host did not hold still, treat this shape's delta as indicative only
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… p50 3.603ms
  gateway…      p50 8.953ms
  direct (2/2)… p50 4.192ms
  WARNING: baseline drifted 16.4% between runs — the host did not hold still, treat this shape's delta as indicative only
── mysql rejection ──
  boot rejected: true, runtime backstop: true, verdict: PASS
### Environment

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor |
| Virtualization | unknown |
| CPU steal since boot | 0.0000% |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 @ `4639295bb23b` |
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
| SELECT one row by primary key | direct | 0.40ms | 0.48ms | 0.54ms | 2000 |
| | **gateway** | **4.93ms** | **5.85ms** | **7.32ms** | 2000 |
| SELECT 1000 rows over an indexed range | direct | 0.96ms | 1.27ms | 1.61ms | 2000 |
| | **gateway** | **6.34ms** | **8.60ms** | **11.76ms** | 2000 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 3.60ms | 5.69ms | 6.04ms | 2000 |
| | **gateway** | **8.95ms** | **11.27ms** | **13.33ms** | 2000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| SELECT one row by primary key | +4.53ms | +5.37ms | +6.78ms | 12.43× | 1.4% | yes |
| SELECT 1000 rows over an indexed range | +5.38ms | +7.33ms | +10.15ms | 6.59× | 17.5% | **no** |
| COUNT + SUM aggregate over 50k rows, one row returned | +5.35ms | +5.59ms | +7.29ms | 2.49× | 16.4% | **no** |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 20033 | — | — | — |
| | **gateway** | **1586** | 28.0 MiB | 0.72 | 2 |
| SELECT 1000 rows over an indexed range | direct | 7787 | — | — | — |
| | **gateway** | **1179** | 33.0 MiB | 1.30 | 2 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 1914 | — | — | — |
| | **gateway** | **867** | 33.6 MiB | 0.85 | 3 |

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

raw results → <scratch>/pg-default-2.json
```

## Invocation 6 — postgres overhead + MySQL boot-rejection → `postgres-quiet.json`

- Command (repository root): `./benchmarks/gateway_overhead.sh --mysql-rejection --queries 20000 --warmup 2000 --out <scratch>/pg-20k.json`
- Exit status: **0**; wall time 92s (includes the cargo build step)
- Host before 2026-11-14T03:38:04Z: loadavg `4.26 8.74 6.88`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:39:36Z: loadavg `8.79 9.05 7.16`, `/proc/stat` steal column `0`
- Artifact: [postgres-quiet.json.gz](postgres-quiet.json.gz) (committed gzipped)

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-14T03:38:05.438569Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:38:05.438592Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:38:05.448427Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:38:05.454617Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway::startup::serve"}
-- measuring (backend=postgres queries=20000 concurrent=8 warmup=2000 instances=1)
seeding 50000 rows…
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 0.426ms
  gateway…      p50 4.931ms
  direct (2/2)… p50 0.460ms
  WARNING: baseline drifted 8.0% between runs — the host did not hold still, treat this shape's delta as indicative only
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 1.125ms
  gateway…      p50 6.278ms
  direct (2/2)… p50 1.067ms
  WARNING: baseline drifted 5.2% between runs — the host did not hold still, treat this shape's delta as indicative only
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… p50 3.680ms
  gateway…      p50 8.822ms
  direct (2/2)… p50 3.313ms
  WARNING: baseline drifted 10.0% between runs — the host did not hold still, treat this shape's delta as indicative only
── mysql rejection ──
  boot rejected: true, runtime backstop: true, verdict: PASS
### Environment

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor |
| Virtualization | unknown |
| CPU steal since boot | 0.0000% |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 @ `4639295bb23b` |
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
| Requests per phase | 20000 |
| Warmup requests | 2000 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `point_lookup` | 10 |
| Row cap — `range_scan` | 2000 |
| Row cap — `aggregate` | 10 |

### Latency

Every row: same postgres query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 0.43ms | 0.51ms | 0.62ms | 20000 |
| | **gateway** | **4.93ms** | **6.35ms** | **10.86ms** | 20000 |
| SELECT 1000 rows over an indexed range | direct | 1.12ms | 1.57ms | 1.91ms | 20000 |
| | **gateway** | **6.28ms** | **8.65ms** | **11.66ms** | 20000 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 3.68ms | 5.75ms | 6.13ms | 20000 |
| | **gateway** | **8.82ms** | **10.97ms** | **13.19ms** | 20000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| SELECT one row by primary key | +4.51ms | +5.84ms | +10.24ms | 11.58× | 8.0% | **no** |
| SELECT 1000 rows over an indexed range | +5.15ms | +7.08ms | +9.75ms | 5.58× | 5.2% | **no** |
| COUNT + SUM aggregate over 50k rows, one row returned | +5.14ms | +5.21ms | +7.06ms | 2.40× | 10.0% | **no** |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 18361 | — | — | — |
| | **gateway** | **1543** | 29.8 MiB | 10.56 | 15 |
| SELECT 1000 rows over an indexed range | direct | 6676 | — | — | — |
| | **gateway** | **1190** | 36.0 MiB | 22.64 | 19 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 1895 | — | — | — |
| | **gateway** | **907** | 36.1 MiB | 10.31 | 25 |

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

raw results → <scratch>/pg-20k.json
```

## Invocation 7 — mongo overhead → `mongo-quiet.json`

- Command (repository root): `./benchmarks/gateway_overhead.sh --backend mongo --queries 20000 --warmup 2000 --out <scratch>/mongo-20k.json`
- Exit status: **0**; wall time 460s (includes the cargo build step)
- Host before 2026-11-14T03:40:03Z: loadavg `5.95 8.32 6.98`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:47:43Z: loadavg `8.21 7.57 7.15`, `/proc/stat` steal column `0`
- Artifact: [mongo-quiet.json.gz](mongo-quiet.json.gz) (committed gzipped)

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Mongo
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-14T03:40:04.171040Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:40:04.171060Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:40:04.180924Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:40:04.187966Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway::startup::serve"}
-- measuring (backend=mongo queries=20000 concurrent=8 warmup=2000 instances=1)
seeding 50000 documents…
── mongo_point_find ── mongo find by _id, one document returned
  direct (1/2)… p50 0.198ms
  gateway…      p50 4.954ms
  direct (2/2)… p50 0.233ms
  WARNING: baseline drifted 17.6% between runs — the host did not hold still, treat this shape's delta as indicative only
── mongo_range_find ── mongo find over the indexed _id range, 1000 documents
  direct (1/2)… p50 2.438ms
  gateway…      p50 8.633ms
  direct (2/2)… p50 2.310ms
  WARNING: baseline drifted 5.3% between runs — the host did not hold still, treat this shape's delta as indicative only
── mongo_aggregate ── mongo $match + $group aggregate, one document returned
  direct (1/2)… p50 36.198ms
  gateway…      p50 69.006ms
  direct (2/2)… p50 35.575ms
### Environment

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor |
| Virtualization | unknown |
| CPU steal since boot | 0.0000% |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 @ `4639295bb23b` |
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
| Requests per phase | 20000 |
| Warmup requests | 2000 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `mongo_point_find` | 10 |
| Row cap — `mongo_range_find` | 2000 |
| Row cap — `mongo_aggregate` | 10 |

### Latency

Every row: same mongo query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| mongo find by _id, one document returned | direct | 0.20ms | 0.25ms | 0.31ms | 20000 |
| | **gateway** | **4.95ms** | **5.72ms** | **7.71ms** | 20000 |
| mongo find over the indexed _id range, 1000 documents | direct | 2.44ms | 3.03ms | 3.90ms | 20000 |
| | **gateway** | **8.63ms** | **10.64ms** | **12.73ms** | 20000 |
| mongo $match + $group aggregate, one document returned | direct | 36.20ms | 54.45ms | 61.78ms | 20000 |
| | **gateway** | **69.01ms** | **75.34ms** | **82.08ms** | 20000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| mongo find by _id, one document returned | +4.76ms | +5.47ms | +7.40ms | 25.04× | 17.6% | **no** |
| mongo find over the indexed _id range, 1000 documents | +6.20ms | +7.61ms | +8.84ms | 3.54× | 5.3% | **no** |
| mongo $match + $group aggregate, one document returned | +32.81ms | +20.89ms | +20.29ms | 1.91× | 1.7% | yes |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| mongo find by _id, one document returned | direct | 39161 | — | — | — |
| | **gateway** | **1570** | 30.7 MiB | 8.19 | 15 |
| mongo find over the indexed _id range, 1000 documents | direct | 3229 | — | — | — |
| | **gateway** | **875** | 41.7 MiB | 40.12 | 26 |
| mongo $match + $group aggregate, one document returned | direct | 206 | — | — | — |
| | **gateway** | **114** | 41.6 MiB | 9.22 | 193 |

### Not measured

- absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and the database, so the throughput reported above is what the whole box managed, not what the gateway alone can serve
- horizontal scaling as a scaling law — adding gateway instances to a host that is already saturated measures contention, not scaling; the scaling section above is labelled as such and needs a separate load host to become a scaling result
- multi-host or multi-region behaviour — one host, one set of cores, one database
- write-path overhead — both targets are read-only here (the postgres role is read-only and the mongo adapter runs a read-only rejector), so a write grant's overhead is not covered
- TLS termination cost — the bench gateway runs with TLS disabled

raw results → <scratch>/mongo-20k.json
```

## Invocation 8 — four gateway instances

- Command (repository root): `./benchmarks/gateway_overhead.sh --instances 4 --queries 20000 --warmup 2000 --out <scratch>/inst4-20k.json`
- Exit status: **1**; wall time 2s (includes the cargo build step)
- Host before 2026-11-14T03:47:43Z: loadavg `8.21 7.57 7.15`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:47:45Z: loadavg `8.21 7.57 7.15`, `/proc/stat` steal column `0`

**Attempt 1 — harness bug, no artifact written.** Every instance tried to open its `/metrics` listener on the default `METRICS_BIND` (`127.0.0.1:9090`); all but one failed to boot and the runner exited 1. Fixed in `gateway_overhead.sh` (each instance now gets `METRICS_BIND=127.0.0.1:<9899+i>`), then retried below. The earlier `instances4.json` predates the dedicated metrics listener, which is why it never hit this.

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
-- booting gateway on 127.0.0.1:8900
-- booting gateway on 127.0.0.1:8901
-- booting gateway on 127.0.0.1:8902
{"timestamp":"2026-11-14T03:47:44.504839Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.504866Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.504955Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.504968Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.505092Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.505109Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.505362Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:47:44.505373Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
Error: failed to bind METRICS_BIND 127.0.0.1:9090: Address already in use (os error 98)
Error: failed to bind METRICS_BIND 127.0.0.1:9090: Address already in use (os error 98)
Error: failed to bind METRICS_BIND 127.0.0.1:9090: Address already in use (os error 98)
{"timestamp":"2026-11-14T03:47:44.516541Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:47:44.522113Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8900","target":"db_mcp_gateway::startup::serve"}
gateway on port 8899 exited during boot
```

## Invocation 8 — four gateway instances (retry) → `instances4-quiet.json`

- Command (repository root): `./benchmarks/gateway_overhead.sh --instances 4 --queries 20000 --warmup 2000 --out <scratch>/inst4-20k.json`
- Exit status: **0**; wall time 144s (includes the cargo build step)
- Host before 2026-11-14T03:48:28Z: loadavg `4.29 6.62 6.84`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:50:52Z: loadavg `6.63 6.64 6.82`, `/proc/stat` steal column `0`
- Artifact: [instances4-quiet.json.gz](instances4-quiet.json.gz) (committed gzipped)

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
-- booting gateway on 127.0.0.1:8900
-- booting gateway on 127.0.0.1:8901
-- booting gateway on 127.0.0.1:8902
{"timestamp":"2026-11-14T03:48:29.494780Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.494811Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.494943Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.494962Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.495154Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.495170Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.495261Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.495273Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:48:29.504415Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:48:29.506343Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:48:29.507935Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:48:29.509611Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:48:29.509978Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway::startup::serve"}
{"timestamp":"2026-11-14T03:48:29.511481Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8900","target":"db_mcp_gateway::startup::serve"}
{"timestamp":"2026-11-14T03:48:29.513598Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8901","target":"db_mcp_gateway::startup::serve"}
{"timestamp":"2026-11-14T03:48:29.515707Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8902","target":"db_mcp_gateway::startup::serve"}
-- measuring (backend=postgres queries=20000 concurrent=8 warmup=2000 instances=4)
seeding 50000 rows…
WARNING: working tree is dirty; the recorded commit does not identify this run
── point_lookup ── SELECT one row by primary key
  direct (1/2)… p50 0.434ms
  gateway…      p50 4.798ms
  direct (2/2)… p50 0.402ms
  WARNING: baseline drifted 7.2% between runs — the host did not hold still, treat this shape's delta as indicative only
── range_scan ── SELECT 1000 rows over an indexed range
  direct (1/2)… p50 1.059ms
  gateway…      p50 6.166ms
  direct (2/2)… p50 1.019ms
── aggregate ── COUNT + SUM aggregate over 50k rows, one row returned
  direct (1/2)… p50 3.498ms
  gateway…      p50 8.668ms
  direct (2/2)… p50 3.392ms
── horizontal scaling ── 4 instance(s) on one host
  1 instance(s): http://127.0.0.1:8899/mcp
  2 instance(s): http://127.0.0.1:8899/mcp, http://127.0.0.1:8900/mcp
  3 instance(s): http://127.0.0.1:8899/mcp, http://127.0.0.1:8900/mcp, http://127.0.0.1:8901/mcp
  4 instance(s): http://127.0.0.1:8899/mcp, http://127.0.0.1:8900/mcp, http://127.0.0.1:8901/mcp, http://127.0.0.1:8902/mcp
  driving: http://127.0.0.1:8899, http://127.0.0.1:8900, http://127.0.0.1:8901, http://127.0.0.1:8902
  1 instance(s): 1642 req/s, p50 4.79ms
  2 instance(s): 1643 req/s, p50 4.79ms
  3 instance(s): 1645 req/s, p50 4.80ms
  4 instance(s): 1639 req/s, p50 4.79ms
  (contention on a single shared host — the load generator, the gateway instances and the database share the same cores, so this is not a scaling law)
### Environment

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor |
| Virtualization | unknown |
| CPU steal since boot | 0.0000% |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 @ `4639295bb23b` (dirty) |
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
| Requests per phase | 20000 |
| Warmup requests | 2000 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `point_lookup` | 10 |
| Row cap — `range_scan` | 2000 |
| Row cap — `aggregate` | 10 |

### Latency

Every row: same postgres query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 0.43ms | 0.57ms | 0.80ms | 20000 |
| | **gateway** | **4.80ms** | **5.05ms** | **6.70ms** | 20000 |
| SELECT 1000 rows over an indexed range | direct | 1.06ms | 1.54ms | 1.94ms | 20000 |
| | **gateway** | **6.17ms** | **8.26ms** | **9.57ms** | 20000 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 3.50ms | 5.30ms | 5.66ms | 20000 |
| | **gateway** | **8.67ms** | **10.69ms** | **12.57ms** | 20000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| SELECT one row by primary key | +4.36ms | +4.47ms | +5.90ms | 11.06× | 7.2% | **no** |
| SELECT 1000 rows over an indexed range | +5.11ms | +6.72ms | +7.63ms | 5.82× | 3.8% | yes |
| COUNT + SUM aggregate over 50k rows, one row returned | +5.17ms | +5.39ms | +6.91ms | 2.48× | 3.0% | yes |

> Rows marked **no** had baseline drift above 5% or non-zero errors. The host moved during the run; treat those deltas as indicative only.

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| SELECT one row by primary key | direct | 17442 | — | — | — |
| | **gateway** | **1637** | 94.7 MiB | 10.35 | 14 |
| SELECT 1000 rows over an indexed range | direct | 7011 | — | — | — |
| | **gateway** | **1218** | 101.1 MiB | 23.82 | 19 |
| COUNT + SUM aggregate over 50k rows, one row returned | direct | 1989 | — | — | — |
| | **gateway** | **912** | 101.4 MiB | 10.52 | 25 |

### Horizontal scaling

> **contention on a single shared host — the load generator, the gateway instances and the database share the same cores, so this is not a scaling law** — these rows do not publish a scaling law.

| Instances | URLs used | req/s | p50 | p95 | p99 | errors |
|---|---|---|---|---|---|---|
| 1 | 1 | 1642 | 4.79ms | 4.99ms | 6.69ms | 0 |
| 2 | 2 | 1643 | 4.79ms | 4.99ms | 6.75ms | 0 |
| 3 | 3 | 1645 | 4.80ms | 5.16ms | 5.93ms | 0 |
| 4 | 4 | 1639 | 4.79ms | 5.01ms | 6.59ms | 0 |

### Not measured

- absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and the database, so the throughput reported above is what the whole box managed, not what the gateway alone can serve
- horizontal scaling as a scaling law — adding gateway instances to a host that is already saturated measures contention, not scaling; the scaling section above is labelled as such and needs a separate load host to become a scaling result
- multi-host or multi-region behaviour — one host, one set of cores, one database
- write-path overhead — both targets are read-only here (the postgres role is read-only and the mongo adapter runs a read-only rejector), so a write grant's overhead is not covered
- TLS termination cost — the bench gateway runs with TLS disabled

raw results → <scratch>/inst4-20k.json
```

## Invocation 9 — write path — UPDATE through the write tier → `postgres-write-quiet.json`

- Command (repository root): `./benchmarks/gateway_overhead.sh --backend postgres-write --queries 20000 --warmup 2000 --out <scratch>/write-20k.json`
- Exit status: **0**; wall time 66s (includes the cargo build step)
- Host before 2026-11-14T03:53:46Z: loadavg `5.44 6.12 6.58`, `/proc/stat` steal column `0`
- Host after 2026-11-14T03:54:52Z: loadavg `5.66 6.14 6.56`, `/proc/stat` steal column `0`
- Artifact: [postgres-write-quiet.json.gz](postgres-write-quiet.json.gz) (committed gzipped)

After the run, the state DB held exactly 22000 `audit_calls` rows for `service:bench` on server `target-write` with `outcome = success` and `rows_affected = 1` — 2000 warmup + 20000 measured gateway requests, every one audited synchronously. `bench_writes` was absent from the target afterwards (`to_regclass` returned NULL): the harness dropped it.

```text
-- dev stack already running, leaving it up afterwards
-- waiting for Postgres
-- building release gateway + harness
-- booting gateway on 127.0.0.1:8899
{"timestamp":"2026-11-14T03:54:14.851488Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:54:14.851514Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"target-write","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:54:14.851516Z","level":"WARN","message":"target TLS is disabled: credentials and results cross the network in plaintext","server":"mongo","target":"db_mcp_gateway"}
{"timestamp":"2026-11-14T03:54:14.861020Z","level":"WARN","message":"schema was migrated by a newer gateway release; running on it as a rollback","store":"state DB","applied":19,"known":18,"target":"db_mcp_gateway::state::migrate"}
{"timestamp":"2026-11-14T03:54:14.866969Z","level":"WARN","message":"TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS.","addr":"127.0.0.1:8899","target":"db_mcp_gateway::startup::serve"}
-- measuring (backend=postgres-write queries=20000 concurrent=8 warmup=2000 instances=1)
seeding 50000 rows…
WARNING: working tree is dirty; the recorded commit does not identify this run
── write_update ── UPDATE one row by primary key, RETURNING it (query_write grant)
  direct (1/2)… p50 2.781ms
  gateway…      p50 7.904ms
  direct (2/2)… p50 2.804ms
dropping bench_writes…
### Environment

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor |
| Virtualization | unknown |
| CPU steal since boot | 0.0000% |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 @ `4639295bb23b` (dirty) |
| Backend measured | postgres-write |

Load generator, gateway and database all run on this one host — see the caveat below.

### Effective configuration

The configuration this run actually applied, so the numbers above can be interpreted without the command line. The row cap is the one the harness requested per shape; the gateway clamps it against the grant's own `row_limit` and its ceiling, so a shape capped below both is never truncated.

| | |
|---|---|
| Backend | postgres-write |
| Server | `target-write` |
| Database | `app` |
| Direct baseline database | `app` |
| Direct baseline target | `localhost:5434` |
| Concurrency | 8 |
| Requests per phase | 20000 |
| Warmup requests | 2000 |
| Statement timeout (harness client) | 30000 ms |
| Seed rows | 50000 |
| Row cap — `write_update` | 10 |

### Latency

Every row: same postgres-write query, same host, same moment, run directly against the database and through the gateway.

| Query | Path | p50 | p95 | p99 | n |
|---|---|---|---|---|---|
| UPDATE one row by primary key, RETURNING it (query_write grant) | direct | 2.78ms | 2.92ms | 3.04ms | 20000 |
| | **gateway** | **7.90ms** | **9.65ms** | **10.76ms** | 20000 |

### Added by the gateway

Differences *between the two distributions at each percentile* — not the percentile of per-request differences, which two independent runs cannot give you.

| Query | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| UPDATE one row by primary key, RETURNING it (query_write grant) | +5.12ms | +6.73ms | +7.72ms | 2.84× | 0.8% | yes |

### Throughput and resource use

Throughput is **completed requests per second on this host**, not an absolute capacity number: the load generator, the gateway and the database compete for the same cores, so this is what the whole box managed. Resource figures are the gateway process's own, sampled from `/proc` during the measured phase.

| Query | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| UPDATE one row by primary key, RETURNING it (query_write grant) | direct | 3307 | — | — | — |
| | **gateway** | **985** | 29.3 MiB | 10.31 | 23 |

### Not measured

- absolute capacity ceiling (qps) — the load generator shares CPU with the gateway and the database, so the throughput reported above is what the whole box managed, not what the gateway alone can serve
- horizontal scaling as a scaling law — adding gateway instances to a host that is already saturated measures contention, not scaling; the scaling section above is labelled as such and needs a separate load host to become a scaling result
- multi-host or multi-region behaviour — one host, one set of cores, one database
- TLS termination cost — the bench gateway runs with TLS disabled

raw results → <scratch>/write-20k.json
```

## Limitations of invocations 4–9

- **Drift still trips the guard.** Even with zero steal and 10× longer phases,
  the two direct baselines of several shapes disagreed by more than 5%; the
  harness marks those rows `Trustworthy: no` and they are published that way.
  The threshold was not changed. On sub-millisecond baselines a 5% band is a
  few tens of microseconds, which a desktop host with an unpinned CPU governor
  does not hold; the per-decile medians in the raw samples show the direct
  path wandering by that much within a single phase, while the gateway path
  stays flat.
- **One host.** Load generator, gateway(s) and databases share 16 hardware
  threads; reported req/s is what this box completed, not a ceiling.
- **Contention, not scaling.** Invocation 8 is labelled as such.
- **Not measured:** absolute capacity ceilings, multi-host or multi-region
  behaviour, TLS termination cost (TLS disabled), MySQL query behaviour (no
  adapter; only the boot-time rejection is verified).

Credential scan: before commit, every captured log and the four new JSON
artifacts were scanned for the service-token pattern (`dbmcp_svc_` + 64 hex)
and for the dev passwords; zero matches.
