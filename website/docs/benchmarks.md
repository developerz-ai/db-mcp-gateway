# Benchmarks

db-mcp-gateway ships its own benchmark harness
([`benchmarks/gateway_overhead.sh`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/gateway_overhead.sh)):
it times the same query on the same host down two paths in sequential phases:
first straight at the database, then through the gateway's `run_query` MCP tool
with normal service-token authentication, normal authorization and the
synchronous audit write intact, then straight at the database again — the two
baselines bracketing the gateway phase are how the harness detects host drift.
Nothing is skipped: a benchmark of a build we do not ship would be worth less
than no benchmark.

This page publishes what the harness measured. Every figure below is quoted
from a committed run artifact — the raw JSON with the full per-request
samples, and [REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md),
the invocation log that records exactly how each artifact was produced,
warnings, failed attempts and exploratory runs included. Nothing here is
hand-derived. An earlier version of this page carried tables of numbers nobody
had measured; they were removed, and the discipline this page keeps —
publishing the caveats with the figures — is the reason.

**Read [How much to trust these numbers](#how-much-to-trust-these-numbers)
before quoting any table.** The figures below come from a bare-metal host with
zero CPU steal, but six of the ten gateway-overhead rows still carry the
harness's own `Trustworthy: no` marking, and they are published that way
rather than dropped, averaged away, or re-run until they looked better.

## What the harness measures

Baseline → gateway → baseline again, per query shape, with the two baselines
compared to detect host drift (>5% disagreement at p50 marks the row
untrustworthy). Errors are counted, never retried. Percentile deltas are
differences between the two distributions at that percentile — not the
percentile of per-request differences, which two independent runs cannot give
you. Full method and countermeasures:
[`benchmarks/README.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/README.md)
in the repository.

Read shapes, three per backend:

| Shape | Postgres | MongoDB |
|---|---|---|
| Point lookup | `SELECT` one row by primary key | `find` by `_id`, one document |
| Range scan | `SELECT` 1000 rows over an indexed range | `find` over the indexed `_id` range, 1000 documents |
| Aggregate | `COUNT` + `SUM` over 50k rows, one row returned | `$match` + `$group`, one document |

Write shape (`--backend postgres-write`): `UPDATE` one row of a 50k-row
scratch table by primary key, `RETURNING` it — sent through `run_query` under
a `query_write` grant, so it runs on the gateway's write tier as the
database's `write_role`; the direct baseline runs the same statement as the
same role. The harness creates the scratch table before measuring and drops
it afterwards.

Workload parameters, identical across the four quiet-host runs:

| Parameter | Value |
|---|---|
| Measured requests per path, per shape | 20000 |
| Concurrency | 8 (closed-loop driver) |
| Warmup requests discarded | 2000 |
| Seeded rows / documents | 50000 |
| Row cap — point / range / aggregate / write | 10 / 2000 / 10 / 10 (never truncated) |
| Statement timeout (harness client) | 30000 ms |
| Database name | `app` |
| Postgres target | dev-stack `target-db`, `localhost:5434` (server `target`; write run: server `target-write`) |
| Mongo target | dev-stack `target-mongo`, `localhost:27018` |
| Gateway build | **release**, real MCP over HTTP, service-token bearer auth, synchronous audit write on the critical path, TLS disabled |
| Gateway instances | 1 (postgres, mongo and write runs), 4 on `127.0.0.1:8899`–`:8902` (instances run) |

20000 requests rather than the harness default of 2000: at the default, a
direct-path phase on this host lasts well under two seconds, and two
exploratory default runs (invocations 4 and 5 in REPORT.md, not quoted here)
drifted 16–34% on some shapes. The longer phases were chosen before the
published runs, and each published run is the first and only run of its
command.

## Environment and revision

Recorded by the harness into every artifact's `environment` object, plus the
host details the capture script logged (REPORT.md, "Quiet-host runs"):

| | |
|---|---|
| CPU | 16 × AMD Ryzen 7 5700X3D 8-Core Processor (8 cores / 16 threads), bare metal |
| Memory | 62.7 GiB |
| OS / kernel | Zorin OS 18.1 / 7.0.0-42-generic |
| CPU steal since boot | 0.0000% in every artifact |
| CPU frequency | `amd-pstate-epp`, `powersave` governor, `balance_performance` — not pinned |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v2.1.0 |
| Revision | `4639295bb23b…` — clean tree for the postgres and mongo runs; dirty for the instances and write runs (see below) |

**Not an isolated machine.** Zero steal means no hypervisor neighbours, not
an idle box: the workstation ran a desktop session (browser, editor, other
sessions) throughout. The load generator, the gateway(s), the state database
and the target databases all shared its 16 hardware threads.

**Dirty-tree caveat (instances and write runs).** The working tree held the
harness changes that add the write shape and the per-instance metrics port,
plus unrelated uncommitted CI and deployment-doc edits from another session.
None of it is under `src/`, so the measured release gateway binary is the
`4639295` gateway code.

Reproduce any of it (brings up the dev stack if it is down, tears down what
it started):

```bash
./benchmarks/gateway_overhead.sh --mysql-rejection --queries 20000 --warmup 2000 --out benchmarks/results/postgres-quiet.json
./benchmarks/gateway_overhead.sh --backend mongo --queries 20000 --warmup 2000 --out benchmarks/results/mongo-quiet.json
./benchmarks/gateway_overhead.sh --instances 4 --queries 20000 --warmup 2000 --out benchmarks/results/instances4-quiet.json
./benchmarks/gateway_overhead.sh --backend postgres-write --queries 20000 --warmup 2000 --out benchmarks/results/postgres-write-quiet.json
```

## How much to trust these numbers

- **Baseline drift, still.** The two baselines of a shape must agree within
  5% at p50. On this host they disagreed by 8.0%, 5.2% and 10.0% (postgres),
  17.6%, 5.3% and 1.7% (mongo), 7.2%, 3.8% and 3.0% (instances run) and 0.8%
  (write run): **6 of 10 overhead rows are marked `Trustworthy: no`**. The
  threshold was not loosened to make them pass. What moved is the *direct*
  path: its baselines here are 0.20ms–3.68ms at p50 (36.20ms for the mongo
  aggregate), so 5% is a few tens of microseconds, which a desktop host with
  an unpinned frequency governor does not hold across phases. The raw samples
  show the direct path wandering by that much within a single phase while the
  gateway path stays flat. Read the marked deltas as the size of the
  overhead, not as certified to the stated precision.
- **Small against the overhead, not against the baseline.** For example, the
  postgres `point_lookup` baselines read 0.43ms and then 0.46ms at p50 (8.0%
  drift), against a measured overhead of +4.51ms. The deltas are computed
  against the first baseline.
- **Contention, not scaling.** The `--instances` run measures how the load
  generator, the gateway processes and the databases divide one host's cores.
  It is labelled as contention everywhere it appears. A scaling result needs
  a separate load host.
- **What the overhead is.** The gateway path is the real released binary:
  one authorization evaluation, one SQL guard pass, one query on a
  per-`(server, database)` pool, and one **synchronous** audit write that
  must commit to the state database before the response goes out — by
  design; an audit failure fails the request (see
  [the architecture spec](initial-idea/02-architecture.md)). The measured
  overhead includes that round trip and cannot be optimised away without
  changing what the product guarantees. These runs did not break the
  overhead down by component.

## Postgres: gateway vs direct

Artifact: [`benchmarks/results/postgres-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres-quiet.json.gz)
(1 gateway instance; invocation 6 in
[REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
n = 20000 per row; p90 comes from the artifact's JSON, the printed report
shows p50/p95/p99 — full distributions, min/max/mean/CV and the raw
per-request samples are in the artifact).

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `point_lookup` — one row by primary key | direct | 0.43ms | 0.49ms | 0.51ms | 0.62ms | 20000 |
| | **gateway** | **4.93ms** | **5.14ms** | **6.35ms** | **10.86ms** | 20000 |
| `range_scan` — 1000 rows over an indexed range | direct | 1.12ms | 1.43ms | 1.57ms | 1.91ms | 20000 |
| | **gateway** | **6.28ms** | **8.12ms** | **8.65ms** | **11.66ms** | 20000 |
| `aggregate` — COUNT + SUM over 50k rows, one row | direct | 3.68ms | 5.69ms | 5.75ms | 6.13ms | 20000 |
| | **gateway** | **8.82ms** | **10.19ms** | **10.97ms** | **13.19ms** | 20000 |

Added by the gateway (differences between the two distributions at each
percentile):

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `point_lookup` | +4.51ms | +5.84ms | +10.24ms | 11.58× | 8.0% | **no** |
| `range_scan` | +5.15ms | +7.08ms | +9.75ms | 5.58× | 5.2% | **no** |
| `aggregate` | +5.14ms | +5.21ms | +7.06ms | 2.40× | 10.0% | **no** |

Throughput and gateway resources (throughput = completed requests/second on
this host while the load generator also ran; resources = per-sample sums
across the gateway fleet, sampled from `/proc` during the measured phase —
peak RSS is the high-water mark over those sums, so the four-instance
figures are what all four processes held together, not the largest single
process, and CPU seconds is each phase's first-to-last `/proc` delta,
summed across the fleet):

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `point_lookup` | direct | 18361 | — | — | — |
| | **gateway** | **1543** | 29.8 MiB | 10.56 | 15 |
| `range_scan` | direct | 6676 | — | — | — |
| | **gateway** | **1190** | 36.0 MiB | 22.64 | 19 |
| `aggregate` | direct | 1895 | — | — | — |
| | **gateway** | **907** | 36.1 MiB | 10.31 | 25 |

## MongoDB: gateway vs direct

Artifact: [`benchmarks/results/mongo-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/mongo-quiet.json.gz)
(1 gateway instance against `target-mongo` through the gateway's mongo
adapter, which is read-only by construction; invocation 7 in
[REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
n = 20000 per row; p90 from the artifact's JSON).

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `mongo_point_find` — find by `_id`, one document | direct | 0.20ms | 0.23ms | 0.25ms | 0.31ms | 20000 |
| | **gateway** | **4.95ms** | **5.31ms** | **5.72ms** | **7.71ms** | 20000 |
| `mongo_range_find` — indexed `_id` range, 1000 documents | direct | 2.44ms | 2.81ms | 3.03ms | 3.90ms | 20000 |
| | **gateway** | **8.63ms** | **10.18ms** | **10.64ms** | **12.73ms** | 20000 |
| `mongo_aggregate` — $match + $group, one document | direct | 36.20ms | 47.37ms | 54.45ms | 61.78ms | 20000 |
| | **gateway** | **69.01ms** | **73.06ms** | **75.34ms** | **82.08ms** | 20000 |

Added by the gateway:

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `mongo_point_find` | +4.76ms | +5.47ms | +7.40ms | 25.04× | 17.6% | **no** |
| `mongo_range_find` | +6.20ms | +7.61ms | +8.84ms | 3.54× | 5.3% | **no** |
| `mongo_aggregate` | +32.81ms | +20.89ms | +20.29ms | 1.91× | 1.7% | yes |

The `mongo_aggregate` overhead is the largest on this page and it passed the
drift guard: through the gateway this shape took nearly twice as long at p50.
It is published as measured; this run did not isolate where the extra time
goes.

Throughput and gateway resources:

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `mongo_point_find` | direct | 39161 | — | — | — |
| | **gateway** | **1570** | 30.7 MiB | 8.19 | 15 |
| `mongo_range_find` | direct | 3229 | — | — | — |
| | **gateway** | **875** | 41.7 MiB | 40.12 | 26 |
| `mongo_aggregate` | direct | 206 | — | — | — |
| | **gateway** | **114** | 41.6 MiB | 9.22 | 193 |

## Write path: UPDATE under a `query_write` grant

Artifact: [`benchmarks/results/postgres-write-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres-write-quiet.json.gz)
(1 gateway instance; server `target-write`, whose read tier connects as a
separate role and whose write tier connects as `write_role`; invocation 9 in
[REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
n = 20000 per row; p90 from the artifact's JSON).

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `write_update` — UPDATE one row by primary key, RETURNING it | direct | 2.78ms | 2.90ms | 2.92ms | 3.04ms | 20000 |
| | **gateway** | **7.90ms** | **9.16ms** | **9.65ms** | **10.76ms** | 20000 |

Added by the gateway:

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `write_update` | +5.12ms | +6.73ms | +7.72ms | 2.84× | 0.8% | yes |

Throughput and gateway resources:

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `write_update` | direct | 3307 | — | — | — |
| | **gateway** | **985** | 29.3 MiB | 10.31 | 23 |

Audit intact: after the run the state database held one `audit_calls` row
per gateway request on `target-write` — 22000 (2000 warmup + 20000
measured), all `outcome = success`, `rows_affected = 1`, attributed to
`service:bench` — and the scratch table was gone from the target (REPORT.md,
invocation 9).

## Four gateway instances: contention, not scaling

Artifact: [`benchmarks/results/instances4-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/instances4-quiet.json.gz)
(four gateway processes on `127.0.0.1:8899`–`:8902`, load spread over them;
invocation 8 — including a failed first attempt and its successful retry —
in [REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
same postgres workload as above; n = 20000 per row; p90 from the artifact's
JSON).

Overhead with the load spread over four instances:

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `point_lookup` | direct | 0.43ms | 0.52ms | 0.57ms | 0.80ms | 20000 |
| | **gateway** | **4.80ms** | **4.90ms** | **5.05ms** | **6.70ms** | 20000 |
| `range_scan` | direct | 1.06ms | 1.38ms | 1.54ms | 1.94ms | 20000 |
| | **gateway** | **6.17ms** | **7.84ms** | **8.26ms** | **9.57ms** | 20000 |
| `aggregate` | direct | 3.50ms | 5.25ms | 5.30ms | 5.66ms | 20000 |
| | **gateway** | **8.67ms** | **10.10ms** | **10.69ms** | **12.57ms** | 20000 |

Added by the gateway:

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `point_lookup` | +4.36ms | +4.47ms | +5.90ms | 11.06× | 7.2% | **no** |
| `range_scan` | +5.11ms | +6.72ms | +7.63ms | 5.82× | 3.8% | yes |
| `aggregate` | +5.17ms | +5.39ms | +6.91ms | 2.48× | 3.0% | yes |

Throughput and gateway resources:

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `point_lookup` | direct | 17442 | — | — | — |
| | **gateway** | **1637** | 94.7 MiB | 10.35 | 14 |
| `range_scan` | direct | 7011 | — | — | — |
| | **gateway** | **1218** | 101.1 MiB | 23.82 | 19 |
| `aggregate` | direct | 1989 | — | — | — |
| | **gateway** | **912** | 101.4 MiB | 10.52 | 25 |

The instance curve — 20000 `point_lookup` requests through 1, 2, 3 and then
4 gateway processes on one host:

| Instances | URLs used | req/s | p50 | p95 | p99 | errors |
|---|---|---|---|---|---|---|
| 1 | 1 | 1642 | 4.79ms | 4.99ms | 6.69ms | 0 |
| 2 | 2 | 1643 | 4.79ms | 4.99ms | 6.75ms | 0 |
| 3 | 3 | 1645 | 4.80ms | 5.16ms | 5.93ms | 0 |
| 4 | 4 | 1639 | 4.79ms | 5.01ms | 6.59ms | 0 |

**Flat, and still not a scaling law.** With a closed-loop driver at
concurrency 8, adding instances changed neither latency nor throughput:
whatever bounds a request here is not the CPU of a single gateway process.
These rows do not say where the bound is, and quoting them as a scaling law
— in either direction — would be quoting a number the harness did not take.

## MySQL is not a query target

Not a performance result — a behaviour check, reported separately so it can
never be read as one. The gateway has no MySQL query adapter
(`ServerKind::has_adapter()` is false for `mysql` and `mssql`), so a server
declaring `kind: mysql` is refused **at boot**, before it could serve a
single query. The harness loads exactly such a config through the gateway's
own config parser and asserts the rejection (run in the postgres invocation;
carried in `postgres-quiet.json`'s `mysql_rejection` field; invocation 6 in
[REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md)):

| Check | Result |
|---|---|
| Boot-time rejection of a `kind: mysql` query target | **rejected** |
| Runtime backstop maps to the stable `internal` code | **ok** |
| Overall verdict | **PASS** |

The rejection message:

```text
invalid config: server `mysql-target` has kind `Mysql`, which has no query adapter yet (supported kinds: postgres, mongo)
```

There is no MySQL query performance number on this page because there is no
MySQL query path to measure. The `permissions-mysql` container in the dev
stack is a permissions *store*, not a query target.

## Earlier run on a shared host

The first published run (2026-11-04, invocations 1–3 in REPORT.md) was taken
on an 8-vCPU KVM guest with ~10.4% CPU steal and the harness defaults (2000
requests per phase). Eight of its nine overhead rows were marked
`Trustworthy: no`, with baseline drift up to 109.7%. Its artifacts —
[`postgres.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres.json),
[`mongo.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/mongo.json),
[`instances4.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/instances4.json)
— stay committed, with their full reports in REPORT.md, as the record of
what a noisy host does to these numbers. They were measured against gateway
v1.6.0 and are not comparable with the figures above.

## What these numbers do not tell you

Deliberately absent, because one host cannot answer them honestly:

- **Absolute throughput ceilings.** The reported req/s is what that host
  completed while the load generator took its share of the same cores. It is
  not a capacity figure.
- **A scaling law.** See above: the instances curve is contention on one host.
- **Real MySQL query behaviour.** Only the boot-time rejection is verified.
- **Multi-host, multi-region, TLS termination cost.** One host; the bench
  gateway runs with TLS disabled, and network round trips between agent,
  gateway, state database and target are all loopback.
- **A certified sub-millisecond baseline.** Six rows above failed the drift
  guard on a zero-steal host; a dedicated machine with a pinned CPU governor
  would be needed to hold the direct path within 5%.
- **Write shapes beyond a single-row UPDATE.** Multi-row writes, INSERT-heavy
  growth and `dry_run` are not measured.

The harness reproduces on your hardware in minutes with no dependencies
beyond `docker`, `cargo`, `curl` and `openssl`:

```bash
./benchmarks/gateway_overhead.sh
```

If you run it against your deployment and the numbers surprise you in either
direction, [open an issue](https://github.com/developerz-ai/db-mcp-gateway/issues/new)
— a real report from a real deployment is worth more than our synthetic run.

## The artifacts

| Artifact | What it carries |
|---|---|
| [`benchmarks/results/postgres-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres-quiet.json.gz) | Postgres run: environment, effective config, full distributions, raw per-request samples, MySQL rejection verdict |
| [`benchmarks/results/mongo-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/mongo-quiet.json.gz) | Mongo run: same fields |
| [`benchmarks/results/postgres-write-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres-write-quiet.json.gz) | Write-path run: same fields |
| [`benchmarks/results/instances4-quiet.json.gz`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/instances4-quiet.json.gz) | Four-instance run: same fields plus the per-instance-count scaling rows |
| [`benchmarks/results/REPORT.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md) | Invocation log: exact commands, exit statuses, host snapshots, the harness's complete captured output verbatim, warnings, failed attempts and exploratory runs |
| `postgres.json`, `mongo.json`, `instances4.json` | The earlier shared-host run (see above) |
| [`benchmarks/README.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/README.md) | The method: what it measures, how it tries not to lie to you, how to extend it |

No credential, connection string, service token or password appears in any
artifact or log line. The bench configs hold only the development
credentials already public in `docker-compose.dev.yml` (and the harness's own
dev-only `bench_ro` role), and the runner mints its service token per run, in
the environment only.
