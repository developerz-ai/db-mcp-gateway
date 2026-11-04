# Benchmarks

db-mcp-gateway ships its own benchmark harness
([`benchmarks/gateway_overhead.sh`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/gateway_overhead.sh)):
it times the same query on the same host at the same moment down two paths —
straight at the database, and through the gateway's `run_query` MCP tool with
normal service-token authentication, normal authorization and the synchronous
audit write intact. Nothing is skipped: a benchmark of a build we do not ship
would be worth less than no benchmark.

This page publishes what the harness measured. Every figure below is quoted
from a committed run artifact — the raw JSON with the full per-request
samples, and [REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md),
the invocation log that records exactly how each artifact was produced,
warnings and all. Nothing here is hand-derived. An earlier version of this
page carried tables of numbers nobody had measured; they were removed, and
the discipline this page keeps — publishing the caveats with the figures —
is the reason.

**Read [How much to trust these numbers](#how-much-to-trust-these-numbers)
before quoting any table.** These runs were taken on a shared, noisy host:
eight of the nine gateway-overhead rows measured carry the harness's own
`Trustworthy: no` marking, and they are published that way rather than
dropped, averaged away, or re-run until they looked better.

## What the harness measures

Baseline → gateway → baseline again, per query shape, with the two baselines
compared to detect host drift (>5% disagreement marks the row untrustworthy).
Errors are counted, never retried. Percentile deltas are differences between
the two distributions at that percentile — not the percentile of per-request
differences, which two independent runs cannot give you. Full method and
countermeasures: [`benchmarks/README.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/README.md)
in the repository.

Three query shapes per backend:

| Shape | Postgres | MongoDB |
|---|---|---|
| Point lookup | `SELECT` one row by primary key | `find` by `_id`, one document |
| Range scan | `SELECT` 1000 rows over an indexed range | `find` over the indexed `_id` range, 1000 documents |
| Aggregate | `COUNT` + `SUM` over 50k rows, one row returned | `$match` + `$group`, one document |

Workload parameters, identical across all three published runs:

| Parameter | Value |
|---|---|
| Measured requests per path, per shape | 2000 |
| Concurrency | 8 (closed-loop driver) |
| Warmup requests discarded | 200 |
| Seeded rows / documents | 50000 |
| Row cap — point / range / aggregate | 10 / 2000 / 10 (never truncated) |
| Statement timeout (harness client) | 30000 ms |
| Database name | `app` |
| Postgres target | dev-stack `target-db`, `localhost:5434` |
| Mongo target | dev-stack `target-mongo`, `localhost:27018` |
| Gateway build | **release**, real MCP over HTTP, service-token bearer auth, synchronous audit write on the critical path, TLS disabled |
| Gateway instances | 1 (postgres and mongo runs), 4 on `127.0.0.1:8899`–`:8902` (instances run) |

## Environment and revision

Recorded by the harness into every artifact's `environment` object:

| | |
|---|---|
| CPU | 8 × Intel(R) Xeon(R) CPU E5-2630L v3 @ 1.80GHz, KVM guest |
| Memory | 31.3 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS / 6.8.0-147-generic |
| CPU steal since boot | 10.43% – 10.46% across all runs |
| Toolchain | rustc 1.96.0 (ac68faa20 2026-05-25) |
| Gateway | v1.6.0 |
| Revision | `230d04bb0eada97adaa2a7f6c08e687c52b18a23` (**dirty tree** — see below) |

**Dirty-tree caveat.** The working tree was dirty during every run, so the
harness recorded the **base commit** above with `git_dirty: true`. The hash
identifies the code the release gateway binary was built from only up to the
uncommitted delta — which was documentation and run-evidence files, no
`src/` change — so the measured binary corresponds to the base commit's
gateway code.

Reproduce any of it (defaults; brings up the dev stack if it is down, tears
down what it started):

```bash
./benchmarks/gateway_overhead.sh --mysql-rejection --out benchmarks/results/postgres.json
./benchmarks/gateway_overhead.sh --backend mongo --out benchmarks/results/mongo.json
./benchmarks/gateway_overhead.sh --instances 4 --out benchmarks/results/instances4.json
```

## How much to trust these numbers

The harness refuses to certify what the host would not hold still for, and
on this box it refused most of it:

- **Baseline drift.** The two baselines of a shape must agree within 5%. On
  this shared host they disagreed by 109.7%, 17.6% and 20.9% (postgres),
  30.3%, 16.0% and 38.8% (mongo) and 35.3%, 79.8% and 3.2% (instances run).
  That is **8 of 9 overhead rows marked `Trustworthy: no`** — the one
  exception is `aggregate` in the instances run. Every row below is
  published with its marking. Treat the marked deltas as indicative of the
  size of the overhead, not as certified measurements; run the harness on a
  quieter box for numbers you can stand behind.
- **CPU steal.** ~10.4% since boot in every run — the neighbours' cycles are
  in these percentiles. Coefficients of variation ran 34% – 110% across
  distributions.
- **Negative delta is the drift talking.** In the mongo run the aggregate
  measured *faster* through the gateway than the second baseline
  (`p50 533.57ms` vs `563.31ms`, deltas −29.73/−58.14/−61.12ms). With a
  38.8% drift between the two baselines (`563.31ms` → `781.98ms`), that is
  the host slowing down mid-run, not a gateway speedup. The row carries
  `Trustworthy: no`.
- **Contention, not scaling.** The `--instances` run measures how the load
  generator, the gateway processes and the database divide one host's cores.
  It is labelled as contention everywhere it appears. A scaling result needs
  a separate load host.
- **What the overhead is.** The gateway path is the real released binary:
  one authorization evaluation, one SQL guard pass, one query on a
  per-`(server, database)` pool, and one **synchronous** audit write that
  must commit to the state database before the response goes out — by
  design; an audit failure fails the request (see
  [the architecture spec](initial-idea/02-architecture.md)). The measured
  overhead includes that round trip and cannot be optimised away without
  changing what the product guarantees.

## Postgres: gateway vs direct

Artifact: [`benchmarks/results/postgres.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres.json)
(1 gateway instance; invocation 1 in
[REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
n = 2000 per row; p90 comes from the artifact's JSON, the printed report
shows p50/p95/p99 — full distributions, min/max/mean/CV and the raw
per-request samples are in the artifact).

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `point_lookup` — one row by primary key | direct | 5.56ms | 10.56ms | 13.19ms | 18.47ms | 2000 |
| | **gateway** | **43.98ms** | **94.42ms** | **121.56ms** | **159.28ms** | 2000 |
| `range_scan` — 1000 rows over an indexed range | direct | 53.11ms | 101.19ms | 118.36ms | 161.18ms | 2000 |
| | **gateway** | **149.96ms** | **253.70ms** | **285.79ms** | **365.15ms** | 2000 |
| `aggregate` — COUNT + SUM over 50k rows, one row | direct | 83.47ms | 175.37ms | 205.67ms | 273.76ms | 2000 |
| | **gateway** | **151.54ms** | **245.71ms** | **274.68ms** | **334.25ms** | 2000 |

Added by the gateway (differences between the two distributions at each
percentile):

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `point_lookup` | +38.41ms | +108.37ms | +140.81ms | 7.90× | 109.7% | **no** |
| `range_scan` | +96.85ms | +167.42ms | +203.98ms | 2.82× | 17.6% | **no** |
| `aggregate` | +68.07ms | +69.01ms | +60.49ms | 1.82× | 20.9% | **no** |

Throughput and gateway resources (throughput = completed requests/second on
this host while the load generator also ran; resources = per-sample sums
across the gateway fleet, sampled from `/proc` during the measured phase —
peak RSS is the high-water mark over those sums, so the four-instance
figures are what all four processes held together, not the largest single
process, and CPU seconds is each phase's first-to-last `/proc` delta,
summed across the fleet):

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `point_lookup` | direct | 1231 | — | — | — |
| | **gateway** | **150** | 26.1 MiB | 7.11 | 16 |
| `range_scan` | direct | 134 | — | — | — |
| | **gateway** | **49** | 30.7 MiB | 47.32 | 47 |
| `aggregate` | direct | 83 | — | — | — |
| | **gateway** | **50** | 30.9 MiB | 11.10 | 44 |

## MongoDB: gateway vs direct

Artifact: [`benchmarks/results/mongo.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/mongo.json)
(1 gateway instance against `target-mongo` through the gateway's mongo
adapter, which is read-only by construction; invocation 2 in
[REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
n = 2000 per row; p90 from the artifact's JSON).

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `mongo_point_find` — find by `_id`, one document | direct | 7.10ms | 24.06ms | 33.24ms | 49.56ms | 2000 |
| | **gateway** | **30.38ms** | **60.33ms** | **72.45ms** | **93.09ms** | 2000 |
| `mongo_range_find` — indexed `_id` range, 1000 documents | direct | 32.64ms | 61.20ms | 70.28ms | 89.09ms | 2000 |
| | **gateway** | **69.12ms** | **126.49ms** | **150.71ms** | **189.49ms** | 2000 |
| `mongo_aggregate` — $match + $group, one document | direct | 563.31ms | 865.57ms | 965.68ms | 1151.74ms | 2000 |
| | **gateway** | **533.57ms** | **800.99ms** | **907.54ms** | **1090.62ms** | 2000 |

Added by the gateway:

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `mongo_point_find` | +23.28ms | +39.20ms | +43.53ms | 4.28× | 30.3% | **no** |
| `mongo_range_find` | +36.49ms | +80.43ms | +100.41ms | 2.12× | 16.0% | **no** |
| `mongo_aggregate` | −29.73ms | −58.14ms | −61.12ms | 0.95× | 38.8% | **no** |

Throughput and gateway resources:

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `mongo_point_find` | direct | 738 | — | — | — |
| | **gateway** | **229** | 26.4 MiB | 3.80 | 10 |
| `mongo_range_find` | direct | 221 | — | — | — |
| | **gateway** | **95** | 34.0 MiB | 21.57 | 24 |
| `mongo_aggregate` | direct | 14 | — | — | — |
| | **gateway** | **14** | 33.6 MiB | 5.38 | 155 |

## Four gateway instances: contention, not scaling

Artifact: [`benchmarks/results/instances4.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/instances4.json)
(four gateway processes on `127.0.0.1:8899`–`:8902`, load spread over them;
invocation 3 — including a killed first attempt and its successful retry —
in [REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md);
same postgres workload as above; n = 2000 per row; p90 from the artifact's
JSON).

Overhead with the load spread over four instances:

| Query shape | Path | p50 | p90 | p95 | p99 | n |
|---|---|---|---|---|---|---|
| `point_lookup` | direct | 11.48ms | 26.61ms | 33.34ms | 45.79ms | 2000 |
| | **gateway** | **34.50ms** | **64.32ms** | **76.86ms** | **184.83ms** | 2000 |
| `range_scan` | direct | 13.53ms | 23.43ms | 27.67ms | 36.24ms | 2000 |
| | **gateway** | **86.44ms** | **153.87ms** | **180.35ms** | **225.93ms** | 2000 |
| `aggregate` | direct | 44.25ms | 78.07ms | 89.88ms | 121.01ms | 2000 |
| | **gateway** | **60.65ms** | **130.40ms** | **151.41ms** | **186.18ms** | 2000 |

Added by the gateway:

| Query shape | p50 | p95 | p99 | p50 ratio | Baseline drift | Trustworthy |
|---|---|---|---|---|---|---|
| `point_lookup` | +23.02ms | +43.52ms | +139.04ms | 3.00× | 35.3% | **no** |
| `range_scan` | +72.91ms | +152.68ms | +189.68ms | 6.39× | 79.8% | **no** |
| `aggregate` | +16.40ms | +61.53ms | +65.17ms | 1.37× | 3.2% | **yes** |

Throughput and gateway resources:

| Query shape | Path | req/s | peak RSS | CPU s | samples |
|---|---|---|---|---|---|
| `point_lookup` | direct | 569 | — | — | — |
| | **gateway** | **198** | 83.5 MiB | 5.51 | 11 |
| `range_scan` | direct | 524 | — | — | — |
| | **gateway** | **82** | 87.8 MiB | 33.05 | 28 |
| `aggregate` | direct | 164 | — | — | — |
| | **gateway** | **108** | 88.1 MiB | 7.31 | 22 |

The instance curve — 2000 `point_lookup` requests through 1, 2, 3 and then 4
gateway processes on one shared host:

| Instances | URLs used | req/s | p50 | p95 | p99 | errors |
|---|---|---|---|---|---|---|
| 1 | 1 | 177 | 42.69ms | 82.92ms | 108.98ms | 0 |
| 2 | 2 | 240 | 27.46ms | 74.46ms | 105.74ms | 0 |
| 3 | 3 | 221 | 30.97ms | 75.48ms | 96.47ms | 0 |
| 4 | 4 | 195 | 36.65ms | 84.61ms | 114.15ms | 0 |

**Contention, not scaling.** The load generator, the gateway instances and
the database share the same 8 cores — already giving ~10% of them away to
neighbours. Throughput peaks at two instances and goes back *down* at three
and four, because the extra processes are competing for the cores the first
two already cannot have. These rows do not publish a scaling law, and
quoting them as one would be quoting a number the harness did not take.

## MySQL is not a query target

Not a performance result — a behaviour check, reported separately so it can
never be read as one. The gateway has no MySQL query adapter
(`ServerKind::has_adapter()` is false for `mysql` and `mssql`), so a server
declaring `kind: mysql` is refused **at boot**, before it could serve a
single query. The harness loads exactly such a config through the gateway's
own config parser and asserts the rejection (run once, in the postgres
invocation; carried in `postgres.json`'s `mysql_rejection` field; invocation
1 in [REPORT.md](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md)):

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

## What these numbers do not tell you

Deliberately absent, because one shared host cannot answer them honestly:

- **Absolute throughput ceilings.** The reported req/s is what that host
  completed while the load generator took its share of the same cores. It is
  not a capacity figure.
- **A scaling law.** See above: the instances curve is contention.
- **Write-path overhead.** The bench grants are `query_read` only; the
  postgres role is read-only and the mongo adapter rejects writes before
  they reach the server.
- **Real MySQL query behaviour.** Only the boot-time rejection is verified.
- **Multi-host, multi-region, TLS termination cost.** One host; the bench
  gateway runs with TLS disabled.
- **A quiet-machine number.** These runs carry ~10% CPU steal and 8-of-9
  untrustworthy rows. They are published because they are real, complete
  with their caveats — not because they are clean. The harness reproduces on
  your hardware in minutes with no dependencies beyond `docker`, `cargo`,
  `curl` and `openssl`:

```bash
./benchmarks/gateway_overhead.sh
```

If you run it against your deployment and the numbers surprise you in either
direction, [open an issue](https://github.com/developerz-ai/db-mcp-gateway/issues/new)
— a real report from a real deployment is worth more than our synthetic run.

## The artifacts

| Artifact | What it carries |
|---|---|
| [`benchmarks/results/postgres.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/postgres.json) | Postgres run: environment, effective config, full distributions, raw per-request samples, MySQL rejection verdict |
| [`benchmarks/results/mongo.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/mongo.json) | Mongo run: same fields |
| [`benchmarks/results/instances4.json`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/instances4.json) | Four-instance run: same fields plus the per-instance-count scaling rows |
| [`benchmarks/results/REPORT.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/results/REPORT.md) | Invocation log: exact commands, exit statuses, the harness's complete captured output verbatim, warnings, the killed attempt and its retry |
| [`benchmarks/README.md`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/benchmarks/README.md) | The method: what it measures, how it tries not to lie to you, how to extend it |

No credential, connection string, service token or password appears in any
artifact or log line. The bench configs hold only the development
credentials already public in `docker-compose.dev.yml`, and the runner mints
its service token per run, in the environment only.
