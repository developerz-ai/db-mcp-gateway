# Benchmarks

A harness for measuring what the gateway costs you. **No published numbers
live here** — see `website/docs/benchmarks.md` for why. This directory exists
so that anyone, including us, can produce their own.

## Run it

```bash
./benchmarks/gateway_overhead.sh
./benchmarks/gateway_overhead.sh --queries 5000 --concurrent 8 --warmup 500
```

Needs `docker`, `cargo`, `curl`, and `openssl`. Nothing else — no k6, no wrk, no JMeter.

The script starts the dev stack if it is not already up, builds and boots a
**release** gateway against `benchmarks/gateway.bench.yaml`, measures, prints a
Markdown report, writes raw JSON to `benchmarks/results/`, and tears down
whatever it started. A stack that was already running is left alone.

### Entry points and flags

| Entry point | What it does |
|---|---|
| `./benchmarks/gateway_overhead.sh` | Postgres gateway-vs-direct overhead, baseline → gateway → baseline |
| `./benchmarks/gateway_overhead.sh --backend mongo` | The same comparison against the `target-mongo` container (localhost:27018, database `app`) |
| `./benchmarks/gateway_overhead.sh --instances 4` | Boots four gateway processes and spreads the load over them |
| `./benchmarks/gateway_overhead.sh --mysql-rejection` | Adds the boot-time MySQL query-target rejection check, in its own report section |

| Flag | Default | Meaning |
|---|---|---|
| `--backend postgres\|mongo` | `postgres` | Which engine to measure |
| `--queries N` | `2000` | Measured requests per path, per shape |
| `--concurrent N` | `8` | Concurrent in-flight requests |
| `--warmup N` | `200` | Requests discarded before measuring |
| `--instances N` | `1` | Gateway instances to boot and spread load over |
| `--db-name NAME` | `app` | Database name for the measured request |
| `--database postgres\|postgresql` | — | Legacy alias for `--backend postgres`; picks the postgres target. **Not** a database name — a bad value exits 2 |
| `--out PATH` | `benchmarks/results/latest.json` | Where the raw JSON result is written |
| `--resource-sample-ms N` | `1000` | Interval between gateway resource samples |
| `--mysql-rejection` | off | Also verify the `kind: mysql` boot-time rejection |
| `-h`, `--help` | — | Usage; exits 0 |

`--database` keeps its original meaning: a **backend** selector, not a
database name. It accepts `postgres` or `postgresql` and selects the postgres
target; anything else exits 2. The database *name* is `--db-name`. The two
are not interchangeable — `--database postgres` measures the postgres target,
it does not ask for a database called `postgres`.

`--db-name` names the measured database on both backends: the gateway path
and the direct baseline are pointed at the same one, because a comparison
across two different databases means nothing.

Prerequisites per backend:

- **postgres** — the dev stack's `target-db` on `localhost:5434` (user `app`,
  database `app`). Started for you by the script.
- **mongo** — the dev stack's `target-mongo` on `localhost:27018` (user `app`,
  database `app`, auth database `admin`). The script starts the container if
  the rest of the stack was already up without it, and stops it again
  afterwards.

The runner boots one gateway process per instance on consecutive ports
(`127.0.0.1:8899`, `:8900`, …), waits for each to answer `/healthz`, and hands
the harness the list of URLs. Everything it starts, it stops.

## What it measures

The same query, on the same host, at the same moment, down two paths:

- **direct** — the driver straight at the database, warm pool sized to the concurrency
- **gateway** — an MCP `tools/call` for `run_query` over HTTP

Postgres measures three query shapes: a primary-key lookup (harshest test —
the gateway is almost the entire measurement), a 1000-row indexed range scan
(shifts weight to serialization), and a server-side aggregate (database works
hard, response is tiny). Mongo measures its own read shapes against the
`target-mongo` container.

The gateway path is the real released binary over the real service-token auth
path, with the synchronous audit write intact. Nothing reaches into the
library to skip a layer. A benchmark of a build we do not ship would be worth
less than no benchmark.

Every phase reports the full distribution — p50, p90, p95, p99, min, max,
mean, coefficient of variation and the sample count — plus the concurrent
throughput that phase achieved. Gateway resource utilization (peak RSS and CPU
time) is sampled per phase and carried into the JSON report and the Markdown
output, so a reader can see what the overhead was bought with.

## How it tries not to lie to you

Benchmarks are easy to get wrong in ways that flatter the thing being
measured. The countermeasures here, and what each one catches:

| Guard | Catches |
|---|---|
| Run order is **baseline → gateway → baseline again** | The machine drifting mid-run. If the two baselines disagree by >5%, the row is marked untrustworthy — a background job starting is otherwise indistinguishable from gateway overhead |
| Warmup requests discarded | Cold pools, first-call permission resolution |
| Both paths drain and touch every row before stopping the clock | A baseline that "finishes" while the server is still streaming, which would inflate apparent overhead |
| Errors counted and reported, never retried | A misconfiguration publishing a fast number because half the requests failed |
| Response payload asserted non-empty | Measuring no-ops |
| A truncated response is not a measurement | Comparing a gateway response against a complete baseline result |
| Coefficient of variation reported per distribution | Noise being mistaken for signal. Above ~10% and the percentiles are describing the host, not the code |
| CPU steal read from `/proc/stat` | A shared host where the numbers describe the neighbours |
| Machine, commit, and dirty-tree flag recorded in every result | A published table claiming hardware it never ran on |
| Row cap set above what any shape returns | Truncation making the two paths incomparable |
| The MySQL rejection is reported in its own section | A config-validation result being read as a performance number |

Percentile deltas are differences **between the two distributions at that
percentile** — not the percentile of per-request differences. Those are
different statistics and only the first is computable from two independent
runs.

## Horizontal scaling: contention, not scaling

`--instances N` boots N gateway processes on one host and spreads the load
over them. What it measures is **contention on a single shared host**: the
load generator, the N gateways and the database all compete for the same
cores, so the curve describes how those processes divide this machine, not how
the gateway scales across a fleet.

It is labelled as contention wherever it appears — in the JSON report, in the
Markdown output, and in this file. Publishing it as a scaling law would be
publishing a number the harness did not take.

## MySQL is not a query target

The gateway has no mysql query adapter. `ServerKind::has_adapter()` is false
for `mysql` and `mssql`, and config validation refuses such a server at boot:

```text
server `mysql-target` has kind `Mysql`, which has no query adapter yet
(supported kinds: postgres, mongo)
```

That is a **boot-time config rejection**, not a query that fails at runtime —
the gateway refuses to start rather than accepting a target it cannot serve.
`benchmarks/gateway.bench.mysql.yaml` declares exactly such a server, and the
harness loads it through the gateway's own `ConfigFile::from_yaml_str` and
asserts the rejection.

There is no MySQL query performance to measure, and the harness does not
invent any. The rejection is reported in its own section, distinct from the
successful-query measurements. (The `permissions-mysql` container in the dev
stack is a permissions *store*, not a query target.)

## What it does not measure

Deliberately absent, because a single host cannot answer them honestly:

- **Absolute throughput ceilings (qps).** The load generator, the gateway and
  the database compete for the same cores. The ceiling you would measure is
  the one left over after the load generator takes its share. Throughput is
  still reported per phase — as what this host achieved — not as a ceiling.
- **Horizontal scaling.** See above: `--instances` measures contention on one
  host, and is labelled as such. A scaling result needs a separate load host.
- **Write workloads.** The bench grants are `query_read` only, and the mongo
  adapter refuses write commands before they reach the server.
- **Real MySQL query behaviour.** MySQL is not a query target; only the
  boot-time rejection is verified.

## Adding a query shape

Add a variant to `Shape` in `harness/workload.rs` and fill in `sql()`,
`description()` and `limit()`. Both paths pick it up automatically — that is
the point of the shared enum. Keep `limit()` above whatever the shape returns
or the gateway will truncate and the comparison becomes meaningless.

## Layout

```text
gateway_overhead.sh    runner: stack up, boot gateway, measure, tear down
gateway.bench.yaml     gateway config (dev credentials only) — postgres + mongo targets
gateway.bench.mysql.yaml
                       a `kind: mysql` target, used only to prove the boot-time rejection
harness/
  main.rs              CLI, run order, report emission
  workload.rs          query shapes + seed data
  gateway.rs           the measured path (MCP over HTTP)
  direct.rs            the baseline path (sqlx)
  driver.rs            closed-loop concurrency, drift detection
  stats.rs             exact percentiles, overhead deltas
  env.rs               machine + build provenance
  report.rs            JSON + Markdown output
results/               raw JSON, gitignored
```

Built only with `--features bench-harness`, so it never enters a release
build or the runtime image.

## Raw results

Every run writes one JSON file under `benchmarks/results/` (gitignored). It
carries the workload definition, the effective configuration, the software
revision (commit hash plus a dirty-tree flag), the environment, and the raw
measurement samples — enough to re-derive the published percentiles rather
than take them on trust.

No credential, connection string, service token or password appears in any
result file, log line, error or Markdown report. The bench configs hold only
the development credentials already public in `docker-compose.dev.yml`.
