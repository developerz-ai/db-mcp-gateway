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

## What it measures

The same SQL, on the same host, at the same moment, down two paths:

- **direct** — sqlx straight at Postgres, warm pool sized to the concurrency
- **gateway** — an MCP `tools/call` for `run_query` over HTTP

Three query shapes: a primary-key lookup (harshest test — the gateway is
almost the entire measurement), a 1000-row indexed range scan (shifts weight
to serialization), and a server-side aggregate (database works hard, response
is tiny).

The gateway path is the real released binary over the real service-token auth
path, with the synchronous audit write intact. Nothing reaches into the
library to skip a layer. A benchmark of a build we do not ship would be worth
less than no benchmark.

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
| Coefficient of variation reported per distribution | Noise being mistaken for signal. Above ~10% and the percentiles are describing the host, not the code |
| CPU steal read from `/proc/stat` | A shared host where the numbers describe the neighbours |
| Machine, commit, and dirty-tree flag recorded in every result | A published table claiming hardware it never ran on |
| Row cap set above what any shape returns | Truncation making the two paths incomparable |

Percentile deltas are differences **between the two distributions at that
percentile** — not the percentile of per-request differences. Those are
different statistics and only the first is computable from two independent
runs.

## What it does not measure

Deliberately absent, because a single host cannot answer them honestly:

- **Absolute throughput (qps).** The load generator, the gateway and the
  database compete for the same cores. The ceiling you would measure is the
  one left over after the load generator takes its share.
- **Horizontal scaling.** Adding gateway instances to a host that is already
  saturated measures contention, not scaling. Needs a separate load host.
- **MongoDB.** Postgres adapter only, so far.

## Adding a query shape

Add a variant to `Shape` in `harness/workload.rs` and fill in `sql()`,
`description()` and `limit()`. Both paths pick it up automatically — that is
the point of the shared enum. Keep `limit()` above whatever the shape returns
or the gateway will truncate and the comparison becomes meaningless.

## Layout

```text
gateway_overhead.sh    runner: stack up, boot gateway, measure, tear down
gateway.bench.yaml     gateway config (dev credentials only)
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
