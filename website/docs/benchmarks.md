# Benchmarks

**We have not benchmarked db-mcp-gateway. This page has no numbers because
there are no measurements, and we would rather publish nothing than publish
an estimate that reads like a result.**

An earlier version of this page carried tables of latency, throughput, and
resource figures — `<5ms` overhead, `p95 35ms`, `700 qps` across four
instances, `300` audit writes per second. None of them were measured. They
were derived from what the architecture *ought* to cost, labelled "target",
and then quoted elsewhere on this site with the label removed. That is a
worse failure than having no benchmarks page, so the tables are gone.

## What we can tell you without measuring

Facts about the code path, not claims about its cost:

| Per query, the gateway does | Where |
|---|---|
| One authorization evaluation over the caller's merged grants | `src/authz/` |
| One SQL guard pass over the parsed statement | `src/exec/` |
| One query against a per-`(server, database)` connection pool | `src/exec/` |
| One **primary synchronous** audit write on the normal success path that must commit before the response is sent; cancellation or primary-write failure can schedule a detached fallback write | `src/audit/` |

That last row is the one that matters for any performance question. The
audit write is on the critical path *by design* — an audit failure fails the
request (see the [architecture spec](initial-idea/02-architecture.md)). Any
benchmark that batched or deferred it would be measuring a gateway we do not
ship, so whatever the real overhead turns out to be, it includes a
round-trip to the state database and cannot be optimised away without
changing what the product guarantees.

## Why there are no numbers yet

We have deferred publication until we can run a harness with the required
tooling. Publishing *meaningful* numbers needs a dedicated, quiet machine —
the kind of isolated runner where a p99 means something. Numbers taken on a
shared VPS can be affected by co-tenancy and may be less reproducible than
measurements from an isolated runner.

So this is deliberately deferred rather than half-done.

## What we will publish when we do measure

Tracked in [#196](https://github.com/developerz-ai/db-mcp-gateway/issues/196):

- A harness committed under `benchmarks/`, runnable by anyone, driving the
  real released binary over the real auth path — not a stripped-down build.
- Gateway overhead against a direct connection to the same database on the
  same host, as a distribution (p50/p95/p99), never a single scalar.
- Behaviour under concurrency, per database engine, and across multiple
  gateway instances.
- The exact machine, database versions, and commit every table came from.
- **Results that look bad.** If overhead is worse than we hoped on some
  workload, that workload gets published too. A benchmark you can only pass
  is not a benchmark.

## In the meantime

Measure it yourself, on your hardware, against your data. That number may
be more relevant to your deployment than a generic published result — and if
it surprises you in either direction, please
[open an issue](https://github.com/developerz-ai/db-mcp-gateway/issues/new);
a real report from a real deployment is worth more than our synthetic run.
