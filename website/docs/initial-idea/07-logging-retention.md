# 07 — Logging & Retention

Two distinct streams. Don't confuse them.

| Stream | Where | Purpose |
|---|---|---|
| **Audit log** | State Postgres: `audit_calls` (one row per call) and `audit_call_intents` (one row per target call, written first) | Forensic record. Synchronous, mandatory, append-only. |
| **Stdout log** | Process stdout, one JSON object per line | Operational observability. Ingested by Loki / Splunk / etc. via Alloy. |

The audit log is the system of record. The stdout log is a sidecar for operators; it MUST NOT be the only place a tool call leaves a trace.

## What "audit log" means here

Append-only record of every tool invocation, written synchronously **before** results return to the agent. If the audit write fails, the request fails. There is no "best effort" audit.

Every `tools/call` gets one `audit_calls` row — including calls rejected before a tool ran (unknown tool, arguments that do not parse: `outcome = invalid_arguments`, `server_name`/`database_name` NULL). The one carve-out: a request shed at the concurrency caps (`429 rate_limited`, `503 service_overloaded`) is a log line and a metric only, so overload never adds a state-DB write per rejected request (spec [03](03-mcp-tools.md) §Errors).

### Intent and completion (two-phase)

A call that reaches a target database is written twice:

1. **Intent** — after authz, before the gateway opens the target pool, it commits an `audit_call_intents` row: `request_id`, `occurred_at`, `user_sub`, `user_email`, `tool`, `server_name`, `database_name`, `db_type`, `access` (`read` or `write`), and the caller's claimed `upstream_actor` / `upstream_run_id` (migration 0014; the reaper copies them into the `abandoned` row). If that write fails, the call is refused with `audit_unavailable` and the target is never reached.
2. **Completion** — after the tool's work, the `audit_calls` row with the outcome, under the same `request_id`. If that write fails, the client gets `audit_unavailable`; a drop guard retries the row with outcome `audit_unavailable` and the tool's own outcome in `error_message`.

Every target call writes an intent — reads and writes alike (owner decision, plan 101). Revisit writes-only if the benchmark shows the extra insert matters; production volume today is tens of calls a day.

**Reaper.** An intent with no `audit_calls` row of the same `request_id` means the gateway stopped between the two writes (crash, OOM kill, a shutdown drain that ran out of time). Every replica runs a sweep each minute under a transaction-scoped advisory lock (one sweep at a time across replicas); it writes an `audit_calls` row with `outcome = abandoned`, `occurred_at` from the intent, and `error_message` naming the access (`access: write` means the statement may have committed). A sweep only considers intents older than the grace — target open allowance (60 s) + statement ceiling (30 s) + two audit-write deadlines (2 × 15 s) + shutdown drain (20 s) = 140 s — so a call still running is never reaped.

**Shutdown drain.** The drop guard's retry, stream-sink deliveries and the exec layer's cancels run on a tracked task set, not bare `tokio::spawn`. After the server stops accepting work, `main` waits for that set for up to 20 s; anything still running past it is left to the reaper.

**Client disconnect.** The dispatch future is dropped; the guard writes `outcome = cancelled` with `error_message = "client disconnected before completion"`.

## Fields

`audit_calls` columns:

| Column | Source |
|---|---|
| `id` | Gateway-minted UUID per row |
| `request_id` | Gateway-minted UUID per request (also the `x-request-id` header and the dispatch log line's `request_id`) |
| `occurred_at` | Server-side `now()` at insert |
| `user_sub`, `user_email`, `groups` | From the session (see [04-auth-sso](04-auth-sso.md)); `groups` is a JSONB snapshot at request time |
| `agent_client` | Self-reported MCP client banner (`User-Agent`) |
| `ip` | Request socket, as text |
| `server_name`, `database_name` | Logical names; NULL for tools that address neither, or when the arguments never parsed |
| `db_type` | `postgres` / `mongo`; NULL for tools that reach no target |
| `tool` | `run_query`, `describe_schema`, …; `unknown` for an unknown or missing tool name |
| `sql` | What the call read: the agent's SQL for `run_query` / `explain`; `schema.table` for `sample_table` / `table_stats`; `schema` or `schema.table` for `describe_schema` (`database[.collection]` on Mongo); the target `request_id` for `cancel_query`; NULL for tools that read no table |
| `sql_truncated` | `sql` was cut at the 64 KiB stored-SQL cap (on a character boundary) — one huge statement must not make a huge row in the store or the SIEM export |
| `reason` | User-provided reason string, if any |
| `row_count` | Final row count returned (after truncation) |
| `rows_affected` | Rows a write changed (rolled back again under `dry_run`); NULL for reads |
| `upstream_actor`, `upstream_run_id` | `x-dbmcp-on-behalf-of` / `x-dbmcp-run-id` a **service-token** caller claimed ([14-service-tokens](14-service-tokens.md)). Unverified — stored for attribution, never used for authz; `user_sub` stays `service:<name>`. NULL for SSO sessions |
| `truncated` | Whether the row cap cut the result |
| `elapsed_ms` | Wall-clock of the tool's work |
| `outcome` | The spec [03](03-mcp-tools.md) code the client saw: `success`, `dry_run`, `forbidden`, `forbidden_sql`, `invalid_arguments`, `reason_required`, `timeout`, `syntax_error`, `unavailable`, `audit_unavailable`, `internal`, …; plus `cancelled` and `abandoned`, which only the audit log carries |
| `error_message` | The sanitized message the client got — no credentials or raw connection details |

`sql` is stored verbatim up to the cap. There is no per-database `sql_capture` (redacted / metadata-only) policy; a database whose literals must not be stored should not be reachable through `run_query`.

## Storage

| Tier | Where | TTL | Purpose | Status |
|---|---|---|---|---|
| **Hot** | Gateway's state Postgres | 90 days (configurable) | Fast operator queries, dashboards | Shipped |
| **Archive** | S3 / GCS / Azure Blob, optional | 1y / 7y / forever | Compliance retention | Not shipped — [roadmap Phase 4](11-roadmap.md) |
| **Stream** | Optional sink: `stdout`, `syslog` (config: `logging.stream: [{kind: stdout}, {kind: syslog, host: ..., port: ...}]`), OTLP, Kafka | live | Plug into existing SIEM/Splunk/Datadog | `stdout` + `syslog` shipped (#218); OTLP/Kafka not shipped |

Hot and stream are independent — you can send everything to Splunk *and* keep 90 days in Postgres. A row is streamed only after its durable write commits.

**Syslog sink.** RFC 5424 over UDP, MSG body = the row as JSON. The receiver address is resolved and the socket bound once, then reused; a failed send forgets both so the next row re-resolves. A datagram is at most 8 KiB: an oversized row has its `sql` cut and suffixed `...[truncated]` (the body stays valid JSON); if that cannot make it fit, the message itself is cut with the same suffix. A row a sink cannot deliver increments `audit_stream_dropped_total{sink}`; the error log is rate-limited to one line a minute carrying the count dropped since the last one.

## Retention pruning

A background task runs hourly and deletes `audit_call_intents` rows, then `audit_calls` rows, older than the hot TTL (intents first, so the reaper never sees an intent whose completion was just pruned). TTL is floored at one day. Deletes run in batches of 5,000 rows, oldest first, each in its own transaction under a transaction-scoped advisory lock — a large backlog never becomes one long transaction, and a replica that finds the lock held leaves the pruning to the replica holding it. No archive tier is shipped, so nothing is exported before the delete. Pruning is logged.

## Operator queries

Common questions, runnable directly against the state DB:

```sql
-- Who ran what against prod in the last hour?
select occurred_at, user_email, database_name, sql, row_count, outcome
from audit_calls
where server_name = 'prod' and occurred_at > now() - interval '1 hour'
order by occurred_at desc;

-- Top callers for the week
select user_email, count(*) from audit_calls
where occurred_at > now() - interval '7 days'
group by user_email order by 2 desc;

-- Find every query that touched a sensitive table
select * from audit_calls
where sql ilike '%customer_pii%'
and occurred_at > now() - interval '30 days';

-- Calls the gateway never finished recording (crash between target and audit)
select occurred_at, user_email, server_name, database_name, error_message
from audit_calls
where outcome = 'abandoned'
order by occurred_at desc;
```

## What is *not* in the audit log

- The DB password / connection string. Never.
- Result row contents. Counts only.
- Anything that would re-identify a user beyond what's already in the session.

## Stdout log — dispatch line contract

Every tool dispatch emits exactly one JSON-per-line record on stdout, in addition to (not in place of) the audit row. Loki / Alloy ingest this without per-line parsing; the keys are top-level and the types are stable. Operator-facing detail lives in [docs/deployment/logging.md](../deployment/logging.md); this section is the canonical field contract.

Baseline keys on every log line:

| Field | Type | Notes |
|---|---|---|
| `timestamp` | RFC 3339 string | Subscriber default |
| `level` | string | `INFO` / `WARN` / `ERROR` / `DEBUG` |
| `message` | string | Static log-line string |

The dispatch line (`message = "tool dispatched"`) carries additionally:

| Field | Type | When set |
|---|---|---|
| `request_id` | string | JSON-RPC request id |
| `user_sub` | string | OIDC `sub` of the caller; `"anonymous"` on unauthenticated paths |
| `tool` | string | Tool name (`run_query`, `explain`, …) |
| `server` | string | Logical server name from call args, empty for tools that aren't server-scoped |
| `db` | string | Logical database name from call args, empty for tools that aren't database-scoped |
| `outcome` | string | The spec 03 code the client saw (`success` / `forbidden` / `forbidden_sql` / `invalid_arguments` / `timeout` / `syntax_error` / `unavailable` / `audit_unavailable` / `internal` / …). Emitted after the audit write, so an audit failure logs `audit_unavailable` |
| `duration_ms` | integer | Wall-clock the tool itself took. `0` for outcomes where no tool work ran (e.g. `forbidden` before dispatch). |
| `access` | string | `write` when the call ran with write access (a data write, or EXPLAIN of one, under `query_write`), else `read` |
| `upstream_run_id`, `upstream_actor` | string | Only on a service-token call that claimed them; unverified |

The audit-write-failure line adds:

| Field | Type | Notes |
|---|---|---|
| `audit_write_duration_ms` | integer | Wall-clock the failed audit insert took. `duration_ms` on the same line keeps the contract above — tool execution time, not audit latency. |
| `class` | string | Credential-free cause (`pool_timed_out`, `database/<sqlstate>`, `timeout`, …) — never the driver error's text |
| `tool_outcome` | string | The outcome the tool produced before the audit write failed |

Audit metrics: `tool_calls{tool,outcome,access}` (outcome as above; `access` is `read`, `write`, or `unknown` for a call dropped before its tool decided), `audit_write_duration_seconds`, `audit_fallback_failures_total` (a drop-guard retry that also failed — that call's row exists only if its intent is reaped), `audit_stream_dropped_total{sink}`.

Renames or removals of any field above are contract breaks. Additions are fine.

## Error reporting (GlitchTip)

Unhandled panics and unexpected errors are shipped to a **GlitchTip** instance (self-hosted Sentry-compatible) for error tracking. This is a third stream, distinct from the audit log and the stdout log, and it carries **no DB credentials** — see the scrubber contract below.

### Initialization order

Sentry inits **first** in `fn main`, *before* the tokio runtime is built. The init returns a guard (`ClientInitGuard`) bound to a variable that lives for the whole process; dropping it early stops event delivery, so it is held until `main` returns. Only then is the multi-thread runtime constructed and the async entry (`run()`) `block_on`'d. This guarantees a panic during runtime setup is still captured.

### Configuration

| Knob | Source | Notes |
|---|---|---|
| `dsn` | `SENTRY_DSN` env var | Unset / empty → client initializes **disabled**; the app runs normally and ships nothing. The DSN is never hardcoded. |
| `environment` | `SENTRY_ENVIRONMENT` env var | Falls back to `development`. |
| `release` | `CARGO_PKG_VERSION` | Pinned to the crate version at build time. |
| `send_default_pii` | — | Hard-coded `false`. The gateway never sends PII. |

**Error tracking only.** GlitchTip supports neither performance tracing nor profiling nor replay. `traces_sample_rate` is pinned to `0.0`; no spans or transactions are created. Adding tracing/profiling/replay options is a contract break against this section.

### `before_send` scrubber (mandatory)

Every outbound event passes through a `before_send` hook that redacts secrets. This is defense-in-depth on top of the typed-error discipline in the stdout contract — GlitchTip payloads cross the process boundary and must never carry a credential. The hook scrubs, replacing the secret portion with `***REDACTED***`:

- URL userinfo — `scheme://user:pass@host`, password-only `scheme://:pass@host`, passwords containing `/` or `@` (the last `@` before whitespace, `?` or `#` delimits the host), and username-only `scheme://token@host`;
- bare service tokens (`dbmcp_svc_…`, truncated ones included), JWTs (`eyJ…`), and `Bearer …` / `Basic …` credentials;
- `key=value`, `key: value` and JSON `"key":"value"` assignments for the keywords `password`, `passwd`, `pwd`, `secret`, `token`, `dsn`, `api_key`/`apikey`, `authorization`, `cookie`, `credential`, `private_key` (plurals included, case-insensitive), with quoted values containing spaces;
- by **key**: every value under a JSON object key that names a credential (same keyword list, matched on the key lowercased with `-`/`_` dropped, so `X-Api-Key`, `access_token`, `Set-Cookie` count), whatever its shape.

The hook serialises the whole event to JSON, walks it once, and deserialises it, so every protocol field is covered — `message`, `logentry.message/params`, `culprit`, `transaction`, `fingerprint`, exception `type`/`value`/`module`/`mechanism.data`, stack-frame `vars`, breadcrumbs, `tags`, `user`, `request` (headers, cookies, env), `extra`, `contexts` — including fields a future SDK adds. An event that cannot round-trip is **dropped**, never shipped unscrubbed.

Env keys whose values must never leak (the scrubber targets their shapes, not the values themselves):

```text
STATE_DB_URL  TARGET_DB_URL  PERMISSIONS_DB_DSN  OIDC_CLIENT_SECRET  SESSION_SIGNING_KEY
```

Scrubber contract:

| Rule | Detail |
|---|---|
| Replace only the secret portion | The match is rewritten; the rest of the string is untouched. |
| Non-matching text is preserved byte-for-byte | An event that carries no secret ships exactly as the SDK built it. |
| A whole field collapsing to `***REDACTED***` is a failure, not a scrub | It destroys the event and fingerprints every distinct error into one issue. |
| Patterns compile once, at boot | A pattern that does not compile **aborts the process** — a scrubber that cannot scrub is a build defect, and the gateway must not open an event stream it cannot clean. |
| The `regex` features the patterns use are named explicitly | `unicode-case` for `(?i)`, `unicode-perl` for `\w` / `\s` / `\b`. |
| `bin/check-scrub-features` asserts those features in the **no-dev-dependency** graph | That is the graph the release image builds; dev-dependencies mask a missing feature from `cargo test`. |

### Runtime injection

The DSN is injected at runtime via a Kubernetes sealed-secret (not baked into the image). Operator setup lives in [deployment/logging](../deployment/logging.md). With no secret mounted, `SENTRY_DSN` is absent and the client is a no-op — a missing GlitchTip config must never prevent the gateway from serving traffic.
