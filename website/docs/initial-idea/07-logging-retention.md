# 07 — Logging & Retention

Two distinct streams. Don't confuse them.

| Stream | Where | Purpose |
|---|---|---|
| **Audit log** | State Postgres `audit_log` table | Forensic record. Synchronous, mandatory, append-only. |
| **Stdout log** | Process stdout, one JSON object per line | Operational observability. Ingested by Loki / Splunk / etc. via Alloy. |

The audit log is the system of record. The stdout log is a sidecar for operators; it MUST NOT be the only place a tool call leaves a trace.

## What "audit log" means here

Append-only record of every tool invocation that hits a target database, written synchronously **before** results return to the agent. If the audit write fails, the request fails. There is no "best effort" audit.

## Fields

| Field | Source |
|---|---|
| `request_id` | Generated per request, returned to client |
| `ts` | Server-side, monotonic |
| `user_email`, `user_id`, `groups`, `session_id` | From session (see [04-auth-sso](04-auth-sso.md)) |
| `agent_client` | Self-reported MCP client banner |
| `ip` | Request socket |
| `server`, `database` | Logical names |
| `tool` | `run_query`, `describe_schema`, … |
| `sql` | Full SQL (or redacted / metadata-only per policy) |
| `reason` | User-provided reason string if policy required one |
| `row_count` | Final row count returned (after truncation) |
| `truncated` | Whether `row_limit` cut the result |
| `duration_ms` | Wall-clock for the DB call |
| `outcome` | `ok`, `forbidden`, `timeout`, `error_*` |
| `error_message` | Sanitized — no credentials or raw connection details |

## SQL capture policies

Per-database setting:

| Policy | Effect |
|---|---|
| `full` (default) | Raw SQL stored verbatim |
| `redacted` | Literals and string constants replaced with placeholders before storage |
| `metadata_only` | SQL not stored; only tables touched (parsed from the query plan) and counts |

`redacted` is the right default for databases known to contain PII in literal values (e.g. `WHERE email='alice@example.com'`). `metadata_only` is for the truly paranoid; it costs you the ability to reproduce a query later.

## Storage

| Tier | Where | TTL | Purpose |
|---|---|---|---|
| **Hot** | Gateway's state Postgres | 90 days (configurable) | Fast operator queries, dashboards |
| **Archive** | S3 / GCS / Azure Blob, optional | 1y / 7y / forever | Compliance retention |
| **Stream** | Optional sink: stdout, syslog, OTLP, Kafka | live | Plug into existing SIEM/Splunk/Datadog |

Hot and stream are independent — you can send everything to Splunk *and* keep 90 days in Postgres. Archive is a periodic batch job that exports hot entries to compressed JSONL files keyed by date.

## Retention pruning

A background task runs hourly:

1. Find audit rows older than hot TTL.
2. If archive is configured and the row hasn't been archived yet → export.
3. Delete from hot once successfully archived (or unconditionally if no archive configured and TTL exceeded).

Pruning is logged. Failures alert (and refuse to delete the row that failed to archive).

## Operator queries

Common questions, runnable directly against state DB:

```sql
-- Who ran what against prod in the last hour?
select ts, user_email, database, sql, row_count
from audit_log
where server = 'prod' and ts > now() - interval '1 hour'
order by ts desc;

-- Top queries by user for the week
select user_email, count(*) from audit_log
where ts > now() - interval '7 days'
group by user_email order by 2 desc;

-- Find every query that touched a sensitive table
select * from audit_log
where sql ilike '%customer_pii%'
and ts > now() - interval '30 days';
```

A small read-only SQL view shipped with the gateway exposes the same fields with friendlier column names.

## What is *not* in the audit log

- The DB password / connection string. Never.
- Result row contents. Counts and column names only. (Storing actual rows would defeat the purpose of redacted-SQL mode.)
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
| `outcome` | string | One of the spec 03 codes (`success` / `forbidden` / `forbidden_sql` / `timeout` / `syntax_error` / `unavailable` / `rate_limited` / `service_overloaded` / `internal`) |
| `duration_ms` | integer | Wall-clock the tool itself took. `0` for outcomes where no tool work ran (e.g. `forbidden` before dispatch). |

The audit-write-failure line adds:

| Field | Type | Notes |
|---|---|---|
| `audit_write_duration_ms` | integer | Wall-clock the failed audit insert took. `duration_ms` on the same line keeps the contract above — tool execution time, not audit latency. |

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

- database connection strings with embedded credentials — `postgres://user:pass@host`, `mysql://…`, `mongodb://…`, and any `scheme://user:pass@host` shape;
- bare password-like values in `message`, exception `value`/`type`, breadcrumb `message`/`data`, `tags`, `user`, `request`, and `extra`/`contexts`.

Env keys whose values must never leak (the scrubber targets their shapes, not the values themselves):

```text
STATE_DB_URL  TARGET_DB_URL  PERMISSIONS_DB_DSN  OIDC_CLIENT_SECRET  SESSION_SIGNING_KEY
```

### Runtime injection

The DSN is injected at runtime via a Kubernetes sealed-secret (not baked into the image). Operator setup lives in [deployment/logging](../deployment/logging.md). With no secret mounted, `SENTRY_DSN` is absent and the client is a no-op — a missing GlitchTip config must never prevent the gateway from serving traffic.
