# 07 — Logging & Retention

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
