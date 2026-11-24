# Logging

The gateway emits one JSON object per line on stdout. Designed to be ingested by Loki via Grafana Alloy without a per-line parser stage — keys are top-level, types are stable.

## Field contract

Every log line has at minimum:

| Field | Type | Notes |
|---|---|---|
| `timestamp` | RFC 3339 string | `tracing-subscriber`'s default |
| `level` | string | `INFO` / `WARN` / `ERROR` / `DEBUG` |
| `message` | string | The static log-line string |

The dispatch-time log line (`message: "tool dispatched"`, one per `tools/call` that reached a tool — after authentication) adds:

| Field | Type | When set |
|---|---|---|
| `request_id` | string | Gateway-minted request id — the same value as `audit_calls.request_id` (not the JSON-RPC `id`) |
| `user_sub` | string | OIDC `sub` claim of the caller, or `service:<name>` for a service token. Always an authenticated identity: unauthenticated requests never reach dispatch (the debug-level `mcp request` line uses `"anonymous"` for them) |
| `tool` | string | `run_query` / `explain` / `list_servers` / … |
| `server` | string | `<server>` from the call args, empty for tools that aren't server-scoped |
| `db` | string | `<database>` from the call args, empty for tools that aren't database-scoped |
| `outcome` | string | The audit outcome code: `success`, `dry_run`, `forbidden`, `forbidden_sql`, `permission_denied`, `undefined_object`, `invalid_arguments`, `reason_required`, `timeout`, `syntax_error`, `unavailable`, `unsupported_backend`, `internal`, `cancelled`, `audit_unavailable` (`abandoned` is written only by the reaper) — the full set, [spec 07 §Outcomes](../initial-idea/07-logging-retention.md#outcomes). `rate_limited` / `service_overloaded` are HTTP rejections before dispatch and never appear here |
| `access` | string | `read` / `write` |
| `upstream_run_id`, `upstream_actor` | string | The service-token attribution headers, when sent ([headless agents](../usage/headless-agents.md)) |
| `duration_ms` | integer | Wall-clock the tool took; `0` for outcomes where the tool didn't start (e.g. forbidden before any work) |

On audit-write failure the line additionally carries `audit_write_duration_ms` (integer) — wall-clock the failed audit insert took. `duration_ms` on that same line keeps the contract above (tool execution time), so `success` and `audit write failed` lines can be compared apples-to-apples.

Other code paths emit a subset of these fields when relevant (e.g. the audit pruner emits `rows`, `ttl_days`). Adding new fields is fine; renaming or removing the ones above is a contract break. The canonical contract lives in [docs/initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md).

Every line logged while a tool call runs — a target connect failure deep in the exec layer included — also carries the call's dispatch span as a nested `span` object: `{"name": "tool_dispatch", "request_id", "user_sub", "tool", "server", "db", "upstream_run_id", "upstream_actor"}` (absent upstream fields are omitted). Correlate such a line with its audit row by `span.request_id`; Alloy's `stage.json` reads it as `span.request_id`, Loki's `| json` exposes it as `span_request_id`. Lines outside a tool call carry no `span`.

## Audit stream

`logging.stream` exports every `audit_calls` row — tool completions and the reaper's `abandoned` rows alike — after it commits ([spec 07 §Storage](../initial-idea/07-logging-retention.md#storage)):

- **`kind: stdout`** — one line per row with `target: "audit_stream"` and `message: "audit row streamed"`, carrying every row field top-level: `audit_id`, `request_id`, `user_sub`, `user_email`, `groups` (JSON array string), `tool`, `server`, `database`, `sql`, `sql_truncated`, `reason`, `outcome`, `elapsed_ms`, `row_count`, `truncated`, `rows_affected` (absent for a read), `error_message`, `agent_client`, `ip`, `db_type`, `upstream_actor`, `upstream_run_id`. Other absent values are `""` / `0` / `false`.
- **`kind: syslog`** — RFC 5424 with the row as a JSON body, over `transport: udp` (default), `tcp`, or `tls` with `ca_file` (PEM bundle the receiver's certificate must chain to; required for `tls`). TCP and TLS use RFC 5425 octet-counting framing, which rsyslog (`imtcp` / `imptcp`) and syslog-ng (`syslog()` source) accept.

`sql` is exported verbatim (up to the 64 KiB audit cap, then to the 8 KiB syslog message cap); there is no redaction setting.

## Dropped lines

Sinks are best-effort copies; the durable copy of every row is `audit_calls` in the state DB. Neither sink applies backpressure — a slow log consumer must never slow a request.

Log lines go through a bounded non-blocking queue so a slow stdout consumer never stalls a request. When the queue is full a line is dropped and counted in `log_lines_dropped_total`. That includes `audit_stream` events from the `logging.stream: [{kind: stdout}]` sink: the `audit_stream` target always logs at INFO whatever `RUST_LOG` says, but a row dropped at the queue shows up only in `log_lines_dropped_total` — the queue cannot tell an audit line from another, so it is never in `audit_stream_dropped_total`.

`audit_stream_dropped_total{sink="syslog"}` counts rows the syslog sink did not deliver: a failed DNS lookup, connect, TLS handshake or send, a step past its 5 s ceiling, or more than 1,024 rows already waiting for one receiver. UDP loss after the send is invisible to the gateway; use `tcp` or `tls` to see a down receiver. A stream connection is reused across rows, so a row written into a stream the receiver has half-closed can be lost without a failed send; and a failed send reconnects and resends once, so a row the receiver did take before the failure arrives twice. Delivery is neither exactly-once nor guaranteed: consumers dedupe on `audit_id`, and the `audit_calls` row — committed before the response — is the authority. Alert on the counter, reconcile against `audit_calls`.

## Redaction

No log line carries:

- Connection strings or any `state_db.url`
- Database passwords (the `Password` type has a hand-rolled `Debug` that prints `<redacted>`)
- OIDC client secrets or bearer tokens
- Raw SQL error strings that may contain host:port (sqlx error `Display` is fine — its rendering does not include URLs)

This is enforced by typed errors (spec 05) rather than a runtime scanner — every site logs typed values (`%err` where `err: thiserror::Error`, span fields whose types have audited `Display`/`Debug` impls). Reviewers of new log sites: if a value isn't a primitive or a type with a known-safe `Display`, don't interpolate it.

## Alloy snippet

The defaults work — Alloy's `loki.source.file` will forward each line verbatim. Add stage hints if you want top-level fields exposed as labels:

```alloy
loki.source.file "gateway" {
  targets    = local.file_match.gateway.targets
  forward_to = [loki.process.gateway.receiver]
}

loki.process "gateway" {
  forward_to = [loki.write.default.receiver]

  stage.json {
    expressions = {
      level    = "level",
      tool     = "tool",
      outcome  = "outcome",
      user_sub = "user_sub",
    }
  }
  stage.labels {
    values = {
      level   = "",
      tool    = "",
      outcome = "",
    }
  }
}
```

Keep label cardinality under control — `user_sub` is high-cardinality (per user), so promote it only if your Loki budget allows.

## Local dev

The JSON formatter runs in every binary, including dev. Pipe through `jq` to read:

```bash
cargo run -- --config config.yml | jq -r '"\(.timestamp) \(.level) \(.tool // "") \(.message)"'
```

`stderr` is intentionally left untouched — `cargo`'s own diagnostics (build progress, panic backtraces) are not JSON and would break `jq`.
