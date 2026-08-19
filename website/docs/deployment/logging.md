# Logging

The gateway emits one JSON object per line on stdout. Designed to be ingested by Loki via Grafana Alloy without a per-line parser stage — keys are top-level, types are stable.

## Field contract

Every log line has at minimum:

| Field | Type | Notes |
|---|---|---|
| `timestamp` | RFC 3339 string | `tracing-subscriber`'s default |
| `level` | string | `INFO` / `WARN` / `ERROR` / `DEBUG` |
| `message` | string | The static log-line string |

The dispatch-time log line (one per `tools/call`) adds:

| Field | Type | When set |
|---|---|---|
| `request_id` | string | JSON-RPC request id |
| `user_sub` | string | OIDC `sub` claim of the caller; `"anonymous"` on unauthenticated paths |
| `tool` | string | `run_query` / `explain` / `list_servers` / … |
| `server` | string | `<server>` from the call args, empty for tools that aren't server-scoped |
| `db` | string | `<database>` from the call args, empty for tools that aren't database-scoped |
| `outcome` | string | `success` / `forbidden` / `forbidden_sql` / `invalid_arguments` / `timeout` / `syntax_error` / `unavailable` / `rate_limited` / `service_overloaded` / `internal` — canonical list per [spec 03 §Errors](../initial-idea/03-mcp-tools.md#errors) |
| `duration_ms` | integer | Wall-clock the tool took; `0` for outcomes where the tool didn't start (e.g. forbidden before any work) |

On audit-write failure the line additionally carries `audit_write_duration_ms` (integer) — wall-clock the failed audit insert took. `duration_ms` on that same line keeps the contract above (tool execution time), so `success` and `audit write failed` lines can be compared apples-to-apples.

Other code paths emit a subset of these fields when relevant (e.g. the audit pruner emits `rows`, `ttl_days`). Adding new fields is fine; renaming or removing the ones above is a contract break. The canonical contract lives in [docs/initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md).

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
