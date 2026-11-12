# 11 — Observability and credential scrubbing

> Part of [`overview.md`](overview.md). Depends on: 04, 06, 09, 10 (they add the counters named here). **`(security review required)`** — `src/sentry_scrub.rs` is the MUST #1 backstop.

Both infra repos alert on the gateway through metrics; today there is one usable series (`tool_calls{tool,outcome}`) and nothing on writes.

## Files to change

- `src/sentry_scrub.rs:48,53,63,119-126,144-236` — pattern gaps, unscrubbed event fields.
- `src/main.rs:150-152` — recorder: no buckets, no idle timeout/upkeep check.
- `src/transport/probes.rs:102` — `/metrics` unauthenticated on the public listener, `db` label exposes topology.
- `src/tools/audit_dispatch/mod.rs:245-250` — the only tool metric.
- `src/auth/session.rs:201,250`, `src/exec/pg/mod.rs:120-123` — `active_sessions` wrong across replicas; `pool_size` is a constant.
- `bin/check-scrub-features`.

## Steps

1. **Scrubber patterns.** Add: bare `dbmcp_svc_<64hex>`; `Authorization: Bearer …`; JWTs (`eyJ…`); password-only userinfo (`scheme://:secret@host`); userinfo containing `/` or `@` (last `@` before the host delimits); JSON form `"password":"…"`; quoted values with spaces; keywords `api_key`, `apikey`, `authorization`, `cookie`, `credential`, `private_key`.
2. **Scrub by key.** `scrub_json` redacts values under sensitive keys, not only by value pattern. Cover `logentry.message/params`, `culprit`, `transaction`, `fingerprint`, `exception[].module`, `mechanism.data`, frame `vars`. Simplest correct form: serialise the event to JSON, walk it once, deserialise.
3. **Metrics added** (names fixed here so dashboards in 14/15 can be written against them):

| Series | Labels | Source slice |
|---|---|---|
| `tool_calls` | `tool`, `outcome`, **`access`** (`read`/`write`), **`identity_kind`** (`sso`/`service`) | 05 |
| `audit_write_failures_total` | `phase` (`intent`/`completion`/`fallback`) | 04 |
| `audit_abandoned_total` | — | 04 |
| `audit_pruner_runs_total` / `audit_pruner_last_success_timestamp` | `result` | 10 |
| `requests_shed_total` | `scope` (`global`/`identity`/`oauth`) | 09 |
| `target_pool_connections` | `db`, `state` (`idle`/`in_use`) — sampled, replaces constant `pool_size` | 06 |
| `state_pool_acquire_seconds` | `pool` | 10 |
| `sessions_created_total` / `sessions_revoked_total` | — | 08 |
| `config_reloads_total` | `result` | 10 |
| `log_lines_dropped_total`, `audit_stream_dropped_total` | — | 10, 04 |

   No label may carry a user, email, SQL text or request id.
4. **Histograms.** `set_buckets_for_metric` for `query_duration_seconds` and `audit_write_duration_seconds` so they aggregate across replicas. Check `metrics-exporter-prometheus` 0.18 upkeep/idle-timeout behaviour in the crate source and set an idle timeout.
5. **`/metrics` exposure.** Serve on a separate bind (`METRICS_BIND`, default loopback/cluster-internal) and remove it from the public router. Both clusters scrape in-cluster (14, 15 adjust ServiceMonitor/NetworkPolicy).
6. **Tracing.** Confirm every tool dispatch span carries `request_id`, `user`, `server`, `database` (CLAUDE.md) plus `access` and, for service identities, the upstream run id (12).
7. Spec/docs: `07-logging-retention.md`, `website/docs/deployment/` (metric catalogue, `METRICS_BIND`), `docs/` security QA notes for the scrubber matrix.

## Tests

- `src/sentry_scrub.rs` tests: table-driven, one row per form in step 1 and per event field in step 2; assert no secret substring survives.
- `tests/metrics_endpoint.rs`: `_bucket` lines present; new series registered; public listener returns 404 for `/metrics`; no forbidden label names.
- `bin/check-scrub-features`, `bin/test`, `bin/lint`.

## Done when

- A service token, bearer header or DSN in any event field never reaches GlitchTip.
- A write, an audit failure, a shed request and a failed prune are each one PromQL query away.
- `/metrics` is not reachable from the public hostname in either cluster.
