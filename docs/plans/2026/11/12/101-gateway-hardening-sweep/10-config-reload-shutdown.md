# 10 — Config, hot reload, startup, shutdown

> Part of [`overview.md`](overview.md). Depends on: 04 (drain tracker), 06 (registry evict). **`(security review required)`** — credential loading, service-token store, TLS to targets.

## Files to change

- `src/startup.rs:12-28,95-130` — SIGHUP reloads TLS only; pruner/GC tasks unsupervised, first tick at boot.
- `src/transport/app_state.rs:29`, `src/main.rs:135,223` — `Arc<ConfigFile>` and `ServiceTokenStore` built once.
- `src/main.rs:66,276-323` — 30 s drain, nothing awaited after `serve()`, HUP handler only when TLS is on; `:102-110` log filter.
- `src/config/yaml.rs:17,338-527` — validation gaps, no `deny_unknown_fields` at top level.
- `src/config/schema.rs:69-76`, `src/exec/pg/config.rs:17,30-33` — `Tls::Required` = encrypt without verify.
- `src/config/mod.rs:30,47,92,121,202-258` — state pool 10 vs 512 concurrency; stale comments.
- `src/state/mod.rs:31-37` — one pool, no server-side timeouts.
- `src/audit/pruner.rs:28-51` — one unbatched DELETE, no lock.
- `Cargo.toml` `[profile.release]`, `Dockerfile:12,44`.

## Steps

1. **Hot reload (implement — four spec files and CLAUDE.md already promise it).** `ArcSwap<ConfigFile>` in `AppState`. On SIGHUP: load → validate → resolve secrets → single swap; on any error keep the old config and log. In the same swap rebuild `ServiceTokenStore`, `invalidate_all` the permissions cache, evict registry slots whose host/port/role/password-ref/tls/pool changed (06). Always install the HUP handler — with TLS off the default disposition kills the process.
2. **Shutdown.** Replace `ShutdownFlag` (`AtomicBool`) with a `CancellationToken`; SSE (if kept) and background loops select on it. After `serve()`: close + await the audit/cancel tracker (04) with a bound, then `state_db.close()`. Drain ≥ pool acquire + statement ceiling + slack + audit timeout (≈ 55 s today); document `terminationGracePeriodSeconds ≥ 75`.
3. **State pools.** Split: request pool (sessions, authz, audit insert) and a small background pool (pruner, GC, reaper, history reads). `statement_timeout` and `idle_in_transaction_session_timeout` via `PgConnectOptions::options`. Boot validation relates pool size to `max_concurrent_requests`; sizes come from 01. `/readyz` uses a non-blocking acquire.
4. **Pruner.** Batched `DELETE … WHERE id IN (SELECT id … ORDER BY occurred_at LIMIT n)` loop under `pg_try_advisory_lock`; also prunes `audit_call_intents` and expired sessions; `interval_at(now + jitter)`; supervised (restart on panic). Partitioning by day is **not** in this plan — revisit if 01 shows `audit_calls` in the tens of millions.
5. **Validation.** Non-zero newtypes for timeouts, row caps, pool sizes, ports; non-empty names; `deny_unknown_fields` on `ConfigFile` and its sections; `STATE_DB_POOL_SIZE=0` rejected with a clear message. `env: production` either rejects inline literal secrets (as `config/example.yaml:15` claims) or the comment goes — implement it.
6. **Target TLS.** Add `Tls::VerifyFull { ca_file: Option<_> }` → `PgSslMode::VerifyFull`; Mongo equivalent; `required` stays but logs a one-shot warn that the peer is unverified.
7. **Logging.** Default filter `info` when `RUST_LOG` is unset; `audit_stream` target always at INFO; export `tracing_appender` dropped-line counter; disable sqlx statement logging on target connections (agent SQL must not land in operational logs).
8. **Build.** `strip = "debuginfo"` (keep symbols for GlitchTip backtraces); digest-pin both Dockerfile base images; `ENV GATEWAY_BIND=0.0.0.0:8443` in the image. Fix stale "every minute" comments (`config/mod.rs:92`, `schema.rs:74`).
9. **Idle cost** (01 findings 3, 4). OAuth/refresh GC interval 30 s → minutes, and it logs only when it deleted something (it is 99.9 % of D1's log volume and ~107k seq-scan DELETEs in five weeks). `/readyz` does not run a state-DB query per probe (09 step 11); decide readiness semantics for a single replica — recommended: a short state-DB blip degrades (requests fail with 5xx) but does not flip readiness until N consecutive failures, so one DNS hiccup is not an hour off the load balancer.
10. Spec: `08-config.md` (reload, `pool:`, `tls`, zero rules, `env`), `05-credentials.md`, `09-deployment.md` + `website/docs/deployment/` (grace period, SIGHUP, `RUST_LOG`), `06-permissions.md` §Hot reload, `14-service-tokens.md` (revocation = reload), `CLAUDE.md` Layers row.

## Tests

- New `tests/config_reload.rs` (model on `tests/tls_reload.rs`): invalid YAML keeps the old config; removed grant → `forbidden` after HUP; removed service account → 401; changed host → new pool; HUP with TLS disabled keeps serving.
- `tests/audit_dispatch_cancellation_real_db.rs`: `pg_sleep`, drop request, shutdown at once → `cancelled` row exists and the backend pid is gone.
- `tests/audit_pruner_real_db.rs`: batch boundary; two concurrent runners, one does the work.
- `src/config/yaml.rs` unit: each rejected zero/blank/unknown key; `src/exec/pg/config.rs` unit: TLS mode mapping; integration with a wrong-CA Postgres.
- `tests/json_logging.rs`: stdout audit stream emits with `RUST_LOG` unset.
- `bin/test`, `bin/lint`, `docker build -t db-mcp-gateway:dev .`.

## Done when

- A merged permissions/service-account change takes effect on SIGHUP with no restart, atomically, or not at all.
- Shutdown under load loses no audit row and leaves no orphan backend query.
- A typo in a top-level config key fails boot.
