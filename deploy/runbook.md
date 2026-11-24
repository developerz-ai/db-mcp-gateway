# db-mcp-gateway runbook

One section per alert in [`prometheus/rules.yaml`](prometheus/rules.yaml) (each alert's `runbook_url` points at its heading here) and one per outcome code an agent or an `audit_calls` row can carry. Metric names, types and labels: `src/startup/metrics/catalogue.rs`. `tests/deploy_catalogue.rs` fails when an alert has no section here or a section names an unknown series.

Most first checks read the audit log in the state DB. A query to start from (read-only role; never paste `sql` output into a ticket without reading it first):

```sql
select occurred_at, request_id, user_email, tool, server_name, database_name, outcome, error_message
from audit_calls
where occurred_at > now() - interval '30 minutes' and outcome = '<code>'
order by occurred_at desc
limit 50;
```

Every agent-facing error carries a `request_id`; it matches `audit_calls.request_id` and the `request_id` field of the gateway's log lines.

## Alerts

### GatewayAuditUnavailable

**Means.** Tool calls were answered `audit_unavailable`: the state DB refused the intent row or the completion row. Audit is synchronous (MUST #4), so agents are getting no answers. Severity critical. It keeps firing for 15m after the last refusal: it reads `audit_last_failure_timestamp{kind="write"}`, which the gateway stamps on every refusal, so a refusal before Prometheus first saw the pod (which `increase()` cannot see) still fires, however late that first scrape. A resolve means no refusal for 15m.

**First checks.**
- `/readyz` on each replica (`503` = the state DB does not answer `SELECT 1` in 2 s).
- State DB health: connections (`max_connections`), disk full, a failover in progress, replication lag on a read-only primary.
- Gateway logs at `ERROR` around the alert: the failing insert's error names the cause (permission, constraint, connection).
- `state_db_pool_connections_in_use / state_db_pool_size` — a saturated request pool waits, then fails the write.

**Fixes.** Restore the state DB (free disk, raise `max_connections`, finish the failover). After an upgrade, re-run the role grants in [operations: state DB roles](../website/docs/deployment/operations.md#state-db-roles) — a new table without grants refuses inserts. Raise `STATE_DB_POOL_SIZE` when the pool is the bottleneck. Never disable audit to restore service.

### GatewayAuditWriteSlow

**Means.** The completion-row insert's p95 (`audit_write_duration_seconds`) is above 250 ms. Every response waits on it; at 15 s it fails as `audit_unavailable`.

**First checks.** State DB CPU, I/O wait and locks (`pg_stat_activity` where `wait_event_type` is `Lock` or `IO`); an autovacuum on `audit_calls`; the pruner deleting a large backlog (`audit_pruner_runs_total`); network latency between gateway and state DB.

**Fixes.** Give the state DB faster storage or more CPU; move it closer to the gateway; let a long prune finish (it is a one-off after a retention change); tune autovacuum on `audit_calls`.

### GatewayAuditFallbackFailures

**Means.** `audit_fallback_failures_total` rose, or `audit_last_failure_timestamp{kind="fallback"}` is under 30m old: an agent disconnected mid-call and the drop-path audit write failed. The call is recorded only once the reaper marks its intent `abandoned`. Like [GatewayAuditUnavailable](#gatewayauditunavailable), the stamp makes a failure before a pod's first scrape fire too; it resolves 30m after the last failure.

**First checks.** Same as [GatewayAuditUnavailable](#gatewayauditunavailable) — the state DB was unreachable when the disconnect happened. Check that [GatewayAuditReaperStale](#gatewayauditreaperstale) is not also firing.

**Fixes.** Fix the state DB; the reaper closes the rows on its next sweep.

### GatewayAuditAbandoned

**Means.** The reaper recorded intent rows with no completion as `abandoned` (`audit_abandoned_total`). A replica crashed, was `SIGKILL`ed mid-drain, or lost the state DB between the intent and the completion write.

**First checks.**
- Pod restarts and `OOMKilled` / exit reasons around the alert.
- `terminationGracePeriodSeconds` ≥ 130 (120 s drain + preStop sleep): a shorter grace kills slow calls mid-drain on every rollout.
- `select * from audit_calls where outcome = 'abandoned' order by occurred_at desc limit 20;` — `access = 'write'` rows are writes that may or may not have committed: check the target.

**Fixes.** Raise the grace period, the memory limit, or fix the crash. Follow up each abandoned write with its user.

### GatewayAuditReaperStale

**Means.** No reaper sweep completed in 10 minutes (`audit_reaper_last_success_timestamp`, 60 s interval), or none since boot, in one gateway deployment (`job`, `namespace`, `service`; a healthy deployment on the same Prometheus, even another release under the same `job`, never hides it). Crashed calls stay open intents.

**First checks.** Gateway logs for `audit_reaper` errors or `background task panicked; restarting`; the background state-DB pool (fixed size 2) blocked by a long lock on `audit_call_intents`.

**Fixes.** Clear the lock or the state DB fault; the supervisor restarts a panicked reaper after 5 s. A reaper that keeps failing is a bug: file it with the log line.

### GatewayAuditPrunerStale

**Means.** No successful retention prune in 3 hours (hourly, first run within 5 minutes of boot), or none since boot, in one gateway deployment (`job`, `namespace`, `service`). Rows past `AUDIT_RETENTION_DAYS` stay; the audit tables grow.

**First checks.** `audit_pruner_runs_total{result="error"}`; gateway logs at `ERROR` from the pruner. The usual cause: `STATE_DB_URL`'s role lacks `DELETE` on `audit_calls`, `audit_call_intents` or `permissions_audit`.

**Fixes.** Restore `DELETE` for the runtime role ([operations: state DB roles](../website/docs/deployment/operations.md#state-db-roles)); fix the state DB fault. The next hourly run catches up.

### GatewayAuditStreamDropped

**Means.** The syslog audit sink failed deliveries (`audit_stream_dropped_total{sink}`): DNS, connect, TLS or send failures, a 5 s step ceiling, or more than 1,024 rows queued. The state DB row is the record; the SIEM copy has gaps.

**First checks.** Receiver reachability from the pod (NetworkPolicy `egress.extra` must allow it); TLS trust of the receiver's certificate; receiver capacity.

**Fixes.** Restore the receiver or the network path; reconcile the gap from `audit_calls` (consumers dedupe on `audit_id`).

### GatewayLogLinesDropped

**Means.** The bounded non-blocking log queue was full and dropped lines (`log_lines_dropped_total`), stdout audit-stream copies included.

**First checks.** The node's log pipeline (container runtime, log shipper) backing up; `RUST_LOG` left at `debug`/`trace`.

**Fixes.** Restore the log consumer; lower `RUST_LOG` to the default `info,sqlx::query=warn`; for a SIEM copy that must not drop on a slow stdout, use the syslog sink.

### GatewayConfigReloadFailed

**Means.** A reload on that replica was refused (`config_reloads_total{result="error"}`); it keeps serving its previous config, so replicas may now disagree (`config_info{hash}` differs).

**First checks.** The replica's log line for the reload names the error (`line:column`, an unresolved `${ENV:…}` / `${FILE:…}`, or a boot-fixed setting changed: `admin`, `permissions_store.driver`, the server set while the admin API is on). Validate the file offline: `db-mcp-gateway --check --config config.yml` (add `--no-secrets` in CI).

**Fixes.** Fix the file and reload again. A boot-fixed change needs a rolling restart. Under Kubernetes the chart rolls pods on a config change instead of reloading.

### GatewayHandlerPanics

**Means.** A panic was caught (`handler_panics_total{layer}`): `http` answered `500`, `tool_work` answered and audited `internal`. Each is a bug.

**First checks.** GlitchTip/Sentry event or the `ERROR` log line with the `request_id`; the audit row of that call.

**Fixes.** File a bug with the request id and log line (never the SQL text of someone else's call without reading it). Roll back if a release introduced it ([operations: rollback](../website/docs/deployment/operations.md#rollback)).

### GatewayRequestsShed

**Means.** Requests refused by a concurrency cap for 10 minutes (`requests_shed_total{scope}`): `global` = `MAX_CONCURRENT_REQUESTS` (agents see `service_overloaded`), `identity` = `MAX_CONCURRENT_PER_IDENTITY` (agents see `rate_limited`), `oauth` = the login routes' cap. Shed requests write no audit row.

**First checks.** Which scope; for `identity`, the caller with the most in-flight calls (`select user_email, count(*) from audit_calls where occurred_at > now() - interval '10 minutes' group by 1 order by 2 desc`); slow queries holding slots (`query_duration_seconds`).

**Fixes.** `identity`: an agent fanning out — lower its parallelism or give a service account its own `max_concurrent_requests`. `global`: add replicas (HPA) or raise the cap if the targets have headroom. `oauth`: a login storm or a client retrying `/token` in a loop.

### GatewayTlsCertExpiringSoon

**Means.** The served certificate (`tls_cert_not_after_timestamp`) expires in under 14 days.

**First checks.** Is renewal automated (cert-manager `Certificate` status, ACME logs)? Did a renewal land in the Secret but not in the pod? The gateway re-reads the PEMs only on `SIGHUP` or restart.

**Fixes.** Renew; then restart the pods (`kubectl rollout restart deployment/<name>`) or wire a reloader (`stakater/reloader` annotation in `podAnnotations`). Under Docker, `docker kill --signal=HUP <container>`.

### GatewayTlsCertExpiryCritical

**Means.** Under 2 days left. Agents cannot connect once it lapses.

**First checks / fixes.** As [GatewayTlsCertExpiringSoon](#gatewaytlscertexpiringsoon), now. Issue a certificate by hand if automation is broken, mount it, restart.

### GatewayLoginFailureSpike

**Means.** More than 10 bridge logins refused in 15 minutes for one cause (`login_failures_total{code}`): `email_unverified` (IdP says the email is unverified), `id_token` (signature, issuer, audience or expiry check failed), `idp_exchange` (code exchange at the IdP token endpoint failed), `state_unavailable` (the state DB could not hold the login flow).

**First checks.** `id_token`: clock skew on nodes, a rotated IdP signing key, `OIDC_AUDIENCE` / `OIDC_CLIENT_ID` mismatch. `idp_exchange`: `OIDC_CLIENT_SECRET` rotated or expired, `OIDC_TOKEN_AUTH_METHOD`, `OIDC_REDIRECT_URL` not registered, egress to the IdP (NetworkPolicy `egress.idp`). `state_unavailable`: the state DB. `email_unverified`: the IdP account's email verification.

**Fixes.** Correct the IdP app or the env vars and roll the pods; restore egress or the state DB.

### GatewayPoolSaturated

**Means.** A target pool (`pool_connections_in_use / pool_size`) above 90 % for 10 minutes. The next waiters time out after 5 s as `unavailable`.

**First checks.** Long-running statements on that database (`query_duration_seconds` by tool; `db_activity`); one caller holding many connections; `pool_kind` (`query` vs `write_query` vs the cancel pools).

**Fixes.** Raise `pool.max_connections` on that database (within the target's `max_connections` and the role's `CONNECTION LIMIT`; `db-mcp-gateway --check` prints the connection budget), or lower the grant's `statement_timeout_ms`. Each replica holds its own pool: total = replicas × pool size.

### GatewayPoolAcquireSlow

**Means.** p95 wait for a target connection (`pool_acquire_wait_seconds`) above 1 s; the acquire timeout is 5 s.

**First checks / fixes.** As [GatewayPoolSaturated](#gatewaypoolsaturated). A slow wait with a non-full pool means connection opens are slow: target TLS handshake, DNS, a pooler (pgcat, PgBouncer) queueing in front of it.

### GatewayStateDbPoolSaturated

**Means.** A state DB pool (`state_db_pool_connections_in_use / state_db_pool_size`, `pool` = `request` or `permissions_mysql`) above 90 % for 10 minutes. Audit writes and session lookups queue behind it.

**First checks.** State DB latency ([GatewayAuditWriteSlow](#gatewayauditwriteslow)); request concurrency per replica.

**Fixes.** Raise `STATE_DB_POOL_SIZE` (≤ `MAX_CONCURRENT_REQUESTS`) within the state DB's `max_connections`; fix the state DB's latency.

### GatewayTargetUnavailable

**Means.** Over 25 % of calls to one database (`tool_calls_by_db{outcome="unavailable"}`) answered `unavailable` for 10 minutes. `/readyz` checks only the state DB, so the pods stay ready.

**First checks.** See [`unavailable`](#unavailable). Target reachable from the pod (NetworkPolicy `egress.targets`); the role's password still valid (a rotated password not yet in the mounted Secret); the target's `max_connections`; a pooler in front of it.

**Fixes.** Restore the target or the path; update the password file and roll (or `SIGHUP`) so pools reopen with it.

### GatewayToolServerErrorRatio

**Means.** Over 5 % of all tool calls ended `internal`, `timeout`, `unavailable` or `audit_unavailable` for 10 minutes.

**First checks.** Break down by outcome and database: `sum by (outcome) (rate(tool_calls[10m]))`, `sum by (db, outcome) (rate(tool_calls_by_db[10m]))`. Then the section of the leading outcome code below.

**Fixes.** Per outcome code.

### GatewayToolDeniedRatio

**Means.** Over 25 % of tool calls ended `forbidden`, `forbidden_sql` or `permission_denied` for 30 minutes. Not an outage: grants, target-role privileges and what agents attempt are out of step. Severity info.

**First checks.** `select user_email, tool, database_name, outcome, count(*) from audit_calls where occurred_at > now() - interval '1 hour' and outcome in ('forbidden','forbidden_sql','permission_denied') group by 1,2,3,4 order by 5 desc;`

**Fixes.** See [`forbidden`](#forbidden), [`forbidden_sql`](#forbidden_sql), [`permission_denied`](#permission_denied). A spike from one identity probing many databases is worth a security look.

### GatewayToolClientErrorRatio

**Means.** Over half of tool calls for 30 minutes ended with a caller-side outcome (`invalid_arguments`, `reason_required`, `syntax_error`, `undefined_object`, `unsupported_backend`). Usually one agent looping on the same bad call. Severity info.

**First checks.** Group the audit rows by `user_email, tool, outcome`; read `error_message` of the top group.

**Fixes.** Point the agent's owner at the error message (every one is self-explaining); for `reason_required`, tell them the grant requires `reason`.

## Outcome codes

The `outcome` label of `tool_calls` / `tool_calls_by_db` and the `audit_calls.outcome` column. Definitions: [spec 03 §Errors](../website/docs/initial-idea/03-mcp-tools.md#errors).

### `success`

The call ran and answered. Nothing to do.

### `dry_run`

A `run_query` write with `dry_run: true` ran and was rolled back. Nothing to do.

### `forbidden`

No grant covers this (identity, server, database, action). **Checks:** the caller's groups (`whoami`; the IdP's groups claim, `OIDC_GROUPS_CLAIM`, `OIDC_GROUPS_PREFIX`); `permissions:` in the YAML or admin-API grants. **Fix:** grant by PR (or the admin API) if the access is intended.

### `forbidden_sql`

The SQL guard refused the statement before it reached the database: a write without `query_write`, DDL, `COPY`, multi-statement, a denied function or relation, a Mongo/Redis command outside the allowlist. **Fix:** none on the gateway — the guard is the policy. If a legitimate read is refused, file it with the statement shape (not the data).

### `permission_denied`

The target role lacks a privilege (SQLSTATE `42501`, `25006`, Redis `NOPERM`, Mongo code 13). **Checks:** `db-mcp-gateway doctor --config config.yml` (privilege drift per role); the target's `GRANT`s for new tables (`ALTER DEFAULT PRIVILEGES`). **Fix:** grant the read role `SELECT` on what the grant allows ([target roles](../website/docs/deployment/target-roles.md)). Never give the read role write privileges.

### `undefined_object`

The statement names a table or column that does not exist. Caller mistake; the answer carries near-miss names. Nothing to do unless a migration dropped something agents rely on.

### `invalid_arguments`

The arguments did not parse or broke a bound (size, identifier shape, unknown key, unknown tool). Caller mistake. A burst with `tool = 'unknown'` is a client calling a tool name this version does not ship.

### `reason_required`

The grant requires `reason` and none was sent. Caller mistake; the agent should pass a reason.

### `timeout`

The statement passed its timeout (grant `statement_timeout_ms`, ceiling 30 s). **Checks:** `query_duration_seconds` by tool; the statement in `audit_calls.sql`. **Fix:** an index, a narrower query, keyset paging; raise `statement_timeout_ms` on the grant only within the 30 s ceiling.

### `syntax_error`

The database rejected the statement (message carries the SQLSTATE in the gateway's wording). Caller mistake.

### `unavailable`

The database was unreachable, refused the role's credentials, had no pooled connection free within 5 s, or rolled back for a retryable reason (`40001`, `40P01`, classes `08`, `53`, `57P`). Retryable only when the body carries no `write` or `write: not_applied` (a read, or a write that never reached a commit). With `write: unknown` the commit may have landed (the connection dropped around the commit): verify the change on the target (the row, the key, the statement in `audit_calls.sql`) before resending, or the write may apply twice. **Checks:** the gateway's `WARN`/`ERROR` lines for that `server`/`db` (they never name the role); pool saturation ([GatewayPoolSaturated](#gatewaypoolsaturated)); credentials (a rotated password); network path. **Fix:** see [GatewayTargetUnavailable](#gatewaytargetunavailable).

### `unsupported_backend`

The tool is not offered on that engine (for example `explain` on Mongo). Caller mistake; `list_databases` lists the tools per database.

### `internal`

A gateway bug, or a tool that panicked. **Checks:** the log line with the `request_id`; GlitchTip. **Fix:** see [GatewayHandlerPanics](#gatewayhandlerpanics).

### `cancelled`

The caller disconnected mid-call (the gateway cancelled the statement on the target), or `cancel_query` stopped it. Expected in small numbers; a rise means clients time out before the gateway does — compare client timeouts with the grant's `statement_timeout_ms`.

### `abandoned`

An intent row the reaper closed because no completion row arrived. Never answered to a client. See [GatewayAuditAbandoned](#gatewayauditabandoned).

### `audit_unavailable`

The audit store refused a write; the call was refused (nothing is returned unaudited). For a write whose completion row failed, the body says `write: applied` or `unknown`: check the target before retrying. See [GatewayAuditUnavailable](#gatewayauditunavailable).

### `rate_limited`

HTTP 429, per-identity concurrency cap (`requests_shed_total{scope="identity"}`). Not an audit outcome. See [GatewayRequestsShed](#gatewayrequestsshed).

### `service_overloaded`

HTTP 503, gateway-wide concurrency ceiling (`requests_shed_total{scope="global"}`). Not an audit outcome. See [GatewayRequestsShed](#gatewayrequestsshed).
