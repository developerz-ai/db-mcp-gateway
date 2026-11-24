# 09 — Deployment

## Distribution

- **OCI image**: `ghcr.io/developerz-ai/db-mcp-gateway:<version>` on GitHub Container Registry (also pushed to DigitalOcean's registry). Multi-arch (amd64, arm64). Distroless `cc` base (glibc; no shell, no `kill`, no `curl`), running as `nonroot`. One binary inside. Public, free, no Docker Hub rate limits.
- **Release trigger**: pushing a `v*` git tag fires `.github/workflows/release.yml`, which re-tags the multi-arch image `ci.yml` already built and tested for that commit (or builds it when there is none), pushes it to GHCR, and cuts a GitHub Release with auto-generated notes.
- **GitHub Releases**: release notes pointing at the image tags. No standalone binaries are attached — build from source (`cargo build --release`) if you need one outside a container.
- **Helm chart / kustomize base**: `deploy/helm/db-mcp-gateway` and `deploy/kustomize/base` in this repository, versioned with the image (`appVersion` is the crate version, pinned by `tests/deploy_catalogue.rs`); not yet published to a chart repository. Kubernetes ≥ 1.30 (the `preStop` hook is the native `sleep` action — the image has no shell). Grace period ≥ 130 s (10 s preStop + the 120 s [shutdown](#shutdown) drain), HTTPS probes with a `startupProbe` covering `STATE_DB_CONNECT_TIMEOUT_SECONDS`, the `restricted` security context, a NetworkPolicy, ServiceMonitor and a PrometheusRule built from `deploy/prometheus/rules.yaml`. Guide: [Kubernetes](../deployment/kubernetes.md).
- **Examples**: `examples/` in this repository (`docker-compose.yml`, `gateway.yaml`). Provisioning SQL per engine lives in the docs ([target roles](../deployment/target-roles.md)), not as shipped templates.

## Minimum viable deployment

```yaml
# docker-compose.yml — minimal
services:
  gateway:
    image: ghcr.io/developerz-ai/db-mcp-gateway:latest
    ports: ["8443:8443"]
    environment:
      STATE_DB_URL: postgres://gateway:${STATE_DB_PW}@state-db:5432/gateway
      OIDC_ISSUER: ${OIDC_ISSUER}
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      OIDC_REDIRECT_URL: https://${GATEWAY_HOST}/auth/callback
      SESSION_SIGNING_KEY: ${SESSION_SIGNING_KEY}   # >= 32 bytes
      TLS_CERT_PATH: /etc/gateway/tls/tls.crt
      TLS_KEY_PATH: /etc/gateway/tls/tls.key
    volumes:
      - ./config.yml:/etc/gateway/config.yml:ro
      - ./tls:/etc/gateway/tls:ro
    depends_on: [state-db]

  state-db:
    image: postgres:16
    environment:
      POSTGRES_DB: gateway
      POSTGRES_USER: gateway
      POSTGRES_PASSWORD: ${STATE_DB_PW}
    volumes:
      - state-db-data:/var/lib/postgresql/data

volumes:
  state-db-data:
```

That's the whole thing: each variable above is one boot refuses to start without (the redirect URL is one login breaks without). It exposes 8443 with the gateway's built-in TLS; behind a TLS-terminating proxy on a trusted network, replace the two cert variables with `TLS_DISABLED=true`. The full walkthrough is the [deployment quickstart](../deployment/quickstart.md#4-bring-it-up-with-docker-compose).

## Provisioning the target databases

The repo ships no SQL templates; the per-engine recipes (Postgres, YugabyteDB, MongoDB, Redis) are in [target roles](../deployment/target-roles.md). For Postgres (`app_owner` = the role that owns the tables):

```sql
-- run once per database the gateway will access
create role mcp_gateway_prod_app_ro with login password :'pw';
grant connect on database app to mcp_gateway_prod_app_ro;
grant usage on schema public to mcp_gateway_prod_app_ro;
grant select on all tables in schema public to mcp_gateway_prod_app_ro;
alter default privileges for role app_owner in schema public
  grant select on tables to mcp_gateway_prod_app_ro;
alter role mcp_gateway_prod_app_ro set statement_timeout = '30s';
alter role mcp_gateway_prod_app_ro set idle_in_transaction_session_timeout = '60s';
```

Operators run this with their own admin credentials. The gateway never gets superuser.

**Write tier.** A database that should accept `query_write` gets a *second* role holding only the data privileges it needs, declared as `write_role` / `write_password` next to the read `role`. The gateway never creates or widens it (MUST #3); reads keep using the read-only role.

```sql
create role mcp_gateway_prod_app_rw with login password :'pw';
grant connect on database app to mcp_gateway_prod_app_rw;
grant usage on schema public to mcp_gateway_prod_app_rw;
grant select, insert, update, delete on table orders, order_items to mcp_gateway_prod_app_rw;
alter role mcp_gateway_prod_app_rw set statement_timeout = '30s';
```

Table scoping is these grants — the gateway has no table allow/deny list ([06-permissions](06-permissions.md)).

## State DB

Co-deployed Postgres. Tiny — audit log is the bulky table and it's pruned (see [07-logging-retention](07-logging-retention.md)). One disk, hourly backups, nothing exotic. Can be the host's existing Postgres if there's a good reason; not recommended because mixing security-sensitive audit data with general app data is asking for trouble.

## TLS

- Gateway terminates TLS in-process via rustls. Reads cert + key paths from `TLS_CERT_PATH` / `TLS_KEY_PATH`.
- Refuses to boot without TLS unless `TLS_DISABLED=true` (dev-only escape; loud `WARN` log on every startup).
- `SIGHUP` reloads the cert + key from the same paths without dropping live connections — rustls re-reads the handshake material atomically, in-flight sessions keep the old cert until they close. Matches cert-manager's rotation contract.
- Reload failures (malformed PEM after a swap, wrong permissions) log the error and keep the previous cert serving; the next `SIGHUP` retries.
- In a Kubernetes deployment, cert-manager mounts the cert as a `Certificate` resource. Cert-manager does NOT send `SIGHUP` itself — a reload controller (e.g. `stakater/reloader`) or a lifecycle/sidecar hook must be wired in to translate the renewal into a `SIGHUP` on the pod. Without that wiring the gateway will keep serving the previous cert until restart.
- For docker-compose without cert-manager, mount your PEMs into the container and `docker kill --signal=HUP <container>` after rotating them. The distroless image has no `kill` binary, so `docker exec … kill` does not work.

## Networking

Two paths must be open:

| From | To | Why |
|---|---|---|
| Developer laptop | Gateway | Agents talk to gateway over HTTPS |
| Gateway | Target DBs | Gateway connects to each DB on its port |
| Gateway | IdP | OIDC discovery, code exchange, JWKS |
| Gateway | State DB | Sessions, audit, permissions |
| Gateway | Syslog receiver (optional) | `logging.stream` syslog sink |

`POST /mcp` validates `Origin` (MCP Streamable HTTP, against DNS rebinding): a request without one passes (non-browser agents), one whose `Origin` is not a bare `scheme://host[:port]` (checked on the raw header before URL parsing: a path, even `/` or `/.`, a `\`, userinfo, whitespace or non-ASCII is refused — the same rule as a listed entry) or not in `MCP_ALLOWED_ORIGINS` — or, on a loopback bind, not a loopback origin — gets `403` before authentication, with no audit row and a `WARN` log line carrying the request id and the reason, never the header value (it may carry URL credentials). A request with more than one `Origin` header is refused the same way, even when the first is allowed.

Behind a reverse proxy, set `TRUSTED_PROXIES` to the proxies' addresses: when the TCP peer is one of them, the audit row's `ip` is the right-most `X-Forwarded-For` hop that is not itself a trusted proxy. Hops are split as bytes, so a non-ASCII entry a client forged does not hide the hops proxies appended after it; a hop that is not an IP (non-UTF-8 included) ends the walk at the trusted hop before it — the gateway records the proxy rather than guess past it. An IPv4-mapped IPv6 entry (`::ffff:10.0.0.0/104`) keeps its IPv6 prefix length and matches the IPv4 peers it maps. Unset, `ip` is the TCP peer and `X-Forwarded-For` is ignored.

No secrets-backend or object-storage path is needed today: secrets arrive as env vars or mounted files (`vault:` / `aws-sm:` / `gcp-sm:` refs abort boot), and there is no archive exporter ([11-roadmap](11-roadmap.md) phase 4).

Run the gateway in the network segment that already reaches the DBs. Most installs put it next to existing internal tools.

## Connection pooling and proxies

Rule: When fronting databases with a connection pool proxy (e.g. pgcat), route the gateway through the proxy endpoint and set TLS based on network scope.

| Scenario | `config.servers[*].host` | `port` | `tls` | Notes |
|---|---|---|---|---|
| Direct to Postgres (no proxy) | `prod-rw.db.example.com` | `5432` | `required` | Standard database connection. |
| Via cluster-internal proxy (Kubernetes) | `pgcat.pgcat.svc.cluster.local` | `6432` | `insecure` | Gateway → proxy → DB legs are mesh traffic; TLS terminates at the gateway or its ingress. Boot logs one `WARN` per `tls: insecure` server. |
| Via cloud-managed proxy (RDS Proxy) | `prod-proxy.proxy.us-east-1.rds.amazonaws.com` | `5432` | `required` | Encryption in-transit expected; network isolation managed by cloud provider. |

What the gateway needs from the proxy (transaction-mode prepared statements, one Postgres server per endpoint for cancellation, the configured role passed through) is the [pooler contract](../deployment/pooler-contract.md). Verify the proxy endpoint and port with your infrastructure team. Proxy unavailability will appear in the gateway's startup logs and connection-attempt logs, or the proxy's own health endpoint — not in the gateway's `/readyz` probe (which only checks state DB reachability and the shutdown flag).

## Replicas

Run as many replicas as you like behind a plain load balancer: no route needs sticky sessions. Sessions, refresh tokens, audit, permissions and the OAuth bridge's login state (pending logins, consents and authorization codes, migration 0022) all live in the shared state DB, so each step of a login may land on a different replica. Every replica must run with the same `SESSION_SIGNING_KEY` and the same `OIDC_REDIRECT_URL` (the load balancer's `/auth/callback`): bearers and the IdP-side login secrets are derived from the key, and the IdP sends every login back to that one URL. See [02-architecture §HA](02-architecture.md#ha).

## Upgrades

- Containers: tag-pinned pulls; the operator bumps the tag and redeploys.
- Migrations: the gateway runs its own state-DB (and MySQL permissions-store) migrations on startup. They follow expand/contract: a migration that drops or narrows an object ships only in a release after the one that stopped using it has run everywhere, so release N-1 runs on schema N. An image therefore boots on a schema a newer release migrated, skipping the versions it does not know and logging `schema was migrated by a newer gateway release`. That makes a one-release rollback an image swap (from 2.0.3). A migration that already ran and was later edited (checksum mismatch) still refuses boot. Procedure: [upgrading-to-2 §Rollback](../deployment/upgrading-to-2.md#rollback).
- Config compatibility: there is no deprecation window. An unknown or renamed YAML key aborts boot with a `line:column` pointer, so a config change that drops or renames a key is a breaking change, listed in the release notes and the upgrade guide. Procedures: [operations](../deployment/operations.md).

## Observability

- `/healthz` (liveness) — always returns 200 if the binary is up.
- `/readyz` (readiness) — 200 only when the state DB is reachable (and the gateway is not shutting down).
- Boot retries an unreachable state DB with backoff for `STATE_DB_CONNECT_TIMEOUT_SECONDS` (default 60 s), then exits. The listener binds only after the state DB is up, so neither probe answers during that window: give the `startupProbe` at least that budget.
- `/metrics` (Prometheus) on its own listener, `METRICS_BIND` (default `127.0.0.1:9090`) — not on the public listener, whose hostname returns 404 for it. Catalogue: [deployment quickstart](../deployment/quickstart.md#metric-catalogue); the source of truth is `src/startup/metrics/catalogue.rs`, pinned to the emit sites by a test.
- `/healthz` and `/readyz` are also served on `METRICS_BIND`, so probes need not reach the public port. That listener binds before boot reaches the state DB: until boot completes it answers liveness `200 starting` and readiness `503 starting`.
- Metric contract: no label carries a user, email, SQL text, request id or host; a `db` label is a configured `server/database`, never a caller-typed name. Every counter is exported at `0` from boot for each stable label set (per tool × outcome, and per configured database × outcome — a reload adds new databases), so `increase()` sees the first event. Target pools (every adapter) and the state DB pools publish size, in-use and idle gauges, sampled every 15 s while the pool is open, plus an acquire-wait histogram. Gauges that change only on an event — `build_info`, `config_info{hash}`, `config_reload_last_success_timestamp`, `tls_cert_not_after_timestamp`, `audit_pruner_last_success_timestamp` — are re-set every minute, so the exporter's one-hour idle eviction (which retires a removed database's series) never drops a live value.
- `PG_CANCEL_POOL_SIZE` (default 2, `1`–`32`) sizes each Postgres tier's cancel pool; out of range aborts boot.
- Structured JSON logs to stdout; `RUST_LOG` defaults to `info`, and the `audit_stream` target is always at INFO.

## Shutdown

`SIGTERM` flips `/healthz` and `/readyz` to 503, stops background loops, and gives in-flight requests an 80 s drain window: the 75 s `/mcp` request timeout (caller pool-share wait 5 s + target pool acquire 5 s + statement ceiling 30 s + two audit writes of 15 s + 5 s slack) plus 5 s, so a call that times out still writes its outcome row. The permissions `LISTEN`/`NOTIFY` listener stays up through the drain, so a revoke announced during shutdown still reaches this replica's cache. Detached audit writes then get up to 20 s, and the request and background state-DB pools close (≤ 10 s each; the listener's pool ends with the drain). Worst case 80 + 20 + 2 × 10 = 120 s: `terminationGracePeriodSeconds` must be ≥ 120 (plus any preStop sleep). `SIGHUP` never terminates the process — the handler is installed whether TLS is on or off.

See [11-roadmap](11-roadmap.md) for what's deferred (k8s operator, multi-replica leader election, etc.).
