# Deployment quickstart

This is the path from zero to a running gateway your team can use. Assumes you're a platform / infra / SRE-flavored human, comfortable with Docker and Postgres.

For the *why* behind these choices, see [../initial-idea/09-deployment.md](../initial-idea/09-deployment.md).

## Status: what works today

This gateway is mid-build (see [../initial-idea/11-roadmap.md](../initial-idea/11-roadmap.md)). The **Run it locally** walkthrough below boots a real gateway against a local Postgres and serves MCP — it works end to end. A few production features referenced later in this doc are still landing:

| Capability | Status |
|---|---|
| MCP tools, OIDC login, per-DB pools, synchronous audit | works |
| `/healthz`, `/readyz`, `/metrics` | **works** — [#13](https://github.com/developerz-ai/db-mcp-gateway/issues/13). k8s probes on the main listener; Prometheus scrape on its own `METRICS_BIND` listener; see [Probes & metrics](#probes--metrics) below |
| In-process TLS + cert reload on `SIGHUP` | **works** — [#12](https://github.com/developerz-ai/db-mcp-gateway/issues/12). `TLS_CERT_PATH` + `TLS_KEY_PATH` point at PEM files; `kill -HUP <pid>` reloads them in place without dropping live connections. Boot refuses to start without TLS unless `TLS_DISABLED=true` is set explicitly (dev-only). |
| `${ENV:NAME}` + `${FILE:/path}` secret refs | **works** — resolved at boot ([#15](https://github.com/developerz-ai/db-mcp-gateway/issues/15)); an unset env or missing file aborts startup |
| `vault:` / `aws-sm:` / `gcp-sm:` secret backends | recognised but **not implemented** — these abort at boot until the backends land |
| Strict config validation | **works** — an unknown/misspelled key anywhere in the file, including the top level, aborts boot with a `line:column` pointer; so do zero/blank values and, under `gateway.env: production`, inline literal secrets. Full key list: [config-reference.md](config-reference.md) |
| Unified `config.yml` | **not yet** — listener, state DB, TLS and OIDC settings come from environment variables (see below); `auth:` in the YAML is a boot error |
| `gateway admin …` subcommands | planned — phase 8 |

## Run it locally

The fastest way to see a working gateway. Brings up two throwaway Postgres containers (gateway state DB + an example target DB) with the bundled `docker-compose.dev.yml`, then runs the gateway image against them.

```bash
# 1. clone + start the dev databases (state DB on :5433, target DB on :5434)
git clone https://github.com/developerz-ai/db-mcp-gateway && cd db-mcp-gateway
cp .env.example .env
bin/dev up

# 2. write a minimal config — servers + permissions only (state DB + OIDC come from env)
cat > config.yml <<'YAML'
servers:
  - name: local
    kind: postgres
    host: localhost
    port: 5434
    tls: insecure          # local Postgres has no TLS — never use in prod
    databases:
      - name: app
        role: app                        # the dev superuser; use a read-only role in prod
        password: ${ENV:TARGET_DB_PASSWORD}   # ${ENV:NAME} or ${FILE:/path}; resolved at boot
permissions:
  - group: devs
    grants:
      - { server: local, database: app, action: query_read, constraints: { row_limit: 1000 } }
YAML

# 3. run the gateway against the dev stack
docker run --rm --network host \
  -e RUST_LOG=info \
  -e DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml \
  -e STATE_DB_URL='postgres://gateway:gateway-dev-only@localhost:5433/gateway' \
  -e TARGET_DB_PASSWORD='app-dev-only' \
  -e TLS_DISABLED=true \
  -v "$PWD/config.yml:/etc/gateway/config.yml:ro" \
  ghcr.io/developerz-ai/db-mcp-gateway:main
```

`TLS_DISABLED=true` is the explicit dev-only opt-out — the gateway refuses to boot otherwise (see [#12](https://github.com/developerz-ai/db-mcp-gateway/issues/12)). Real deploys mount cert+key and unset this var.

The binary needs its config path. The published image bakes `DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml` in (see [#10](https://github.com/developerz-ai/db-mcp-gateway/issues/10)), but passing it explicitly above keeps the recipe working for a locally-built image too — equivalently, append `--config /etc/gateway/config.yml` as a command argument.

The `:main` tag is published on every push to `main` (see [#10](https://github.com/developerz-ai/db-mcp-gateway/issues/10)). Building from source instead? `docker build -t db-mcp-gateway:dev .` and swap that tag into the `docker run` above.

With `RUST_LOG` unset the gateway logs at `info`. If you mistype a secret ref or leave `TARGET_DB_PASSWORD` unset, the gateway **fails fast at boot** rather than at first query — e.g. `Error: env var TARGET_DB_PASSWORD referenced in config but not set in process environment`.

You should see the gateway load config, migrate the state DB, and start listening:

```json
{"message":"config loaded; all secret refs resolved","path":"/etc/gateway/config.yml","servers":1,"permissions":1}
{"message":"state DB connected, migrations applied","pool_size":10}
{"message":"db-mcp-gateway listening","addr":"127.0.0.1:8443","path":"/mcp"}
```

It's now serving MCP on `http://localhost:8443/mcp`. An unauthenticated call returns `401`, which confirms the endpoint and auth gate are live:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8443/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
# 401
```

> **About login.** The bundled dev stack has no identity provider. The gateway refuses to boot without `OIDC_ISSUER` and `OIDC_CLIENT_ID`; it does not contact the IdP at boot, but completing an SSO login — and therefore running an *authenticated* query — needs them (plus `OIDC_CLIENT_SECRET`) pointed at a real IdP: your org's, or a throwaway local Keycloak/Dex. If the IdP is unreachable, `/auth/login` returns `502` because OIDC discovery fails.

Tear down with `bin/dev down` (add `reset` to wipe the volumes).

### The environment variables the gateway reads

The env→YAML unification is still pending, so these come from the environment, not the `--config` file:

| Variable | Default | Purpose |
|---|---|---|
| `STATE_DB_URL` | `postgres://gateway:gateway-dev-only@localhost:5433/gateway` | Gateway's own Postgres (sessions + audit) |
| `GATEWAY_BIND` | `127.0.0.1:8443` (image: `0.0.0.0:8443`) | Listen address |
| `METRICS_BIND` | `127.0.0.1:9090` | Prometheus `/metrics` listener — separate from `GATEWAY_BIND`, which no longer serves `/metrics`. Set `0.0.0.0:9090` for an in-cluster scrape and fence the port with a NetworkPolicy; must differ from `GATEWAY_BIND` |
| `MAX_CONCURRENT_REQUESTS` / `MAX_CONCURRENT_PER_IDENTITY` | `512` / `16` | In-flight ceilings (global → 503, per caller → 429). `0` aborts boot |
| `STATE_DB_POOL_SIZE` | `10` | Request-path state-DB pool. `0`, or more than the concurrent-request ceiling (512), aborts boot. Pruner/GC use a separate fixed pool of 2 |
| `OIDC_ISSUER` | — (required) | IdP issuer URL (OIDC discovery base). A trailing slash is ignored |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — (client id required) | Gateway's OIDC client credentials |
| `OIDC_REDIRECT_URL` | `http://localhost:8443/auth/callback` | Must match the IdP app's redirect URI |
| `OIDC_GROUPS_CLAIM` | `groups` | ID-token claim carrying group membership |
| `SESSION_SIGNING_KEY` | dev-only default | HMAC key for gateway-issued session JWTs — **set this in any real deploy**. Minimum 32 bytes; empty, shorter or the dev default are refused at boot |
| `ALLOW_INSECURE_SIGNING_KEY` | `false` | Local dev only: accept a short or dev-default `SESSION_SIGNING_KEY`. Refused at boot unless `OIDC_ISSUER` is a loopback URL; logs a `WARN` when set |
| `SESSION_TTL_HOURS` | `8` | Session (access token) lifetime, `1`–`168` |
| `REFRESH_TTL_DAYS` | `1` | Absolute refresh-chain lifetime, `1`–`90`; see [auth & SSO](../initial-idea/04-auth-sso.md#token-endpoint--post-token) |
| `TLS_CERT_PATH` | — | PEM-encoded leaf cert (+ intermediates). Required unless `TLS_DISABLED=true` |
| `TLS_KEY_PATH` | — | PEM-encoded private key. Required unless `TLS_DISABLED=true` |
| `TLS_DISABLED` | `false` | Dev-only escape. `true` serves plain HTTP and emits a `WARN` log on startup |
| `AUDIT_RETENTION_DAYS` | `90` | Hot-retention window for the audit log |
| `PERMISSIONS_CACHE_TTL_SECONDS` | `60` | Per-user DB-grant cache TTL; bounds how long a revoked grant is honoured on a replica that missed the invalidation. Above `300` aborts boot |
| `SESSION_CACHE_TTL_SECONDS` | `30` | Freshness window for the in-memory session cache. Bounds how long a revoked session stays honored on *other* HA replicas; `0` re-validates every request. See [auth & SSO](../initial-idea/04-auth-sso.md#session-tokens) |
| `RUST_LOG` | `info,sqlx::query=warn` | Log filter. Invalid directives are skipped. The `audit_stream` target always logs at INFO regardless |

> **Shutdown.** On `SIGTERM` the gateway stops accepting work, gives in-flight requests up to 55 s, waits up to 20 s for detached audit writes, then closes its state-DB pools (≤ 10 s each). Set `terminationGracePeriodSeconds: 75` or more, or Kubernetes `SIGKILL`s a pod mid-drain.

> **Cert rotation.** `kill -HUP <pid>` (or a pod lifecycle hook, sidecar, or reload controller that sends `SIGHUP`) re-reads `TLS_CERT_PATH` + `TLS_KEY_PATH` in place. The `SIGHUP` handler is installed with TLS off too, so the signal never kills the process. In-flight connections keep their old cert until they close; new handshakes pick up the new one. Kubernetes does not send `SIGHUP` on its own — `terminationGracePeriodSeconds` only governs `SIGTERM` at shutdown — so operators must wire the reload signal explicitly. Cert-manager integration can automate this once #17 lands the infra stack.

### Permissions in a nutshell

Every grant is `group × server × database × action`, with optional per-grant `constraints`. Actions are hierarchical (`query_write` ⊇ `query_read` ⊇ `schema_read`; `history_read` is separate), and `"*"` matches any server or database.

```yaml
permissions:
  - group: data-analysts        # matches an SSO group from the IdP groups claim
    grants:
      - server: prod
        database: "*"           # every database on the prod server
        action: query_read      # SELECT + schema reads; never writes
        constraints:
          require_reason: true  # agent must supply a reason → audit log
          row_limit: 1000       # gateway truncates beyond this
          statement_timeout_ms: 5000
```

Most restrictive value wins when multiple grants match. See [../initial-idea/06-permissions.md](../initial-idea/06-permissions.md).

## What you'll end up with

```
┌──────────────────────────────────────────────────────────┐
│  Your network                                            │
│                                                          │
│    ┌──────────┐       ┌─────────────┐    ┌───────────┐  │
│    │ Gateway  │───────▶│ state DB    │    │ target    │  │
│    │ (docker) │       │ (postgres)  │    │ DBs (yours) │
│    └────┬─────┘       └─────────────┘    └─────▲─────┘  │
│         │                                       │        │
│         └───── read-only role per DB ───────────┘        │
│         ▲                                                │
└─────────┼────────────────────────────────────────────────┘
          │ HTTPS (MCP)
       ┌──┴───┐
       │ devs │  ── via Claude Code / Cursor / etc.
       └──────┘
```

## Prerequisites

| You need | Why |
|---|---|
| Docker + docker-compose (or k8s manifests) | Run the gateway image. A Helm chart is on the roadmap — until then, hand-roll the manifests (see below). |
| One Postgres instance for *gateway state* (sessions + audit) | Keep gateway state separate from your prod DBs |
| Network reachability gateway → each target DB | Self-evident |
| An OIDC IdP (Okta, Google Workspace, Authentik, Keycloak, Entra) | Identity |
| Admin access to each target DB | Create the read-only roles |
| A secret manager (Vault / AWS SM / GCP SM) | Not strictly required but strongly recommended |
| A DNS name + TLS cert for the gateway | Devs hit it over HTTPS |

## 1. Provision read-only roles on each target DB

Run this once **per database** the gateway will access (Postgres example):

```sql
create role mcp_gateway_prod_app_ro with login password :'pw';
grant connect on database app to mcp_gateway_prod_app_ro;
grant usage on schema public to mcp_gateway_prod_app_ro;
grant select on all tables in schema public to mcp_gateway_prod_app_ro;
alter default privileges in schema public
  grant select on tables to mcp_gateway_prod_app_ro;

-- defense in depth — gateway also enforces these
alter role mcp_gateway_prod_app_ro set statement_timeout = '30s';
alter role mcp_gateway_prod_app_ro set idle_in_transaction_session_timeout = '60s';
```

Store the password in your secret manager. Never paste it into config.

### Optional: a write role for `query_write`

Writes are opt-in, and the gateway never provisions them (MUST #3). For a
database where some group should be able to `INSERT`/`UPDATE`/`DELETE`,
create a **second** role and wire it as `write_role` — never widen the
read-only role, which every read keeps using:

```sql
create role mcp_gateway_prod_app_rw with login password :'rw_pw';
grant connect on database app to mcp_gateway_prod_app_rw;
grant usage on schema public to mcp_gateway_prod_app_rw;
-- data writes only: no CREATE, no TRUNCATE, no ownership
grant select, insert, update, delete on all tables in schema public
  to mcp_gateway_prod_app_rw;
grant usage on all sequences in schema public to mcp_gateway_prod_app_rw;
alter default privileges in schema public
  grant select, insert, update, delete on tables to mcp_gateway_prod_app_rw;

alter role mcp_gateway_prod_app_rw set statement_timeout = '30s';
alter role mcp_gateway_prod_app_rw set idle_in_transaction_session_timeout = '60s';
```

```yaml
      - name: app
        role: mcp_gateway_prod_app_ro
        password: ${ENV:PROD_APP_RO_PASSWORD}
        write_role: mcp_gateway_prod_app_rw
        write_password: ${ENV:PROD_APP_RW_PASSWORD}
```

Narrow the write role's table grants as far as the use case allows: table
scoping is the role's job, not the gateway's. The introspection tools need
nothing extra — `table_stats` only lists tables the read role can `SELECT`,
and `db_activity` / `cancel_query` see and cancel only the gateway's own
roles' backends, which a role may always do for itself.

## 2. Register an OIDC application

In your IdP, create an OIDC app for the gateway:

| Setting | Value |
|---|---|
| Application type | Web / OIDC |
| Redirect URI | `https://<your-gateway>/auth/callback` |
| Grant types | Authorization code + refresh token |
| Scopes | `openid email profile groups` |
| Group claim | Add `groups` to the ID token (or use SCIM — see below) |

Note the `client_id` and `client_secret`.

> **MCP OAuth — what a reverse proxy / WAF must allow.** The gateway speaks the
> MCP Authorization spec (OAuth 2.1 + PKCE) so clients like Claude Code
> authenticate with zero manual credential wiring. A `401` on `/mcp` carries a
> `WWW-Authenticate` header; the client discovers and completes the flow against
> endpoints the gateway serves itself. If you front the gateway with a proxy or
> WAF, the following **unauthenticated** paths must reach it:
>
> ```text
> GET  /.well-known/oauth-protected-resource        (also the <mcp-path>-suffixed variant)
> GET  /.well-known/oauth-authorization-server
> GET  /.well-known/openid-configuration
> GET  /authorize
> POST /token
> POST /register
> ```
>
> The gateway **is** the authorization server — it brokers the IdP login
> internally. Do **not** add a second OAuth/SSO layer (e.g. an access proxy) in
> front of `/mcp`; that would break client auto-discovery. See
> [../initial-idea/04-auth-sso.md](../initial-idea/04-auth-sso.md) for the full
> OAuth bridge spec.

## 3. Configure the gateway

Drop `config.yml` somewhere — full shape below. Listener, state DB and OIDC settings are environment variables (see the env table above), not YAML; an unknown key anywhere in the file — `auth:` included — aborts boot with a `line:column` pointer. `databases[*].password` accepts `${ENV:NAME}` and `${FILE:/path}` refs today — both resolved at boot. `vault:` / `aws-sm:` / `gcp-sm:` refs parse but are **recognised-and-rejected** at boot until the backends land (see the status table above); use env or file refs in the meantime.

```yaml
gateway:
  env: production        # inline literal secrets abort boot

servers:
  - name: prod
    kind: postgres
    host: prod-rw.db.internal
    port: 5432
    tls: required
    databases:
      - name: app
        role: mcp_gateway_prod_app_ro
        password: ${ENV:PROD_APP_RO_PASSWORD}   # or ${FILE:/run/secrets/prod-app-ro}
        # sql_capture / pool are in the spec but not enforced yet; the parser
        # rejects unknown keys (#16), so keep them commented until they ship:
        # sql_capture: redacted
        # pool: { max_connections: 5 }

permissions:
  - group: backend-engineers
    grants:
      - { server: prod, database: "*", action: schema_read }

  - group: oncall
    grants:
      - server: prod
        database: "*"
        action: query_read
        constraints:
          require_reason: true
          statement_timeout_ms: 5000
          row_limit: 1000
```

See [../initial-idea/08-config.md](../initial-idea/08-config.md) for the full schema and validation rules.

## 4. Bring it up with docker-compose

```yaml
# docker-compose.yml
services:
  gateway:
    image: ghcr.io/developerz-ai/db-mcp-gateway:latest
    ports: ["8443:8443"]
    environment:
      DB_MCP_GATEWAY_CONFIG: /etc/gateway/config.yml
      STATE_DB_URL: postgres://gateway:${STATE_DB_PW}@state-db:5432/gateway
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      PROD_APP_RO_PASSWORD: ${PROD_APP_RO_PASSWORD}
    volumes:
      - ./config.yml:/etc/gateway/config.yml:ro
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

`.env` next to it:

```env
STATE_DB_PW=...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
PROD_APP_RO_PASSWORD=...
```

Don't commit `.env`. In real deploys, inject `PROD_APP_RO_PASSWORD` from your orchestrator's secret store and reference it as `${ENV:PROD_APP_RO_PASSWORD}`, or mount a sealed-secret file and use `${FILE:/run/secrets/prod-app-ro}`. (Native `vault:` / `aws-sm:` / `gcp-sm:` backends are recognised but not yet implemented — see the status table above.)

```bash
docker compose up -d
docker compose logs -f gateway
```

You should see schema migrations run, OIDC discovery succeed, and each target DB pool come up healthy.

## 5. Smoke test

The gateway's MCP endpoint is bearer-gated, so an unauthenticated POST returning `401` confirms it's up and the auth gate is live:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://db.internal.acme.com/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
# 401
```

For richer signals use the dedicated endpoints below.

## Probes & metrics

Three unauthenticated ops endpoints. `/healthz` and `/readyz` are mounted alongside `/mcp`; `/metrics` is served only on `METRICS_BIND` (default `127.0.0.1:9090`) — never on the public listener, because its labels name every configured database:

| Endpoint | Returns | What's behind it |
|---|---|---|
| `/healthz` | `200 ok` while running; `503 shutting down` once the process catches SIGTERM/Ctrl-C | Process liveness only — does not touch the state DB |
| `/readyz` | `200 ok` when the state DB answers `SELECT 1` within 2s; `503` otherwise (or during shutdown) | Pulls the pod out of the Service endpoint set on transient DB outages, no restart |
| `/metrics` (on `METRICS_BIND`) | Prometheus text exposition (`text/plain; version=0.0.4`) | See the metric catalogue below |

### Metric catalogue

Names are fixed — dashboards and alerts are written against them. No label carries a user, email, SQL text or request id.

| Series | Type | Labels |
|---|---|---|
| `tool_calls` | counter | `tool`, `outcome` (the spec 03 code the client saw — an intent or completion write that failed shows as `audit_unavailable`), `access` (`read`/`write`/`unknown` for a call dropped before it decided) |
| `query_duration_seconds` | histogram (fixed buckets 5 ms – 60 s) | `tool` |
| `audit_write_duration_seconds` | histogram (fixed buckets 1 ms – 5 s) | — |
| `audit_fallback_failures_total` | counter | — (a disconnect-path audit write failed; the row exists only once the reaper records it) |
| `audit_abandoned_total` | counter | — (intents the reaper recorded as `abandoned`; only the lock-holding replica increments it, so `sum()` across replicas is exact) |
| `audit_pruner_runs_total` | counter | `result` (`ok`/`error`) |
| `audit_pruner_last_success_timestamp` | gauge (unix seconds) | — |
| `requests_shed_total` | counter | `scope` (`global`/`identity`/`oauth`) |
| `pool_size` | gauge (configured max connections) | `db`, `pool_kind` (`query`/`cancel`, plus `write_query`/`write_cancel` when `write_role` is set) |
| `sessions_created_total` / `sessions_revoked_total` | counter | — |
| `config_reloads_total` | counter | `result` (`ok`/`error`) |
| `log_lines_dropped_total` | counter | — |
| `audit_stream_dropped_total` | counter | `sink` (`syslog`) |

Histograms use fixed buckets so they aggregate across replicas. Gauges and histograms untouched for an hour leave the output (an evicted database's labels do not linger); counters never expire.

### k8s probes

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 8443 }
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /readyz, port: 8443 }
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Prometheus scrape

```yaml
# METRICS_BIND=0.0.0.0:9090 on the pod; port 9090 reachable only from the
# Prometheus namespace (NetworkPolicy). Never route it through the ingress.
- job_name: db-mcp-gateway
  metrics_path: /metrics
  static_configs:
    - targets: ['db-mcp-gateway.gateway.svc:9090']
```

Smoke test (from inside the pod or cluster — the public hostname returns 404):

```bash
curl -s http://127.0.0.1:9090/metrics | head
# # TYPE tool_calls counter
# tool_calls{tool="list_servers",outcome="success"} 4
# …
```

Then add the gateway to your own Claude Code and try a query — start with the 5-minute [first-query walkthrough](../usage/first-query.md), or jump to the full [Claude Code reference](../usage/claude-code.md).

## 6. Hand it to the team

Tell your engineers:

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com
```

Commit the resulting `.mcp.json` to whichever repo they should have access from. First call triggers SSO.

Point them at [../usage/first-query.md](../usage/first-query.md) — 5-minute happy path that takes them from `mcp add` to a real query against a real DB with their own audit row.

## Day-2

| Task | How |
|---|---|
| Change permissions / service accounts | PR against the gateway config repo. Operator merges, `kill -HUP` on every pod. The reload is atomic: a bad file is logged, counted in `config_reloads_total{result="error"}`, and the old config keeps serving. Admin API mount/group and `permissions_store` need a restart. |
| Rotate a DB password | Update in secret manager. `${FILE:…}` refs are re-read whenever a pool opens; to force it, change the ref (or anything else on that database) and `kill -HUP` — changed databases get a fresh pool, old connections drain. |
| Revoke a session | A `gateway admin` CLI is planned (phase 8). Today: insert the session into the state DB denylist directly via `psql`. |
| Audit a query | `psql` into state DB → `select * from audit_log where ...` (see [../initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md)) |
| Upgrade | Bump the image tag, redeploy. Migrations run on startup. |

## Production hardening checklist

- [ ] All DB passwords sourced from secret manager, not env literals.
- [ ] `gateway: { env: production }` in config — inline literal secrets abort boot.
- [ ] TLS terminating on the gateway or fronting proxy; never plain HTTP from devs.
- [ ] State DB on its own volume, backed up.
- [ ] Two replicas behind a load balancer for HA. The OAuth bridge keeps its login-flow state in-process, so pin `/register`, `/authorize`, `/auth/callback`, and `/token` with sticky routing (or run a single replica); steady-state `/mcp` traffic needs no stickiness. See [../initial-idea/02-architecture.md](../initial-idea/02-architecture.md#ha).

## Helm / Kubernetes

A Helm chart is on the roadmap (see [../initial-idea/11-roadmap.md](../initial-idea/11-roadmap.md), phase 8). Until then, the docker-compose layout translates cleanly to a `Deployment` + `Service` + `PersistentVolumeClaim` + `Secret` set if you'd rather hand-roll it.
