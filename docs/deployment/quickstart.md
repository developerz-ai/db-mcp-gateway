# Deployment quickstart

This is the path from zero to a running gateway your team can use. Assumes you're a platform / infra / SRE-flavored human, comfortable with Docker and Postgres.

For the *why* behind these choices, see [../initial-idea/09-deployment.md](../initial-idea/09-deployment.md).

## Status: what works today

This gateway is mid-build (see [../initial-idea/11-roadmap.md](../initial-idea/11-roadmap.md)). The **Run it locally** walkthrough below boots a real gateway against a local Postgres and serves MCP — it works end to end. A few production features referenced later in this doc are still landing:

| Capability | Status |
|---|---|
| MCP tools, OIDC login, per-DB pools, synchronous audit | works |
| `/healthz`, `/readyz`, `/metrics` | planned — [#13](https://github.com/developerz-ai/db-mcp-gateway/issues/13) |
| In-process TLS | planned — [#12](https://github.com/developerz-ai/db-mcp-gateway/issues/12); front with a TLS-terminating proxy meanwhile |
| `${ENV:NAME}` + `${FILE:/path}` secret refs | **works** — resolved at boot ([#15](https://github.com/developerz-ai/db-mcp-gateway/issues/15)); an unset env or missing file aborts startup |
| `vault:` / `aws-sm:` / `gcp-sm:` secret backends | recognised but **not implemented** — these abort at boot until the backends land |
| Strict config validation | **works** — [#16](https://github.com/developerz-ai/db-mcp-gateway/issues/16): an unknown/misspelled key under `servers`/`databases`/`permissions`/`grants`/`constraints` aborts boot with a `line:column` pointer. Full key list: [config-reference.md](config-reference.md) |
| Unified `config.yml` | **not yet** — the `--config` file carries `servers:` + `permissions:` only; `gateway:` / `auth:` / `logging:` are accepted-but-ignored and come from environment variables today (see below) |
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
  -v "$PWD/config.yml:/etc/gateway/config.yml:ro" \
  ghcr.io/developerz-ai/db-mcp-gateway:main
```

The binary needs its config path. The published image bakes `DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml` in (see [#10](https://github.com/developerz-ai/db-mcp-gateway/issues/10)), but passing it explicitly above keeps the recipe working for a locally-built image too — equivalently, append `--config /etc/gateway/config.yml` as a command argument.

The `:main` tag is published on every push to `main` (see [#10](https://github.com/developerz-ai/db-mcp-gateway/issues/10)). Building from source instead? `docker build -t db-mcp-gateway:dev .` and swap that tag into the `docker run` above.

`RUST_LOG` matters: without it the default filter suppresses the startup lines. If you mistype a secret ref or leave `TARGET_DB_PASSWORD` unset, the gateway **fails fast at boot** rather than at first query — e.g. `Error: env var TARGET_DB_PASSWORD referenced in config but not set in process environment`.

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

> **About login.** The bundled dev stack has no identity provider. The gateway boots and serves without one, but completing an SSO login — and therefore running an *authenticated* query — needs `OIDC_ISSUER` (plus `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`) pointed at a real IdP: your org's, or a throwaway local Keycloak/Dex. Without it, `/auth/login` returns `502` because OIDC discovery fails.

Tear down with `bin/dev down` (add `reset` to wipe the volumes).

### The environment variables the gateway reads

The env→YAML unification is still pending, so these come from the environment, not the `--config` file:

| Variable | Default | Purpose |
|---|---|---|
| `STATE_DB_URL` | `postgres://gateway:gateway-dev-only@localhost:5433/gateway` | Gateway's own Postgres (sessions + audit) |
| `GATEWAY_BIND` | `127.0.0.1:8443` | Listen address |
| `OIDC_ISSUER` | — | IdP issuer URL (OIDC discovery base) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — | Gateway's OIDC client credentials |
| `OIDC_REDIRECT_URL` | `http://localhost:8443/auth/callback` | Must match the IdP app's redirect URI |
| `OIDC_GROUPS_CLAIM` | `groups` | ID-token claim carrying group membership |
| `SESSION_SIGNING_KEY` | dev-only default | HMAC key for gateway-issued session JWTs — **set this in any real deploy** |
| `AUDIT_RETENTION_DAYS` | `90` | Hot-retention window for the audit log |
| `RUST_LOG` | (off) | Log filter — set `info` (or `info,db_mcp_gateway=debug`) to see startup/request logs |

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
| Docker + docker-compose (or k8s + Helm) | Run the gateway image |
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

## 3. Configure the gateway

Drop `config.yml` somewhere — full target shape below. **Heads-up:** the running binary reads only `servers:` and `permissions:` from this file; the `gateway:` / `auth:` / `logging:` blocks shown here are the planned shape but are accepted-but-ignored today and come from environment variables (see the env table above). Unknown keys *inside* `servers`/`databases`/`permissions`/`grants`/`constraints` abort boot ([#16](https://github.com/developerz-ai/db-mcp-gateway/issues/16)). `databases[*].password` accepts `${ENV:NAME}`, `${FILE:/path}`, or a `vault:`/`aws-sm:`/`gcp-sm:` ref — all resolved at boot.

```yaml
gateway:
  bind: 0.0.0.0:8443
  external_url: https://db.internal.acme.com
  env: production
  state_db:
    url: ${STATE_DB_URL}
    pool_size: 10

auth:
  oidc:
    issuer: https://acme.okta.com
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}
    groups_claim: groups
    session_ttl_hours: 8

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

logging:
  hot_retention_days: 90
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

> Dedicated `/healthz` `/readyz` `/metrics` endpoints are planned in [#13](https://github.com/developerz-ai/db-mcp-gateway/issues/13). Until then, watch `docker compose logs gateway` for `db-mcp-gateway listening` and use the `401` probe above for liveness.

Then add the gateway to your own Claude Code and try a query — see [../usage/claude-code.md](../usage/claude-code.md).

## 6. Hand it to the team

Tell your engineers:

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com
```

Commit the resulting `.mcp.json` to whichever repo they should have access from. First call triggers SSO.

## Day-2

| Task | How |
|---|---|
| Change permissions | PR against the gateway config repo. Operator merges, `kill -HUP` on the container. |
| Rotate a DB password | Update in secret manager, `kill -HUP`. New connections use the new password; old ones drain. |
| Revoke a session | A `gateway admin` CLI is planned (phase 8). Today: insert the session into the state DB denylist directly via `psql`. |
| Audit a query | `psql` into state DB → `select * from audit_log where ...` (see [../initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md)) |
| Upgrade | Bump the image tag, redeploy. Migrations run on startup. |

## Production hardening checklist

- [ ] All DB passwords sourced from secret manager, not env literals.
- [ ] `env: production` in config — locks out inline secrets.
- [ ] TLS terminating on the gateway or fronting proxy; never plain HTTP from devs.
- [ ] State DB on its own volume, backed up.
- [ ] At least one streaming sink (OTLP / syslog) into your existing SIEM, in addition to the hot retention table.
- [ ] Archive sink configured if your compliance window > 90 days.
- [ ] Operator runbook for `revoke-session` and `replay-audit` documented somewhere your oncall can find it at 2am.
- [ ] Two replicas behind a load balancer for HA.

## Helm / Kubernetes

A Helm chart is on the roadmap (see [../initial-idea/11-roadmap.md](../initial-idea/11-roadmap.md), phase 8). Until then, the docker-compose layout translates cleanly to a `Deployment` + `Service` + `PersistentVolumeClaim` + `Secret` set if you'd rather hand-roll it.
