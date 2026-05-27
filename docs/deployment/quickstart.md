# Deployment quickstart

This is the path from zero to a running gateway your team can use. Assumes you're a platform / infra / SRE-flavored human, comfortable with Docker and Postgres.

For the *why* behind these choices, see [../initial-idea/09-deployment.md](../initial-idea/09-deployment.md).

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

Drop `config.yaml` somewhere — example:

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
        password: ${PROD_APP_RO_PASSWORD}
        sql_capture: redacted
        pool: { max_connections: 5 }

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
      STATE_DB_URL: postgres://gateway:${STATE_DB_PW}@state-db:5432/gateway
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      PROD_APP_RO_PASSWORD: ${PROD_APP_RO_PASSWORD}
    volumes:
      - ./config.yaml:/etc/db-mcp-gateway/config.yaml:ro
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

Don't commit `.env`. In real deploys, use a secret manager and the `vault:` / `aws-sm:` / `gcp-sm:` reference syntax instead.

```bash
docker compose up -d
docker compose logs -f gateway
```

You should see schema migrations run, OIDC discovery succeed, and each target DB pool come up healthy.

## 5. Smoke test

```bash
curl -sf https://db.internal.acme.com/healthz   # liveness
curl -sf https://db.internal.acme.com/readyz    # readiness — fails until target DBs are reachable
```

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
| Revoke a session | `docker exec gateway gateway admin revoke-session user@acme.com` |
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
