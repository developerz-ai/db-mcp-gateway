# 08 — Configuration

## Shape

A single YAML file. Everything operational lives here. No per-environment forks of the binary; one binary, many configs.

```yaml
# config.yaml — illustrative, not final schema

gateway:
  bind: 0.0.0.0:8443
  external_url: https://db.internal.acme.com
  env: production               # rejects inline secrets when 'production'
  state_db:
    url: ${ENV:STATE_DB_URL}    # gateway's own Postgres
    pool_size: 10

auth:
  oidc:
    issuer: https://acme.okta.com
    client_id: ${ENV:OIDC_CLIENT_ID}
    client_secret: ${ENV:OIDC_CLIENT_SECRET}
    groups_claim: groups        # or 'scim' / 'directory_api'
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
        password: vault:secret/prod/db/app_ro_password
        description: "Main customer-facing app DB"
        sql_capture: redacted
        pool:
          max_connections: 5

      - name: billing
        role: mcp_gateway_prod_billing_ro
        password: vault:secret/prod/db/billing_ro_password
        sql_capture: metadata_only
        pool: { max_connections: 3 }

  - name: staging
    kind: postgres
    host: staging.db.internal
    port: 5432
    tls: required
    databases:
      - name: app
        role: mcp_gateway_staging_app_ro
        password: ${FILE:/run/secrets/staging-app-ro-password}

permissions:
  - group: backend-engineers
    grants:
      - { server: staging, database: "*", action: query_read }
      - { server: prod,    database: "*", action: schema_read }

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
  archive:
    kind: s3
    bucket: acme-db-mcp-audit
    prefix: gateway/
    region: us-east-1
  stream:
    - kind: otlp
      endpoint: https://otel.internal:4317
```

## Resolution order

1. File at `--config` flag, else `$DB_MCP_GATEWAY_CONFIG`, else `/etc/gateway/config.yml`.
2. `${ENV:NAME}` placeholders expanded from process env; `${FILE:/path}` placeholders read from disk (trailing newline stripped). Unresolved or empty refs abort boot.
3. `vault:`, `aws-sm:`, `gcp-sm:` references resolved from the named backend (when backend integrations land — until then, recognised refs also abort boot rather than silently failing at first DB connect).
4. Final config validated against the schema. Errors at this stage refuse to start the process — no half-loaded state.

## Validation rules (non-exhaustive)

- `env: production` ⇒ inline literal passwords rejected (must be reference).
- Every `permissions[*].group` must be a syntactically valid group name; gateway warns (not errors) if no IdP user is in the group — groups can be defined ahead of population.
- Every `permissions[*].grants[*].server` / `database` must exist in `servers`, or be the literal `"*"`.
- Every server's `tls` must be `required` when `env: production` unless explicitly `tls: insecure` (which logs a warning every minute).
- Role names must match `^[a-zA-Z_][a-zA-Z0-9_]*$`. Catch typos before they become connection failures.

## Hot reload

`SIGHUP` re-reads the file. On success, swaps live config atomically. On failure, keeps the old config and logs the error — never half-applies. Pools for removed databases drain; new pools for added databases come up lazily.

## What is *not* in config

- Anything user-facing. No UI strings, no branding, no email templates (this isn't that kind of product).
- Per-user permissions. Users get permissions through groups, period.
- DB schemas. The gateway reads the DB's own schema; it doesn't maintain a separate model.
