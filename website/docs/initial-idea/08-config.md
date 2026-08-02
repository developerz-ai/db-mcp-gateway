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

# Optional. Absent ⇒ /admin/v1/* returns 404, YAML-only permissions path.
admin:
  enabled: true
  group: db-admins           # SSO group claim authorising admin calls

# Optional. Absent ⇒ pg (state DB) backs users/databases/grants.
permissions_store:
  driver: pg                 # or 'mysql' — see boot-gate below

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
- A database's `role` must not be the stock superuser account its backend ships with (`postgres` for Postgres, `root` for MySQL, `sa` for MSSQL, `root`/`admin` for Mongo). Matched case-insensitively on the name only — a superuser renamed to `app` still passes; the real least-privilege guarantee lives target-side. Rejected at boot so the "never run as DB superuser" rule (see [05-credentials.md](05-credentials.md)) can't be defeated by a config typo.
- Every server's `kind` must have a query adapter wired (today `postgres` and `mongo`). A `mysql`/`mssql` target is rejected at boot rather than parsing clean and failing every query at runtime — these kinds are reserved for the roadmap adapters and only become valid when their adapters land.
- `MCP_PATH` (env-driven for now, folded into YAML with #16) must not collide with a path the gateway already mounts. Reserved exact paths: `/healthz`, `/readyz`, `/metrics`, `/auth/login`, `/auth/callback`, `/auth/logout`, `/authorize`, `/token`, `/revoke`, `/register`. Reserved route families (the path and anything under `<prefix>/…`): `/admin` (owned by the admin API — reserved unconditionally so toggling `admin.enabled` can't turn a working config into a boot panic) and `/.well-known` (RFC 8414/9728 discovery metadata). Segment-based match: `/adminy` or `/tokens` are fine. Overlap surfaces as a typed boot error naming the offending path, not an axum router panic.
- `admin.enabled` defaults to `false` — absent or false leaves `/admin/v1/*` unmounted (404). When `enabled: true`, `admin.group` is required and must be non-empty/non-whitespace, else boot aborts (every authenticated caller would otherwise be an admin). Full surface in [12-dynamic-permissions.md](12-dynamic-permissions.md).
- `permissions_store.driver: mysql` combined with `admin.enabled: true` is rejected at boot — admin handlers are pg-only today. Use `driver: pg` (the default when the block is absent) for the admin path, or `mysql` with YAML grants only.

## Hot reload

`SIGHUP` re-reads the file. On success, swaps live config atomically. On failure, keeps the old config and logs the error — never half-applies. Pools for removed databases drain; new pools for added databases come up lazily.

## What is *not* in config

- Anything user-facing. No UI strings, no branding, no email templates (this isn't that kind of product).
- Per-user permissions. Users get permissions through groups, period.
- DB schemas. The gateway reads the DB's own schema; it doesn't maintain a separate model.
