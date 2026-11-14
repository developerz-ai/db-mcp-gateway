# 08 — Configuration

## Shape

A single YAML file. Everything operational lives here. No per-environment forks of the binary; one binary, many configs.

```yaml
# config.yaml — illustrative, not final schema

# Listener, state DB, TLS and OIDC settings are environment variables
# (GATEWAY_BIND, METRICS_BIND, STATE_DB_URL, STATE_DB_POOL_SIZE, TLS_*, OIDC_*,
# SESSION_TTL_HOURS) — see website/docs/deployment/config-reference.md.
gateway:
  env: production               # rejects inline literal secrets; default: development

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
          idle_timeout_s: 300

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
        # Optional write tier (postgres only). Present ⇒ `query_write` grants
        # on this database run as this role; every read still runs as `role`.
        write_role: mcp_gateway_staging_app_rw
        write_password: ${FILE:/run/secrets/staging-app-rw-password}

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

  # Service-token group (spec 14). Each entry is the single permissions
  # group a `service_accounts:` token acts as. Empty `grants:` is valid —
  # it recognizes a group that authorizes nothing (authentication never
  # implies authorization).
  - group: svc-ci-bot
    grants: []               # fill in the minimal grants this service needs

# Optional. Absent ⇒ /admin/v1/* returns 404, YAML-only permissions path.
admin:
  enabled: true
  group: db-admins           # SSO group claim authorising admin calls

# Optional. Absent ⇒ pg (state DB) backs users/databases/grants.
permissions_store:
  driver: pg                 # or 'mysql' — see boot-gate below

# Optional. Absent ⇒ no static bearer tokens accepted (OIDC sessions only).
# Headless-client credentials — name + one permissions group + secret ref.
# Full design: 14-service-tokens.md.
service_accounts:
  - name: ci-bot
    group: svc-ci-bot        # must exist in permissions:; never the admin group
    token: ${ENV:SERVICE_TOKEN_CI_BOT}
    max_concurrent_requests: 64   # optional; replaces the per-identity cap (16) for this token
    require_upstream: true        # optional; refuse calls without x-dbmcp-run-id + x-dbmcp-on-behalf-of

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

1. File at `--config` flag, else `$DB_MCP_GATEWAY_CONFIG`. The binary has no default path — with neither set it exits. The published image sets `DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml`.
2. `${ENV:NAME}` placeholders expanded from process env; `${FILE:/path}` placeholders read from disk (trailing newline stripped). A `${ENV:…}` ref whose variable is unset or empty aborts boot, as does a missing or empty file.
3. `vault:`, `aws-sm:`, `gcp-sm:` references resolved from the named backend (when backend integrations land — until then, recognised refs also abort boot rather than silently failing at first DB connect).
4. Final config validated against the schema. Errors at this stage refuse to start the process — no half-loaded state.

## Validation rules (non-exhaustive)

- Unknown keys fail boot — at the top level and in every section. A misspelled `permisions:` is a boot error naming the line, never a silently ignored block.
- `gateway.env: production` ⇒ inline literal secrets rejected: every `servers[].databases[].password` and `service_accounts[].token` must be a `${ENV:…}` / `${FILE:…}` reference. The error names the field, never the value. `gateway.env` defaults to `development`, which tolerates literals (local dev, tests).
- Zero and blank values that parse but mean nothing are rejected: blank server/database `name` or `host`, `port: 0`, and `row_limit: 0` / `statement_timeout_ms: 0` in grant constraints (Postgres reads a zero statement timeout as *no* timeout). Env side: `STATE_DB_POOL_SIZE=0` and a pool larger than the concurrent-request ceiling abort boot; `METRICS_BIND` may not equal `GATEWAY_BIND`.
- Every `permissions[*].group` must be non-blank. The gateway never checks whether any IdP user is in the group — groups can be defined ahead of population, and no warning is logged.
- Every `permissions[*].grants[*].server` / `database` must exist in `servers`, or be the literal `"*"`.
- Server and database names may not be `*` (reserved for the grant wildcard).
- `pool:` (on a server and/or a database: `max_connections` > 0, `min_connections` ≥ 0, `idle_timeout_s` > 0) — `min_connections` above `max_connections` at the same level fails boot. Each field resolves database → server → built-in default.
- `tls_ca_file` is valid only with `tls: verify_full` and must be readable at boot.
- Target TLS: on Postgres, `tls: required` (the default) encrypts but does **not** verify the server certificate (`sslmode=require`); on Mongo it verifies chain and hostname. `tls: verify_full` verifies chain and hostname on both (Postgres `sslmode=verify-full`), against `tls_ca_file` or the system roots — the setting to use for Postgres in production. `tls: insecure` is plaintext. Boot logs one warning per unverified or plaintext server, naming it.
- `write_role` and `write_password` come as a pair, on `postgres` databases only; `write_role` follows the role-name and superuser rules below and must differ from `role` (the read role must not hold write privileges). In `gateway.env: production`, `write_password` must be a secret reference like `password`.
- Every database a YAML `query_write` grant matches — wildcards expanded against the configured databases — must declare a `write_role`; otherwise boot fails naming the group, database and server. (A DB-backed `query_write` grant on such a database is refused at request time with `forbidden`.)
- `service_accounts[].max_concurrent_requests`, when set, must be ≥ 1; `require_upstream` defaults to `false`.
- Role names must match `^[a-zA-Z_][a-zA-Z0-9_]*$`. Catch typos before they become connection failures.
- A database's `role` must not be the stock superuser account its backend ships with (`postgres` for Postgres, `root` for MySQL, `sa` for MSSQL, `root`/`admin` for Mongo). Matched case-insensitively on the name only — a superuser renamed to `app` still passes; the real least-privilege guarantee lives target-side. Rejected at boot so the "never run as DB superuser" rule (see [05-credentials.md](05-credentials.md)) can't be defeated by a config typo.
- Every server's `kind` must have a query adapter wired (today `postgres` and `mongo`). A `mysql`/`mssql` target is rejected at boot rather than parsing clean and failing every query at runtime — these kinds are reserved for the roadmap adapters and only become valid when their adapters land.
- `MCP_PATH` (env-driven for now, folded into YAML with #16) must not collide with a path the gateway already mounts. Reserved exact paths: `/healthz`, `/readyz`, `/metrics`, `/auth/login`, `/auth/callback`, `/auth/logout`, `/authorize`, `/token`, `/revoke`, `/register`. Reserved route families (the path and anything under `<prefix>/…`): `/admin` (owned by the admin API — reserved unconditionally so toggling `admin.enabled` can't turn a working config into a boot panic) and `/.well-known` (RFC 8414/9728 discovery metadata). Segment-based match: `/adminy` or `/tokens` are fine. Overlap surfaces as a typed boot error naming the offending path, not an axum router panic.
- `admin.enabled` defaults to `false` — absent or false leaves `/admin/v1/*` unmounted (404). When `enabled: true`, `admin.group` is required and must be non-empty/non-whitespace, else boot aborts (every authenticated caller would otherwise be an admin); when disabled it is optional and ignored. Full surface in [12-dynamic-permissions.md](12-dynamic-permissions.md).
- Auth env (until #16 folds it into YAML): `OIDC_ISSUER` and `OIDC_CLIENT_ID` are required (absent or blank aborts boot). `SESSION_TTL_HOURS` must be a whole number in `1..=168`, `REFRESH_TTL_DAYS` in `1..=366`; anything else — `0`, out of range, overflow, non-numeric — aborts boot with the variable named. `SESSION_SIGNING_KEY` must be at least 32 bytes and not the committed dev default, unless `ALLOW_INSECURE_SIGNING_KEY=true`, which is accepted only with a loopback `OIDC_ISSUER` (local dev against a mock or local IdP) and logs a `WARN` at boot; with any other issuer it aborts boot.
- `permissions_store.driver: mysql` combined with `admin.enabled: true` is rejected at boot — admin handlers are pg-only today. Use `driver: pg` (the default when the block is absent) for the admin path, or `mysql` with YAML grants only.

## YAML parser

Config YAML is parsed **only** through `config::yaml::non_leaking_options` — never `serde_saphyr::from_str`. A config file is mostly credentials, so a parse failure is a disclosure risk.

Crate: `serde-saphyr`, the serde front-end for [saphyr](https://github.com/saphyr-rs/saphyr) (`yaml-rust2` successor).

| Candidate | Status | Verdict |
|---|---|---|
| `serde_yaml` | archived Mar 2024 | rejected — no fixes, and it parses every boot |
| `serde_yml` | archived | rejected — the popular fork is dead too |
| `serde_yaml_ng` | ~1 yr idle | rejected — less audit surface than what it replaces |
| `serde_norway` | ~1 yr idle | rejected — same |
| **`serde-saphyr`** | **1.0, active** | **chosen** |

The ecosystem never migrated off `serde_yaml`; it still outpulls every fork combined. Swapping to an idle fork trades a scrutinised frozen crate for an unscrutinised quiet one.

## Parse errors never quote the file

A parse error carries a **position and the schema's expectations, never the file's content**. Both come from the gateway's own types:

```text
Error: /etc/gateway/config.yml:3:11: invalid configuration (expected one of postgres, mysql, mssql, mongo)
```

Three independent controls enforce this. Each has been observed to fail alone.

| Control | Without it |
|---|---|
| Snippet rendering disabled (`non_leaking_options`) | Parser attaches a window of *surrounding* source — discloses neighbouring credentials even when the error is elsewhere |
| Error stores no parser text — only position + the text *after* `expected one of` | The offending scalar rides along in the message |
| `Parse` has no `#[source]` | `main` returns `anyhow::Result`; `anyhow` prints every `source()` link under `Caused by:`, so a "suppressed" message still reaches the terminal |

The third was missed originally: suppressing at `Display` is not sufficient, the chain must be severed. Re-attaching a `#[source]` reopens it, so a test asserts the chain has no second link.

Extraction is an allowlist, not a redaction. serde puts the input token *before* `expected one of` and the schema's alternatives *after* it, so copying only the tail is safe by construction — a redaction rule would have to track the parser's phrasing, whereas this can only fail closed by finding no marker.

Operators lose nothing: `:line:column` points at the offending value in a file they already have, and the list names what the field accepts.

## Hot reload

`SIGHUP` re-reads the file (and, with TLS on, the cert + key). The reload runs the boot path — parse, validate, resolve every secret ref, build the service-token store — and only then swaps, in one step, the config snapshot, the service tokens and the `logging.stream` sinks, invalidates every cached grant, and evicts the target pool of each `(server, database)` whose connection settings (host, port, `tls`, `tls_ca_file`, role, `auth_database`, password ref, `pool`) changed or that was removed. Any failure before the swap keeps the running config whole and logs the error — never half-applies. Each request reads one snapshot, so a request in flight finishes on the config it started with; evicted pools serve their in-flight queries and close, new ones open lazily. A database with an inline literal password is always evicted (the literal is never compared).

Outcomes count in `config_reloads_total{result="ok"|"error"}`. A `SIGHUP` with TLS off reloads the config too; the handler is always installed, so the signal never terminates the process.

**Fixed at boot — a reload that changes them is refused whole** (restart instead):

- the admin API: whether it is mounted, its `group`, `session_max_age_secs`;
- the admin API's known-server list (wildcard grants and server checks in `/admin/v1/*`) — while the admin API is mounted, renaming, adding or removing a server is refused; reordering `servers:` is not a change;
- `permissions_store.driver`.

Env-driven settings (listeners, state DB, TLS paths, OIDC) are read once at boot.

## What is *not* in config

- Anything user-facing. No UI strings, no branding, no email templates (this isn't that kind of product).
- Per-user permissions. Users get permissions through groups, period.
- DB schemas. The gateway reads the DB's own schema; it doesn't maintain a separate model.
