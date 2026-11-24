# Deployment quickstart

This is the path from zero to a running gateway your team can use. Assumes you're a platform / infra / SRE-flavored human, comfortable with Docker and Postgres.

For the *why* behind these choices, see [../initial-idea/09-deployment.md](../initial-idea/09-deployment.md).

## Status: what works today

The gateway is stable (2.x) and in production use; [../initial-idea/11-roadmap.md](../initial-idea/11-roadmap.md) tracks what is still planned. The **Run it locally** walkthrough below boots a real gateway against a local Postgres and serves MCP. What is and is not shipped, for the features this page touches:

| Capability | Status |
|---|---|
| MCP tools, OIDC login, per-DB pools, synchronous audit | works |
| `/healthz`, `/readyz`, `/metrics` | **works** — [#13](https://github.com/developerz-ai/db-mcp-gateway/issues/13). k8s probes on the main listener; Prometheus scrape on its own `METRICS_BIND` listener; see [Probes & metrics](#probes--metrics) below |
| In-process TLS + cert reload on `SIGHUP` | **works** — [#12](https://github.com/developerz-ai/db-mcp-gateway/issues/12). `TLS_CERT_PATH` + `TLS_KEY_PATH` point at PEM files; a `SIGHUP` (`docker kill --signal=HUP <container>` — the image is distroless, there is no `kill` inside it) reloads them in place without dropping live connections. Boot refuses to start without TLS unless `TLS_DISABLED=true` is set explicitly (dev-only). |
| `${ENV:NAME}` + `${FILE:/path}` secret refs | **works** — resolved at boot ([#15](https://github.com/developerz-ai/db-mcp-gateway/issues/15)); an unset env or missing file aborts startup |
| `vault:` / `aws-sm:` / `gcp-sm:` secret backends | recognised but **not implemented** — these abort at boot until the backends land |
| Strict config validation | **works** — an unknown/misspelled key anywhere in the file, including the top level, aborts boot with a `line:column` pointer; so do zero/blank values and, under `gateway.env: production`, inline literal secrets. Full key list: [config-reference.md](config-reference.md) |
| Unified `config.yml` | **not yet** — listener, state DB, TLS and OIDC settings come from environment variables (see below); `auth:` in the YAML is a boot error |
| Admin API (`/admin/v1/*`) for users, databases, grants and session revocation | **works**, off by default — [admin-api.md](admin-api.md) |
| `gateway admin …` CLI subcommands | planned — phase 8 |

## Run it locally

**Just want to see a query go through?** `examples/demo/` is a one-command demo — gateway, state DB, a seeded Postgres and a dev-only service token, no IdP needed:

```bash
git clone https://github.com/developerz-ai/db-mcp-gateway && cd db-mcp-gateway/examples/demo
docker compose up -d --wait
docker compose run --rm ready   # prints the `claude mcp add …` line
```

`docker compose --profile sso up -d --wait` adds a local Dex IdP for the browser-login path. Loopback and plain HTTP only — a demo, never a deployment. The walkthrough below builds the same thing by hand against the dev stack.

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
  -e GATEWAY_BIND=127.0.0.1:8443 \
  -e RUST_LOG=info \
  -e DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml \
  -e STATE_DB_URL='postgres://gateway:gateway-dev-only@localhost:5433/gateway' \
  -e TARGET_DB_PASSWORD='app-dev-only' \
  -e TLS_DISABLED=true \
  -e OIDC_ISSUER=http://localhost:5556 \
  -e OIDC_CLIENT_ID=dev \
  -e ALLOW_INSECURE_SIGNING_KEY=true \
  -v "$PWD/config.yml:/etc/gateway/config.yml:ro" \
  ghcr.io/developerz-ai/db-mcp-gateway:main
```

`GATEWAY_BIND=127.0.0.1:8443` matters: the image defaults to `0.0.0.0:8443`, and with `--network host` that would publish plain HTTP, signed with the public dev key, on every interface of your machine. `TLS_DISABLED=true` is the explicit dev-only opt-out — the gateway refuses to boot otherwise (see [#12](https://github.com/developerz-ai/db-mcp-gateway/issues/12)). Real deploys mount cert+key and unset this var. `OIDC_ISSUER` and `OIDC_CLIENT_ID` are required at boot but the IdP is not contacted until a login; `ALLOW_INSECURE_SIGNING_KEY=true` lets the dev default session key through and is refused unless the issuer is a loopback URL — see *About login* below.

The binary needs its config path. The published image bakes `DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml` in (see [#10](https://github.com/developerz-ai/db-mcp-gateway/issues/10)), but passing it explicitly above keeps the recipe working for a locally-built image too — equivalently, append `--config /etc/gateway/config.yml` as a command argument.

The `:main` tag is published on every push to `main` (see [#10](https://github.com/developerz-ai/db-mcp-gateway/issues/10)). Building from source instead? `docker build -t db-mcp-gateway:dev .` and swap that tag into the `docker run` above.

With `RUST_LOG` unset the gateway logs at `info`. If you mistype a secret ref or leave `TARGET_DB_PASSWORD` unset, the gateway **fails fast at boot** rather than at first query, listing every unresolved ref with its site — e.g. ``servers[local].databases[app].password (read tier): env var `TARGET_DB_PASSWORD` referenced in config is unset or empty in process environment``. Validate a config without booting — every error at once, warnings, and the connection budget — with `db-mcp-gateway --config config.yml --check` (add `--no-secrets` in CI); see the [operator CLI](cli.md).

You should see the gateway load config, migrate the state DB, and start listening:

```json
{"message":"config loaded; all secret refs resolved","path":"/etc/gateway/config.yml","servers":1,"permissions":1}
{"message":"state DB connected, migrations applied","pool_size":10}
{"message":"db-mcp-gateway listening (plain HTTP)","addr":"127.0.0.1:8443","path":"/mcp"}
```

(Abridged: real lines also carry `timestamp`, `level` and more fields, and with `tls: insecure` and `TLS_DISABLED=true` you also get one `WARN` each.)

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
| `DB_MCP_GATEWAY_CONFIG` | — (image: `/etc/gateway/config.yml`) | YAML config path; same as `--config`. One of the two is required |
| `STATE_DB_URL` | `postgres://gateway:gateway-dev-only@localhost:5433/gateway` | Gateway's own Postgres (sessions + audit) |
| `PERMISSIONS_DB_DSN` | — | DSN of the MySQL 8 permissions store; required only with `permissions_store.driver: mysql` |
| `GATEWAY_BIND` | `127.0.0.1:8443` (image: `0.0.0.0:8443`) | Listen address |
| `MCP_ALLOWED_ORIGINS` | unset (none) | Comma-separated browser origins (`https://host[:port]`, no path or wildcard) allowed to call `POST /mcp` (MCP spec: servers MUST validate `Origin` against DNS rebinding). A request **without** `Origin` (every non-browser agent) always passes; one **with** an `Origin` not listed gets `403` before authentication — no tool runs, no audit row is written, a `WARN` `rejected a request from a disallowed Origin` line is logged. With `GATEWAY_BIND` on loopback, loopback origins (`localhost`, `127.0.0.0/8`, `[::1]`, any port) are also allowed. A malformed entry aborts boot |
| `TRUSTED_PROXIES` | unset (none) | Comma-separated IPs/CIDRs (`10.0.0.0/8,fd00::/8`) of reverse proxies in front of the gateway. When the TCP peer is one of them, the audit row's `ip` is the right-most `X-Forwarded-For` hop not itself a trusted proxy; otherwise `ip` is the TCP peer and `X-Forwarded-For` is ignored. List only proxies that overwrite or append to `X-Forwarded-For` — a listed address can claim any client IP. A malformed entry aborts boot |
| `MCP_PATH` | `/mcp` | Absolute path the MCP endpoint mounts at. A path the gateway already serves (`/healthz`, `/auth/…`, `/admin…`, `/.well-known…`, …) aborts boot |
| `METRICS_BIND` | `127.0.0.1:9090` | Internal listener: Prometheus `/metrics`, plus `/healthz` and `/readyz` for probes that should not reach the public port — separate from `GATEWAY_BIND`, which does not serve `/metrics`. Set `0.0.0.0:9090` for an in-cluster scrape and fence the port with a NetworkPolicy; must differ from `GATEWAY_BIND` |
| `MAX_CONCURRENT_REQUESTS` / `MAX_CONCURRENT_PER_IDENTITY` | `512` / `16` | In-flight ceilings (global → 503, per caller → 429). `0` aborts boot |
| `STATE_DB_POOL_SIZE` | `10` | Request-path state-DB pool. `0`, or more than the concurrent-request ceiling (512), aborts boot. `1` works: pruner/GC/reaper use a separate fixed pool of 2, and the permissions `LISTEN` connection (plus its liveness ping) another fixed pool of 2 |
| `PG_CANCEL_POOL_SIZE` | `2` | Connections in each Postgres tier's dedicated cancel pool (the pool `pg_cancel_backend` runs on, so a cancel never queues behind the queries it cancels). One per tier per database: a database with a `write_role` holds two. Integer `1`–`32`; anything else aborts boot |
| `STATE_DB_CONNECT_TIMEOUT_SECONDS` | `60` | How long boot keeps retrying the state DB (backoff 0.5 s doubling to 8 s; each attempt waits up to 5 s, never past the budget; no attempt starts with under 0.5 s left) before exiting. `0` = one attempt. Whole seconds, `0`–`3600`; anything else aborts boot. A malformed `STATE_DB_URL` or a failed migration is not retried. The HTTP listener binds only once the state DB is up, so `/healthz` and `/readyz` do not answer while boot retries — give a Kubernetes `startupProbe` at least this budget, or liveness restarts the pod mid-retry |
| `OIDC_ISSUER` | — (required) | IdP issuer URL (OIDC discovery base). A trailing slash is ignored |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — (client id required) | Gateway's OIDC client credentials |
| `OIDC_AUDIENCE` | `OIDC_CLIENT_ID` | Expected `aud` of IdP ID tokens |
| `OIDC_REDIRECT_URL` | `http://localhost:8443/auth/callback` | Must match the IdP app's redirect URI |
| `OIDC_GROUPS_CLAIM` | `groups` | ID-token claim carrying group membership |
| `OIDC_SCOPES` | `openid email profile groups` | Space-separated scopes requested at the IdP. Must include `openid`; RFC 6749 scope characters only, anything else aborts boot. Google: `openid email profile` (it rejects an unknown `groups` scope) |
| `OIDC_GROUPS_PREFIX` | unset | Only groups starting with this prefix count, matched against `permissions[].group` / `admin.group` with the prefix removed (`dbmcp-oncall` → `oncall`). ≤128 characters, no whitespace; empty = unset |
| `OIDC_TOKEN_AUTH_METHOD` | `client_secret_post` | How the gateway authenticates at the IdP's token endpoint: `client_secret_post` (secret in the form body) or `client_secret_basic` (HTTP Basic, for IdP apps that accept only that, e.g. some Okta apps). Anything else aborts boot |
| `GROUPS_MAX_AGE` | unset | Longest a session may run on the groups read at its login, e.g. `12h` (`s`/`m`/`h`/`d`, `1m`–`366d`; anything else aborts boot). Caps each session's lifetime, and a refresh past it is refused with `invalid_grant` + `"code": "relogin_required"`, so the next login reads the user's current IdP groups. Unset = groups refresh only when the refresh chain (`REFRESH_TTL_DAYS`) ends. See [auth & SSO](../initial-idea/04-auth-sso.md#token-endpoint--post-token) |
| `GATEWAY_SUPPORT_CONTACT` | unset | One line (≤200 characters) shown on the gateway's login error pages next to the request id — an address, a channel, a URL. Empty = unset |
| `SESSION_SIGNING_KEY` | dev-only default | HMAC key for gateway-issued session JWTs — **set this in any real deploy**. Minimum 32 bytes; empty, shorter or the dev default are refused at boot |
| `ALLOW_INSECURE_SIGNING_KEY` | `false` | Local dev only: accept a short or dev-default `SESSION_SIGNING_KEY`. Refused at boot unless `OIDC_ISSUER` is a loopback URL **and** `GATEWAY_BIND` is a loopback address (the dev key is public: on a reachable listener anyone could mint bearers); logs a `WARN` when set. Strict boolean: `true`/`false`/`1`/`0`, anything else aborts boot |
| `SESSION_TTL_HOURS` | `8` | Session (access token) lifetime, `1`–`168` |
| `REFRESH_TTL_DAYS` | `1` | Absolute refresh-chain lifetime, `1`–`366`; see [auth & SSO](../initial-idea/04-auth-sso.md#token-endpoint--post-token) |
| `TLS_CERT_PATH` | — | PEM-encoded leaf cert (+ intermediates). Required unless `TLS_DISABLED=true` |
| `TLS_KEY_PATH` | — | PEM-encoded private key. Required unless `TLS_DISABLED=true` |
| `TLS_DISABLED` | `false` | Dev-only escape. `true` serves plain HTTP and emits a `WARN` log on startup. Strict boolean: `true`/`false`, `1`/`0` or `yes`/`no` (case-insensitive; empty = `false`); anything else aborts boot |
| `AUDIT_RETENTION_DAYS` | `90` | Hot-retention window for `audit_calls`, `audit_call_intents` and `permissions_audit`; the hourly pruner deletes older rows. State-DB backups and log stores (Loki etc.) keep their own retention — set them to match ([spec 07](../initial-idea/07-logging-retention.md#retention-surfaces-outside-the-gateway)) |
| `PERMISSIONS_CACHE_TTL_SECONDS` | `60` | Per-user DB-grant cache TTL; bounds how long a revoked grant is honoured on a replica that missed the invalidation. Above `300` aborts boot |
| `SESSION_CACHE_TTL_SECONDS` | `30` | Freshness window for the in-memory session cache. Bounds how long a revoked session stays honored on *other* HA replicas; `0` re-validates every request. Values above `300` are clamped to `300` with a `WARN`. See [auth & SSO](../initial-idea/04-auth-sso.md#session-tokens) |
| `SENTRY_DSN` / `SENTRY_ENVIRONMENT` | unset (disabled) / `development` | GlitchTip/Sentry error tracking; every event passes a credential scrubber |
| `RUST_LOG` | `info,sqlx::query=warn` | Log filter. Invalid directives are skipped. The `audit_stream` target always logs at INFO regardless |

> **Shutdown.** On `SIGTERM` the gateway stops accepting work, gives in-flight requests up to 80 s (the 75 s `/mcp` request timeout + 5 s), waits up to 20 s for detached audit writes, then closes its request and background state-DB pools (≤ 10 s each). Set `terminationGracePeriodSeconds: 120` or more, or Kubernetes `SIGKILL`s a pod mid-drain.

> **Cert rotation.** A `SIGHUP` re-reads `TLS_CERT_PATH` + `TLS_KEY_PATH` in place. The `SIGHUP` handler is installed with TLS off too, so the signal never kills the process. Send it from outside the container — the image is distroless, with no shell and no `kill`: `docker kill --signal=HUP <container>` under Docker; under Kubernetes a reload sidecar in a pod with `shareProcessNamespace: true`, or a rolling restart. In-flight connections keep their old cert until they close; new handshakes pick up the new one. Kubernetes does not send `SIGHUP` on its own — `terminationGracePeriodSeconds` only governs `SIGTERM` at shutdown — so operators must wire the reload signal explicitly. Cert-manager integration can automate this once #17 lands the infra stack.

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
| Docker + docker-compose (or k8s manifests) | Run the gateway image. On Kubernetes, use the in-repo Helm chart or kustomize base: [Kubernetes](kubernetes.md). |
| One Postgres instance for *gateway state* (sessions + audit) | Keep gateway state separate from your prod DBs |
| Network reachability gateway → each target DB | Self-evident |
| An OIDC IdP whose ID token carries a verified `email` and a `groups` claim | Identity. Guides: [Okta](idp/okta.md), [Entra ID](idp/entra.md), [Google Workspace](idp/google.md) (needs a broker), [Keycloak](idp/keycloak.md) |
| Admin access to each target DB | Create the read-only roles |
| A secret manager (Vault / AWS SM / GCP SM) | Not strictly required but strongly recommended |
| A DNS name + TLS cert for the gateway | Devs hit it over HTTPS |

## 1. Provision read-only roles on each target DB

Run this once **per database** the gateway will access (Postgres example; MongoDB, Redis and YugabyteDB recipes are in [target-roles.md](target-roles.md)). `app_owner` stands for the role that owns your tables — the one your migrations run as:

```sql
create role mcp_gateway_prod_app_ro with login password :'pw';
grant connect on database app to mcp_gateway_prod_app_ro;
grant usage on schema public to mcp_gateway_prod_app_ro;
grant select on all tables in schema public to mcp_gateway_prod_app_ro;
-- tables app_owner creates later: without `for role`, this would cover only
-- tables created by whoever runs this statement
alter default privileges for role app_owner in schema public
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
alter default privileges for role app_owner in schema public
  grant select, insert, update, delete on tables to mcp_gateway_prod_app_rw;
alter default privileges for role app_owner in schema public
  grant usage on sequences to mcp_gateway_prod_app_rw;

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
| Group claim | A `groups` claim (array of strings, or an object keyed by group name as Zitadel emits) in the **ID token**; another claim name works with `OIDC_GROUPS_CLAIM` |
| Email | The ID token must carry `email` and `email_verified: true`, or the login is refused |
| Client authentication | Client secret, sent in the token request body (`client_secret_post`), or in a Basic header with `OIDC_TOKEN_AUTH_METHOD=client_secret_basic` |

Note the `client_id` and `client_secret`. The gateway requests `openid email profile groups` (change with `OIDC_SCOPES`) and uses PKCE (S256). Per-IdP walkthroughs: [Okta](idp/okta.md), [Microsoft Entra ID](idp/entra.md), [Google Workspace](idp/google.md), [Keycloak](idp/keycloak.md), [Zitadel](idp/zitadel.md). There is no SCIM sync: groups come from the ID token at login.

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
    tls: verify_full     # Postgres `required` encrypts but does not verify the cert
    databases:
      - name: app
        role: mcp_gateway_prod_app_ro
        password: ${ENV:PROD_APP_RO_PASSWORD}   # or ${FILE:/run/secrets/prod-app-ro}
        pool: { max_connections: 4 }            # optional; per (server, database)
        # sql_capture is spec-only (not shipped); the parser rejects it

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

Every variable below is one the gateway refuses to boot without (or, for `OIDC_REDIRECT_URL`, one the login breaks without). The gateway terminates TLS itself here; behind a TLS-terminating proxy, drop the two cert variables and the volume, and set `TLS_DISABLED=true` only if the proxy-to-gateway hop never leaves a trusted network.

```yaml
# docker-compose.yml
services:
  gateway:
    image: ghcr.io/developerz-ai/db-mcp-gateway:2.4.0   # pin a release
    ports: ["8443:8443"]
    environment:
      DB_MCP_GATEWAY_CONFIG: /etc/gateway/config.yml
      STATE_DB_URL: postgres://gateway:${STATE_DB_PW}@state-db:5432/gateway
      OIDC_ISSUER: ${OIDC_ISSUER}                     # e.g. https://acme.okta.com
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      OIDC_REDIRECT_URL: https://db.internal.acme.com/auth/callback
      SESSION_SIGNING_KEY: ${SESSION_SIGNING_KEY}     # >= 32 bytes: openssl rand -hex 32
      TLS_CERT_PATH: /etc/gateway/tls/tls.crt
      TLS_KEY_PATH: /etc/gateway/tls/tls.key
      PROD_APP_RO_PASSWORD: ${PROD_APP_RO_PASSWORD}
    volumes:
      - ./config.yml:/etc/gateway/config.yml:ro
      - ./tls:/etc/gateway/tls:ro
    depends_on:
      state-db:
        condition: service_healthy
    restart: unless-stopped
    # The image is distroless (no shell, curl or wget): the binary probes its
    # own /healthz (see the operator CLI page). Readiness (/readyz) is for
    # your load balancer or orchestrator.
    healthcheck:
      test: ["CMD", "/usr/local/bin/db-mcp-gateway", "--healthcheck"]
      interval: 10s
      timeout: 6s

  state-db:
    image: postgres:16
    environment:
      POSTGRES_DB: gateway
      POSTGRES_USER: gateway
      POSTGRES_PASSWORD: ${STATE_DB_PW}
    healthcheck:
      # TCP, not the unix socket: first-boot init runs a socket-only temporary server.
      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U gateway -d gateway"]
      interval: 5s
      retries: 10
    volumes:
      - state-db-data:/var/lib/postgresql/data

volumes:
  state-db-data:
```

`.env` next to it:

```env
STATE_DB_PW=...
OIDC_ISSUER=...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
SESSION_SIGNING_KEY=...
PROD_APP_RO_PASSWORD=...
```

Don't commit `.env`. In real deploys, inject `PROD_APP_RO_PASSWORD` from your orchestrator's secret store and reference it as `${ENV:PROD_APP_RO_PASSWORD}`, or mount a sealed-secret file and use `${FILE:/run/secrets/prod-app-ro}`. (Native `vault:` / `aws-sm:` / `gcp-sm:` backends are recognised but not yet implemented — see the status table above.) `SESSION_SIGNING_KEY` signs every session JWT: rotating it signs everyone out.

The `tls/` directory holds the PEM cert (with intermediates) and key for the gateway's DNS name; the container runs as the distroless `nonroot` user, so both files must be readable by it.

```bash
docker compose up -d
docker compose logs -f gateway
```

You should see `config loaded; all secret refs resolved`, `state DB connected, migrations applied` and `db-mcp-gateway listening (TLS)`. The gateway does not contact the IdP or the target databases at boot: OIDC discovery runs at the first login, and each target pool opens on its first query. A bad IdP setting shows up as a `502` from the login; a bad target credential as `unavailable` on the first tool call.

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

Three unauthenticated ops endpoints. `/healthz` and `/readyz` are mounted alongside `/mcp` **and** on the internal `METRICS_BIND` listener (default `127.0.0.1:9090`); `/metrics` is served only on `METRICS_BIND` — never on the public listener, because its labels name every configured database:

| Endpoint | Returns | What's behind it |
|---|---|---|
| `/healthz` | `200 ok` while running; `503 shutting down` once the process catches SIGTERM/Ctrl-C. On `METRICS_BIND` also `200 starting` while boot is still connecting to the state DB | Process liveness only — does not touch the state DB |
| `/readyz` | `200 ok` when the state DB answers `SELECT 1` within 2s; `503` otherwise (or during shutdown). On `METRICS_BIND` also `503 starting` until boot completes | Pulls the pod out of the Service endpoint set on transient DB outages, no restart |
| `/metrics` (on `METRICS_BIND`) | Prometheus text exposition (`text/plain; version=0.0.4`) | See the metric catalogue below |

`METRICS_BIND` binds before boot connects to the state DB, so probes pointed at it answer during `STATE_DB_CONNECT_TIMEOUT_SECONDS` retries (liveness `200 starting`, readiness `503 starting`) — no `startupProbe` budget needed for that window.

### Metric catalogue

Names are fixed — dashboards and alerts are written against them. No label carries a user, email, SQL text or request id.

| Series | Type | Labels |
|---|---|---|
| `tool_calls` | counter | `tool`, `outcome` (the spec 03 code the client saw — an intent or completion write that failed shows as `audit_unavailable`), `access` (`read`/`write`/`unknown` for a call dropped before it decided) |
| `tool_calls_by_db` | counter | `db` (`server/database`), `outcome`, `access` — only calls that named a database the config holds; a name the caller made up never becomes a label |
| `query_duration_seconds` | histogram (fixed buckets 5 ms – 60 s) | `tool`, `db` (empty when the call named no configured database) |
| `audit_write_duration_seconds` | histogram (fixed buckets 1 ms – 5 s) | — |
| `audit_fallback_failures_total` | counter | — (a disconnect-path audit write failed; the row exists only once the reaper records it) |
| `audit_last_failure_timestamp` | gauge (unix seconds) | `kind` (`write`: a call answered `audit_unavailable`; `fallback`: a disconnect-path write failed) — absent until that kind's first failure since boot, and an hour after its last; the audit alerts read how recent it is, which a pod first scraped after the failure still shows |
| `audit_abandoned_total` | counter | — (intents the reaper recorded as `abandoned`; only the lock-holding replica increments it, so `sum()` across replicas is exact) |
| `audit_reaper_last_success_timestamp` | gauge | — (Unix seconds of the last completed reaper sweep; alert when it falls behind) |
| `audit_pruner_runs_total` | counter | `result` (`ok`/`error`) |
| `audit_pruner_last_success_timestamp` | gauge (unix seconds) | — |
| `audit_stream_dropped_total` | counter | `sink` (`syslog`) |
| `requests_shed_total` | counter | `scope` (`global`/`identity`/`oauth`) |
| `handler_panics_total` | counter | `layer` (`http`: a route handler, answered `500`; `tool_work`: a tool's work, answered and audited `internal`) |
| `pool_size` | gauge (configured max connections) | `db`, `pool_kind` (`query`/`cancel`, plus `write_query`/`write_cancel` when `write_role` is set; Mongo and Redis: `query`) |
| `pool_connections_in_use` | gauge | `db`, `pool_kind` |
| `pool_connections_idle` | gauge | `db`, `pool_kind` (Postgres and Redis; the Mongo driver does not expose it) |
| `pool_acquire_wait_seconds` | histogram (fixed buckets 0.5 ms – 5 s) | `db`, `pool_kind` — every acquire, timed-out waits included (they sit at the 5 s acquire timeout) |
| `state_db_pool_size` / `state_db_pool_connections_in_use` / `state_db_pool_connections_idle` | gauge | `pool` (`request`, `permissions_mysql`) |
| `sessions_created_total` / `sessions_revoked_total` | counter | — |
| `login_failures_total` | counter | `code` (`email_unverified`, `id_token`, `idp_exchange`, `state_unavailable`) |
| `config_reloads_total` | counter | `result` (`ok`/`error`) |
| `config_reload_last_success_timestamp` | gauge (unix seconds) | — (boot load or last successful SIGHUP reload) |
| `config_info` | gauge (`1`) | `hash` (first 12 hex of the SHA-256 of the parsed config with every credential field (`password`, `write_password`, `token`, `tokens`) removed; `${…}` references are never resolved) |
| `tls_cert_not_after_timestamp` | gauge (unix seconds) | — (the served leaf certificate; absent with `TLS_DISABLED`) |
| `build_info` | gauge (`1`) | `version`, `git_sha` (`unknown` when the build had no `GIT_SHA`) |
| `process_start_time_seconds` | gauge (unix seconds) | — (set at boot) |
| `log_lines_dropped_total` | counter | — |

`audit_stream_dropped_total` counts only syslog deliveries that failed. The `stdout` stream sink writes through the same non-blocking log queue as every other log line, so an audit row it drops when that queue is full is counted only in `log_lines_dropped_total` — the two are not separable by metric. Every stream sink is a best-effort copy; the state DB row is the record.

Every counter is exported at `0` from boot for each stable label set — `tool_calls` for every tool × outcome, `tool_calls_by_db` for every configured database × outcome (a reload adds new databases' series) — so `increase()` sees the first event. Histograms use fixed buckets so they aggregate across replicas. Pool gauges are sampled every 15 s while the pool is open; the other gauges are re-set every minute. A gauge or histogram untouched for an hour leaves the output, so a database removed by a reload stops being reported an hour after its pool closes; counters never expire. The source of truth for names, types and labels is `src/startup/metrics/catalogue.rs`.

### k8s probes

```yaml
# scheme: HTTPS while the gateway terminates TLS (drop it with TLS_DISABLED=true)
livenessProbe:
  httpGet: { path: /healthz, port: 8443, scheme: HTTPS }
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /readyz, port: 8443, scheme: HTTPS }
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
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com/mcp
```

The URL is the gateway origin **plus `/mcp`** (your `MCP_PATH`); the bare origin answers `404`. Commit the resulting `.mcp.json` to whichever repo they should have access from. First call triggers SSO.

Point them at [../usage/first-query.md](../usage/first-query.md) — 5-minute happy path that takes them from `mcp add` to a real query against a real DB with their own audit row.

## Day-2

| Task | How |
|---|---|
| Change permissions / service accounts | PR against the gateway config repo. Operator merges and sends `SIGHUP` to every replica (`docker kill --signal=HUP <container>`; the distroless image has no `kill` inside). The reload is atomic: a bad file is logged, counted in `config_reloads_total{result="error"}`, and the old config keeps serving. Admin API mount/group and `permissions_store` need a restart. |
| Rotate a DB password | Update in secret manager. `${FILE:…}` refs are re-read whenever a pool opens; to force it, change the ref (or anything else on that database) and send `SIGHUP` — changed databases get a fresh pool, old connections drain. |
| Revoke a user's sessions | With the admin API on: `POST /admin/v1/users/<id>/revoke-sessions` — every session and refresh chain of that subject, audited ([admin-api.md](admin-api.md#revoke-a-users-sessions)). Without it: `update sessions set revoked_at = now() where user_sub = '<sub>' and revoked_at is null;` and `delete from oauth_refresh_tokens where user_sub = '<sub>';` in the state DB (unaudited — prefer the API). Either way other replicas stop honouring a cached session within `SESSION_CACHE_TTL_SECONDS` (30 s). |
| Audit a query | `psql` into the state DB → `select occurred_at, user_email, tool, server_name, database_name, outcome, sql from audit_calls where ... order by occurred_at desc;` (see [../initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md)) |
| Back up, restore, upgrade, roll back | [operations.md](operations.md) |

## Production hardening checklist

- [ ] All DB passwords sourced from secret manager, not env literals.
- [ ] A unique `SESSION_SIGNING_KEY` (≥ 32 bytes); `ALLOW_INSECURE_SIGNING_KEY` unset.
- [ ] Postgres targets on `tls: verify_full` — `required` encrypts but does not verify the server certificate.
- [ ] `gateway: { env: production }` in config — inline literal secrets abort boot.
- [ ] TLS terminating on the gateway or fronting proxy; never plain HTTP from devs.
- [ ] State DB on its own volume, backed up ([operations.md](operations.md#backup)).
- [ ] Two replicas behind a load balancer for HA — no sticky routing for any route: login state lives in the state DB. Give every replica the same `SESSION_SIGNING_KEY` and `OIDC_REDIRECT_URL`. See [../initial-idea/02-architecture.md](../initial-idea/02-architecture.md#ha).

## Helm / Kubernetes

The Helm chart (`deploy/helm/db-mcp-gateway`) and a kustomize base ship in this repository, with Prometheus alerts, a Grafana dashboard and a runbook: see [Kubernetes](kubernetes.md).
