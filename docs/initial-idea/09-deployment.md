# 09 — Deployment

## Distribution

- **OCI image**: `ghcr.io/developerz-ai/db-mcp-gateway:<version>` on GitHub Container Registry. Multi-arch (amd64, arm64). Distroless base. Single static binary inside. Public, free, no Docker Hub rate limits.
- **Release trigger**: pushing a `v*` git tag fires `.github/workflows/release.yml`, which builds the multi-arch image, pushes it to GHCR, and cuts a GitHub Release with auto-generated notes.
- **GitHub Releases**: prebuilt static binaries for Linux amd64 / arm64 and macOS (dev convenience) attached to the same release.
- **Helm chart**: published alongside the image on the same tag (roadmap, phase 8).
- **Example repo**: a separate small repo with `docker-compose.yml` + skeleton `config.yaml` + provisioning SQL for the DB roles. Fork-and-edit shape.

## Minimum viable deployment

```yaml
# docker-compose.yml — minimal
services:
  gateway:
    image: ghcr.io/developerz-ai/db-mcp-gateway:latest
    ports: ["8443:8443"]
    environment:
      STATE_DB_URL: postgres://gateway:${STATE_DB_PW}@state-db:5432/gateway
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
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

That's the whole thing. Put it behind your existing TLS-terminating reverse proxy or expose 8443 directly with the gateway's built-in TLS.

## Provisioning the target databases

The repo ships SQL templates for the read-only roles, per DB engine. For Postgres:

```sql
-- run once per database the gateway will access
create role mcp_gateway_prod_app_ro with login password :'pw';
grant connect on database app to mcp_gateway_prod_app_ro;
grant usage on schema public to mcp_gateway_prod_app_ro;
grant select on all tables in schema public to mcp_gateway_prod_app_ro;
alter default privileges in schema public
  grant select on tables to mcp_gateway_prod_app_ro;
alter role mcp_gateway_prod_app_ro set statement_timeout = '30s';
alter role mcp_gateway_prod_app_ro set idle_in_transaction_session_timeout = '60s';
```

Operators run this with their own admin credentials. The gateway never gets superuser.

## State DB

Co-deployed Postgres. Tiny — audit log is the bulky table and it's pruned (see [07-logging-retention](07-logging-retention.md)). One disk, hourly backups, nothing exotic. Can be the host's existing Postgres if there's a good reason; not recommended because mixing security-sensitive audit data with general app data is asking for trouble.

## TLS

- Gateway terminates TLS in-process via rustls. Reads cert + key paths from `TLS_CERT_PATH` / `TLS_KEY_PATH`.
- Refuses to boot without TLS unless `TLS_DISABLED=true` (dev-only escape; loud `WARN` log on every startup).
- `SIGHUP` reloads the cert + key from the same paths without dropping live connections — rustls re-reads the handshake material atomically, in-flight sessions keep the old cert until they close. Matches cert-manager's rotation contract.
- Reload failures (malformed PEM after a swap, wrong permissions) log the error and keep the previous cert serving; the next `SIGHUP` retries.
- Cert-manager + the Kustomize stack in `developerz-ai/infrastructure` mounts the cert as a `Certificate` resource. Cert-manager does NOT send `SIGHUP` itself — a reload controller (e.g. `stakater/reloader`) or a lifecycle/sidecar hook must be wired in to translate the renewal into a `SIGHUP` on the pod. Without that wiring the gateway will keep serving the previous cert until restart.
- For docker-compose without cert-manager, mount your PEMs into the container and `docker exec ... kill -HUP 1` after rotating them.

## Networking

Two paths must be open:

| From | To | Why |
|---|---|---|
| Developer laptop | Gateway | Agents talk to gateway over HTTPS |
| Gateway | Target DBs | Gateway connects to each DB on its port |
| Gateway | IdP | OIDC discovery + token validation |
| Gateway | Secrets backend | Pull DB credentials |
| Gateway | Object storage (optional) | Audit archive |

Run the gateway in the network segment that already reaches the DBs. Most installs put it next to existing internal tools.

## Upgrades

- Containers: tag-pinned pulls; the operator bumps the tag and redeploys.
- Migrations: the gateway runs its own state-DB migrations on startup; safe to roll across versions one minor at a time.
- Backward compat: config schema changes that drop or rename fields ship with a one-version deprecation window; the gateway warns when it sees the old name.

## Observability

- `/healthz` (liveness) — always returns 200 if the binary is up.
- `/readyz` (readiness) — 200 only when state DB connects, IdP discovery succeeded, and every configured DB has at least one healthy pool connection.
- `/metrics` (Prometheus): per-tool latency histograms, per-database connection counts, auth failures, audit write latency.
- Structured JSON logs to stdout.

See [11-roadmap](11-roadmap.md) for what's deferred (k8s operator, multi-replica leader election, etc.).
