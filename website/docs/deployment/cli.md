# Operator CLI

The gateway binary is also its operator tool. Without a subcommand it serves; everything below runs, prints, and exits without booting the gateway — no state DB connection, no listener, no Sentry stream. The same commands ship in the image:

```bash
docker run --rm -v "$PWD/config.yml:/etc/gateway/config.yml:ro" \
  ghcr.io/developerz-ai/db-mcp-gateway --check --no-secrets
```

None of them prints a credential: errors name the field, server, database and tier, never a value; the admin commands keep their session token in an owner-only file.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success: config valid, gateway healthy, no doctor findings, admin call accepted |
| `1` | A negative answer: config invalid, unhealthy, doctor findings, an admin call the gateway refused |
| `2` | Usage error (unknown flag, missing argument, invalid service name) |
| `3` | The command could not run: I/O, network, a database it could not reach |

## `--check` — validate a config without booting

```bash
db-mcp-gateway --config config.yml --check               # also resolves every secret ref
db-mcp-gateway --config config.yml --check --no-secrets  # CI: no secrets needed
```

Parses and validates the file and reports **every** error, not just the first (boot does the same: one abort lists them all). Without `--no-secrets` it also resolves every `${ENV:…}` / `${FILE:…}` reference and reports each failure with its site — `servers[prod].databases[app].write_password (write tier)`, `service_accounts[ci-bot].tokens[0]`. With `--no-secrets` the references are left unresolved, so a CI job can validate the committed YAML with none of the production secrets. Exit `0` when there is no error (warnings allowed), `1` otherwise.

Warnings, which never fail the check:

- **Target TLS** — a Postgres server on `tls: required` (encrypted, certificate not verified) or any server on `tls: insecure`. Boot logs the same lines.
- **Inert constraints** — a constraint no tool under its action reads: `row_limit` on a `schema_read` grant, `row_limit` or `statement_timeout_ms` on a `history_read` grant.
- **Unknown environment variables** — a variable that shares a prefix with the gateway's own (`OIDC_`, `TLS_`, `STATE_DB_`, …) but is not one of them, e.g. `OIDC_ISUER`: the setting it was meant for silently keeps its default. Only names are read. A variable the config references as `${ENV:…}` is never flagged.

Then the **connection budget**: for each target server, the connections one replica may open with every pool full — per database the read tier, the write tier when `write_role` is set, and each Postgres tier's two-connection cancel pool — and for the state DB the request pool (`STATE_DB_POOL_SIZE`) plus the background and `LISTEN` pools. Pools are lazy, so this is the ceiling, not the steady state. Sum every `servers:` entry that points at the same database instance (same host and port), multiply that sum by the replica count, and keep it under the instance's `max_connections` (`doctor` reads that live). `--check` totals each entry on its own and cannot tell that two entries share an instance.

```text
config: config.yml
secrets: not resolved (--no-secrets)
warning: server `prod`: target TLS is encrypted but the server certificate is NOT verified (set `tls: verify_full`)
warning: env `OIDC_ISUER` is set but the gateway reads no such variable (known: OIDC_ISSUER, OIDC_CLIENT_ID, …)
connection budget (one replica, every pool full; multiply by replicas):
  prod/app: read 6 + cancel 2, write 6 + cancel 2 = 16
  prod total: 16 — keep below the target's max_connections (`db-mcp-gateway doctor` reads it)
  state DB: request 10 (STATE_DB_POOL_SIZE) + background 2 + listener 2 = 14
result: valid (0 error(s), 2 warning(s))
```

### JSON Schema

[`config.schema.json`](pathname:///config.schema.json) (served at `/config.schema.json` on this site) describes every key, with types, enums and defaults, for editor completion and pre-commit checks — e.g. `# yaml-language-server: $schema=https://developerz-ai.github.io/db-mcp-gateway/config.schema.json` at the top of the file. It covers the shape only; cross-field rules (unique names, grants naming declared servers, `write_role` pairing, production literals) are `--check`'s job. A test pins the schema's keys to the parser's.

## `--healthcheck` — self-probe for the distroless image

```bash
db-mcp-gateway --healthcheck
```

GETs this host's own `/healthz` — the address from `GATEWAY_BIND` (a wildcard bind is probed on loopback), `https` unless `TLS_DISABLED` — and exits `0` on a 200 from that endpoint itself, `1` otherwise — proxy environment variables are ignored and a redirect is not followed. The runtime image has no shell, curl or wget, so this is the container healthcheck:

```yaml
healthcheck:
  test: ["CMD", "/usr/local/bin/db-mcp-gateway", "--healthcheck"]
  interval: 10s
  timeout: 6s
```

The probe runs with the container's environment, so it reads the listener exactly as boot does. Over TLS it does not verify the certificate (it names the public host, not `127.0.0.1`); it sends no credential and reads only the status.

## Admin commands

Thin clients of the [admin API](admin-api.md): they hold no privilege of their own. Your session must carry the admin group, and every write lands in `permissions_audit` server-side, exactly as any other admin API call.

### `login`

```bash
db-mcp-gateway login --url https://gateway.example.com
```

Runs the gateway's own OAuth 2.1 flow as a native app (RFC 8252): registers a client with a loopback redirect (`POST /register`), prints the `/authorize` URL (PKCE S256) to open in a browser, catches the authorization code on `127.0.0.1`, and redeems it at `/token`. The session token lands in `$XDG_CONFIG_HOME/db-mcp-gateway/session.json` (else `~/.config/…`; `--token-file` to choose), written to a fresh `0600` file and renamed into place (a process holding the old file open never sees the new token). A session file other users can read is refused. The session lasts `SESSION_TTL_HOURS`; log in again when a command answers `401`.

Every admin command takes `--token-file` and `--url`. The session belongs to the gateway `login` stored, so `--url` may only restate it: a different URL is refused rather than sent the token — log in to the other gateway with its own `--token-file`. The URL must be `https://`, or `http://` to a loopback host (`127.0.0.1`, `[::1]`, `localhost`); any other `http://` URL is refused before a request is sent, so a bearer never crosses the network in clear text.

### `grants list` / `grants apply`

```bash
db-mcp-gateway grants list [--user-id UUID] [--database-id UUID] [--limit N] [--offset N]
db-mcp-gateway grants apply grants.json
```

`list` prints `GET /admin/v1/grants` as JSON. `apply` reads a JSON array of create-grant bodies ([admin API §Grants](admin-api.md)) and POSTs each in order, printing the id of each created grant; it stops at the first refusal (exit `1`), and the grants created before it stay — it is not a transaction.

### `sessions revoke`

```bash
db-mcp-gateway sessions revoke alice@example.com   # or a user_sub, or the user's id
```

`POST /admin/v1/users/:id/revoke-sessions`: every live session and refresh chain of that subject, in one audited transaction. The argument is matched against each user's id, `user_sub` and email through `GET /admin/v1/users`; `--by id|sub|email` restricts it to one field, and a value that matches two different users (a UUID-shaped `user_sub` equal to another user's id) is refused until you pass `--by`.

### `audit query` / `audit export`

```bash
db-mcp-gateway audit query --param user=alice@example.com --param limit=100
db-mcp-gateway audit export --param since=2026-11-01T00:00:00Z --out audit.ndjson
```

`GET /admin/v1/audit/calls` (NDJSON). Each `--param key=value` is passed through as a query parameter — the filters are the endpoint's ([admin API](admin-api.md)). Both stream the response chunk by chunk. `query` prints to stdout; `export` writes an owner-only temp file beside `--out` and links it to `--out` only once the whole export arrived, so a cut transfer leaves nothing behind and never replaces an existing file.

## `mint-service-token`

```bash
db-mcp-gateway mint-service-token ci-bot
```

Prints a fresh `dbmcp_svc_<64 hex>` token from the OS CSPRNG — shown once — plus the `service_accounts:` stanza (carrying `${ENV:SERVICE_TOKEN_CI_BOT}`, never the value) and the rotation and revocation steps of [spec 14](../initial-idea/14-service-tokens.md). The name must match `^[a-z0-9][a-z0-9-]{0,62}$` (exit `2` otherwise). `bin/mint-service-token` in a checkout is a wrapper over this command.

## `roles` — provisioning SQL

```bash
db-mcp-gateway roles --config config.yml [--server S] [--database D] [--owner app_owner] [--schema public]...
```

Prints, for each configured database, the statements that provision its read role — `CREATE ROLE … LOGIN`, `GRANT CONNECT`, then `\connect <database>` (every later grant is database-local, so psql must be in the right database), `GRANT USAGE` and `GRANT SELECT ON ALL TABLES` per `--schema`, `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` so tables the owner creates later stay readable, `default_transaction_read_only = on`, and the statement and idle timeouts — and, when `write_role` is set, the write role's. Mongo databases get `db.getSiblingDB(…)` and the `db.createUser` call, Redis databases the `ACL SETUSER` line — an explicit allowlist of the gateway's read commands without `SCAN`, `KEYS` or `DBSIZE`, which ignore key patterns and would list keys outside them. Names in comments are escaped onto one line; a database or Redis user name with a control character is refused. It never connects: review the output and run it with your own admin credentials (the gateway does not provision roles — MUST #3). The recipes are explained in [target roles](target-roles.md).

## `doctor` — live privilege check

```bash
db-mcp-gateway doctor --config config.yml [--server S] [--database D] [--schema public]...
```

Connects to each configured Postgres database as each configured role (resolving its secret like boot does) and reports, as findings:

- the role is a superuser or holds `BYPASSRLS` / `CREATEROLE` / `CREATEDB` (both tiers);
- the read role can `INSERT` / `UPDATE` / `DELETE` / `TRUNCATE` any relation (a column-level `INSERT` / `UPDATE` grant counts), or `CREATE` in the database or a schema;
- the read role has no `USAGE` on an in-scope schema or cannot `SELECT` an in-scope relation (`--schema`, default `public`).

It notes a read role without `default_transaction_read_only = on`, and prints the target's `max_connections` beside this config's per-replica budget for the server. Exit `0` with no findings, `1` with any, `3` when a database cannot be reached. Doctor runs catalog queries only, in a `READ ONLY` transaction it rolls back; it never grants or revokes anything — the fix is yours, e.g. from `roles`. Mongo and Redis targets are skipped.
