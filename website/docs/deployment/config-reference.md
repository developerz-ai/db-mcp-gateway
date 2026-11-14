# Config reference

Single-page reference for the gateway's YAML config — every key the parser
accepts today, with type, requirement, and a short description. The spec at
[`../initial-idea/08-config.md`](../initial-idea/08-config.md) covers
*intended* shape — e.g. the illustrative `logging:` block
([08-config.md §Shape](../initial-idea/08-config.md#shape)), whose
`hot_retention_days`, `archive: s3` and `otlp` stream sink the parser
rejects today (retention stays env-driven via `AUDIT_RETENTION_DAYS`);
this page is what the binary actually checks at boot — top level included.

Boot-time validation (issue #16):

- Unknown keys inside `servers[].*`, `databases[].*`, `permissions[].*`,
  `grants[].*`, `constraints.*`, and `service_accounts[].*` are **errors**
  with a line:column pointer
  and the list of expected fields. A typo like `statemnt_timeout_ms` aborts
  startup rather than silently dropping the constraint.
- Unknown keys at the top level are **errors** — the top level denies
  unknown keys too (see the note under [Top level](#top-level)), so a
  misspelled section name aborts startup instead of being ignored.
- Every `${ENV:…}` / `${FILE:…}` ref must resolve cleanly; an unset or empty
  env var, or a missing or empty file, aborts startup (issue #15).
- Server and database names may not be `*` (reserved for the grant wildcard).

## Top level

| Key | Type | Required | Notes |
|---|---|---|---|
| `gateway` | `{ env: production \| development }` | no (defaults `development`) | `production` rejects inline literal secrets (DB passwords, service tokens) at boot. |
| `servers` | list of [Server](#server) | no (defaults `[]`) | Target DBs the gateway can dispatch to. |
| `permissions` | list of [Permission](#permission) | no (defaults `[]`) | Group→grant mapping. Empty list means no caller can reach anything. |
| `admin` | [Admin](#admin) | no | `/admin/v1/*` surface gating — see [admin-api.md](admin-api.md). |
| `permissions_store` | [PermissionsStore](#permissionsstore) | no | Storage backend for users/databases/grants. Absent → state DB (pg). |
| `service_accounts` | list of [ServiceAccount](#serviceaccount) | no (defaults `[]`) | Static bearer tokens for headless clients — see [spec 14](../initial-idea/14-service-tokens.md). |
| `logging` | [Logging](#logging) | no | Audit stream sinks. Absent → none. |

> The top level denies unknown keys: `auth:`, `gateway.bind` or a misspelled
> section name abort boot. Listener, state DB, TLS and OIDC settings come from
> environment variables — see [`.env.example`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/.env.example)
> and the [quickstart env table](quickstart.md#the-environment-variables-the-gateway-reads).

## Server

`#[serde(deny_unknown_fields)]` — unknown keys here are boot errors.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | **yes** | — | Stable identifier used in grants, audit, and `list_servers`. |
| `kind` | `postgres` \| `mongo` \| `mysql` \| `mssql` | **yes** | — | `postgres` and `mongo` work today (#56–#58); `mysql` / `mssql` parse but are **rejected by boot validation** — the process refuses to start (`ServerKind::has_adapter`). Unrelated to `permissions_store.driver: mysql`, which is supported. |
| `host` | string | **yes** | — | DNS or IP of the target DB. |
| `port` | u16 | no | `5432` | |
| `tls` | `required` \| `verify_full` \| `insecure` | no | `required` | `required` encrypts; on Postgres it does **not** verify the certificate (boot warns), on Mongo it does. `verify_full` verifies chain + hostname. `insecure` is plaintext (boot warns). |
| `tls_ca_file` | path | no | system roots | CA bundle (PEM) for `verify_full`. Boot error when set without `verify_full` or when unreadable. |
| `pool` | [Pool](#pool) | no | built-in defaults | Applies to every database on the server; a database's own `pool` wins per field. |
| `description` | string | no | `""` | Human-readable purpose; surfaced by `list_servers`. |
| `databases` | list of [Database](#database) | no | `[]` | Per-DB definitions. |

## Database

`#[serde(deny_unknown_fields)]` — unknown keys here are boot errors.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | **yes** | — | DB name on the target server. |
| `role` | string | **yes** | — | Postgres role / mongo username (`^[A-Za-z_][A-Za-z0-9_]*$`). Typo here is caught at boot. |
| `password` | [secret ref](#secret-references) | **yes** | — | `${ENV:…}` / `${FILE:…}` / `vault:…` / `aws-sm:…` / `gcp-sm:…` / inline literal. |
| `description` | string | no | `""` | |
| `pool` | [Pool](#pool) | no | server's `pool`, then built-in defaults | Per-field override of the server's `pool`. |
| `auth_database` | string | no | `None` (falls back to `name`) | Mongo `authSource`. Set to `"admin"` when the role lives outside the target DB (container-bootstrapped users). Empty/whitespace is a boot error — omit to fall back. Ignored by pg. See [multi-db.md](../usage/multi-db.md). |
| `write_role` | string | no | none | Postgres only. The role a `query_write` grant runs as; every read — under any grant — still connects as `role` in a read-only transaction. Same shape and stock-superuser checks as `role`, and must differ from it. Set together with `write_password` (one without the other aborts boot). Absent → the database is read-only through the gateway. See [Write tier](#write-tier). |
| `write_password` | [secret ref](#secret-references) | with `write_role` | none | Password of `write_role`. Same forms and production-literal rule as `password`. |

### Write tier

A database with `write_role` gets a second pool, keyed by the same
`(server, database)` and sized by the same `pool` settings, that connects as
`write_role`. Only `run_query` under a `query_write` grant (including
`dry_run`) and `explain` of an `INSERT`/`UPDATE`/`DELETE` use it; `explain`
there runs in a read-only transaction, so the statement is planned, never
executed. Everything else — reads, `describe_schema`, `sample_table`,
`table_stats`, `explain` of a `SELECT` — runs as `role`. So a read-tier token
cannot reach a write-capable role at all: the guarantee rests on the
database's privileges, not on the SQL guard.

Boot rules:

- A `query_write` grant on a database without `write_role` aborts boot.
  Wildcards expand against the configured databases, so
  `{ server: "*", database: "*", action: query_write }` needs a `write_role`
  on every database. A `query_write` grant added later through the admin API
  on such a database fails each write with `forbidden`.
- `write_role` on a non-postgres server aborts boot (Mongo stays read-only).
- `write_role` equal to `role` aborts boot.

Upgrading: a deployment that wired a write-capable role as `role` for a
`query_write` grant now fails boot. Move that role to `write_role` +
`write_password` and provision a read-only `role` (no compatibility shim).

The gateway never creates or grants either role — see
[quickstart §1](quickstart.md#1-provision-read-only-roles-on-each-target-db).

> Spec also defines `sql_capture` on Database. It isn't enforced yet — it's
> commented out in `config/example.yaml` because the parser rejects it.

## Pool

`#[serde(deny_unknown_fields)]`, on [Server](#server) and [Database](#database). Each field resolves database → server → built-in default independently.

| Key | Type | Required | Notes |
|---|---|---|---|
| `max_connections` | u32 > 0 | no | `0` is a boot error. |
| `min_connections` | u32 | no | Connections kept while idle; `0` = fully lazy. Above `max_connections` at the same level is a boot error. |
| `idle_timeout_s` | u64 > 0 | no | Seconds an idle connection above the minimum lives. |

### Mongo

- **Minimum server version: 4.4.** The gateway stamps a `comment` field on
  every command so a disconnected agent's operation can be found in
  `currentOp` and cancelled — `comment` on an arbitrary command requires
  MongoDB 4.4+. Older servers are unsupported; there is no compatibility
  fallback.
- **Cancellation is best-effort, and off by default.** `killOp` is a
  cluster-admin action, not part of a least-privilege read-only role. If the
  gateway's mongo `role` lacks it, a disconnected agent's operation keeps
  running until it finishes or hits `statement_timeout_ms` — bounded, same
  as before this was added, just not actively killed. To opt in, grant the
  role the built-in `clusterManager` role (or the narrower `inprog` +
  `killop` privileges on the `cluster` resource) in addition to its
  read-only grant on the target database. Even with the privilege, the
  cancel is a best-effort lookup-then-kill (see the `cancel` module docs in
  `src/exec/mongo/cancel.rs`) — `statement_timeout_ms` remains the
  guaranteed bound either way.

## Permission

`#[serde(deny_unknown_fields)]`.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `group` | string | **yes** | — | Group claim from the IdP token (e.g. `engineers`, `oncall`). |
| `grants` | list of [Grant](#grant) | no | `[]` | Empty means the group is recognized but grants nothing. |

## Admin

`#[serde(deny_unknown_fields)]`. Gates the `/admin/v1/*` surface — full reference at [admin-api.md](admin-api.md).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `enabled` | bool | no | `false` | When `false` (or `admin:` absent), `/admin/*` returns 404 — the route never mounts. |
| `group` | string | **yes when `enabled: true`** | — | SSO group claim that authorizes admin calls. Required and non-blank when `enabled: true` — empty/whitespace aborts boot (every authenticated user would otherwise be an admin). Optional and ignored when disabled. |
| `session_max_age_secs` | u64 | no | no cap | Reject admin requests from sessions older than this many seconds, forcing a re-login. Group membership is frozen at login, so this caps how long someone removed from the admin group in the IdP keeps admin access (otherwise up to `SESSION_TTL_HOURS`). See [spec 04](../initial-idea/04-auth-sso.md). |

## PermissionsStore

`#[serde(deny_unknown_fields)]`. Selects the backend for users / databases / grants — see [admin-api.md §Storage backend](admin-api.md#storage-backend).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `driver` | `pg` \| `mysql` | **yes** | — | `pg` (default if the block is absent) shares the state DB. `mysql` opens a separate pool via `PERMISSIONS_DB_DSN` env at boot. |

> **Boot-gate**: `driver: mysql` + `admin.enabled: true` is rejected — admin handlers haven't been ported to mysql. Use pg for the admin path, or mysql with YAML grants only.

## ServiceAccount

`#[serde(deny_unknown_fields)]`. A static bearer credential for a headless client (CI job, agent runner). Full design + mint/rotate/revoke runbook: [spec 14](../initial-idea/14-service-tokens.md).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | **yes** | — | Stable service identity; becomes the audit identity `service:<name>`. Must match `^[a-z0-9][a-z0-9-]{0,62}$`, unique across the list. |
| `group` | string | **yes** | — | The single permissions group the token acts as. Must be declared in `permissions:` (an empty `grants:` list recognizes a group that grants nothing) and must not equal `admin.group` when the admin surface is enabled — both abort boot. |
| `token` | [secret ref](#secret-references) | **yes** | — | `${ENV:…}` or `${FILE:…}` (spec 14 — YAML carries the secret reference, never the bearer value). An inline literal token is accepted under the default `gateway.env: development` (dev/test parity with `password:`) and **rejected at boot under `gateway.env: production`**. Committed config is also checked in CI by the advisory `secret-scan` job, which fails on any literal `dbmcp_svc_<64hex>` in a tracked file outside its exempt paths. Resolved value must match `dbmcp_svc_` followed by exactly 64 lowercase hexadecimal characters (`0-9a-f`) — mint with `bin/mint-service-token <name>`. Short, overlong, non-hex, or mixed-case bodies abort boot with `ServiceTokenError::WeakToken`. Two accounts resolving to the same value abort boot (audit attribution would be ambiguous). |
| `max_concurrent_requests` | u32 > 0 | no | `MAX_CONCURRENT_PER_IDENTITY` (16) | In-flight request cap for this token, replacing the per-identity cap so a fleet of agents behind one token is not throttled as one user. The global `MAX_CONCURRENT_REQUESTS` cap still applies. `0` aborts boot. |
| `require_upstream` | bool | no | `false` | Reject calls that lack the `x-dbmcp-run-id` and `x-dbmcp-on-behalf-of` headers (`invalid_arguments`). The headers are **claimed** by the caller: stored on the audit row, never verified, never used for authorization. The audit identity stays `service:<name>`. |

Minting the first production token is an operator action, not a deploy side effect: run `bin/mint-service-token <name>`, store the value in the secret store, deliver it as a SealedSecret env/file, PR the stanza, roll.

## Logging

`#[serde(deny_unknown_fields)]`. Spec 07 §Storage.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `stream` | list of [StreamSink](#streamsink) | no | `[]` | Fire-and-forget copies of every audit row, in addition to the mandatory synchronous state-DB write. A sink outage never fails a request. |

Hot-tier retention stays env-driven (`AUDIT_RETENTION_DAYS`); there is no
`archive` key yet.

### StreamSink

Tagged by `kind`; unknown keys and unshipped kinds (`otlp`, `kafka`) abort boot.

| `kind` | Other keys | Notes |
|---|---|---|
| `stdout` | none | Emits the full audit row as a tracing event with `target: "audit_stream"` on the JSON stdout log. That target always logs at INFO, whatever `RUST_LOG` says. Lines dropped by a full log queue count in `log_lines_dropped_total` — see [logging.md](logging.md). |
| `syslog` | `host` (string, non-blank), `port` (u16, non-zero) | RFC 5424 over UDP. Blank `host` or `port: 0` aborts boot. |

## Grant

`#[serde(deny_unknown_fields)]`.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `server` | string | **yes** | — | Must match a `servers[].name`, or `"*"` for all visible servers. |
| `database` | string | **yes** | — | Must match a `databases[].name` somewhere, or `"*"`. Catches typos at boot. |
| `action` | `schema_read` \| `query_read` \| `query_write` \| `history_read` | **yes** | — | Misspelled variants (e.g. `query_reed`) fail at boot with the expected list. |
| `constraints` | [Constraints](#constraints) | no | empty | Most-restrictive-merged across all matching grants (spec 06). |

### Action hierarchy

`query_write` ⊇ `query_read` ⊇ `schema_read`. `history_read` is its own track.
A `query_write` grant needs a `write_role` on every database it matches —
see [Write tier](#write-tier).

## Constraints

`#[serde(deny_unknown_fields)]` — this is where the headline typo case from
issue #16 lives. Unknown keys here used to silently drop the constraint;
now they abort boot.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `require_reason` | bool | no | `false` | Caller must pass a non-empty `reason` arg. |
| `row_limit` | u32 | no | none | Truncate cap. Combined with caller's `limit`, most-restrictive wins. `0` aborts boot. |
| `statement_timeout_ms` | u32 | no | none | Postgres-side `SET LOCAL statement_timeout` for queries under this grant. `0` aborts boot (Postgres reads it as no timeout). |

## Secret references

Used wherever the schema expects a password.

| Form | When to use | Resolution timing |
|---|---|---|
| `${ENV:NAME}` | dev / CI; secret is in process env | startup + every pool open |
| `${FILE:/path}` | k8s sealed-secret, file-projected secret, Vault Agent sidecar | startup + every pool open (so rotation works) |
| `vault:secret/...` | recognized, not implemented; aborts boot | — |
| `aws-sm:arn:...` | recognized, not implemented; aborts boot | — |
| `gcp-sm:projects/...` | recognized, not implemented; aborts boot | — |
| anything else | inline literal (dev/test only) | startup |

Boot-time guarantees (issue #15):

- Missing env var → boot abort with `EnvNotSet(name)`.
- Missing or empty file → boot abort with `FileUnreadable` / `FileEmpty(path)`.
- Malformed `${…}` ref (legacy `${VAR}` syntax, empty `${ENV:}`, unknown
  scheme) → YAML parse error pointing at the line.

## Hot reload

`SIGHUP` re-reads the file, validates it and resolves every secret ref; any
failure keeps the running config whole. A successful reload swaps
permissions, service accounts, stream sinks and changed target pools at once.
Some settings are fixed at boot, and a reload that changes them is refused:
`admin` (enabled, `group`, `session_max_age_secs`), `permissions_store.driver`,
and — while the admin API is mounted — the set of server names (adding,
removing or renaming a server). Reordering `servers:` is not a boot-fixed
change.

## What the parser does NOT validate (yet)

- Network reachability — boot doesn't try to connect to listed servers;
  pools open lazily on first use.

When any of those fields ship, this page gets the corresponding row.
