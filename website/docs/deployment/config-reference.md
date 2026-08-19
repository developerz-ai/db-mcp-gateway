# Config reference

Single-page reference for the gateway's YAML config — every key the parser
accepts today, with type, requirement, and a short description. The spec at
[`../initial-idea/08-config.md`](../initial-idea/08-config.md) covers
*intended* shape (including sections like `gateway:` / `auth:` / `logging:`
that the parser doesn't enforce yet); this page is what the binary actually
checks at boot.

Boot-time validation (issue #16):

- Unknown keys inside `servers[].*`, `databases[].*`, `permissions[].*`,
  `grants[].*`, `constraints.*`, and `service_accounts[].*` are **errors**
  with a line:column pointer
  and the list of expected fields. A typo like `statemnt_timeout_ms` aborts
  startup rather than silently dropping the constraint.
- Unknown keys at the top level (`gateway:`, `auth:`, `logging:`, …) are
  ignored for now — strictness there waits on the env→YAML unification.
- Every `${ENV:…}` / `${FILE:…}` ref must resolve cleanly; unresolved refs
  abort startup (issue #15).

## Top level

| Key | Type | Required | Notes |
|---|---|---|---|
| `servers` | list of [Server](#server) | no (defaults `[]`) | Target DBs the gateway can dispatch to. |
| `permissions` | list of [Permission](#permission) | no (defaults `[]`) | Group→grant mapping. Empty list means no caller can reach anything. |
| `admin` | [Admin](#admin) | no | `/admin/v1/*` surface gating — see [admin-api.md](admin-api.md). |
| `permissions_store` | [PermissionsStore](#permissionsstore) | no | Storage backend for users/databases/grants. Absent → state DB (pg). |
| `service_accounts` | list of [ServiceAccount](#serviceaccount) | no (defaults `[]`) | Static bearer tokens for headless clients — see [spec 14](../initial-idea/14-service-tokens.md). |

> Other top-level keys (`gateway:`, `auth:`, `logging:`) are accepted for
> forward-compat with the full spec but not parsed. Their settings come from
> environment variables today — see [`.env.example`](https://github.com/developerz-ai/db-mcp-gateway/blob/main/.env.example).

## Server

`#[serde(deny_unknown_fields)]` — unknown keys here are boot errors.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | **yes** | — | Stable identifier used in grants, audit, and `list_servers`. |
| `kind` | `postgres` \| `mongo` \| `mysql` \| `mssql` | **yes** | — | `postgres` and `mongo` work today (#56–#58); `mysql` / `mssql` parse but are **rejected by boot validation** — the process refuses to start (`ServerKind::has_adapter`). Unrelated to `permissions_store.driver: mysql`, which is supported. |
| `host` | string | **yes** | — | DNS or IP of the target DB. |
| `port` | u16 | no | `5432` | |
| `tls` | `required` \| `insecure` | no | `required` | `insecure` logs a warning every minute when used in prod. |
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
| `auth_database` | string | no | `None` (falls back to `name`) | Mongo `authSource`. Set to `"admin"` when the role lives outside the target DB (container-bootstrapped users). Empty/whitespace is a boot error — omit to fall back. Ignored by pg. See [multi-db.md](../usage/multi-db.md). |

> Spec also defines `sql_capture` and `pool:` on Database. Those aren't
> enforced yet — they're commented out in `config/example.yaml` so the parser
> doesn't reject them. Will land when the relevant features ship.

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
| `group` | string | **yes when `enabled: true`** | — | SSO group claim that authorizes admin calls. Empty/whitespace with `enabled: true` aborts boot (every authenticated user would otherwise be an admin). |

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
| `token` | [secret ref](#secret-references) | **yes** | — | `${ENV:…}` or `${FILE:…}` (spec 14 — YAML carries the secret reference, never the bearer value). The loader accepts inline literal tokens (`Password::Literal`) for dev/test parity with `password:` and does not reject them at boot; credential-free committed config is guarded at CI by the `secret-scan` job — ADVISORY: it scans every tracked file (not just YAML) and fails the job on any literal `dbmcp_svc_<64hex>` (`tests/**` fixtures excluded), but does not block a merge until made a required check (#190 follow-up), not by the loader. Inline literals are therefore valid only in programmatic test fixtures constructed via `ConfigFile::from_yaml_str` / `ServiceTokenStore::from_config` directly. Resolved value must match `dbmcp_svc_` followed by exactly 64 lowercase hexadecimal characters (`0-9a-f`) — mint with `bin/mint-service-token <name>`. Short, overlong, non-hex, or mixed-case bodies abort boot with `ServiceTokenError::WeakToken`. Two accounts resolving to the same value abort boot (audit attribution would be ambiguous). |

Minting the first production token is an operator action, not a deploy side effect: run `bin/mint-service-token <name>`, store the value in the secret store, deliver it as a SealedSecret env/file, PR the stanza, roll.

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

## Constraints

`#[serde(deny_unknown_fields)]` — this is where the headline typo case from
issue #16 lives. Unknown keys here used to silently drop the constraint;
now they abort boot.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `require_reason` | bool | no | `false` | Caller must pass a non-empty `reason` arg. |
| `row_limit` | u32 | no | none | Truncate cap. Combined with caller's `limit`, most-restrictive wins. |
| `statement_timeout_ms` | u32 | no | none | Postgres-side `SET LOCAL statement_timeout` for queries under this grant. |

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

## What the parser does NOT validate (yet)

- Top-level `gateway:` / `auth:` / `logging:` sections are silently ignored.
  Their values come from env vars today.
- Pool sizing (`pool: { max_connections, idle_timeout_seconds, … }`) on
  databases — gateway uses fixed defaults until per-DB pool sizing ships.
- `env: production` strictness (rejecting inline literal passwords) is in
  the spec but not enforced today.
- Network reachability — boot doesn't try to connect to listed servers;
  pools open lazily on first use.

When any of those fields ship, this page gets the corresponding row.
