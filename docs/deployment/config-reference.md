# Config reference

Single-page reference for the gateway's YAML config — every key the parser
accepts today, with type, requirement, and a short description. The spec at
[`../initial-idea/08-config.md`](../initial-idea/08-config.md) covers
*intended* shape (including sections like `gateway:` / `auth:` / `logging:`
that the parser doesn't enforce yet); this page is what the binary actually
checks at boot.

Boot-time validation (issue #16):

- Unknown keys inside `servers[].*`, `databases[].*`, `permissions[].*`,
  `grants[].*`, and `constraints.*` are **errors** with a line:column pointer
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

> Other top-level keys (`gateway:`, `auth:`, `logging:`) are accepted for
> forward-compat with the full spec but not parsed. Their settings come from
> environment variables today — see [`.env.example`](../../.env.example).

## Server

`#[serde(deny_unknown_fields)]` — unknown keys here are boot errors.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | **yes** | — | Stable identifier used in grants, audit, and `list_servers`. |
| `kind` | `postgres` \| `mysql` \| `mssql` | **yes** | — | Only `postgres` is implemented today. |
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
| `role` | string | **yes** | — | Postgres role (`^[A-Za-z_][A-Za-z0-9_]*$`). Typo here is caught at boot. |
| `password` | [secret ref](#secret-references) | **yes** | — | `${ENV:…}` / `${FILE:…}` / `vault:…` / `aws-sm:…` / `gcp-sm:…` / inline literal. |
| `description` | string | no | `""` | |

> Spec also defines `sql_capture` and `pool:` on Database. Those aren't
> enforced yet — they're commented out in `config/example.yaml` so the parser
> doesn't reject them. Will land when the relevant features ship.

## Permission

`#[serde(deny_unknown_fields)]`.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `group` | string | **yes** | — | Group claim from the IdP token (e.g. `engineers`, `oncall`). |
| `grants` | list of [Grant](#grant) | no | `[]` | Empty means the group is recognized but grants nothing. |

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
