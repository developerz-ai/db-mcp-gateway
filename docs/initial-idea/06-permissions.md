# 06 — Permissions

## Model

Permissions are **grants** that attach a **group** to a **(server, database, action)** with optional **constraints**.

```
group  ⨯  (server, database)  ⨯  action  ⨯  constraints  →  allowed
```

| Piece | Meaning |
|---|---|
| **Group** | An SSO group claim (e.g. `backend-engineers`, `oncall`, `data-platform`). Synced from IdP. |
| **Server / database** | Logical names from the config — never raw hosts. |
| **Action** | `schema_read`, `query_read`, `query_write`, `history_read`. |
| **Constraint** | Per-grant overrides: `require_reason`, `row_limit`, `statement_timeout_ms`, `allowed_schemas`, `denied_tables`, `time_window` (e.g. business hours only). |

A request is allowed iff *some* grant matches. Denies are not explicit — absence of a matching grant denies.

## Actions in detail

| Action | What it unlocks |
|---|---|
| `schema_read` | `list_databases`, `describe_schema`, `sample_table` (size-capped) |
| `query_read` | `run_query` with read-only enforcement, `explain`, `get_query_history` |
| `query_write` | `run_query` with write grants (requires the DB role to also have write privileges) |
| `history_read` | Read your *own* query history. Other users' history is never readable here — admin-only via state DB |

`query_read` implies `schema_read`. `query_write` implies `query_read`.

## Worked examples

**Backend engineer on staging:** full query, schema-read on prod.
```yaml
- group: backend-engineers
  grants:
    - server: staging
      database: "*"
      action: query_read
    - server: prod
      database: "*"
      action: schema_read
```

**Oncall with audited prod access:** query on prod, but reason required and short timeouts.
```yaml
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

**Data platform with writes to a single sandbox DB:**
```yaml
- group: data-platform
  grants:
    - server: analytics
      database: sandbox
      action: query_write
      constraints:
        require_reason: true
```

**New hires:** no entry → no access. The default is *nothing*.

**Worker-db rollout (issue `#19`):** deployable config lives at `config/permissions.yml`. Zitadel groups `devs`, `devops`, and `cto` use group-based access on the shared CNPG cluster. v1 is `query_read` only with `statement_timeout_ms: 30000` and `row_limit: 10000`. Per-dev DB ownership is deferred because it requires group-per-app mapping in Zitadel.

## Evaluation

For a request `(user, groups, server, db, action)`:

1. Resolve groups from the session.
2. Collect every grant matching one of the user's groups and the target `(server, db)`.
3. If no grant has an action ≥ the requested action → `forbidden`.
4. Merge constraints across matching grants: take the **most restrictive** value for each (lowest `row_limit`, lowest `statement_timeout_ms`, `require_reason` = true wins, schema/table allow/deny intersected).
5. Apply constraints to the call.

Most-restrictive merging means you can't accidentally upgrade your access by being in two groups.

## Hot reload

Permission changes land via PR → merge → operator runs `kill -HUP` on the gateway (or rolling restart). Live sessions keep their existing grants snapshot until next login (matches [04-auth-sso](04-auth-sso.md)).

## Admin operations

There is no in-band admin UI. Operator actions are CLI subcommands of the gateway binary, run inside the container, against the state DB:

- `gateway admin revoke-session <user_email>`
- `gateway admin list-active-sessions`
- `gateway admin replay-audit <query>` (for compliance investigations)

Admin commands authenticate via a separate mechanism (Unix socket / shell access), not SSO — they're for whoever has prod shell access.
