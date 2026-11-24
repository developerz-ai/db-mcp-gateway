# Your first query

A 5-minute walkthrough for a new engineer whose org has already deployed the gateway. Start to finish: install Claude Code → sign in → run a real query against a real DB. There's an optional last step for operators who want to peek at the audit row directly — it needs `psql` and state-DB access, so most engineers can stop after step 5.

If you're standing the gateway up, you want [../deployment/quickstart.md](../deployment/quickstart.md) instead. If you've already done a first query and want the day-to-day reference, jump back to [claude-code.md](claude-code.md). For MongoDB targets the path is the same — see [multi-db.md](multi-db.md) for what changes at the `sql` field and which commands are allowed.

> **Placeholder:** every `https://db.internal.acme.com` below is a stand-in. Your platform team will give you the real one (looks the same, different domain). The MCP endpoint is that origin **plus `/mcp`** — the bare origin has no route and answers `404`.

## Before you start

| You need | How to check |
|---|---|
| Claude Code installed and logged in to your Anthropic account | `claude --version` |
| Your gateway URL | Ask your platform team — it'll be on the Discord pin or the internal wiki |
| An SSO account at your org's IdP | The same login you use for the rest of your internal tools |
| Membership in at least one group with a grant | Without this you authenticate fine but `list_servers` returns nothing — see [Gotchas](#gotchas) |

That's it. You don't need: a DB password, a VPN profile (unless your gateway is private), or any local DB driver. The optional audit-row peek in step 6 needs `psql` plus operator-granted state-DB access — skip that step if you don't have both.

## 1. Add the gateway as an MCP server

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com/mcp
```

`--scope project` writes the config into `.mcp.json` in the current repo so your teammates inherit it on `git pull`. Use `--scope user` if it's just for you. Either way nothing sensitive lands in the file — no tokens, no DB info, just the URL. Keep the `/mcp` path: it is where the gateway serves MCP (operators can move it with `MCP_PATH`; then use theirs).

Verify Claude Code picked it up:

```text
/mcp
```

You'll see `db-gateway` listed with status `disconnected` or `needs auth`. That's expected — you haven't signed in yet.

## 2. First call triggers SSO

Ask the agent anything that needs the gateway:

```text
What databases can I see through db-gateway?
```

The gateway answers Claude Code's first request with `401` and a `WWW-Authenticate` header. Claude Code discovers the gateway's OAuth endpoints from it and tells you to authenticate: run `/mcp`, pick `db-gateway`, choose *Authenticate*, and a browser opens (copy the URL by hand if your terminal can't open one). You'll go through your org's IdP — same flow as logging into any internal app — and then a short consent page on the gateway itself.

When the browser lands back, Claude Code stores the token in your system keychain (macOS) or credentials file (Linux/Windows). Ask again and the call goes through.

Expected total time: 10–30 seconds.

## 3. List what you can reach

After SSO, the same prompt completes:

```text
You:    What databases can I see through db-gateway?

Claude: [calls list_servers — each server comes back with its databases]

        You have access to:
        • staging (postgres) — staging/app, staging/billing
        • prod (postgres)    — prod/billing (read-only, reason required)
```

Each database in the answer carries what you may do there: `actions` (`schema_read`, `query_read`, …), `writes`, the `tools` that work on it, and per action the `row_limit`, `statement_timeout_ms` and `require_reason` your grant enforces. To see your own identity, groups, session expiry and every grant in one call, ask the agent to call `whoami`.

If you see **nothing** here, the auth worked but you're not in any group that has grants. Skip to [Gotchas → I see no servers](#i-see-no-servers).

## 4. Look at a schema

Pick any database the list showed you. Ask in natural language:

```text
What columns does the users table have in staging/app?
```

The agent calls `describe_schema` and renders something like:

```text
staging/app.users

| column     | type        | nullable |
|------------|-------------|----------|
| id         | bigint      | no       |
| email      | text        | no       |
| created_at | timestamptz | no       |
| status     | text        | no       |
```

Each `describe_schema` call goes to the database and writes its own audit row — the gateway does not cache schemas.

Three levels of detail: `detail: "names"` lists tables and their kind, the default `columns` adds column types, `full` adds real types (`varchar(64)`, `integer[]`, enum labels), primary and foreign keys, indexes, comments and a row estimate. `search: "email"` finds the tables whose name or a column name contains the term, across every schema when no `schema` is named. On MongoDB, `full` infers each collection's fields from a sample of up to 100 documents, under a `query_read` grant.

When a query names a table or column that does not exist, the error carries up to five near-miss names the agent can see (`users` for `usres`), the position of the error in the statement and, for a parser error, Postgres' own hint — so the next call is usually the fix.

## 5. Run a query

```text
How many users signed up in staging/app over the last 7 days?
```

The agent writes the SQL, picks `run_query`, and gets back rows + execution stats:

```text
Claude: [calls run_query staging/app]
          select count(*) from users where created_at > now() - interval '7 days';

        → 412 (returned in 38ms)
```

That's it. You ran a real query against a real DB without ever touching a credential.

## 6. (Optional) Read your own audit row

Every `run_query` call writes a row to the gateway's audit log **before** the result comes back — user, SQL, reason, row count, duration, outcome.

With the `get_query_history` tool shipped in [#169](https://github.com/developerz-ai/db-mcp-gateway/issues/169), ask your agent to call it for the `(server, database)` you ran against:

```
get_query_history(server="...", database="...", limit=20)
```

It returns only *your* queries (scoped by the SSO-verified identity — no client-supplied user field). If you can't call it, the operator hasn't granted `history_read` to your group yet; ask the platform team to add one. See [../initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md) for the schema and access model.

## Gotchas

### I see no servers

You're authenticated but not a member of any group with a grant. The fix is *not* in this repo or in Claude Code — it's a PR against the gateway's permissions config. Ping the platform team with: "I logged in as `<you@org>`, `list_servers` returns empty. Which group should I be in?"

### The browser popup blocker ate the SSO redirect

Some browsers block window.open() on the first IdP redirect. Two workarounds:

- Copy the login URL Claude Code prints and paste it into a new tab manually.
- In Claude Code: `/mcp` → *Reconnect* — usually skips the popup and uses your default browser directly.

### Corporate proxy / VPN

If your laptop routes through a TLS-inspecting proxy, the gateway's cert will fail to validate in Claude Code. You'll see a TLS error in the `/mcp` output, not a 401. Two options:

- Add your proxy's CA cert to the system trust store (preferred — IT usually has a how-to).
- Ask your platform team if the gateway is reachable on a path that bypasses the proxy (e.g. a dedicated internal DNS name).

The gateway itself does not support `--insecure` mode for clients; if cert validation fails it's a real problem to fix, not a flag to flip.

### `forbidden` on a query that used to work

Two reasons:

- You were removed from a group. Check with whoever owns the permissions config.
- The grant was tightened — same group still listed, but the new YAML revoked the action you tried. Permissions are reviewed in git, so `git log` on the config repo tells you when and why.

### `reason_required`

Some grants — typically anything against prod — require a one-line reason on every query. The gateway refuses the call with `reason_required`; there is no special client prompt, the agent reads the error and usually asks you in chat, something like:

```text
The gateway requires a reason for this query against prod.
What should I tell it? (e.g. "investigating ticket SUPPORT-4421")
```

Answer it (or put the reason in your request up front) and the agent retries with `reason` set. It lands verbatim in the audit row, so future-you on an audit review will thank present-you for being specific. `"checking stuff"` is a bad reason; `"verifying SUPPORT-4421 root cause"` is a good one.

### `timeout` on `run_query`

The query exceeded the grant's `statement_timeout_ms` — the error names the budget in its message and in `limit` (`{"name": "statement_timeout_ms", "value": …}`). Don't try to bypass it — narrow the query (tighter `WHERE`, smaller table, smaller window) or ask the agent to `explain` first to see what's expensive.

### `truncated: true` in the response

The result was clipped at the row cap (the grant's `row_limit`, else 1000) or at the gateway's result-size cap. It is not an error: the rows that fit come back with `truncated: true`. Add a `LIMIT`, a tighter `WHERE`, or aggregate (`count`, `sum`, `group by`) before the gateway has to truncate. The response says which cap cut — `truncated_by`: `limit` (raise `limit`), `grant_row_limit` (the grant's cap; page instead) or `byte_cap` — next to the effective `row_limit` and a `hint` on how to page by key. To keep a result small for the agent's context, pass `max_bytes` (cap on the returned rows' JSON) and `max_cell_bytes` (an oversized cell becomes a `{"$dbmcp_truncated": {"bytes", "preview"}}` marker); `sample_table` also takes `columns`.

### "I want to write, not just read"

By design, every grant defaults to read-only. Writes need (a) an explicit `query_write` grant on that `(server, database)` AND (b) a target-DB role with write privileges. Both are operator-side changes, behind a PR review. The gateway will never let an agent self-elevate.

A `query_write` grant permits **data writes only** — a single `INSERT`, `UPDATE`, or `DELETE` per call, run through `run_query` exactly like a read (same statement timeout, row cap, and synchronous audit). Schema changes stay blocked no matter what: `CREATE` / `ALTER` / `DROP` / `TRUNCATE`, `GRANT` / `REVOKE`, and multi-statement bodies are all rejected with `forbidden_sql`. The gateway never issues DDL.

### Token expired silently

Sessions are short-lived (8h by default; the operator's `SESSION_TTL_HOURS`). Claude Code refreshes them while the refresh chain lasts (`REFRESH_TTL_DAYS`, default 1 day). If every call starts answering `401`, that's it — `/mcp` → *Reconnect* runs the SSO flow again. Tokens never live in any config file, so there's nothing to clean up.

### Gateway tools missing from `/mcp` entirely

Either:

- The gateway URL is wrong — re-add with the right one.
- The gateway is down — `curl -s -o /dev/null -w '%{http_code}\n' https://db.internal.acme.com/readyz` should print `200` (checks state-DB reachability, not just liveness).
- Claude Code hasn't reconnected — restart Claude Code or run `/mcp` → *Reconnect*.

## Where to go next

- [claude-code.md](claude-code.md) — full reference for the Claude Code integration (scope flags, removal, pre-configured OAuth)
- [other-agents.md](other-agents.md) — Cursor, Continue, Claude Desktop
- [../initial-idea/03-mcp-tools.md](../initial-idea/03-mcp-tools.md) — every tool the gateway exposes and what it returns
- [../initial-idea/06-permissions.md](../initial-idea/06-permissions.md) — exactly how grants are evaluated
