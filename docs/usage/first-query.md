# Your first query

A 5-minute walkthrough for a new engineer whose org has already deployed the gateway. Start to finish: install Claude Code → sign in → run a real query against a real DB → read your own audit row.

If you're standing the gateway up, you want [../deployment/quickstart.md](../deployment/quickstart.md) instead. If you've already done a first query and want the day-to-day reference, jump back to [claude-code.md](claude-code.md). For MongoDB targets the path is the same — see [multi-db.md](multi-db.md) for what changes at the `sql` field and which commands are allowed.

> **Placeholder:** every `https://db.internal.acme.com` below is a stand-in. Your platform team will give you the real one (looks the same, different domain).

## Before you start

| You need | How to check |
|---|---|
| Claude Code installed and logged in to your Anthropic account | `claude --version` |
| Your gateway URL | Ask your platform team — it'll be on the Discord pin or the internal wiki |
| An SSO account at your org's IdP | The same login you use for the rest of your internal tools |
| Membership in at least one group with a grant | Without this you authenticate fine but `list_servers` returns nothing — see [Gotchas](#gotchas) |

That's it. You don't need: a DB password, a VPN profile (unless your gateway is private), the `psql` CLI, or any local DB driver.

## 1. Add the gateway as an MCP server

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com
```

`--scope project` writes the config into `.mcp.json` in the current repo so your teammates inherit it on `git pull`. Use `--scope user` if it's just for you. Either way nothing sensitive lands in the file — no tokens, no DB info, just the URL.

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

Claude Code calls `list_servers`, gets back `401 unauthenticated`, and surfaces the login link. Click it (or copy-paste into a browser if your terminal can't open URLs). You'll be redirected through your org's IdP — same flow as logging into any internal app.

When the IdP redirects back, Claude Code stores the token in your system keychain (macOS) or credentials file (Linux/Windows) and retries the call automatically.

Expected total time: 10–30 seconds.

## 3. List what you can reach

After SSO, the same prompt completes:

```text
You:    What databases can I see through db-gateway?

Claude: [calls list_servers]
        [calls list_databases for each server]

        You have access to:
        • staging (postgres) — staging/app, staging/billing
        • prod (postgres)    — prod/billing (read-only, reason required)
```

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

Schema lookups are cached by the gateway — re-asking is cheap.

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

Every `run_query` call writes a row to the gateway's audit log **before** the result comes back. You can ask the agent for your own recent calls:

```text
Show me my last 3 queries through db-gateway.
```

The agent calls `get_query_history`, which returns *only your own* SQL + timestamp + duration + row count. Other users' queries are not visible.

If your operators have given you direct read access to the audit table, the row also lives in the state DB and can be pulled with `psql` — see [../initial-idea/07-logging-retention.md](../initial-idea/07-logging-retention.md).

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

Some grants — typically anything against prod — require a one-line reason on every query. Claude Code surfaces this as a prompt:

```text
The gateway requires a reason for this query against prod.
What should I tell it? (e.g. "investigating ticket SUPPORT-4421")
```

Just type the reason. It lands verbatim in the audit row, so future-you on an audit review will thank present-you for being specific. `"checking stuff"` is a bad reason; `"verifying SUPPORT-4421 root cause"` is a good one.

### `timeout` on `run_query`

The query exceeded the grant's `statement_timeout_ms`. Don't try to bypass it — narrow the query (tighter `WHERE`, smaller table, smaller window) or ask the agent to `explain` first to see what's expensive.

### `row_limit_exceeded` (or `truncated: true` in the response)

The result was clipped at the grant's `row_limit`. Add a `LIMIT`, a tighter `WHERE`, or aggregate (`count`, `sum`, `group by`) before the gateway has to truncate.

### "I want to write, not just read"

By design, every grant defaults to read-only. Writes need (a) an explicit `query_write` grant in the YAML AND (b) a target-DB role with write privileges. Both are operator-side changes, behind a PR review. The gateway will never let an agent self-elevate.

### Token expired silently

Sessions are short-lived (8h by default). If you see `unauthenticated` after lunch, that's it — `/mcp` → *Reconnect* runs the SSO flow again. Tokens never live in any config file, so there's nothing to clean up.

### Gateway tools missing from `/mcp` entirely

Either:

- The gateway URL is wrong — re-add with the right one.
- The gateway is down — `curl -s -o /dev/null -w '%{http_code}\n' https://db.internal.acme.com/healthz` should print `200`.
- Claude Code hasn't reconnected — restart Claude Code or run `/mcp` → *Reconnect*.

## Where to go next

- [claude-code.md](claude-code.md) — full reference for the Claude Code integration (scope flags, removal, pre-configured OAuth)
- [other-agents.md](other-agents.md) — Cursor, Continue, Claude Desktop
- [../initial-idea/03-mcp-tools.md](../initial-idea/03-mcp-tools.md) — every tool the gateway exposes and what it returns
- [../initial-idea/06-permissions.md](../initial-idea/06-permissions.md) — exactly how grants are evaluated
