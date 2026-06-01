# Connecting Claude Code

This is the reference for engineers whose org has already deployed the gateway. **Brand new?** Run through the 5-minute [first-query walkthrough](first-query.md) — it covers install → SSO → first real query end-to-end. Come back here for the full surface (scope flags, troubleshooting, pre-configured OAuth, removal).

If you're standing the gateway up, see [../deployment/quickstart.md](../deployment/quickstart.md) first.

> Every `https://db.internal.acme.com` below is a placeholder. Your platform team gives you the real one — same shape, different domain.

## Prerequisites

- Claude Code installed and logged in.
- Your gateway's URL (ask your platform team — looks like `https://db.internal.acme.com`).
- A working SSO login at your org's IdP.

## Add the gateway as a remote MCP server

The gateway speaks MCP over HTTP. One command:

```bash
claude mcp add --transport http db-gateway https://db.internal.acme.com
```

That's it. Restart Claude Code (or run `/mcp` to verify).

### Scope flags

The example above uses **local** scope (just this project, just you). Two other options:

| Scope | When to use | Stored in |
|---|---|---|
| `--scope local` (default) | One-off / per-project | `~/.claude.json` (your home) |
| `--scope user` | Want it in every project on your machine | `~/.claude.json` |
| `--scope project` | Want every teammate on this repo to get it | `.mcp.json` in the repo |

Most teams want `--scope project` so the config lands in `.mcp.json` and gets reviewed in PR like anything else:

```bash
claude mcp add --transport http db-gateway --scope project https://db.internal.acme.com
```

The resulting `.mcp.json`:

```json
{
  "mcpServers": {
    "db-gateway": {
      "type": "http",
      "url": "https://db.internal.acme.com"
    }
  }
}
```

## Sign in

First time you call a gateway tool, Claude Code will hit a `401` and Claude will tell you to run `/mcp`. Do that and follow the browser SSO flow.

```text
/mcp
```

Tokens are stored in your system keychain (macOS) or credentials file, refreshed automatically until they expire. To start over: `/mcp` → *Clear authentication*.

## Verify it works

In a Claude Code session, ask the agent to list databases:

```text
What databases can I see through db-gateway?
```

The agent calls `list_servers` / `list_databases` and shows what your group has access to. Empty list = authenticated but no grants — see [first-query.md → I see no servers](first-query.md#i-see-no-servers).

For a full first-query walkthrough — including reading your own audit row — see [first-query.md](first-query.md).

## Daily use

You don't invoke gateway tools directly. You talk to the agent in natural language and it picks the right tool:

```text
Why is invoice 1042 stuck? Check the prod billing DB.
```

The agent figures out it needs to:
1. `describe_schema` on `prod / billing`
2. write a query against `invoices` joining `events`
3. call `run_query`
4. surface the result

Every step is logged on the gateway side with your identity.

## When something requires a reason

Some grants require a reason string (typical for prod). When the gateway returns `reason_required`, Claude Code surfaces it and you type the reason in chat. The agent then retries the call with `reason: "..."` baked in. That reason ends up in the audit log.

You'll see something like:

```text
The gateway requires a reason for this query against prod.
What should I tell it? (e.g. "investigating ticket SUPPORT-4421")
```

Just type the reason. Be specific — *future you*, on an audit review, will thank present you.

## Troubleshooting

Quick reference. The deeper explanations + corporate-proxy / popup-blocker / `reason_required` cases live in [first-query.md → Gotchas](first-query.md#gotchas).

| Symptom | Likely cause |
|---|---|
| [`401` on every call, login URL loops](first-query.md#the-browser-popup-blocker-ate-the-sso-redirect) | Browser callback got blocked. Copy the callback URL from the address bar into the prompt Claude Code shows. |
| `forbidden` on a query that used to work | You were removed from a group, or the group's grant was changed. Permissions are reviewed in git — check the gateway's config repo. |
| [`timeout` on `run_query`](first-query.md#timeout-on-run_query) | Query was slow. Ask the agent to `explain` first, or narrow it. Operator-set; not bypassable. |
| [`row_limit_exceeded` (or `truncated: true`)](first-query.md#row_limit_exceeded-or-truncated-true-in-the-response) | Result was clipped. Add a tighter `WHERE`/`LIMIT`, or aggregate. |
| Gateway tools missing from `/mcp` | Either the gateway URL is wrong, the gateway is down, or your token expired silently. `/mcp` → *Reconnect*. |
| TLS / cert error instead of `401` | Corporate proxy is intercepting. See [first-query.md → Corporate proxy / VPN](first-query.md#corporate-proxy--vpn). |

## Removing the server

```bash
claude mcp remove db-gateway
```

## Pre-configured OAuth (rare)

If your org's deployment doesn't support OAuth Dynamic Client Registration, your platform team will give you a `client-id` and tell you which callback port to use. Then:

```bash
claude mcp add --transport http \
  --client-id <your-client-id> --client-secret --callback-port 8080 \
  db-gateway https://db.internal.acme.com
```

`--client-secret` prompts you to paste the secret with masked input; it's stored in your system keychain, not in any config file.

## See also

- [First-query walkthrough](first-query.md) — 5-minute happy path + the full gotchas list
- [Other MCP-aware agents](other-agents.md) — Cursor, Continue, etc.
- [Permissions model](../initial-idea/06-permissions.md) — what `forbidden` actually means
- [MCP tool surface](../initial-idea/03-mcp-tools.md) — every tool the gateway exposes
