# Connecting other MCP-aware agents

The gateway speaks standard MCP over HTTP+SSE, so any client that supports the protocol works. This page collects the configuration shapes for the major ones. The Claude Code instructions live in [claude-code.md](claude-code.md).

Throughout, replace `https://db.internal.acme.com` with your gateway URL.

## Cursor

`~/.cursor/mcp.json` (user-wide) or `.cursor/mcp.json` (project):

```json
{
  "mcpServers": {
    "db-gateway": {
      "url": "https://db.internal.acme.com",
      "type": "http"
    }
  }
}
```

Cursor will prompt for SSO on first use.

## Continue

`~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: db-gateway
    transport:
      type: http
      url: https://db.internal.acme.com
```

## Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) / `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

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

## Generic MCP client

Any client implementing the spec accepts:

| Field | Value |
|---|---|
| Transport | `http` (preferred) or `sse` |
| URL | gateway URL, root path |
| Auth | OIDC via the gateway — client should treat `401` responses as a trigger to open the `login_url` returned in the body |

## What every client needs to know

- **Token handling is opaque to the user.** The gateway issues short-lived JWTs (default 8h). The client caches them and re-auths when expired.
- **No client-side credentials.** You never paste a DB URL, password, or service-account file.
- **Result size is server-capped.** If a result is truncated, the response carries `truncated: true` — the agent should surface that, not hide it.
- **Reason capture happens via tool errors.** If a tool returns `reason_required`, the client should ask the user, then retry with `reason: "..."` in the args.

If your client doesn't support OAuth flows yet, talk to your platform team — they can issue a long-lived service token for that client only. Service tokens are auditable to a named system identity (e.g. `ci-bot`), not to a human, and are gated by their own group in the permissions config.
