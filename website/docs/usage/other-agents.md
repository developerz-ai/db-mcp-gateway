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

## Headless clients (no browser): service tokens

If your client runs unattended — a CI job, an agent runner, another service — it cannot drive the browser SSO flow. It authenticates with a **service token** instead: a static bearer your platform team issues out-of-band.

```json
{
  "mcpServers": {
    "db-gateway": {
      "url": "https://db.internal.acme.com",
      "type": "http",
      "headers": {
        "Authorization": "Bearer dbmcp_svc_..."
      }
    }
  }
}
```

- Service tokens are auditable to a named system identity (`service:<name>` in the audit log), not to a human, and are gated by their own group in the permissions config — a token reaches exactly what its group's grants allow, nothing else.
- They never expire and cannot be revoked in-band; rotation and revocation are operator actions (config edit + rollout). Treat the value like any other long-lived credential: store it in your secret manager, never in a repo.
- Service tokens are for tool calls only — they cannot reach the `/admin/*` surface and cannot mint login sessions.

Operators: the mint/rotate/revoke runbook is [spec 14](../initial-idea/14-service-tokens.md) (`bin/mint-service-token`).
