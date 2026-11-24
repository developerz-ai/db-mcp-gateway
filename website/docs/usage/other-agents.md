# Connecting other MCP-aware agents

The gateway speaks MCP over Streamable HTTP (protocol `2025-06-18`): the client `POST`s JSON-RPC to one endpoint and gets JSON back. `GET` on that endpoint answers `405` — the gateway never opens a server-to-client stream, and the legacy HTTP+SSE transport is not served. Any client that supports Streamable HTTP with OAuth works. This page collects the configuration shapes for the major ones. The Claude Code instructions live in [claude-code.md](claude-code.md).

Throughout, replace `https://db.internal.acme.com/mcp` with your gateway's MCP URL — the origin **plus `/mcp`** (or the operator's `MCP_PATH`). The bare origin has no route and answers `404`.

## Cursor

`~/.cursor/mcp.json` (user-wide) or `.cursor/mcp.json` (project):

```json
{
  "mcpServers": {
    "db-gateway": {
      "url": "https://db.internal.acme.com/mcp",
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
    type: streamable-http
    url: https://db.internal.acme.com/mcp
```

Older Continue releases used a different shape; check your version's MCP docs if this one is rejected.

## Claude Desktop

Add the gateway as a remote (custom) connector in Claude Desktop's settings, with `https://db.internal.acme.com/mcp` as the URL; the OAuth sign-in runs from there. `claude_desktop_config.json` launches local `stdio` servers — a remote `url` entry there is not how Desktop connects to a remote server. Custom connectors depend on your Claude plan and on the gateway being reachable from where the connector runs; check Anthropic's current connector docs before rolling this out.

## Generic MCP client

Any client implementing the spec accepts:

| Field | Value |
|---|---|
| Transport | Streamable HTTP (`POST` only). Legacy `sse` is not served |
| URL | gateway origin + `/mcp` (the `MCP_PATH`) |
| Auth | MCP Authorization (OAuth 2.1 + PKCE). A `401` carries `WWW-Authenticate` pointing at `/.well-known/oauth-protected-resource`; the client discovers `/authorize`, `/token` and `/register` from there. The gateway brokers the IdP login itself |

## What every client needs to know

- **Token handling is opaque to the user.** The gateway issues short-lived session JWTs (default 8h) plus a refresh token (chain lifetime default 1 day). The client caches them, refreshes, and re-auths when the chain ends.
- **No client-side credentials.** You never paste a DB URL, password, or service-account file.
- **Result size is server-capped.** If a result is truncated, the response carries `truncated: true` — the agent should surface that, not hide it.
- **Reason capture happens via tool errors.** If a tool returns `reason_required`, the client should ask the user, then retry with `reason: "..."` in the args.

## Headless clients (no browser): service tokens

If your client runs unattended — a CI job, an agent runner, another service — it cannot drive the browser SSO flow. It authenticates with a **service token** instead: a static bearer your platform team issues out-of-band.

```json
{
  "mcpServers": {
    "db-gateway": {
      "url": "https://db.internal.acme.com/mcp",
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

Send `x-dbmcp-run-id` and `x-dbmcp-on-behalf-of` with every call so the audit log can tell your runs apart — see [Headless agents](headless-agents.md) for the headers, the read/write tiers and write semantics.

Operators: the mint/rotate/revoke runbook is [spec 14](../initial-idea/14-service-tokens.md) (`bin/mint-service-token`).
