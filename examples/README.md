# Examples

Starter templates for deploying and using the db-mcp-gateway.

## Files

| File | Purpose |
|---|---|
| `.mcp.json` | Claude Code MCP server configuration — add to your repo for team-wide access |
| `docker-compose.yml` | Production-like deployment with gateway + state DB (customize secrets per your env) |
| `gateway.yaml` | Minimal gateway config — servers + permissions. Extend per [docs/deployment/config-reference.md](../docs/deployment/config-reference.md) |

## Quick start

### For developers (add gateway to Claude Code)

```bash
# Copy the example MCP config to your project
cp examples/.mcp.json .mcp.json

# Commit to repo — teammates pick it up automatically
git add .mcp.json && git commit -m "add: db-gateway MCP config"

# In Claude Code, run /mcp to authenticate
```

Full walkthrough: [`docs/usage/first-query.md`](../docs/usage/first-query.md)

### For operators (deploy the gateway)

```bash
# Copy the example config and compose file
cp examples/gateway.yaml ./config.yml
cp examples/docker-compose.yml ./docker-compose.yml

# Edit both:
# - gateway.yaml: add your servers, permissions, IdP settings
# - docker-compose.yml: set STATE_DB_PW, OIDC secrets, target DB passwords

# For production: inject secrets from your orchestrator's vault/SM
# (not .env) — see docs/deployment/quickstart.md#3-configure-the-gateway

docker compose up -d
docker compose logs -f gateway
```

Detailed guide: [`docs/deployment/quickstart.md`](../docs/deployment/quickstart.md)

## Next steps

- **Gateway admins:** [`docs/deployment/config-reference.md`](../docs/deployment/config-reference.md) for the full config schema, [`docs/deployment/logging.md`](../docs/deployment/logging.md) for audit retention and sinks.
- **Developers:** [`docs/usage/claude-code.md`](../docs/usage/claude-code.md) for scope flags, troubleshooting, and multi-DB access patterns.
- **Architecture:** [`docs/initial-idea/`](../docs/initial-idea/) for design docs.
