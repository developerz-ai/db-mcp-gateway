# 04 — Auth & SSO

## Identity flow

```
agent ──▶ gateway (no token / expired token)
                │
                └── 401 with login URL
                        │
                        ▼
                  browser ──▶ IdP ──▶ gateway /auth/callback
                                        │
                                        └── issues session JWT, stores in agent config
                                        
agent ──▶ gateway (Bearer: <jwt>) ──▶ permission check ──▶ DB
```

## Protocol

OIDC. The gateway is an OIDC *Relying Party*, not an IdP. Supported IdPs (anything OIDC-compliant works; these are tested):

- Okta
- Google Workspace
- Microsoft Entra ID
- Authentik
- Keycloak

## Login UX

1. Agent calls any tool with no token (or expired token).
2. Gateway returns a 401 with a `login_url` field.
3. Agent surfaces the URL to the user ("Open this to sign in").
4. User completes SSO in their browser. Gateway sets a short-lived authorization code.
5. Agent polls a paired endpoint (or the MCP client passes the code back — exact handshake TBD when MCP auth spec stabilizes); gateway exchanges code for a session token.
6. Token cached in the agent's MCP config dir.

This is **device-code-like**, not the classic web redirect, because agents don't have a browser. The pattern is borrowed from `gh auth login` and `gcloud auth login`.

## Session tokens

- Signed JWT, gateway-issued (not the IdP's ID token directly — we re-sign so we can revoke).
- Short TTL (default 8 hours).
- Refresh by re-running SSO; no long-lived refresh tokens stored on the developer's machine.
- Revocation: server-side denylist in state DB. Logout writes to the denylist; every request checks.

## Group resolution

Group membership comes from one of:

- OIDC `groups` claim (preferred — set IdP to include it)
- SCIM sync to the state DB (for IdPs that don't expose groups in tokens)
- Directory API lookup at token-issue time (Google Workspace fallback)

Cached for the session TTL. Group changes in the IdP take effect at the next login.

## What lands in the audit log per request

| Field | Source |
|---|---|
| `user_email` | OIDC `email` claim |
| `user_id` | OIDC `sub` |
| `groups` | snapshot at token issue time |
| `session_id` | gateway-issued, links to login event |
| `agent_client` | self-reported by the MCP client (`claude-code/0.x`, `cursor/x.y`, …) |
| `ip` | request socket |

## Failure modes worth thinking about

| Failure | Behavior |
|---|---|
| IdP unreachable during login | Surface clearly; do not fall back to local auth |
| IdP unreachable mid-session | Existing valid tokens keep working (we don't introspect every request) |
| User removed from IdP | Token still valid until TTL; revoke explicitly via admin command if needed |
| Group changed mid-session | Old group snapshot applies until re-login (documented; reduces every-request IdP load) |
| Token leaked | Revoke via admin command; user re-runs login |

Local accounts, password auth, and "admin bypass" are explicitly out of scope. The gateway has no users of its own.
