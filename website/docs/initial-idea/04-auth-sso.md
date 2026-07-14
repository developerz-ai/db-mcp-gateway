# 04 — Auth & SSO

## Identity flow

```text
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

## MCP OAuth bridge

Spec-compliant MCP clients (Claude Code, Cursor) don't speak the bespoke flow above; on a `401` they follow the MCP Authorization spec. The gateway fronts the full OAuth 2.1 surface and drives the same OIDC login underneath (see `src/transport/oauth.rs`).

### Flow

```text
1. 401 → WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource"
2. GET /.well-known/oauth-protected-resource         → names this gateway as its own AS
   GET /.well-known/oauth-authorization-server       → AS metadata (RFC 8414)
   GET /.well-known/openid-configuration             → alias for the AS metadata
3. POST /register                                    → Dynamic Client Registration (RFC 7591)
                                                       returns client_id
4. GET /authorize?response_type=code                 → PKCE + state validation;
                                                       browser redirected to IdP;
                                                       IdP redirects to /auth/callback;
                                                       302 to client redirect_uri with ?code=…&state=…
5. POST /token  (grant_type=authorization_code)      → PKCE verifier checked; returns
                                                       access_token + refresh_token
6. POST /token  (grant_type=refresh_token)           → rotates; returns new pair
7. POST /revoke                                      → RFC 7009; invalidate a refresh
                                                       or access token (always 200)
```

The access token is the same HS256 gateway session JWT the bespoke flow issues, so the bearer middleware, revocation, and audit are all unchanged.

### Discovery endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /.well-known/oauth-protected-resource[/<mcp-path>]` | none | RFC 9728 resource metadata; names this gateway as its AS |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414 AS metadata (`authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported: ["S256"]`) |
| `GET /.well-known/openid-configuration` | none | Alias for the AS metadata above |

The base URL for all metadata is derived from the configured `OIDC_REDIRECT_URL` origin. If that value is unparseable the gateway fails closed with `500` rather than trusting the `Host` header.

### HTTPS requirement for production

The gateway's OIDC configuration must use **HTTPS in production**. The `external_url` (or `OIDC_REDIRECT_URL` in env-based config) **must be an HTTPS URL** for any production deployment:

- OAuth flows carry authorization codes and tokens in redirects and form posts; an unencrypted channel (HTTP) exposes them to network sniffing.
- IdPs typically reject non-HTTPS `redirect_uri` values as a security requirement.
- Clients (MCP editors, IdP servers) may log or cache these URLs; plain HTTP leaks credentials to anyone on the network path.

**Dev exception:** `http://localhost` and `http://127.0.0.1` are permitted for local development (the loopback guarantee). This mirrors OAuth 2.1 / RFC 8252 treatment of localhost redirects.

Operators should enforce this at deployment time (reverse-proxy validation, network policy, or gateway-level checks). A misconfigured non-HTTPS `external_url` in production is a credential-transport risk.

### Dynamic Client Registration — `POST /register`

Accepts JSON. Required field: `redirect_uris` (non-empty array). Optional: `client_name`.

Each redirect URI must be **HTTPS** (any host) or **HTTP with a loopback host** (`localhost`, `127.0.0.0/8`, `::1`). Anything else — including `http://` to a non-loopback host — is rejected with `invalid_redirect_uri`.

Returns `{ "client_id": "mcp-<uuid>", "redirect_uris": […], "token_endpoint_auth_method": "none" }`.

The registry is persisted in the state DB (`oauth_clients`, migration 0008) and bounded (24h TTL + hard cap) because this endpoint is unauthenticated. Registrations **survive restarts and redeploys** and are shared across replicas, so a client that caches its `client_id` (most do) keeps working across a gateway rollout instead of hitting `invalid_client`. (Auth codes, pending logins, and refresh tokens remain in-process — see [State & persistence](#state--persistence) below.)

### Authorization endpoint — `GET /authorize`

All parameters below are **required**. Missing or invalid → `invalid_request` (400).

| Parameter | Requirement |
|---|---|
| `response_type` | must be `code` |
| `client_id` | must match a `POST /register` client; unknown → `invalid_client` |
| `redirect_uri` | must **exactly match** a URI the client registered (see Redirect-URI matching below) |
| `code_challenge` | non-empty base64url-encoded SHA-256 hash of the verifier (PKCE S256) |
| `code_challenge_method` | must be `S256` — `plain` is never accepted |
| `state` | non-empty string; echoed back verbatim on the `302` as the client's CSRF token |
| `resource` | optional; forwarded as-is to the token response (RFC 8707) |

On success the browser is redirected to the IdP login. After the user authenticates, the gateway 302s back to the registered `redirect_uri` with `?code=<one-time>&state=<echoed>`. On IdP failure the 302 carries `?error=access_denied&state=<echoed>` so the client's loopback handler completes rather than hanging.

#### Redirect-URI matching (OAuth 2.1 + RFC 8252 §7.3)

For **HTTPS** URIs: the requested `redirect_uri` must be a byte-for-byte match of a registered URI. No prefix matching, no wildcard.

For **loopback HTTP** URIs: scheme, host, and path must match exactly; the **port may differ** (a native client binds an ephemeral port at request time, RFC 8252 §7.3). Port-flexibility does not extend across distinct loopback hostnames — `localhost` and `127.0.0.1` are not interchangeable.

### Token endpoint — `POST /token`

Accepts `application/x-www-form-urlencoded`.

**`grant_type=authorization_code`**

| Field | Requirement |
|---|---|
| `code` | the one-time code from the `302` |
| `code_verifier` | the raw PKCE verifier; gateway checks `BASE64URL(SHA256(verifier)) == stored_challenge` |
| `client_id` | optional but recommended; if sent, must match the registrant |
| `redirect_uri` | required; must exactly match the `redirect_uri` used at `/authorize` (OAuth 2.1 §4.1.3). Missing → `invalid_request`; mismatch → `invalid_grant` |

The code is consumed on first use (replay → `invalid_grant`).

**`grant_type=refresh_token`**

| Field | Requirement |
|---|---|
| `refresh_token` | the token from a previous `/token` response |

Refresh tokens rotate: presenting one consumes it and a new pair is returned. A replayed (already-rotated) token → `invalid_grant`.

Rotation does **not** extend the token's lifetime. A chain has an **absolute TTL** (24 hours) measured from the *first* token's mint; the original `issued_at` is carried verbatim through every rotation, so a continuously refreshed chain still expires on schedule and forces a fresh `/authorize` login. The cap is deliberately short because a refresh re-mints the session from the IdP identity — **groups included** — that was frozen at the original login; until the chain dies, a group change at the IdP (off-boarding, role downgrade) can't reach the gateway. One day keeps that staleness within a normal deprovisioning window while still spanning a working day of silent renewals. (Re-validating the identity against the IdP on each refresh would lift the cap but needs an IdP refresh token / `offline_access` the bridge doesn't yet hold — deferred.) Refresh tokens (and the short-lived authorization codes) are stored **hashed** (SHA-256) — the in-memory store holds only digests, so a memory dump or a stray log of flow state can't be replayed as a live token.

**Token response** (both grant types, `Cache-Control: no-store`):

```json
{
  "access_token":  "<gateway session JWT>",
  "token_type":    "Bearer",
  "expires_in":    28800,
  "refresh_token": "<opaque rotating token>",
  "scope":         "mcp"
}
```

The access token is an HS256 gateway session JWT (same as the bespoke flow). Authorization is by IdP group membership against the permissions YAML, not by OAuth scope — `mcp` is the single umbrella scope advertised.

### Revocation endpoint — `POST /revoke`

RFC 7009 OAuth 2.0 Token Revocation. Accepts `application/x-www-form-urlencoded`. Unauthenticated like `/token` — the presented token is itself the credential, so a caller can only revoke a token it already holds.

| Field | Requirement |
|---|---|
| `token` | the token to revoke — a refresh token or a session access token |
| `token_type_hint` | optional (`access_token` \| `refresh_token`); accepted but advisory — the gateway probes both stores regardless |

The gateway invalidates whichever the token matches:

- **Refresh token** → dropped from the rotation store. Since a rotated chain keeps exactly one live token, this ends the whole chain.
- **Access token** (session JWT) → its backing session row is revoked, so the bearer stops working on the next request (RFC 7009 §2.1 — kill the access token too, not just the refresh token).

Per RFC 7009 §2.2 the response is **`200` for any well-formed request** — an unknown, expired, forged, or already-revoked token included — so the endpoint can't be used to probe token validity. A missing `token` is the lone malformed case → `invalid_request` (400). Responses carry `Cache-Control: no-store`.

### Proxy / WAF requirements

If the gateway is fronted by a reverse proxy or WAF, the following paths must reach it **unauthenticated**:

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
GET  /authorize
POST /token
POST /revoke
POST /register
```

Do **not** add a second OAuth/SSO layer in front of `/mcp`. The gateway is the authorization server and brokers the IdP login internally.

The MCP OAuth bridge's short-lived flow state — pending IdP round-trips, one-time authorization codes, and rotating refresh tokens — is **in-process**, not in the state DB. A restart drops an in-flight login, and under HA the login endpoints (`/authorize`, `/auth/callback`, `/token`) must run **single-replica** or behind **sticky routing** so every step of one login hits the same replica. **Dynamic client registrations, by contrast, are persisted in the state DB** (`oauth_clients`) — they survive restarts/redeploys and are shared across replicas, so `/register` needs no sticky routing and a cached `client_id` no longer breaks with `invalid_client` after a rollout. See [02-architecture §HA](02-architecture.md#ha). Already-authenticated `/mcp` traffic is unaffected — those sessions live in the state DB.

## Session tokens

- Signed JWT (HS256), gateway-issued — not the IdP's ID token directly; we re-sign so we can revoke.
- Short TTL (default 8 hours; `expires_in` in the token response reflects the actual value).
- **Bespoke flow:** refresh by re-running SSO. No long-lived refresh token on the developer's machine.
- **OAuth bridge flow:** a rotating opaque refresh token is returned at `/token`. Presenting it issues a new access+refresh pair and consumes the old refresh token (replay → `invalid_grant`). Rotation never extends the chain: an absolute 24-hour TTL runs from the first token's mint, after which the client must re-authenticate via `/authorize`. The cap is short on purpose — refresh re-uses the groups frozen at login, so it doubles as the staleness bound for a revoked group (see the `/token` section above). Refresh tokens are stored hashed, in-memory, and lost on restart.
- Revocation: server-side, in the state DB. Logout (`POST /auth/logout`) revokes the session row **and** purges every refresh-token chain for that identity — otherwise a logged-out client could silently mint a fresh session via the refresh grant. Clients may also revoke a single token out-of-band via `POST /revoke` (RFC 7009). Every `/mcp` request resolves the session through a small in-memory cache fronting the state DB: a cache hit newer than `SESSION_CACHE_TTL_SECONDS` (default 30s) is served without a DB read; an older hit re-reads and re-validates against `revoked_at`. The replica that processes the revoke evicts its own entry immediately, so the next call there is rejected at once.
  - **Multi-replica (HA) caveat.** A revoke only evicts the cache on the replica that handled it. On other replicas the session stays honored until their cached entry ages past `SESSION_CACHE_TTL_SECONDS` (≤30s by default), at which point the next lookup re-reads the DB and sees the revoke. Lower the TTL to tighten this cross-replica window (`0` = re-validate every request) at the cost of more state-DB reads; raise it to spend fewer reads for a wider window. The cache is also size-bounded, so a flood of distinct sessions can't grow it without limit.

## Group resolution

Group membership comes from one of:

- OIDC `groups` claim (preferred — set IdP to include it)
- SCIM sync to the state DB (for IdPs that don't expose groups in tokens)
- Directory API lookup at token-issue time (Google Workspace fallback)

Groups are **snapshotted at login** into the session row. Cached for the session TTL; a
gateway-side DB re-read (e.g. bypassing the 30 s session cache) still returns the same
frozen snapshot — the session row is the source of truth, not the IdP.

Group changes in the IdP take effect at the next login (session expiry or explicit revocation).

### Admin group propagation

The admin group check (`admin.group`) runs on every `/admin/v1/*` request using the groups
frozen at login time.

| Event | When it takes effect |
|---|---|
| Grant admin group in IdP | Next login (existing sessions are unaffected) |
| Revoke admin group in IdP | Next login **or** explicit session revocation (`POST /revoke`) |
| Explicit session revoke by operator | Immediately on the revoking replica; within `SESSION_CACHE_TTL_SECONDS` (≤ 30 s) on other replicas |

**Exposure window:** a user removed from the admin group in the IdP can still call
`/admin/*` for up to `auth.oidc.session_ttl_hours` (default 8 h) unless their session is
explicitly revoked.

**Mitigation — `admin.session_max_age_secs`:** set this in the admin config block to cap
the exposure window for admin routes specifically. Sessions older than this limit are
rejected with `403 session_too_old`, forcing re-login. The next login picks up the current
IdP group state. Example: `session_max_age_secs: 3600` means a removed admin loses access
within 1 h, regardless of the global `session_ttl_hours`.

Recommended values by risk tolerance:

| Risk tolerance | `session_max_age_secs` |
|---|---|
| Default / low-risk | absent (rely on session TTL + manual revoke) |
| Standard | `3600` (1 h) |
| High-security | `900` (15 min) |

## What lands in the audit log per request

| Field | Source |
|---|---|
| `user_email` | OIDC `email` claim — required, and only trusted when the token also asserts `email_verified == true` (see Failure modes) |
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
| Session revoked under HA | Effective immediately on the revoking replica (cache evicted); on other replicas honored until their session-cache entry ages out (≤ `SESSION_CACHE_TTL_SECONDS`, default 30s), then re-validated against the DB |
| ID token has no `email`, or `email_verified` is not `true` | Login rejected (`oidc_email_unverified`). Email is the audit/admin identity, so an absent or unverified — often user-settable — address is never minted into a session |
| ID token is expired (`exp`) or not yet valid (`nbf`) | Login rejected (`oidc_id_token_invalid`). Both claims are enforced; a future-dated `nbf` token is refused before any claim is trusted |

Local accounts, password auth, and "admin bypass" are explicitly out of scope. The gateway has no users of its own.
