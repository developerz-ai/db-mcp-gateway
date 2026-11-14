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

Accepts JSON. Required field: `redirect_uris` (1–8 entries, each at most 2048 bytes). Optional: `client_name` — trimmed; blank counts as absent; more than 100 characters, or any control or bidi-formatting character (U+061C, U+200E/F, U+202A–202E, U+2066–2069), → `invalid_client_metadata`. It is stored with the registration (`oauth_clients.client_name`, migration 0019, nullable so a rolled-back 2.1.0 still inserts) and echoed trimmed in the response; it is self-asserted and never verified. A body that is not valid JSON gets `invalid_client_metadata` (RFC 7591 §3.2.2).

Each redirect URI must be **HTTPS** (any host) or **HTTP with a loopback host** (`localhost`, `127.0.0.0/8`, `::1`). Anything else — including `http://` to a non-loopback host, or more/longer URIs than the bounds above — is rejected with `invalid_redirect_uri`. A redirect URI carrying a fragment — even an empty `#` — is rejected the same way (RFC 6749 §3.1.2), both here and on the loopback-adopt path of `/authorize`.

Returns `{ "client_id": "mcp-<uuid>", "redirect_uris": […], "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"] }`.

`/token` and `/revoke` answer an undecodable form (wrong content type, unreadable body) with the RFC 6749 §5.2 shape `{"error": "invalid_request", "error_description": …}`, never plain text.

The registry is persisted in the state DB (`oauth_clients`, migration 0008) and bounded (TTL + hard cap) because this endpoint is unauthenticated. Registrations **survive restarts and redeploys** and are shared across replicas, so a client that caches its `client_id` (most do) keeps working across a gateway rollout instead of hitting `invalid_client`. (Auth codes and pending logins remain in-process — see [State & persistence](#state--persistence) below.)

A new registration lives **1 hour** until it is first used. The first successful `/authorize` promotes it to **90 days, sliding**: every later `/authorize` renews it, so a client that keeps signing in keeps its registration and only an abandoned one ages out. (A client adopted by `/authorize` counts as used at once.) The long window exists because real clients cache the `client_id` for as long as they stay signed in, then replay it days later. The hard cap is 10 000 rows. At the cap a registration first evicts the oldest expired or never-used row, in the same statement as the insert. A client that has authorized is never evicted, so an unauthenticated `/register` flood only displaces its own junk. Only a table full of used clients refuses with `503 temporarily_unavailable`. Expired rows are deleted by the background GC task, not on the request path.

Pending IdP logins (`/auth/login`, bridged `/authorize`) are capped at 10 000 in-process. At the cap the **oldest** pending login is evicted, so a flood can never block a fresh login. Every pending login has the same 15-minute TTL, so the oldest one is also the first to expire.

#### Unknown `client_id`: adopt on loopback, reject off-box

A cached `client_id` can still fail to resolve — an install predating migration 0008, a state DB restored from backup, a registration that genuinely aged out. The spec's answer is that the client should discard the dead id and re-register at the advertised `registration_endpoint`, but in practice several MCP clients don't: the browser lands on a bare `invalid_client` JSON page and the user is stuck, because nothing in the redirect leg tells the client to re-register.

So `/authorize` self-heals, in exactly one direction:

| Requested `redirect_uri` | Unknown `client_id` |
|---|---|
| HTTP loopback (`localhost`, `127.0.0.0/8`, `::1`) | **Adopted** — the id is registered against that URI and the flow proceeds |
| Anything else (including HTTPS) | `invalid_client` — hard reject |

Adoption is safe only for loopback because the authorization code can then only be delivered to the user's own machine — there is no third party to leak it to (RFC 8252 §7.3, the same carve-out that lets a loopback redirect vary its port). An HTTPS redirect is precisely the case the allowlist exists to stop: waving an unknown client through would let a code be sent to a host nobody vouched for. Adopted ids are length- and charset-bounded (≤128 printable-ASCII characters), the adopted redirect URI obeys the same 2048-byte bound as `/register`, and the id is recorded only after every other `/authorize` parameter (PKCE, `state`) validates — a request that fails validation leaves nothing in the registry. Adoption is still subject to the registry's hard cap, so `/authorize` can't be used to stuff the table.

### Authorization endpoint — `GET /authorize`

All parameters below are **required**. Missing or invalid → `invalid_request` (400).

| Parameter | Requirement |
|---|---|
| `response_type` | must be `code` |
| `client_id` | must match a `POST /register` client; unknown → `invalid_client` |
| `redirect_uri` | must **exactly match** a URI the client registered (see Redirect-URI matching below) |
| `code_challenge` | base64url-no-pad SHA-256 hash of the verifier (PKCE S256): exactly 43 characters of `A-Z a-z 0-9 - _` |
| `code_challenge_method` | must be `S256` — `plain` is never accepted |
| `state` | non-empty string of at most 512 bytes; echoed back verbatim on the `302` as the client's CSRF token |
| `resource` | optional, at most 512 bytes; forwarded as-is to the token response (RFC 8707) |

`/authorize` is unauthenticated and parks these values in the pending-flow store (≤10,000 flows, 15-minute TTL) across the IdP leg, so each one is bounded; a value outside its bound is `400 invalid_request`.

On success the browser is redirected to the IdP login. After the user authenticates, a **loopback** redirect gets `?code=<one-time>&state=<echoed>` at once; any other redirect goes through the consent step below first. On IdP failure the gateway redirects back with `?error=<code>&state=<echoed>` so the client's loopback handler completes rather than hanging.

#### Consent for non-loopback redirects (confused deputy)

The IdP only ever sees the gateway's own static client, so the user's IdP consent (often silent, with a live IdP session) says nothing about which dynamically registered client receives the code. Without a second check, anyone could `POST /register` an `https://attacker.example/cb` redirect, send a victim the matching `/authorize` link with the attacker's own PKCE challenge, and redeem the code that lands on their host. The MCP authorization spec (security best practices, "Confused Deputy") requires per-client user consent for exactly this case.

After `/auth/callback` verifies the login, a bridge flow whose redirect is **not** HTTP loopback mints no code. The gateway instead renders a consent page showing who is signed in, the **redirect host the code will be sent to** (prominently, punycode for IDNs), the full redirect URI, the client id — labelled self-registered, since nothing about a DCR client is verified — and, as smaller secondary text after them, the `client_name` the client registered, labelled unverified ("(no name)" for an adopted or unnamed client). The name is attacker-chosen (anything can call itself "Claude"), so the page tells the user to judge by the redirect host, never the name. Every value is HTML-escaped. Consent sits after the callback rather than before the IdP redirect: the gateway can show the signed-in identity, and the decision is bound to a flow that only exists once that user has logged in, so it cannot be pre-clicked or pre-filled.

- **Approve / Deny** submit `POST /authorize/consent` (form: `consent_id`, `csrf`, `decision=approve|deny`; any other field → `400`). Both tokens are 128-bit random values; the pending consent is taken (single-use) before the CSRF token is compared in constant time, so a wrong token burns the flow. Pending consents live in memory for 10 minutes, capped at 1,000 (at the cap the soonest-expiring one is dropped).
- **Approve** mints the one-time code and `303`s to the redirect with `?code=…&state=…`. **Deny** `303`s with `?error=access_denied&state=…` (RFC 6749 §4.1.2.1).
- An unknown, expired, reused or CSRF-mismatched submission gets a `400` page and **never** a redirect.
- The page is served with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' <redirect origin>` (the redirect origin is listed because browsers apply `form-action` to the post-submit redirect), `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`. Every interpolated value is HTML-escaped.
- Consent is never remembered: each non-loopback authorization asks again.

Loopback redirects (`localhost`, `127.0.0.0/8`, `::1`) skip consent: the code can only reach the user's own machine (RFC 8252 §7.3), the same reasoning as the adopt rule above.

**`/auth/callback` without a code.** The IdP may send the browser back with `error` (RFC 6749 §4.1.2.1 — the user declined, or the IdP failed) and no `code`. The gateway takes the pending flow by `state` either way. For an OAuth-bridge login it 302s to the client's redirect with `error=temporarily_unavailable` or `server_error` when the IdP said so, else `access_denied`; the IdP's `error_description` is logged server-side only. For the bespoke `/auth/login` flow it shows a `400` "sign-in not completed" page. A missing or unknown `state` shows the "login session expired" page, as before.

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

Refresh tokens rotate: presenting one consumes it and a new pair is returned. A replayed (already-rotated) token → `invalid_grant`, and it **revokes the whole chain** — its live refresh token and paired access session — because the server can't tell the thief from the legitimate client (OAuth 2.1 §4.3.1, RFC 9700 §4.14.2). Rotated-out token hashes are kept as tombstones (`oauth_refresh_rotated`, migration 0017, SHA-256 digests only) until the chain's absolute expiry; each chain carries a stable `chain_id`, and the reuse is logged as a warning with that id, never the token. A replay within 10 s of the rotation (`REUSE_GRACE`) is only `invalid_grant` and leaves the chain alive, so a client firing parallel refreshes from several connections isn't signed out; a replay after that revokes the chain. (The in-memory test backend doesn't track chains.) Each refresh token is paired with the access session minted alongside it (`oauth_refresh_tokens.session_id`, migration 0012); rotation revokes that previous session, so after a refresh the old access token is rejected. Consuming the old token, revoking its session, and storing the new session and token are one state-DB transaction: a failure part-way commits nothing, the response is a 5xx, and the presented refresh token stays redeemable — a transient error is never a sign-out.

Rotation does **not** extend the token's lifetime. A chain has an **absolute TTL** measured from the *first* token's mint; the original `issued_at` is carried verbatim through every rotation, so a continuously refreshed chain still expires on schedule and forces a fresh `/authorize` login. The TTL is set by `REFRESH_TTL_DAYS` (**default 1 day**); an operator who wants a longer "stay signed in" window — up to 366 days (a year) — raises it there. The default is deliberately short because a refresh re-mints the session from the IdP identity — **groups included** — that was frozen at the original login; until the chain dies, a group change at the IdP (off-boarding, role downgrade) can't reach the gateway. So the TTL is directly a group-staleness window: one day keeps it within a normal deprovisioning cadence while still spanning a working day of silent renewals, and a long setting (months, a year) trades that freshness for convenience — pair it with prompt out-of-band revocation (`POST /revoke`, logout) for off-boarding. (Re-validating the identity against the IdP on each refresh would decouple lifetime from staleness but needs an IdP refresh token / `offline_access` the bridge doesn't yet hold — deferred.) Refresh tokens (and the short-lived authorization codes) are stored **hashed** (SHA-256) — the store holds only digests, so neither a memory dump nor a dump of `oauth_refresh_tokens` can be replayed as a live token. Lowering `REFRESH_TTL_DAYS` applies to chains already minted under the old, longer window: redemption re-checks the chain's birth against the *currently configured* TTL rather than honoring the deadline stamped at mint time.

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

- **Refresh token** → dropped from the rotation store, and its paired access session revoked in the same transaction. Since a rotated chain keeps exactly one live token, this ends the whole chain and leaves no live bearer for it.
- **Access token** (session JWT) → its backing session row is revoked, so the bearer stops working on the next request (RFC 7009 §2.1 — kill the access token too, not just the refresh token).

Per RFC 7009 §2.2.1 the response is **`200` for any well-formed request** — an unknown, expired, forged, or already-revoked token included — so the endpoint can't be used to probe token validity. A missing `token` is the lone malformed case → `invalid_request` (400). When the state DB cannot record the revocation the response is **`503`** (`server_error`), never a `200` claiming a revoke that did not happen; the client should retry. Responses carry `Cache-Control: no-store`.

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

### State & persistence

The split is by lifetime. State that only has to outlive one browser round-trip — pending IdP logins and one-time authorization codes — is **in-process**. A restart drops a login that is mid-flight (the client just retries), and under HA the login endpoints (`/authorize`, `/auth/callback`, `/token`) must run **single-replica** or behind **sticky routing** so every step of one login hits the same replica.

State that is *meant* to outlive the process is in the state DB: **dynamic client registrations** (`oauth_clients`, migration 0008) and **refresh-token chains** (`oauth_refresh_tokens`, migration 0009). Both survive restarts and redeploys and are shared across replicas, so `/register` and `grant_type=refresh_token` need no sticky routing, a cached `client_id` doesn't break with `invalid_client` after a rollout, and a signed-in agent stays signed in across one. Persisting the chain is what makes `REFRESH_TTL_DAYS` mean what it says — in memory, the real ceiling was time-until-the-next-deploy. See [02-architecture §HA](02-architecture.md#ha). Already-authenticated `/mcp` traffic is unaffected either way — those sessions live in the state DB.

## Session tokens

- Signed JWT (HS256), gateway-issued — not the IdP's ID token directly; we re-sign so we can revoke.
- Short TTL (default 8 hours; `expires_in` in the token response reflects the actual value).
- **Bespoke flow:** refresh by re-running SSO. No long-lived refresh token on the developer's machine.
- **OAuth bridge flow:** a rotating opaque refresh token is returned at `/token`. Presenting it issues a new access+refresh pair and consumes the old refresh token (replay → `invalid_grant`). Rotation never extends the chain: an absolute TTL (`REFRESH_TTL_DAYS`, default 1 day, raise up to 90 for a longer "stay signed in" window) runs from the first token's mint, after which the client must re-authenticate via `/authorize`. The TTL doubles as the staleness bound for a revoked group — refresh re-uses the groups frozen at login — so a longer window trades group freshness for convenience (see the `/token` section above). Refresh tokens are stored hashed (SHA-256) in the state DB, so a chain survives a restart or redeploy — the configured window is the real one.
- Revocation: server-side, in the state DB. Logout (`POST /auth/logout`) signs the identity out **everywhere**: it revokes every live session of that `sub` (every device) **and** deletes every refresh-token chain for it, in one transaction — otherwise a logged-out client could silently mint a fresh session via the refresh grant. If the state DB cannot record that, logout answers 5xx instead of a `204` that would leave bearers live. Clients may also revoke a single token out-of-band via `POST /revoke` (RFC 7009). Every `/mcp` request resolves the session through a small in-memory cache fronting the state DB: a cache hit newer than `SESSION_CACHE_TTL_SECONDS` (default 30s) is served without a DB read; an older hit re-reads and re-validates against `revoked_at`. Concurrent requests that miss the cache for the same session share one DB read. The replica that processes the revoke leaves a **tombstone** for the session (kept at least `max(SESSION_CACHE_TTL_SECONDS, 60s)`): the next call there is rejected without a DB read, and a lookup that read the row just before the revoke committed cannot re-cache it. A session found revoked, expired or missing is tombstoned the same way.
- **Credential vs. gateway failure.** A missing, malformed, expired or revoked bearer is a `401` with `WWW-Authenticate` — the client should re-run login. A state-DB or other gateway-side failure while checking the bearer is a `5xx` with no `WWW-Authenticate`: re-login would not fix it, so a state-DB blip never signs a working user out.
- **Garbage collection.** A background task deletes session rows that expired more than one hour ago (`sessions_expires_at_idx`). Revoked rows are kept until they expire — until then they are the denylist entry for a JWT that still verifies — so the table holds at most the live sessions plus one hour of expired ones. The session JWT allows 30 s of clock skew on `exp`, well inside that hour.
  - **Multi-replica (HA) caveat.** A revoke only evicts the cache on the replica that handled it. On other replicas the session stays honored until their cached entry ages past `SESSION_CACHE_TTL_SECONDS` (≤30s by default), at which point the next lookup re-reads the DB and sees the revoke. Lower the TTL to tighten this cross-replica window (`0` = re-validate every request) at the cost of more state-DB reads; raise it to spend fewer reads for a wider window. The cache is also size-bounded, so a flood of distinct sessions can't grow it without limit.

## Service tokens (headless clients)

Everything above assumes a human with a browser. A headless client — CI job, agent runner, another service — has neither, so it authenticates with a **service token**: a static bearer declared in `service_accounts:` in the YAML config, carrying a name (audit identity `service:<name>`), exactly one permissions group, and a `${ENV:…}` / `${FILE:…}` secret reference (the loader also accepts inline literals for dev/test parity with `Database.password`; committed config is kept credential-free by the `secret-scan` CI job (ADVISORY until made a required check — see spec 14), not by boot enforcement).

`bearer_auth` tries the boot-resolved service-token store first (constant-time compare), then the session-JWT path unchanged. Service identities never touch the sessions table — no expiry, no in-band revocation — and never hold the admin group (boot-enforced), so the `/admin/*` middleware is untouched. Mint/rotate/revoke is GitOps: `bin/mint-service-token`, a secret-store update, a PR, a rollout.

Full design and operator runbook: [14 — Service tokens](14-service-tokens.md).

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
| `user_id` | OIDC `sub` — never starting with the reserved `service:` prefix (see Failure modes) |
| `groups` | snapshot at token issue time |
| `session_id` | gateway-issued, links to login event |
| `agent_client` | self-reported by the MCP client (`claude-code/0.x`, `cursor/x.y`, …): `User-Agent`, else `x-mcp-client`, cut to 128 bytes on a character boundary |
| `ip` | request socket |

## Failure modes worth thinking about

| Failure | Behavior |
|---|---|
| IdP unreachable during login | Surface clearly; do not fall back to local auth |
| IdP unreachable mid-session | Existing valid tokens keep working (we don't introspect every request) |
| State DB unreachable | Bearer checks that miss the session cache, logout, `/token` and `/revoke` answer 5xx (no `WWW-Authenticate`); clients retry rather than re-login |
| IdP rotates its signing keys | An ID token naming an unknown `kid` refetches the JWKS — at most once per 60 s, and concurrent misses share one fetch — so a rotation is picked up without a restart and a bogus `kid` can't turn into a flood of IdP requests. The JWKS is otherwise cached for an hour and the discovery document for an hour. RSA keys verify `RS256`/`PS256`, P-256 keys `ES256`; a JWK that declares its `alg` verifies only that one, and `none`/HMAC are never accepted |
| Configured `OIDC_ISSUER` differs from the IdP's only by a trailing slash | Accepted: discovery compares the normalized form, and the ID token's `iss` is checked against the discovery document's `issuer` exactly (OIDC Core 3.1.3.7) |
| User removed from IdP | Token still valid until TTL; revoke explicitly via admin command if needed |
| Group changed mid-session | Old group snapshot applies until re-login (documented; reduces every-request IdP load) |
| Token leaked | Revoke via admin command; user re-runs login |
| Session revoked under HA | Effective immediately on the revoking replica (cache evicted); on other replicas honored until their session-cache entry ages out (≤ `SESSION_CACHE_TTL_SECONDS`, default 30s), then re-validated against the DB |
| ID token `sub` starts with `service:` (any case) | Login rejected (`oidc_id_token_invalid`, server-side warn names the reason, not the subject). The prefix is reserved for YAML service identities (spec 14); a pre-existing session or refresh chain with such a subject is refused too |
| ID token has no `email`, or `email_verified` is not `true` | Login rejected (`oidc_email_unverified`). Email is the audit/admin identity, so an absent or unverified — often user-settable — address is never minted into a session |
| ID token is expired (`exp`) or not yet valid (`nbf`) | Login rejected (`oidc_id_token_invalid`). Both claims are enforced; a future-dated `nbf` token is refused before any claim is trusted |

Local accounts, password auth, and "admin bypass" are explicitly out of scope. The gateway has no users of its own.
