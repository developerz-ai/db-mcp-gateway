# 02 — Authentication

> **Remediation status (2026-06-30):** All findings in this report are closed.
> A1/A2/A4 → **fixed @ f7fb7fc** (#86) · A3 → **fixed @ 73d7d99** (#94) · A5/A6 → **fixed @ bf7b280** (#93).

Scope: `src/auth/{mod,config,errors,jwt,oidc,session}.rs`, `src/transport/{auth_middleware,auth_routes}.rs`, admin auth gate. Library behavior verified against vendored `jsonwebtoken 9.3.1`.

No remote auth bypass in the code as written. The two High items are fail-open / weak-default *design* issues that bite before the multi-replica Helm rollout; the rest are revocation/TLS/hardening gaps.

---

## A1 — Committed default session signing key used silently when `SESSION_SIGNING_KEY` unset — **High** · `fixed @ f7fb7fc`

**File:** `src/auth/config.rs:12`, `:69`, `:107-109`

```rust
const DEFAULT_DEV_SIGNING_KEY: &str = "dev-only-session-signing-key-change-me";
...
session_signing_key: DEFAULT_DEV_SIGNING_KEY.as_bytes().to_vec(),
...
if let Ok(value) = std::env::var("SESSION_SIGNING_KEY") {
    config.session_signing_key = value.into_bytes();
}
```

`from_env` never *requires* the key; absent env var ⇒ a constant committed to the public repo. The session bearer is an HS256 JWT signed with this key (`jwt.rs:41-45`). Knowing the key lets an attacker mint a valid-signature session JWT for any `sid`.

Mitigating: session authority is DB-backed (`SessionStore::lookup` reads the row, not JWT claims), so forging requires a live session UUID. But the `sid` is **not treated as a secret** — `auth_middleware.rs:38` logs it:
```rust
tracing::debug!(user_sub = %identity.user_sub, session = ?identity.session_id, "request authenticated");
```
Any leaked `sid` (debug log, etc.) + the public default key = forgeable bearer until the 8h TTL. No boot-time guard rejects the default key (deferred to issue #16, not yet enforced).

**Fix:** Refuse to boot when `session_signing_key` equals the default (or is < 32 bytes) and `mock_mode` is false. Treat `sid` as a credential — drop it from the debug line or log a hash. Severity depends partly on prod `tracing` level; the weak-default-key gap stands regardless.

---

## A2 — `bearer_auth` fails open when the auth facade is absent — **High** · `fixed @ f7fb7fc`

**File:** `src/transport/auth_middleware.rs:21-26`

```rust
let Some(auth) = state.auth.as_ref() else {
    // Test bootstrap: no auth wired. Production main never builds AppState this way.
    return next.run(req).await;
};
```

If `state.auth` is `None`, every gated route — including `/mcp` (`transport/mod.rs:51-57`) — runs with no authentication and no `Identity`. Protection rests entirely on the convention "production main never builds AppState this way." A wiring regression or future config path that leaves `auth` unset silently opens the entire query surface. (The admin gate still 401s because it separately requires an `Identity`; the DB-query path does not.)

**Fix:** Fail closed — make the gated router refuse to build without an auth facade, or have the middleware return 401 instead of passing through. Make the auth-less `AppState` a `#[cfg(test)]`-only constructor so it cannot exist in a release binary.

---

## A3 — Session revocation not honored across replicas; cache has no TTL — **Medium** · `fixed @ 73d7d99`

**File:** `src/auth/session.rs:189-214`, `:217-232`

```rust
if let Some(session) = self.cache.read().await.get(&id).cloned()
    && session.is_active(now)
{
    return Ok(session.identity());   // served from cache, no DB re-check
}
...
pub async fn revoke(&self, id: SessionId) -> Result<(), AuthError> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")...;
    self.cache.write().await.remove(&id);   // clears THIS process only
```

The module docstring claims "Every lookup goes through here so revocation is honored," but an active cache hit returns without touching the DB, and `revoke` only evicts the local process cache. In a multi-replica deployment (Helm on the roadmap), a revoke on replica A leaves replica B serving the revoked session until its 8h expiry — the exact denylist the spec relies on, bypassed by the cache. Cache entries also have no TTL/eviction (unbounded growth; revoked-elsewhere entries persist until expiry-on-lookup).

**Fix:** Add a short cache TTL forcing periodic DB re-validation, or cross-replica invalidation (Postgres `LISTEN/NOTIFY` on revoke). At minimum re-check `revoked_at` against the DB on a bounded interval.

**Needs verification:** confirm the production target runs >1 replica (Helm roadmap suggests yes). Single-replica today ⇒ lower impact.

---

## A4 — No TLS enforcement on OIDC issuer / discovered endpoints — **Medium/Low** · `fixed @ f7fb7fc`

**File:** `src/auth/oidc.rs:209-233`, `:129-155`

```rust
let url = format!("{}/.well-known/openid-configuration", self.config.issuer.trim_end_matches('/'));
```

Neither the configured `issuer` nor the discovered `token_endpoint`/`jwks_uri`/`authorization_endpoint` are required to be `https`. An `http://` issuer (or discovery doc returning `http` endpoints) sends the authorization code **and the `client_secret`** in plaintext (`:139-145`). The redirect-policy SSRF guard (`:94-97`) is good but orthogonal.

**Fix:** Reject a non-`https` issuer and non-`https` discovered endpoints at boot/discovery; permit `http` only for `localhost`/mock mode.

---

## A5 — ID-token algorithm taken from token header (RS/HS confusion shape) — **Low (not exploitable in 9.3.1)** · `fixed @ bf7b280`

**File:** `src/auth/oidc.rs:166`

```rust
let mut validation = Validation::new(header.alg);
```

The classic confusion anti-pattern. Verified **not exploitable in this build**: `decoding_key` filters JWKS to `kty == "RSA"` (`oidc.rs:262`), so every `DecodingKey` is `AlgorithmFamily::Rsa`; `jsonwebtoken 9.3.1` rejects a family mismatch (`decoding.rs:216-221`) before signature work, so an `alg: HS256` token is rejected before reaching the `unreachable!()` panic. Attacker is confined to RSA variants, all requiring the IdP private key.

**Fix (defense-in-depth):** Pin `Validation::new(Algorithm::RS256)` (or the IdP's actual algs) so safety no longer depends on the JWKS filter plus a library internal — a future change to either reopens the hole.

---

## A6 — `email` optional, `email_verified` never checked — **Low** · `fixed @ bf7b280`

**File:** `src/auth/oidc.rs:187-191`

```rust
let email = claims.get("email").and_then(|v| v.as_str()).unwrap_or_default().to_string();
```

`email_verified` is never consulted. The email is persisted as the admin/audit identity (`permissions_users` upsert, `admin/middleware.rs:113`). Authz is group-based (low impact), but an IdP emitting an unverified/user-settable email feeds a spoofable value into the audit identity.

**Fix:** Require `email_verified == true` when an email is used as identity.

---

## Also noted

- **JWKS refetch on unknown `kid` discards freshly-fetched keys; no negative caching** (`oidc.rs:257-282`): the early `ok_or(AuthError::IdToken)?` returns before the cache write, so every `kid` miss triggers a fresh IdP fetch. Low (reachable only post-valid-`state` in the callback) — IdP fetch-amplification/robustness. Fix: write the cache before the `kid` lookup.

---

## Controls verified correct (no action)

- **Session JWT:** signature verified, `exp` validated, `iss` pinned to `"db-mcp-gateway"`, wrong-key rejected; HMAC compare constant-time via ring. `validate_aud=false` is correct (no `aud` issued). (`jwt.rs:49-61`)
- **ID token:** `iss` + `aud` + `exp` + signature enforced, then `nonce` matched per-flow (`oidc.rs:157-203`). JWKS filtered to `kty=="RSA"`, `use=="sig"`.
- **Token-exchange client** built with `redirect::Policy::none()` as a deliberate SSRF guard, with explicit refusal to fall back to a redirect-following default (`oidc.rs:94-97`).
- **Discovery `issuer`** compared against configured issuer, blocking a tampered discovery doc from repointing the RP (`oidc.rs:227-229`).
- **CSRF `state`** single-use (`PendingFlows::take`) with 5-min TTL + GC; `nonce` bound to `state` (`app_state.rs:101-125`, `auth_routes.rs:25-58`).
- **Session token** returned in JSON body, not a cookie — no ambient-credential CSRF surface (HttpOnly/Secure/SameSite N/A).
- **`state`/`nonce`/`SessionId`** use UUIDv4 CSPRNG (122-bit) entropy.
- **Confidential client** holds `client_secret`, so absence of PKCE is acceptable.
- **Secret/PII redaction:** `client_secret`, `session_signing_key`, `PgPool`, `user_email` redacted in hand-rolled `Debug`; `AuthError::Display` carries no token/secret.
- **Admin gate fails closed:** missing `Identity` → 401, missing admin group → 403; non-admin not upserted; admin surface unmounted unless `admin.enabled` + deps present.
- **`unix_now()`** returns 0 on pre-epoch clock → JWT fails closed, no panic (`jwt.rs:63-70`).
