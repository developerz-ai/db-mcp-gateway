# 08 — Auth and sessions

> Part of [`overview.md`](overview.md). Depends on: 02, 03 (`0012`, `0015`). **`(security review required)`** — `src/auth/`. Reviewers look for: sessions that outlive revocation, tokens in logs, fail-open on state-DB errors.

The human + Claude Code path (SSO, OAuth bridge, refresh). Goal: a state-DB blip is not a logout, a logout is a logout.

## Files to change

- `src/transport/auth_middleware.rs:45-50,80-109` — every lookup error → 401.
- `src/auth/session.rs:169-172,201,212-251,274` — single-id revoke, swallowed JSON errors, gauge, expired → `RevokedSession`.
- `src/auth/session_cache.rs:90-144` — stampede, O(n) eviction under the write lock, full `Session` clone.
- `src/transport/oauth/revoke.rs:55-78`, `src/transport/auth_routes.rs:135-141`, `src/transport/oauth_state.rs:550-565` — failures reported as success.
- `src/transport/oauth/token.rs:136,172-223` — rotation not atomic; old session never revoked.
- `src/auth/config.rs:31,44,46,132-163` — `mock_mode`, unvalidated TTLs, plain-`String` secrets.
- `src/auth/jwt.rs:39,49-61` — `Validation`/keys rebuilt per request.
- `src/auth/oidc/mod.rs:146,154,205-296` — JWKS refetch on unknown kid, no single-flight, discovery cached forever, issuer slash asymmetry.
- `src/startup.rs` — no session GC.

## Steps

1. **Status mapping.** `bearer_auth` returns 401 + `WWW-Authenticate` only for `MissingBearer`/`InvalidSession`/`RevokedSession`/`Jwt`; everything else via `AuthError::into_response` (5xx, no challenge). Distinguish `ExpiredSession` from `RevokedSession`.
2. **Revoke-all.** `SessionStore::revoke_all_for_sub`; logout calls it; refresh rotation revokes the previous session (via `oauth_refresh_tokens.session_id`, 0012); `/revoke` on a refresh token revokes the paired session. Add `POST /admin/v1/users/{sub}/revoke-sessions` — SSO-gated, audited to `permissions_audit` in the same transaction — the "operator revoke" spec 04 promises.
3. **Honest failures.** `purge_for_sub` returns `Result`; logout → 5xx on failure; `/revoke` → 503 on backend error, 200 for unknown tokens (RFC 7009 §2.2.1).
4. **Atomic rotation.** Delete-old + insert-new + session insert in one state-DB transaction. SQL moves to `src/state/` (02).
5. **Cache.** Store `Arc<Identity>` + `expires_at`; tombstone on revoke (kept ≥ TTL, `insert` refuses to overwrite) — closes the revoke/lookup race and gives a negative entry; single-flight per session id; periodic sweep from the GC task, not at-cap `retain`.
6. **Session GC.** `SessionStore::gc_expired()` in the startup GC task under the pruner's advisory lock.
7. **Config.** Rename `OIDC_MOCK_MODE` → `ALLOW_INSECURE_SIGNING_KEY`; `warn!` at boot; refuse with a non-loopback https issuer. TTLs validated into a newtype (non-zero, upper bound, `checked_mul`); remove `unwrap_or` fallbacks; require issuer + client id. `SecretString`/`SecretSlice<u8>` for `client_secret`/`session_signing_key`.
8. **JWT.** Build `EncodingKey`/`DecodingKey`/`Validation` once (`SessionJwt` in `AuthFacade`); explicit leeway.
9. **OIDC.** Unknown kid with a fresh cache → at most one refetch per ~60 s; `tokio::sync::Mutex` around refresh with re-check; discovery TTL; normalise issuer once; accept ES256/PS256 if the IdP's JWKS advertises them.
10. Groups JSONB via `sqlx::types::Json` (decode error = `AuthError::State`). Replace `active_sessions` gauge with created/revoked counters.
11. Spec: `04-auth-sso.md` (logout/rotation/revoke semantics, 5xx, JWKS), `08-config.md`, `12-dynamic-permissions.md` (admin revoke endpoint), `website/docs/usage/` — Claude Code connect + what a 5xx vs 401 means.

## Tests

- `tests/auth_e2e.rs`: closed state pool → 5xx without `WWW-Authenticate`; two logins, logout one → the other is 401; logout with failing DB → 5xx.
- `tests/oauth_bridge_e2e.rs`: after refresh the old access token is rejected; `/revoke` with closed pool → 503; rotation failure leaves the old chain usable.
- `tests/session_cache_real_db.rs`: tombstone beats a racing insert; expired rows GC'd, live rows kept; concurrent stale lookups issue one query.
- `tests/auth_hardening_id_token.rs`: mock IdP counts JWKS hits; trailing-slash issuer.
- `src/auth/config.rs` unit: TTL bounds, insecure-key refusal.
- `bin/test`, `bin/lint`.

## Done when

- State-DB outage never triggers a client re-login flow.
- Logout, rotation, `/revoke` and the admin endpoint each leave zero live bearers for what they revoked.
- `sessions` row count is bounded by live + grace.
