# 09 — Transport: limits, lifecycle, framing

> Part of [`overview.md`](overview.md). Depends on: 02, 04. `(security review required)` only for the steps touching `auth_middleware`/OAuth routes.

Unauthenticated traffic must not be able to take `/mcp` down; ids and errors must be usable by a human or an agent.

## Files to change

- `src/transport/mod.rs:63-77,116-131,163-174,216-235,254-291` — one limiter for OAuth + `/mcp`; admin outside both caps; parse-error mapping; duplicated id checks.
- `src/transport/limit.rs:36-41,61-67,92-114,121-169` — constants, identity-entry race, silent shedding.
- `src/main.rs:300-320`, `Cargo.toml:49` — no request/body timeout (tower-http `timeout` feature not enabled).
- `src/transport/client_registry.rs:40,49,175-225` — 10 000 cap, 90-day TTL, reject-at-cap, unbounded `redirect_uris`.
- `src/transport/oauth/register.rs:27-63`, `oauth/authorize.rs:96-152` — adoption insert before validation.
- `src/transport/oauth_state.rs:28,77,146-163,601-650` — `PendingFlows` flood, 3 queries per mint.
- `src/transport/auth_routes.rs:45-60` — callback requires `code`.
- `src/tools/audit_dispatch/outcome.rs:19-24`, `src/transport/admin/middleware.rs:99-105` — `request_id` is the client's JSON-RPC id; admin has its own copy.
- `src/transport/sse.rs:29-76` — unauthenticated, `pending()` forever.
- `src/transport/protocol.rs:91` — `tools/list` schemas rebuilt per call.
- `src/transport/probes.rs:78` — `/readyz` hits the state pool uncapped.

## Steps

1. **Budgets.** Separate, smaller semaphore for the unauthenticated OAuth routes; `limit::enforce` on `admin_gated`; `max_concurrent_requests` global + per-identity become config (per service account in 12). Reject cap 0. Delete the unused `ConcurrencyLimiter::new`/`Default`/module constants. Fix the identity-entry race (hold the map entry until the permit is taken).
2. **Timeouts.** tower-http `TimeoutLayer` on every router: short for OAuth/probes, statement ceiling + audit timeout + slack for `/mcp`; body-read timeout; explicit `DefaultBodyLimit` (small for OAuth/admin, sized for `/mcp`).
3. **Shed visibility.** `limited()` emits a log line, `requests_shed_total{scope}` and `Retry-After`.
4. **Request id.** One outermost middleware mints the gateway UUID, stores it as an extension, returns `x-request-id`; `tool_error`, `limited`, `unauthorized`, `RequestContext` and admin all read it. Client-supplied `x-request-id` is length/charset-capped and stored separately, never as the audit key. Fix the unit test asserting the old behaviour (`outcome.rs:152`).
5. **Client registry.** Cap `redirect_uris` count and length; never-authorised clients get a short TTL extended on first successful `/authorize`; at cap evict the oldest never-used row; adoption insert moves after PKCE/state validation; cap-full surfaces as `StoreFull`; one TTL constant.
6. **Pending flows.** At cap evict oldest, never reject; at-cap sweep at most once per N seconds.
7. **Fewer round trips.** `/token` and `/register`: single `INSERT … SELECT … WHERE (SELECT count(*)) < cap`; expiry GC only in the background task.
8. **Callback errors.** `CallbackParams.code: Option`, accept `error`/`error_description`; take the flow by `state`; bridge flows `redirect_with_error`.
9. **SSE.** `GET /mcp` returns 405 (the stream carries no messages; MCP allows it). If kept instead: bearer + per-identity cap + ends on the shutdown token (10).
10. **Framing.** Parse to `Value` first: valid JSON that is not a request → `-32600` with the id when recoverable; batch arrays → `-32600` with a clear message; extractor rejections on `/mcp`, `/token`, `/revoke`, `/register` return the protocol's own error shape, not axum plain text.
11. **Static data.** `ToolsListResult` in a `LazyLock`. `/readyz` result cached ~1 s.
12. Dedupe: `internal`/`invalid_body`/`trimmed_non_empty` ×3, `random_token` ×2, id checks ×2 → one home each. `/register` metadata lists `refresh_token` in `grant_types`. Fix stale comments (`main.rs:240`, `startup.rs` "no I/O").
13. Spec: `02-architecture.md` (SSE, error mapping), `03-mcp-tools.md` (`request_id`, caps, timeouts), `04-auth-sso.md` (callback, registration bounds).

## Tests

- `tests/run_query_e2e.rs` (cap tests at `:874+`): stalled OAuth bodies saturate their budget, `/mcp` still 200; response `request_id` equals `audit_calls.request_id`.
- `tests/transport.rs`: `-32600` cases, 405 on GET, golden JSON for each error shape, `x-request-id` on 401/429/503.
- `tests/client_registry_real_db.rs`, `tests/oauth_bridge_e2e.rs`: at-cap eviction; oversized `redirect_uris` rejected; IdP `error=access_denied` redirects back to the client.
- `tests/admin_users_e2e.rs`: admin routes are capped.
- `bin/test`, `bin/lint`.

## Done when

- No unauthenticated request pattern can exhaust the `/mcp` budget or wedge registration.
- Every response, success or error, carries the id that the audit row and logs use.
