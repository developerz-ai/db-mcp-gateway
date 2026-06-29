# 03 — Transport / MCP Protocol / TLS / DoS / Resource Safety

Scope: `src/transport/{mod,dispatch,jsonrpc,protocol,sse,tls,probes,app_state,auth_middleware,auth_routes}.rs`, `src/auth/oidc.rs`, `src/main.rs`, `src/lib.rs`. Dependency behavior verified against vendored `jsonwebtoken 9.3.1`, `axum 0.7.9`.

No credential leak, no auth bypass, no request-path panic, no algorithm-confusion bypass. Every gap here is **DoS / resource exhaustion** — and the project's own "one noisy user must not starve others" rule is unmet on multiple axes.

---

## T1 — No per-user / global rate or concurrency limit on the request path — **Medium**

**File:** `src/transport/mod.rs:46-108` (entire router). Confirmed by grep: the only `.layer`/`route_layer` calls in `src/` are the two `bearer_auth` middlewares and `require_admin_group`. No `tower::limit`, `ConcurrencyLimit`, `load_shed`, `buffer`, or governor anywhere.

```rust
.route_layer(middleware::from_fn_with_state(
    state.clone(),
    auth_middleware::bearer_auth,
));
```

**Exploit:** One authenticated user (or one stolen session) fires thousands of concurrent `POST /mcp` `tools/call` requests. Each spawns a tokio task and contends for the per-DB pool. The only backpressure is `PgAdapter`'s `acquire_timeout` (`exec/pg.rs:60`), which just converts the flood into pool-timeout errors that still starve every *other* user of the same `(server, database)`. Directly violates the CLAUDE.md non-negotiable.

**Fix:** Add `tower` `GlobalConcurrencyLimitLayer` plus a per-identity rate/concurrency limiter (keyed on `Identity.user_sub`, applied after `bearer_auth`). At minimum `load_shed` + a concurrency bound so the gateway returns 429/503 instead of unboundedly queuing tasks.

---

## T2 — Unauthenticated SSE endpoint, no connection cap — **Medium**

**File:** `src/transport/mod.rs:59-60`, `src/transport/sse.rs:16-29`

```rust
let open = Router::new()
    .route(&path, get(sse::handler))   // GET /mcp — no bearer middleware
```
```rust
let stream = stream::once(async move { Ok::<Event, Infallible>(greeting) })
    .chain(stream::pending::<Result<Event, Infallible>>());
Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
```

**Exploit:** `GET /mcp` is on the *open* (unauthenticated) router. The stream is `stream::pending()` — it never ends; each connection holds a socket + task + 15s keep-alive forever. An unauthenticated attacker opens tens of thousands of `GET /mcp` connections and exhausts file descriptors / sockets / task memory. No cap on concurrent streams, no idle/lifetime bound.

**Fix:** Cap concurrent SSE connections via a shared `Arc<Semaphore>` acquired in the handler (503 when full) and/or require auth on the SSE GET if the protocol allows. Add a maximum stream lifetime.

---

## T3 — OIDC discovery / JWKS / token-exchange HTTP client has no timeout — **Medium**

**File:** `src/auth/oidc.rs:94-97` (client built once, reused at `:136-148`, `:213-223`, `:245-255`)

```rust
let http = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .map_err(|_| AuthError::HttpClient)?;
```

`reqwest` applies **no default timeout**. A slow/hung IdP (or JWKS host) makes `/auth/login` (→ `discover()`) and `/auth/callback` (→ `exchange_and_verify`) block indefinitely, holding a task + connection per request. Both routes are **unauthenticated** (`transport/mod.rs:61-62`), so attacker-driven pile-up is trivial whenever the IdP is degraded.

**Fix:** Set `.timeout(...)` and `.connect_timeout(...)` (e.g. 10s total / 5s connect). Optionally single-flight discovery/JWKS to avoid a thundering herd on cache miss.

**SSRF note (not a finding):** token/JWKS endpoints come from the discovery doc, but `discover()` pins the doc's `issuer` against the configured issuer (`oidc.rs:227-229`) and redirects are disabled — a tampered doc can't redirect the gateway to an internal host. Adequate.

---

## Request-path panic triage (clean)

Ran `grep -rn "unwrap()\|expect(\|panic!\|unreachable!\|\.index(" src/ | grep -v test`. Every hit on a request-reachable path is safe or test-only:
- All `unwrap()/expect()` matches are inside `#[cfg(test)]` modules or `main.rs` CLI tests.
- `probes.rs:106` → `.unwrap_or_default()`. `oidc.rs:175` → `.unwrap_or("")`. `mod.rs:133,152,160` → `Option::unwrap_or(...)`. All total/safe.
- `jsonrpc.rs:48-58` `Response::result` deliberately avoids `unwrap` — serialization failure degrades to an internal error.
- No `panic!`/`unreachable!`/`expect`/slice-indexing on the request path.

---

## Controls verified correct (no action)

- **Request body bound:** no `DefaultBodyLimit::disable()` anywhere; `body: String` extractor (`mod.rs:129`) inherits axum 0.7's default 2 MiB cap. *Minor nit:* limit is implicit — add an explicit `DefaultBodyLimit::max(...)` so a future extractor swap can't silently remove it.
- **No JSON-RPC batch support:** `serde_json::from_str::<Request>` rejects arrays → no batch-amplification vector.
- **Malformed input handled:** parse error / wrong `jsonrpc` version → proper `-32700`/`-32600`; `id` defaults to `Null`, no panic (`mod.rs:130-147`).
- **TLS:** rustls 0.23 + `aws-lc-rs`, secure defaults (TLS 1.2/1.3, no weak ciphers); verification never disabled; no `danger_accept_invalid_*`. TLS is **enforced** — `tls_from_env` (`config/mod.rs:218-247`) refuses to boot without certs unless `TLS_DISABLED=true` is set explicitly. Default bind `127.0.0.1:8443`.
- **Graceful shutdown:** `main.rs:267-300` handles Ctrl-C + SIGTERM, never resolves `select!` on handler-install failure (`pending()`), flips the shutdown flag before draining so `/healthz`/`/readyz` go 503 for k8s deregistration, then 30s drain.
- **Probes:** `/healthz`, `/readyz` return generic strings; `readyz` DB-error body deliberately generic (`probes.rs:80-93`) with a test asserting no driver/role/host leak. Unauthenticated by design (spec 09).
- **Pending-flow store** TTL-bounded and GC'd (`app_state.rs:101-125`).

**Minor info-disclosure (Low):** the unauthenticated SSE `greeting` (`sse.rs:19`) and `initialize` emit `SERVER_VERSION` (= `CARGO_PKG_VERSION`, `protocol.rs:13`), letting an unauthenticated client fingerprint the exact gateway version. Acceptable for an open-source binary; note if version-based exploit targeting is a concern.
