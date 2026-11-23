# 07 — Docs and onboarding

> Part of [`overview.md`](overview.md). Depends on: none (docs-only PRs can go any time after 01).

## Files to change

**P0 — things that fail when pasted**

| ID | Where | Defect → fix |
|---|---|---|
| D1 **V** | `README.md:55`, `examples/.mcp.json:5`, `usage/{first-query.md:23,claude-code.md:20,38,48,146,other-agents.md:15-76}`, `deployment/quickstart.md:448`, `comparison.md:35` vs `src/transport/mod.rs:60` | Every client URL is the bare origin; MCP lives at `/mcp`, `/` has no route → 404, no SSO. Append `/mcp`; product: `/` answers a JSON hint (or alias) |
| D2 **R** | `quickstart.md:314-350` | Compose omits `OIDC_ISSUER`, signing key, TLS, redirect → four boot aborts |
| D3 **R** | `examples/docker-compose.yml:22,26,56,74` | Pins 1.0.0; `wget` healthcheck impossible on distroless; missing env in header list |
| D4 **R** | `config/example.yaml:1,17,28,41,74` | "Copy" aborts boot (`vault:`). Use `${FILE:}` |
| D5 **R** | `quickstart.md:51` | `--network host` + image bind `0.0.0.0` publishes plain HTTP with the dev key. `GATEWAY_BIND=127.0.0.1:8443` |
| D6 **R** | `quickstart.md:189,207`, spec 09:44 | `alter default privileges` lacks `for role`; spec claims SQL templates that do not exist |
| D7 **R** | `quickstart.md:461` | Denylist table / `audit_log` do not exist (`sessions.revoked_at`, `audit_calls`); distroless has no `kill` (`:127`) |
| D8 **R** | `deployment/admin-api.md` | IdP token ≠ session JWT; pagination, `expected_updated_at`, 409, `session_too_old`, `revoke-sessions` undocumented |

**P1 — one-command demo** `examples/demo/`: gateway + state DB + seeded Postgres + dev-only service account (`bin/mint-service-token`, spec 14) so no IdP is needed; second profile adds Dex with a static user for the SSO path. `docker compose up` + one printed `claude mcp add …/mcp` line. Quickstart rewritten around it.

**P2 — accuracy**: check each against code and fix or delete: false claims in `features.md:70,146,152,206`, `comparison.md:43-55` (marks inverted, "immediate" revocation), `use-cases.md:52,80`, `first-query.md:61,88` (cached, prompt), `logging.md:19,24`, spec 03:21,192-218, 04:20,255 (SCIM), 09:7,9,123, 10, 11 (phases 1/3/4/5/7/8/9), `00-seed.md:3` header, `quickstart.md:9,20,24,64,77,289,359`, `admin-api.md:38`.

**P3 — new pages**: per-IdP guides (Okta, Entra, Google, Keycloak), role SQL per engine (Mongo has none), pooler contract, `operations.md` (backup/restore/upgrade/rollback), comparison vs MCP DB toolboxes and access gateways instead of poolers.

**Login UX** (`auth_routes.rs:219`, `oauth/consent.rs`, `oauth/bridge_login.rs`): gateway name + request id + support contact on denied/expired pages; explicit "no groups" and "email unverified" text. Auth path → label.

## Tests
- `tests/doc_drift.rs`: image version, env names, routes, tool names, outcome codes, metric names in docs exist in code; `examples/*.yaml` parse; every documented client URL ends in the MCP path.
- CI smoke: `examples/demo` up → `tools/call` returns rows.

## Done when
- Fresh box, Docker only → query in ≤ 3 commands; drift test in CI.
