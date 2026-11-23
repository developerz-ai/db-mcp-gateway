# 04 — Auth, authz, transport

> Part of [`overview.md`](overview.md). Depends on: 02. Label: `security review required`.

## Files to change

| ID | Sev | Where | Defect → fix |
|---|---|---|---|
| A1 H3 | med | `src/authz/mod.rs:90-103`, `effective.rs:42` vs spec 06 §Evaluation | Merge scope is per action. Recommendation: state the rule in spec 06 + cross-action proptest pinning it |
| A2 H4 | med | `src/config/yaml/mod.rs:36`, `startup/boot.rs:72,110`, `authz/cache.rs:90` vs spec 12 | Store consulted even with no `permissions_store:`. Explicit mode + spec fix (documented `permissions.store.*` shape does not exist) |
| A3 **P** | med | `src/state/permissions/pg/notify.rs:59` | LISTEN has no liveness: silent drop → revokes only by TTL. Timeout + self-NOTIFY; on miss flush `All`, resubscribe; log recovery too |
| A4 **R** | low | `src/transport/admin/databases/handlers.rs:35,100` | `db_name` not validated against config → dormant grant armed by a later reload |
| A5 **R** | low | `src/transport/admin/audited_tx.rs:57`, `state/permissions/pg/users.rs:42,104` | Actor upsert is an unaudited write, breaks before/after chain, spurious 409s. Insert-if-absent |
| A6 **R** | low | `src/config/env.rs:191` | `SESSION_CACHE_TTL_SECONDS` unbounded → clamp 300 |
| A7 **R** | low | `src/transport/probes.rs:98` | Raw `sqlx::Error` logged → `connect_error_class` (MUST #1) |
| A8 **R** | low | `src/auth/oauth/{pending_flows.rs:65,109,auth_codes.rs:24,mod.rs:53}`, `oidc/types.rs:40` | Derived `Debug` on secrets/PII → redacting impls |
| A9 **R** | low | `src/transport/oauth/authorize.rs:234`, `token.rs:166` | RFC 8707 `resource` stored, never checked. Reject mismatch |
| A10 **P** | low | `src/transport/bounds.rs:36` vs `src/auth/oidc/mod.rs:54,64` | Callback inner budget 65 s > router 60 s → raw 504 |
| A11 **V** | low | `src/config/reload.rs:63` | Config stored before service tokens; swap order |
| A12 **R** | low | `src/transport/mcp_handler.rs` | No `Origin` check (MCP MUST). 403 on a present, unlisted Origin |
| A13 **R** | low | `admin/users/mod.rs:29,97`, `auth_routes.rs:136` | Length bounds on sub/email/groups; `service:` check case-insensitive; `Cache-Control: no-store` |
| A14 | med | `src/auth/oauth/grants.rs:82`, `token.rs:122` | Refresh copies the identity frozen at login: IdP group removal never lands until chain end. Add `GROUPS_MAX_AGE` (re-login required) or upstream re-check |
| A15 | med | `src/auth/oidc/helpers.rs:5`, `oidc/mod.rs:225` | `groups` scope hard-coded; non-array claim → silent zero groups. `OIDC_SCOPES`, claim shapes (object keys, prefix map), warn log |
| A16 | med | `src/auth/service_token.rs:53`, `config/schema/mod.rs:30`, `yaml/service_accounts.rs:20` | Rotation renames the audit identity. `tokens: [..]` per account (spec 14) |
| A17 | low | `src/auth/config.rs:176` | `ALLOW_INSECURE_SIGNING_KEY` + non-loopback bind boots. Refuse. One shared boolean parser with `TLS_DISABLED` |
| A18 | low | `mcp_handler.rs:151` | Audit `ip` is the TCP peer. `TRUSTED_PROXIES` |
| A19 | low | spec 04:179 vs 238 | `REFRESH_TTL_DAYS` 366 vs 90; code 366 |
| A20 | low | spec 06 | Promised CLI absent → 08 |

## Tests
- Concurrent/liveness rows need a real state DB; A1 proptest; A14–A16 e2e with audit rows.

## Done when
- Each row fixed or its spec line corrected; spec 04/06/12/14 match code.
