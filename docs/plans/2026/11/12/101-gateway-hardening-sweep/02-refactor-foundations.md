# 02 — Refactor foundations

> Part of [`overview.md`](overview.md). Depends on: 01. Every step is **behaviour-preserving** unless marked; one PR per numbered step. `(security review required)` on steps 3–6 (they move code under `src/tools/`, `src/auth/`, `src/exec/`, the audit path).

Structure work that the fix slices (04–12) build on. Doing it first avoids fixing the same bug in seven copies.

## Files to change

| Problem | Where |
|---|---|
| Test boot harness duplicated: `state_db_url` ×21, `spawn_gateway` ×18, `AppState {…}` ×16, `AuthConfig {…}` ×13 | `tests/*.rs`; `tests/common/mod.rs` holds only the mock IdP |
| Outcome/error codes are string literals at ~30 sites; one drifted (`"invalid_argument"`, `src/tools/sample_table.rs:238`) | `src/tools/audit_dispatch/types.rs:17`, `outcome.rs:97-114`, `src/audit/mod.rs:68` |
| Tool pipeline copy-pasted ×7; `#[allow(clippy::too_many_arguments)]` ×8 | `src/tools/{run_query,explain,describe_schema,sample_table,list_databases,list_servers,get_query_history}.rs`, `src/tools/mod.rs:105,160-253` |
| SQL outside `src/state/` (admin ×15 sites, OAuth ×11, sessions ×3, audit ×6) | `src/transport/admin/**`, `src/transport/oauth_state.rs`, `client_registry.rs`, `src/auth/session.rs`, `src/audit/` |
| `tools ↔ transport` import cycle | `src/transport/mod.rs:45` vs `src/tools/mod.rs:31,78-84` |
| `DbAdapter` leaks engine specifics; Postgres SQL in tools | `src/tools/describe_schema.rs:226-275`, `sample_table.rs:~178`, `explain.rs:165,219`; `src/exec/adapter.rs:66,129-153` |
| Auth state lives in transport | `src/transport/oauth_state.rs`, `client_registry.rs`, `app_state.rs:89-107` |
| `AppState`: 10 fields, 5 `Option` | `src/transport/app_state.rs:25-60` |
| 23 files over 300 LOC | list in step 9 |

## Steps

1. **Test harness.** `tests/common/{env.rs, gateway.rs, audit.rs, pg_target.rs, mongo_target.rs, cleanup.rs}`: a gateway builder (yaml, groups, caps, cache, admin), `assert_audit_outcome`, target fixtures. Migrate every test file to it. No production change. Unblocks step 8 and slice 13.
2. **Outcome enum.** `enum OutcomeCode` with `as_str()`; `Outcome.code: OutcomeCode`; `error_outcome` takes the enum; stringify once at the audit-row boundary. Behaviour change (deliberate): `invalid_argument` → `invalid_arguments` per spec 03:88. Slice 04 extends this enum.
3. **Tool context.** `src/tools/context.rs` (`ToolCtx<'a>`), `src/tools/target.rs` (`resolve_target`, `ensure_reason`, `effective_row_limit`), `audit_dispatch::run_audited(ctx, id, header, work)` owning the grants load and its failure branch. Remove the eight `allow`s and the stale comment at `src/tools/mod.rs:102-104`. Each tool file drops under 300 LOC.
4. **Protocol module.** Move `transport/jsonrpc.rs` and the tool-name constants of `transport/protocol.rs` to `src/mcp/`; both layers import it. Breaks the cycle. Update `CLAUDE.md` §Layout.
5. **State owns SQL.** `src/state/{sessions,audit,oauth}.rs` and `src/state/permissions/pg_tx.rs` (free functions over `&mut Transaction<Postgres>`, shared row mappers, `tx_upsert_actor`). Callers keep their logic; only queries move. Delete or re-home the nine unused `PermissionsRepo` write methods (07 decides which).
6. **Auth owns auth state.** `PendingFlows`, `AuthCodes`, `RefreshTokens`, `ClientRegistry`, `AuthFacade` → `src/auth/oauth/`; handlers stay in `src/transport/oauth/`. One `DEFAULT_REFRESH_TTL`. This is also the `oauth_state.rs` split.
7. **Adapter trait does its job.** Add `describe_schema`, `sample`, `explain` to `DbAdapter` (or a `SchemaIntrospect` trait); Postgres SQL moves to `src/exec/pg/{catalog,sample,explain}.rs`; Mongo returns a typed unsupported error for now (12 implements it). Delete `ExecError::NotImplemented`, `kind()`, `AdapterKind`; `health()` per 06 step 9.
8. **`AppState` split.** `McpState` + `OAuthState`, no `Option` soup; `#[cfg(feature = "test-support")]` constructor. Removes `TransportError::AdminDepsMissing`.
9. **Mechanical splits** (parallel, one file per PR, tests move to sibling files):

| File (prod / test LOC) | Split into |
|---|---|
| `src/config/yaml.rs` (631 / 1008) | `yaml/{mod,error,validate}.rs` + `yaml/tests/*.rs`; `validate()` (197 lines) → one fn per section |
| `src/exec/sql_guard.rs` (348 / 737) | `sql_guard/{mod,shape,visitor,tests,proptests}.rs` |
| `src/sentry_scrub.rs` (307 / 360) | `sentry_scrub/{mod,scrubber,event,tests}.rs`; update `bin/check-scrub-features` paths |
| `src/tools/audit_dispatch/mod.rs` (346 / 129) | `cancel_guard.rs`, `metrics.rs`, `tests.rs`; build `AuditRow` once |
| `src/tools/get_query_history.rs` (329 / 144) | `args.rs` + thin `run` |
| `src/config/mod.rs` (341 / 106) | `config/env.rs` + tests out |
| `src/exec/mongo/mod.rs` (367 / 78) | `mongo/{dispatch,bson_json}.rs` |
| `src/state/permissions/pg.rs` (420), `mod.rs` (333) | `pg/{users,databases,grants,rows}.rs`; `types.rs`, `error.rs` |
| `src/audit/stream.rs` (202 / 211) | `stream/{mod,syslog,tests}.rs` |
| `src/main.rs` (358 / 46) | `run()` (258 lines) → `init_tracing`, `build_permissions_repo`, `build_app_state`, `serve` in `startup.rs` |
| `src/transport/mod.rs` (320), `admin/middleware.rs` (230 / 96), `admin/databases/mod.rs` (321) | `transport/mcp_handler.rs`; `databases/handlers.rs`; `admin/validation.rs` (triplicated helpers); `admin/audited_tx.rs` (begin → mutate → audit → commit → invalidate, ×9) |
| `src/config/secret.rs`, `src/authz/mod.rs`, `src/auth/{service_token,session}.rs`, `src/authz/wildcard_proptests.rs` | tests to sibling files only |

10. **Dead code.** `tower-http` if still unused after 09 adds `timeout` (it will be used — keep); `audit::latest_for_user_tool` (`pub`, test-only); `_signature_check`; stale docs (`app_state.rs:31`, `exec/mod.rs:4`, `adapter.rs:129-135`, `authz/mod.rs:4`).
11. `CLAUDE.md` §Layers: either the table matches reality after step 5, or the table is corrected. No third state.

## Tests

- Whole suite green after each step with no test assertion changed (except the step-2 code fix, which gets a new assertion).
- `find src -name '*.rs' | xargs wc -l | awk '$1>300'` empty at the end; add this as a check in `bin/lint`.
- `bin/test`, `bin/lint`.

## Done when

- No file in `src/` over 300 LOC; no `sqlx::query` outside `src/state/`; no `tools ↔ transport` cycle.
- A new tool needs one file plus one match arm.
