# 14 — Service tokens (headless auth)

Issue: #185. Implementation: `src/auth/service_token.rs`, `src/transport/auth_middleware.rs`.

The browser SSO flow ([04 — Auth & SSO](04-auth-sso.md)) assumes a human with
a browser. A headless client — a CI job, an agent runner, another service —
has neither. This spec adds the second credential kind: the **service token**,
a static bearer that authenticates a named service identity with its own
permissions group and audit attribution.

## Decisions

### Token type

Opaque static bearer, shape `dbmcp_svc_<64 hex chars>` (32 bytes of CSPRNG
entropy), minted operator-side by `bin/mint-service-token <name>`.

The prefix is enforced at boot, and it is load-bearing, not cosmetic:

- **Leak detection** — a self-identifying token is scannable; `dbmcp_svc_` in
  a log, a paste, or a repo is unambiguous.
- **Fail-loud misconfiguration** — an operator who pastes a session JWT or a
  DB password into the token slot gets a boot error naming the mistake,
  instead of a credential that silently authenticates as nothing.

Comparison is constant-time (`auth::pkce::ct_eq`, the same primitive PKCE
verification uses), and the boot path rejects anything other than the exact
`dbmcp_svc_` + 64 lowercase hex shape — short, overlong, missing prefix,
non-hex, or mixed-case tokens abort boot with a `WeakToken` error naming the
mint verb. Token material never appears in `Debug`/`Display`/errors — same
discipline as `config::secret::Password`, with tests pinning the redaction.

### Permissions group — mandatory, exactly one

Every service account names **one** group in `permissions:`. That is the whole
scope model: the token inherits exactly that group's grants, evaluated by the
same `authz` engine (YAML grants merged most-restrictively, deny-by-default)
that IdP-backed identities use. There is no per-token scope on top of the
group — a second scope language would be a second authz surface to review.

Boot validation makes the group real rather than aspirational:

- the group **must exist** in `permissions:` — a typo'd group name would
  otherwise authenticate cleanly and silently reach nothing (an empty
  `grants:` list is the explicit way to recognize a group that grants
  nothing);
- the group **must not be the admin group** — the admin middleware
  (`transport/admin/middleware.rs`) gates on group membership alone and is
  deliberately **not** widened or otherwise changed, so this boot gate is
  what keeps service tokens off `/admin/*`.

Convention (not enforced): name service groups `svc-<name>` so they read
distinct from IdP-sourced groups (`devs` / `devops` / `cto`) in permissions
reviews. The mint verb prints the stanza that way.

### Audit identity

Every headless call attributes to the service identity, through the same
`Identity` the audit layer already consumes:

- `user_sub` = `service:<name>` — the `service:` scheme keeps service
  principals unambiguous next to IdP subjects in `audit_calls`. The prefix is
  **reserved** (case-insensitively): an IdP login whose `sub` starts with it is
  refused, and a session or refresh chain minted for one before that check
  existed no longer authenticates or rotates. Otherwise an SSO user could read
  the service account's query history and be audited as it;
- `user_email` = `<name>@service-accounts.invalid` — the audit column is
  `NOT NULL`, and the `.invalid` TLD (RFC 2606) marks the address as
  synthesized;
- `groups` = the single configured group, snapshotted per call like any
  other identity.

Names are boot-validated to `^[a-z0-9][a-z0-9-]{0,62}$` so audit fields stay
clean and greppable. There is no session row behind a service identity: no
revocation bitmap, no expiry, no refresh chain — and the
`sessions_created_total` / `sessions_revoked_total` counters are untouched.

### Upstream attribution

Many agents share one token — a fleet of coding agents, a devops runner
working for many people — so the identity alone says *which token* acted,
not *which run* or *for whom*. Two request headers carry that:

| Header | Audit column | Meaning |
|---|---|---|
| `x-dbmcp-run-id` | `audit_calls.upstream_run_id` | The agent's task / run / job id |
| `x-dbmcp-on-behalf-of` | `audit_calls.upstream_actor` | The person or system the run acts for |

- **Claimed, never verified.** The gateway cannot check either value: it
  stores them, logs them on the dispatch line and span, copies them onto the
  intent row (so an `abandoned` row keeps them) — and never uses them for
  authz. The audit subject stays `service:<name>`; the four properties of
  the service-identity exception (CLAUDE.md) are untouched.
- **Capped.** Each is one header value of 1–128 characters from
  `[A-Za-z0-9._:@/+=-]`. A repeated, empty, overlong or out-of-charset value
  refuses the call `invalid_arguments` (audited) rather than being dropped,
  so a claim is never silently lost.
- **Service tokens only.** On an SSO session both headers are ignored — the
  identity is already verified — and nothing is stored.
- **`require_upstream: true`** on the account refuses any call that lacks
  either header with `invalid_arguments` (audited, nothing runs). Use it when
  every call must be attributable to a run and a requester.
- **History is per run.** `get_query_history` called with `x-dbmcp-run-id`
  returns only rows recorded with that run id, so agents sharing a token do
  not read each other's history by default ([03](03-mcp-tools.md)).

### Per-account concurrency

`max_concurrent_requests` (≥ 1) replaces the per-identity cap (default 16)
for that token, so a fleet behind one token is not throttled as one user.
The global cap still applies; a change takes effect on the next request after
a reload.

### Scope

Group-bounded. Per-database and per-action scope is expressed as grants on
the service's group (`server`/`database`/`action`/`constraints`, including
`row_limit`, `statement_timeout_ms`, `require_reason`), identical to human
groups. Per-table scope remains what it is for humans: out of scope.

Service identities resolve grants from **YAML only**, enforced twice. The
resolver never reads the permissions store for a service identity, so even a
DB grant planted for `service:<name>` by direct database access is inert
(`tests/service_tokens_e2e.rs`). And `POST /admin/v1/users` rejects any
`service:*` subject with `400`, so the audited admin API cannot create one.
That is deliberate: every grant a service token can exercise is reviewed by
PR.

### Mint / rotate / revoke

There is no in-band lifecycle API. The admin API is not widened, and nothing
about tokens is callable over HTTP — the lifecycle is GitOps:

- **Mint** — a human operator runs `bin/mint-service-token <name>`, stores
  the value in the org secret store, and PRs the `service_accounts:` stanza
  (name + group + secret **reference** — never the value). The gateway
  refuses to boot on a stanza whose ref does not resolve. In production,
  `service_accounts[].token` carries a `${ENV:…}` or `${FILE:…}` reference,
  identical to the `password:` policy documented in
  [config-reference.md § ServiceAccount](../deployment/config-reference.md#serviceaccount).
  Under `gateway.env: production` an inline literal token is rejected at
  boot (the error names the field, never the value); the default
  `development` accepts one for dev/test parity with `Database.password`.
  Committed config is also guarded at the CI layer: the `secret-scan` job in `.github/workflows/ci.yml` scans
  every tracked file (not just YAML) and FAILS on any literal
  `dbmcp_svc_<64hex>` token (test fixtures under `tests/**` are excluded).
  It is ADVISORY — it fails the job on every PR, but does not by itself
  block a merge until made a required branch-protection check (#190
  follow-up). So an inline literal is not an option for committed config
  (the secret-scan job fails it, `tests/**` fixtures excepted) or for
  production (boot rejects it); the parser itself tolerates one only under
  the default `gateway.env: development` — which is what the in-code test
  fixtures exercise via `ConfigFile::from_yaml_str` /
  `ServiceTokenStore::from_config` (`tests/config/yaml/boot_rules.rs`).
- **Rotate** — overlap is mandatory: every configured account loads at once
  (`ServiceTokenStore::from_config` resolves ALL of them at boot,
  `src/auth/service_token.rs`), and two boot rejections close the shortcuts —
  the YAML validator (`src/config/yaml/service_accounts.rs`) aborts boot on a duplicate
  service-account **name**, and the token store (`src/auth/service_token.rs`,
  `DuplicateToken`) aborts boot on a duplicate token **value** — so the new
  value can neither reuse the original `<name>` nor the original token value.
  Sequence: (1) mint a new value under a DISTINCT temporary name
  (`<name>-next` is the recommended convention); (2) add a *second*
  `service_accounts:` entry (with its own matching `permissions:` block)
  to the gateway YAML; (3) `kill -HUP` every pod (or roll the deployment)
  and wait until it completes — a reload rebuilds the token store, but a
  `${ENV:…}` ref reads the pod's environment, which only changes on a
  restart, so a value delivered as a new env var needs a roll, while one
  delivered as a mounted file (`${FILE:…}`) is picked up by `SIGHUP`; (4)
  update every client to use the new value; (5) remove the old
  `service_accounts:` entry and roll or `SIGHUP` again. **Audit-identity trade-off**: because the
  temporary entry uses a different name, audit rows for the rotation
  window attribute to `service:<name>-next` instead of `service:<name>` —
  pick deliberately and document the trade-off in the PR. If preserving
  the exact `service:<name>` audit identity across rotation is required,
  configuration support for multiple tokens under one name must be added
  first; until then same-name rotation is not supported and must not be
  documented.
- **Revoke** — remove the complete `service_accounts:` stanza (the name,
  the group, and the token reference together) and `kill -HUP` every pod
  (or roll). A reload rebuilds the token store in the same swap as the
  config, so the removed token gets 401 on its next call. Emptying or
  unsetting the secret is **not** a valid revocation: unresolved or empty
  secret references abort boot (`SecretError::EnvNotSet` /
  `SecretError::FileUnreadable` for unreadable / missing files, and
  `SecretError::FileEmpty` for a present-but-empty file), and a gateway
  that refuses to start on a misconfigured stanza is a feature, not a
  bypass — on reload the same failure keeps the old store, token
  included. There is no instant revocation; the exposure window is the
  time to merge and signal. That is the honest
  price of a stateless compare, and it is documented rather than papered
  over.

`/auth/logout` with a service token is a harmless no-op (204) and does not
revoke anything — there is no session row to revoke.

### Storage path

Two homes, both pre-existing conventions:

- **Record of truth:** the org secret store (an operator-held password-manager
  item), because the gateway cannot recover the value — it is shown once at
  mint.
- **Delivery to the gateway:** the same secret-reference mechanism DB
  passwords already use — `${ENV:VAR}` (env from a k8s Secret/SealedSecret)
  or `${FILE:/run/secrets/…}` (mounted file). The YAML carries only
  `name`, `group`, and the reference, so the committed config stays
  credential-free and PR-reviewable.

The per-machine `~/.config/db-mcp-gateway/token` cache that interactive
clients use today is a *client-side* session cache and stays exactly that —
a fleet client's deployment manifests are the analogue of it.

### Why not OAuth client-credentials

The standards-shaped answer is an IdP-issued machine token (client
credentials / JWT-profile) introspected or JWKS-verified per call. It buys
automatic expiry at the cost of an IdP dependency on the headless hot path,
clock-skew and cache-staleness handling, and IdP-side service-user
provisioning machinery — to end at the same group + audit model. The static
token behind the existing secret-ref mechanism is boring, reviewable, and
revocable by PR. If the IdP story matures, a client-credentials grant can
land as a third credential kind without changing anything here.

## Request path

`bearer_auth` tries the service-token store first — a constant-time scan over
the boot-resolved values — and falls through to the session-JWT path
unchanged on no match. A presented token that matches nothing is *not* an
auth failure by itself; it just takes the JWT path, whose failure produces
the same 401 contract as before (`unauthenticated` + `login_url`). Anonymous
requests are untouched.

Downstream nothing changes: the resolved `Identity` flows into authz, the
per-identity concurrency limiter (a service gets its own bucket keyed by
`service:<name>`, sized by its `max_concurrent_requests` when set), and the
synchronous audit write — failure of which still
fails the request.

## What this is not

- Not a user impersonation path. A service identity cannot hold the admin
  group (boot-enforced) and cannot mint sessions.
- Not a second permissions source. Grants stay in `permissions:` YAML.
- Not a replacement for SSO. Humans log in exactly as before.
