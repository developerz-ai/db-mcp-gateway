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
  principals unambiguous next to IdP subjects in `audit_calls`;
- `user_email` = `<name>@service-accounts.invalid` — the audit column is
  `NOT NULL`, and the `.invalid` TLD (RFC 2606) marks the address as
  synthesized;
- `groups` = the single configured group, snapshotted per call like any
  other identity.

Names are boot-validated to `^[a-z0-9][a-z0-9-]{0,62}$` so audit fields stay
clean and greppable. There is no session row behind a service identity: no
revocation bitmap, no expiry, no refresh chain — and `active_sessions`
metrics are untouched.

### Scope

Group-bounded. Per-database and per-action scope is expressed as grants on
the service's group (`server`/`database`/`action`/`constraints`, including
`row_limit`, `statement_timeout_ms`, `require_reason`), identical to human
groups. Per-table scope remains what it is for humans: out of scope.

Service identities resolve grants from **YAML only**. The DB-backed grant
resolver keys off `permissions_users` rows, which only SSO login and admin
mutations create — a service token never has one, so dynamic grants simply
do not apply. That is deliberate: every grant a service token can exercise
is reviewed by PR.

### Mint / rotate / revoke

There is no in-band lifecycle API. The admin API is not widened, and nothing
about tokens is callable over HTTP — the lifecycle is GitOps:

- **Mint** — a human operator runs `bin/mint-service-token <name>`, stores
  the value in the org secret store, and PRs the `service_accounts:` stanza
  (name + group + secret **reference** — never the value). The gateway
  refuses to boot on a stanza whose ref does not resolve.
- **Rotate** — overlap is mandatory, because each pod only loads one token at
  boot. Sequence: (1) mint a new value with the same `<name>` (or a
  temporary `<name>-next` if the audit identity must change too); (2) add a
  *second* `service_accounts:` entry to the gateway YAML so new pods accept
  the new value; (3) roll the deployment and wait until the rollout
  completes; (4) update every client to use the new value; (5) remove the
  old `service_accounts:` entry and roll again. If the temporary entry uses
  a different `<name>`, audit rows for the rotation window attribute to
  `<name>-next` instead of `<name>` — pick deliberately and document the
  trade-off in the PR.
- **Revoke** — remove the complete `service_accounts:` stanza (the name,
  the group, and the token reference together) and roll. Emptying or
  unsetting the secret is **not** a valid revocation: unresolved or empty
  secret references abort boot (`SecretError::EnvNotSet` /
  `SecretError::FileMissing`), and a gateway that refuses to start on a
  misconfigured stanza is a feature, not a bypass. There is no instant
  revocation; the exposure window is the rollout time. That is the honest
  price of a stateless compare, and it is documented rather than papered
  over.

`/auth/logout` with a service token is a harmless no-op (204) and does not
revoke anything — there is no session row to revoke.

### Storage path

Two homes, both pre-existing conventions:

- **Record of truth:** the org secret store (an operator-held Vaultwarden
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
`service:<name>`), and the synchronous audit write — failure of which still
fails the request.

## What this is not

- Not a user impersonation path. A service identity cannot hold the admin
  group (boot-enforced) and cannot mint sessions.
- Not a second permissions source. Grants stay in `permissions:` YAML.
- Not a replacement for SSO. Humans log in exactly as before.
