# Okta

Wiring the gateway's SSO to Okta. Read [what every IdP must provide](#what-the-gateway-needs-from-any-idp) first; the Okta steps follow. Okta's admin console changes; the setting names below may move.

## What the gateway needs from any IdP

The gateway is a generic OIDC client (`src/auth/oidc/`). For every IdP:

| Requirement | Why |
|---|---|
| Authorization-code flow with PKCE (S256) and a client secret, sent in the token request body (`client_secret_post`, default) or an HTTP Basic header (`OIDC_TOKEN_AUTH_METHOD=client_secret_basic`) | That is the only flow the gateway runs |
| Redirect URI `https://<gateway>/auth/callback`, equal to `OIDC_REDIRECT_URL` | Both the browser login and the MCP OAuth bridge land there |
| The gateway asks for scopes `OIDC_SCOPES` (default `openid email profile groups`; must include `openid`) | Drop `groups` for an IdP that rejects or does not define it |
| ID token signed with a key that has a `kid`, published in the JWKS | Tokens without `kid` are refused |
| `email` claim **and** `email_verified: true` in the ID token | Email is the audit identity; an unverified one is refused (`oidc_email_unverified`; the MCP login flow shows the user a page saying so) |
| A groups claim in the ID token (name set by `OIDC_GROUPS_CLAIM`, default `groups`): a JSON **array of strings**, or an **object** whose keys are the group names (Zitadel) | Group names are matched verbatim against `permissions[].group` (after `OIDC_GROUPS_PREFIX` is stripped, when set). A missing claim, or any other shape, means no groups: the user signs in and sees nothing, the gateway logs a warning naming the claim and its shape, and the consent page tells the user |
| An `https` issuer (plain `http` only for `localhost`) | Discovery refuses anything else |

Groups are read once, at login, and stored with the session. A group change takes effect at the user's next login (or after [revoke-sessions](../admin-api.md#revoke-a-users-sessions)). Set `GROUPS_MAX_AGE` (e.g. `12h`) to force that next login within a bound even for a client that keeps refreshing.

## Create the app

1. **Applications → Create App Integration → OIDC – OpenID Connect → Web Application.**
2. **Grant type:** Authorization Code (keep Refresh Token off — the gateway issues its own refresh tokens).
3. **Sign-in redirect URI:** `https://db.internal.acme.com/auth/callback`.
4. **Assignments:** the groups whose members may sign in.
5. Save; note the **Client ID** and **Client secret**.
6. **Client authentication:** client secret. Some Okta apps accept only `client_secret_basic`: if the token exchange fails with `invalid_client`, set `OIDC_TOKEN_AUTH_METHOD=client_secret_basic` on the gateway (or switch the app's `token_endpoint_auth_method` to `client_secret_post`).

## Groups claim

On the app's **Sign On** tab → *OpenID Connect ID Token* → **Groups claim type: Filter**, **Groups claim filter:** name `groups`, *Matches regex* `.*` (or a narrower regex such as `^db-` so tokens stay small). This puts an array of group names in the ID token.

This applies to Okta's org authorization server (issuer `https://<org>.okta.com`). With a custom authorization server (issuer `https://<org>.okta.com/oauth2/<id>`), add a `groups` claim of type *Groups*, included in the **ID Token**, for *Any scope* or the `groups` scope, on that server's **Claims** tab instead.

`email_verified` is set from the user's Okta profile; users whose primary email Okta has not verified cannot sign in.

## Gateway settings

```env
OIDC_ISSUER=https://acme.okta.com          # or https://acme.okta.com/oauth2/<server-id>
OIDC_CLIENT_ID=0oa…
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URL=https://db.internal.acme.com/auth/callback
# OIDC_GROUPS_CLAIM=groups                 # default
# OIDC_TOKEN_AUTH_METHOD=client_secret_basic  # if the app accepts only Basic
# OIDC_GROUPS_PREFIX=db-                   # optional: only db-* groups count, matched without the prefix
```

```yaml
permissions:
  - group: db-oncall          # the Okta group name, verbatim
    grants:
      - { server: prod, database: "*", action: query_read, constraints: { require_reason: true } }
```

## Check it

`POST /auth/login`, open the `login_url`, sign in. A `session_token` back means the login works; `list_servers` returning nothing means the groups claim is missing or the names do not match `permissions[].group`.
