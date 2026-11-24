# Zitadel

Wiring the gateway's SSO to Zitadel. Read [what the gateway needs from any IdP](okta.md#what-the-gateway-needs-from-any-idp) first.

> **Known limitation: Zitadel's roles claim is an object.** Zitadel puts project roles in `urn:zitadel:iam:org:project:roles` as a JSON **object** keyed by role name (`{"db-oncall": {"<org-id>": "<org-domain>"}}`). The gateway reads the groups claim only as an **array of strings**; any other shape counts as no groups. So `OIDC_GROUPS_CLAIM=urn:zitadel:iam:org:project:roles` signs users in with no groups — they see nothing. Reading object keys is planned; until it ships, emit a flat array claim with a Zitadel Action (below).

## Application

1. In a project, **New application → Web → Code** (authorization code). PKCE is sent either way; pick the variant that issues a **client secret** and set authentication to *POST* (`client_secret_post`).
2. **Redirect URI:** `https://db.internal.acme.com/auth/callback`.
3. **Token settings:** turn on *User roles inside ID Token* and *User Info inside ID Token*, so claims set by the action reach the ID token.
4. Define project **roles** (for example `db-oncall`, `db-readers`) and grant them to users or via organisation grants.

Zitadel sets `email_verified` from the user's verified email; users with an unverified email are refused (`oidc_email_unverified`).

## Flatten roles into `groups`

Add an Action to the *Complement Token* flow, on the trigger that builds the ID token / userinfo claims, that copies the role keys into a `groups` array. With Actions v1 the script has this shape (check the context API of your Zitadel version):

```js
function groupsClaim(ctx, api) {
  const groups = [];
  const grants = (ctx.v1.user.grants && ctx.v1.user.grants.grants) || [];
  grants.forEach(grant => (grant.roles || []).forEach(role => {
    if (!groups.includes(role)) groups.push(role);
  }));
  api.v1.claims.setClaim('groups', groups);
}
```

Then the default `OIDC_GROUPS_CLAIM=groups` works, and `permissions[].group` uses the role keys verbatim.

## Gateway settings

```env
OIDC_ISSUER=https://auth.acme.com        # your Zitadel instance / custom domain
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URL=https://db.internal.acme.com/auth/callback
```
