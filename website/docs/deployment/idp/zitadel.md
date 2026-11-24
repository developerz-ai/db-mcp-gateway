# Zitadel

Wiring the gateway's SSO to Zitadel. Read [what the gateway needs from any IdP](okta.md#what-the-gateway-needs-from-any-idp) first.

Zitadel puts project roles in the ID token as a JSON **object** keyed by role name (`{"db-oncall": {"<org-id>": "<org-domain>"}}`). The gateway reads an object-shaped groups claim by its **keys**, so the role names become the groups — no Action needed.

## Application

1. In the gateway's project, **New application → Web → Code** (authorization code). PKCE is sent either way; pick the variant that issues a **client secret** and set authentication to *POST* (`client_secret_post`, the gateway's default). If you pick *Basic*, set `OIDC_TOKEN_AUTH_METHOD=client_secret_basic`.
2. **Redirect URI:** `https://db.internal.acme.com/auth/callback`.
3. **Token settings:** turn on *User roles inside ID Token* and *User Info inside ID Token*.
4. Define project **roles** (for example `db-oncall`, `db-readers`) and grant them to users.

Zitadel sets `email_verified` from the user's verified email; users with an unverified email are refused and shown a page saying so.

## Use the project-scoped roles claim

Zitadel emits two role claims of the same shape:

| Claim | Holds |
|---|---|
| `urn:zitadel:iam:org:project:roles` | roles from **every** project the token covers |
| `urn:zitadel:iam:org:project:<projectId>:roles` | roles of **one** project |

Use the **project-scoped** one, with the gateway's own project id. With the unscoped claim, a role named `db-oncall` in an unrelated project would match `permissions[].group: db-oncall`.

```env
OIDC_GROUPS_CLAIM=urn:zitadel:iam:org:project:<projectId>:roles
OIDC_SCOPES=openid email profile
```

`OIDC_SCOPES` drops `groups`, which Zitadel does not define.

**Organisations.** The value under each role lists the organisations that granted it; the gateway reads only the role name. If the project is granted to other organisations (project grants), their users holding a role match too. Either don't grant the gateway's project to organisations you don't trust, or emit a filtered claim with an Action (below).

### Filtering with an Action (only when needed)

When you need to restrict roles to trusted organisations, add an Action to the *Complement Token* flow that emits only this project's roles from trusted organisations as a flat `groups` array. With Actions v1 the script has this shape (check the context API of your Zitadel version):

```js
const PROJECT_ID = '<projectId>';
const TRUSTED_ORGS = ['<orgId>'];

function groupsClaim(ctx, api) {
  const groups = [];
  const grants = (ctx.v1.user.grants && ctx.v1.user.grants.grants) || [];
  grants
    .filter(grant => grant.projectId === PROJECT_ID && TRUSTED_ORGS.includes(grant.resourceOwner))
    .forEach(grant => (grant.roles || []).forEach(role => {
      if (!groups.includes(role)) groups.push(role);
    }));
  api.v1.claims.setClaim('groups', groups);
}
```

Then keep the default `OIDC_GROUPS_CLAIM=groups`.

**Prefix.** If the project's roles also serve other apps, give the gateway's roles a prefix (`dbmcp-oncall`) and set `OIDC_GROUPS_PREFIX=dbmcp-`: other roles are ignored, and `permissions[].group` uses `oncall`.

## Gateway settings

```env
OIDC_ISSUER=https://auth.acme.com        # your Zitadel instance / custom domain
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URL=https://db.internal.acme.com/auth/callback
OIDC_GROUPS_CLAIM=urn:zitadel:iam:org:project:<projectId>:roles
OIDC_SCOPES=openid email profile
```

```yaml
permissions:
  - group: db-oncall          # the Zitadel role key, verbatim
    grants:
      - { server: prod, database: "*", action: query_read }
```

A wrong claim name, or a claim of an unexpected shape, signs users in with **no groups**: the gateway logs a warning naming the claim and the consent page tells the user.
