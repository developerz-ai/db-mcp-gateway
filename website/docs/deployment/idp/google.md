# Google Workspace

Google Workspace accounts can sign in to the gateway, but **not by pointing the gateway at Google directly**. Read [what the gateway needs from any IdP](okta.md#what-the-gateway-needs-from-any-idp) for the reasons:

- Google's ID token carries `email` and `email_verified`, but **no groups claim**. Every user would sign in with no groups and see nothing.
- The gateway always requests the `groups` scope, which Google does not define; Google's authorization endpoint can refuse an unknown scope (`invalid_scope`).

## Use a broker

Put an OIDC broker between Google and the gateway. The broker logs the user in with Google, looks up their Workspace groups through the Admin SDK Directory API, and issues its own ID token with a `groups` array.

| Broker | How it gets groups |
|---|---|
| Dex | The `google` connector, with a service account that has domain-wide delegation for the Directory API (`fetchTransitiveGroupMembership` for nested groups) |
| Keycloak | Google as an identity provider, plus an IdP mapper or sync that sets Keycloak groups; see [Keycloak](keycloak.md) for the claim side |
| Authentik, Zitadel | Their Google source/IdP plus a group mapping; see [Zitadel](zitadel.md) for that claim's shape |

Gateway settings then point at the **broker**, not Google:

```env
OIDC_ISSUER=https://dex.internal.acme.com
OIDC_CLIENT_ID=db-mcp-gateway
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URL=https://db.internal.acme.com/auth/callback
```

`permissions[].group` holds whatever the broker emits — with Dex's Google connector, the group email (`db-oncall@acme.com`).

## Google OAuth client (for the broker)

In Google Cloud console → *APIs & Services → Credentials → Create OAuth client ID → Web application*, with the **broker's** callback as the redirect URI. Restrict sign-in to your domain in the broker (Dex: `hostedDomains`), not only in Google.
