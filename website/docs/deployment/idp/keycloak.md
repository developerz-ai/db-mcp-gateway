# Keycloak

Wiring the gateway's SSO to Keycloak. Read [what the gateway needs from any IdP](okta.md#what-the-gateway-needs-from-any-idp) first. Keycloak also works as a broker in front of IdPs the gateway cannot use directly ([Google](google.md), possibly [Entra](entra.md)).

## Client

1. **Clients → Create client.** Type *OpenID Connect*, client ID `db-mcp-gateway`.
2. **Client authentication: On** (confidential client). Flow: *Standard flow* only.
3. **Valid redirect URIs:** `https://db.internal.acme.com/auth/callback`.
4. **Advanced → Proof Key for Code Exchange Code Challenge Method:** `S256` (optional; the gateway always sends PKCE).
5. **Credentials** tab: authenticator *Client Id and Secret*; copy the secret.

## Groups claim

1. **Client scopes → Create client scope** named `groups` (type *Default*, include in token scope). Requesting it is what the gateway does.
2. In that scope, **Mappers → By configuration → Group Membership**:
   - Token claim name: `groups`
   - **Full group path: On** — values are the full path, such as `/engineering/db-oncall`. Keep it on: with it off, `/engineering/db-oncall` and `/contractors/db-oncall` both become `db-oncall` and grant the same access. Write the full path, leading slash included, in `permissions[].group` and `admin.group`
   - Add to ID token: **On**
3. **Clients → db-mcp-gateway → Client scopes → Add client scope →** `groups`, as *Default*.

Realm roles work too: a *User Realm Role* mapper with claim name `roles`, multivalued, in the ID token, and `OIDC_GROUPS_CLAIM=roles`.

```yaml
permissions:
  - group: /engineering/db-oncall   # the full group path, verbatim
    grants:
      - { server: prod, database: "*", action: query_read }
```

## Verified email

Keycloak emits `email_verified` from the user's *Email verified* flag. Users created by an admin or imported without verification have it off and are refused (`oidc_email_unverified`). Turn on *Verify email* in the realm's login settings, or set the flag for federated / imported users you trust.

## Gateway settings

```env
OIDC_ISSUER=https://sso.internal.acme.com/realms/acme
OIDC_CLIENT_ID=db-mcp-gateway
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URL=https://db.internal.acme.com/auth/callback
```
