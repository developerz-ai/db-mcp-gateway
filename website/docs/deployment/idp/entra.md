# Microsoft Entra ID

Wiring the gateway's SSO to Microsoft Entra ID (formerly Azure AD). Read [what the gateway needs from any IdP](okta.md#what-the-gateway-needs-from-any-idp) first.

> **Known limitation: `email_verified`.** The gateway refuses a login whose ID token lacks `email_verified: true` (`oidc_email_unverified`). Entra ID tokens carry an optional `email` claim but, as of writing, no `email_verified` claim. Decode a real ID token from your tenant before rolling out; a login refused with `oidc_email_unverified` is this limitation. If the claim is absent, Entra cannot be used directly today: put a broker that asserts verified email in front — Keycloak ([guide](keycloak.md)) or Dex with Entra as the upstream — and point the gateway at the broker.

## Register the app

1. **Entra admin center → App registrations → New registration.** Single tenant.
2. **Redirect URI:** platform *Web*, `https://db.internal.acme.com/auth/callback`.
3. **Certificates & secrets → New client secret.** Note the value and the **Application (client) ID**.
4. **Token configuration → Add optional claim → ID → `email`.**
5. **Token configuration → Add groups claim.** Pick *Security groups* (or *Groups assigned to the application*, which keeps tokens small), and for the **ID** token choose how groups are emitted:
   - Default: group **object IDs** (GUIDs). Then `permissions[].group` must be the GUID: `- group: 3f2a…-…`.
   - *sAMAccountName* emits names, but only for groups synced from on-premises AD.
   - *Cloud-only group display names* is available only with *Groups assigned to the application*.

   Users in more than about 200 groups get an overage claim instead of a list — the gateway then sees no groups. Assigning groups to the app avoids it.

App roles are an alternative: define roles on the registration, assign groups to them, and they arrive as an array in the `roles` claim. Set `OIDC_GROUPS_CLAIM=roles` and use the role values as `permissions[].group`.

## Gateway settings

```env
OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_CLIENT_ID=<application-client-id>
OIDC_CLIENT_SECRET=…
OIDC_REDIRECT_URL=https://db.internal.acme.com/auth/callback
# OIDC_GROUPS_CLAIM=groups    # or roles, with app roles
```

The gateway requests the `groups` scope along with `openid email profile`; if Entra rejects the authorize request over it (`AADSTS…` invalid scope), set `OIDC_SCOPES=openid email profile` — Entra's `groups` claim comes from the app's token configuration, not from a scope.
