//! MCP OAuth bridge — makes the gateway speak the MCP Authorization spec
//! (2025-06-18) so spec-compliant clients (Claude Code, Cursor, …) can log in
//! with zero manual credential wiring.
//!
//! The gateway already runs a full OIDC Relying-Party dance against the org's
//! IdP (`/auth/login` → IdP → `/auth/callback` → gateway session JWT). That
//! flow is *bespoke*: the agent POSTs `/auth/login`, reads a JSON session
//! token, and sends it as a bearer. MCP clients don't speak that — on a `401`
//! they follow OAuth 2.1 discovery:
//!
//! 1. `401` carries `WWW-Authenticate: Bearer resource_metadata="…"` (RFC 9728).
//! 2. `GET /.well-known/oauth-protected-resource` → the resource's metadata,
//!    naming this gateway as its own authorization server.
//! 3. `GET /.well-known/oauth-authorization-server` → AS metadata (RFC 8414).
//! 4. `POST /register` → Dynamic Client Registration (RFC 7591); pins the
//!    client's redirect-URI allowlist so step 5 can match against it.
//! 5. `GET /authorize` (PKCE) → we drive the IdP login, then 302 back to the
//!    client's *registered* redirect with a one-time authorization code.
//! 6. `POST /token` (PKCE verifier) → we hand back the gateway session JWT as
//!    the OAuth `access_token`.
//!
//! This module is a thin *front* over the existing `auth::oidc` + session
//! machinery: the access token IS the same HS256 session JWT the bespoke flow
//! issues, so the bearer middleware, revocation, and audit are all unchanged.
//! Because the token is signed with the gateway-private key and only ever
//! minted for this resource, the RFC 8707 audience requirement ("only accept
//! tokens issued for us") is satisfied structurally — no other party can mint
//! a valid-signature bearer.

mod authorize;
mod discovery;
mod helpers;
mod register;
mod revoke;
mod token;
mod urls;

// Re-export everything the parent module (transport) accesses via `oauth::*`
pub(super) use authorize::{authorize, complete_bridge_login};
pub(super) use discovery::{authorization_server_metadata, protected_resource_metadata};
pub(super) use register::register;
pub(super) use revoke::revoke;
pub(super) use token::token;
pub(crate) use urls::{base_url, resource_metadata_url};
