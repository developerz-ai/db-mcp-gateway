//! Auth layer: OIDC login → gateway-issued session JWT → state-DB-backed
//! revocable session. All HTTP handlers and the bearer middleware read
//! identity through `SessionStore::lookup` so revocation is honored.
//!
//! Security review required (see CLAUDE.md). Credentials never appear in
//! `Display` for any error in this module; see `errors::AuthError`.

pub mod config;
pub mod errors;
pub mod jwt;
pub mod oidc;
pub mod session;

pub use config::AuthConfig;
pub use errors::AuthError;
pub use oidc::{OidcClient, VerifiedIdentity};
pub use session::{Identity, Session, SessionId, SessionStore};
