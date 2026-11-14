//! Integration tests that need no database: wire protocol, OAuth discovery,
//! TLS reload, ID-token hardening, shipped config and the audit-assertion
//! guard. One binary for the same link-time reason as `tests/it_db/`.

#[path = "../common/mod.rs"]
mod common;

mod audit_assertion_guard;
mod auth_hardening_id_token;
mod auth_reserved_subject;
mod oauth_discovery;
mod permissions_shipped_yml;
mod tls_reload;
mod transport;
mod transport_wave2_mcp_headers;
