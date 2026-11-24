//! Integration tests that need no database: wire protocol, OAuth discovery,
//! TLS reload, ID-token hardening, shipped config and the audit-assertion
//! guard. One binary for the same link-time reason as `tests/it_db/`.

// CLAUDE.md §Conventions: tests may panic; `[lints.clippy]` denies it for shipped code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod audit_assertion_guard;
mod auth_hardening_id_token;
mod auth_login_options;
mod auth_reserved_subject;
mod cli_check;
mod cli_config_schema;
mod cli_mint;
mod cli_roles;
mod isolation_guard;
mod mcp_surface;
mod metrics_catalogue;
mod oauth_discovery;
mod oauth_resource;
mod oauth_slow_body;
mod permissions_shipped_yml;
mod proptests_inputs;
mod proptests_rejectors;
mod redis_tls;
mod tls_reload;
mod transport;
mod transport_overload;
mod transport_wave2_mcp_headers;
