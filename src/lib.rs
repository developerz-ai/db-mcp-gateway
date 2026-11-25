//! db-mcp-gateway library crate. The binary entry point lives in `src/main.rs`;
//! everything testable lives here so integration tests can drive it directly.

// Shipped code has one exception: `exec::sql_guard::pg_tree::ffi`.
#![cfg_attr(not(test), deny(unsafe_code))]

pub mod audit;
pub mod auth;
pub mod authz;
pub mod config;
pub mod exec;
pub mod mcp;
pub mod state;
pub mod tools;
pub mod transport;
