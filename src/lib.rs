//! db-mcp-gateway library crate. The binary entry point lives in `src/main.rs`;
//! everything testable lives here so integration tests can drive it directly.

pub mod auth;
pub mod authz;
pub mod config;
pub mod exec;
pub mod state;
pub mod tools;
pub mod transport;
