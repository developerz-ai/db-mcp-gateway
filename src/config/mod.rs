//! Bootstrap configuration for the gateway.
//!
//! Two-layered today:
//! - `Config` (`env`) carries env-driven runtime knobs: bind address,
//!   MCP path, state DB pool — what we needed for #1 and #2.
//! - `ConfigFile` (`yaml`) carries the operator's YAML: `servers:` +
//!   `permissions:` — what we need for #3.
//!
//! Unification of both into a single YAML lands with issue #16.

mod env;
pub mod schema;
pub mod secret;
pub mod yaml;

pub use env::{
    Config, ConfigError, DEFAULT_MAX_CONCURRENT_PER_IDENTITY, DEFAULT_MAX_CONCURRENT_REQUESTS,
    StateDbConfig, TlsConfig,
};
pub use schema::ServiceAccount;
pub use schema::{
    Action, Constraints, Database, Grant, LoggingBlock, Permission, Server, ServerKind,
    StreamSinkConfig, Tls,
};
pub use secret::{Password, SecretError};
pub use yaml::{
    AdminBlock, ConfigFile, ConfigFileError, ConfigLoadError, PermissionsStoreBlock,
    PermissionsStoreDriver,
};
