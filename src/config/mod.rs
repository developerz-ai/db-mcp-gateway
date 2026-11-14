//! Bootstrap configuration for the gateway, in two layers:
//! - `Config` (`env`) carries env-driven runtime knobs: listeners, MCP path,
//!   state DB pool, TLS, cache TTLs.
//! - `ConfigFile` (`yaml`) carries the operator's YAML: `gateway:`,
//!   `servers:`, `permissions:`, `service_accounts:`, `admin:`,
//!   `permissions_store:`, `logging:` (spec 08).

mod env;
mod pool;
pub mod reload;
pub mod schema;
pub mod secret;
pub mod yaml;

pub use env::{
    Config, ConfigError, DEFAULT_MAX_CONCURRENT_PER_IDENTITY, DEFAULT_MAX_CONCURRENT_REQUESTS,
    StateDbConfig, TlsConfig,
};
pub use pool::PoolConfig;
pub use schema::ServiceAccount;
pub use schema::{
    Action, Constraints, Database, Grant, LoggingBlock, Permission, Server, ServerKind,
    StreamSinkConfig, Tls,
};
pub use secret::{Password, SecretError};
pub use yaml::{
    AdminConfig, AdminGroup, ConfigFile, ConfigFileError, ConfigLoadError, Environment,
    GatewayBlock, PermissionsStoreBlock, PermissionsStoreDriver,
};
