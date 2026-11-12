//! Execution layer: per-`(server, database)` adapters that enforce
//! `statement_timeout`, row caps, and cancellation.
//!
//! The trait surface lives in [`adapter`]; the Postgres impl in [`pg`], the
//! Mongo impl in [`mongo`]. Tools consume an `Arc<dyn DbAdapter>` from
//! [`AdapterRegistry`] and never see backend-specific types or SQL — mysql
//! (#59) slots in here without touching `src/tools/`.
//!
//! Security-required (see CLAUDE.md). The non-negotiables — no credentials
//! in errors/logs, DB-side `statement_timeout` set per-tx — are documented
//! and enforced on the per-adapter side; see [`pg`] for the Pg pattern. The
//! one piece that is *not* per-adapter is the timeout ceiling
//! ([`DEFAULT_STATEMENT_TIMEOUT_MS`]): it's gateway policy, lives in
//! [`adapter`], and every impl applies it identically.

pub mod adapter;
mod budget;
pub mod ident;
pub mod mongo;
pub mod pg;
mod pool_sizing;
mod query;
mod registry;
mod rejection;
pub mod sql_guard;

pub use adapter::{
    AdapterKind, DEFAULT_STATEMENT_TIMEOUT_MS, DbAdapter, ExecError, ExecResult, MAX_RESULT_BYTES,
};
pub use ident::{IDENTIFIER_PATTERN, Identifier, InvalidIdentifier};
pub use mongo::MongoAdapter;
pub use pg::PgAdapter;
pub use pool_sizing::{
    DEFAULT_POOL_IDLE_TIMEOUT, DEFAULT_POOL_MAX_CONNECTIONS, InvalidPoolSizing, PoolSizing,
};
pub use query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};
pub use registry::AdapterRegistry;
pub use rejection::{DbRejection, RejectionKind};
pub use sql_guard::{Access, GuardedSql};
