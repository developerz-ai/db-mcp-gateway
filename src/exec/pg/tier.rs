//! One role's pools on a database. Every Postgres database has a read tier
//! (its `role`); one with a `write_role` also has a write tier. The tiers
//! never share a connection, so a read can never run as the write role.

use metrics::gauge;
use secrecy::SecretString;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::config::{Database, Password, Server};

use super::super::adapter::ExecError;
use super::super::pool_sizing::PoolSizing;
use super::config::{build_connect_options, resolve_password};
use super::error::log_discarded;
use super::{CANCEL_POOL_MAX_CONNECTIONS, POOL_ACQUIRE_TIMEOUT, reset_on_release};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TierKind {
    Read,
    Write,
}

impl TierKind {
    /// The `pool` label in metrics and in `db_activity` rows.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// The query pool and its dedicated cancel pool (see
/// [`super::CANCEL_POOL_MAX_CONNECTIONS`]), both connected as `role`: a role
/// can cancel its own backends without extra privileges.
pub(super) struct Tier {
    pub(super) kind: TierKind,
    pub(super) pool: PgPool,
    pub(super) cancel_pool: PgPool,
    /// Redacted from server messages before they reach the agent.
    pub(super) role: String,
}

impl Tier {
    /// The read tier connects once, so a misconfigured database errors on
    /// first use of the adapter.
    pub(super) async fn open_read(
        server: &Server,
        database: &Database,
        sizing: PoolSizing,
        db_label: &str,
    ) -> Result<Self, ExecError> {
        let password = resolve_password(&database.password).await?;
        let opts = build_connect_options(server, database, &database.role, &password);
        let pool = query_pool_options(sizing)
            .connect_with(opts.clone())
            .await
            .map_err(|err| {
                log_discarded(&err, "target pool open failed");
                ExecError::Connection
            })?;
        Ok(Self::assemble(
            TierKind::Read,
            pool,
            opts,
            &database.role,
            sizing,
            db_label,
        ))
    }

    /// The write tier connects on its first write: most callers of a
    /// database never write, and a write role that fails to connect should
    /// fail writes, not reads.
    pub(super) async fn open_write(
        server: &Server,
        database: &Database,
        (role, password): (&str, &Password),
        sizing: PoolSizing,
        db_label: &str,
    ) -> Result<Self, ExecError> {
        let password: SecretString = resolve_password(password).await?;
        let opts = build_connect_options(server, database, role, &password);
        let pool = query_pool_options(sizing).connect_lazy_with(opts.clone());
        Ok(Self::assemble(
            TierKind::Write,
            pool,
            opts,
            role,
            sizing,
            db_label,
        ))
    }

    fn assemble(
        kind: TierKind,
        pool: PgPool,
        opts: PgConnectOptions,
        role: &str,
        sizing: PoolSizing,
        db_label: &str,
    ) -> Self {
        let cancel_pool = PgPoolOptions::new()
            .max_connections(CANCEL_POOL_MAX_CONNECTIONS)
            .min_connections(0)
            .idle_timeout(sizing.idle_timeout)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_lazy_with(opts);
        // Configured maxima, one gauge per pool — cheap first signal for
        // "pool exists for this db" with bounded label cardinality.
        let (query_kind, cancel_kind) = match kind {
            TierKind::Read => ("query", "cancel"),
            TierKind::Write => ("write_query", "write_cancel"),
        };
        gauge!("pool_size", "db" => db_label.to_string(), "pool_kind" => query_kind)
            .set(f64::from(sizing.max_connections));
        gauge!("pool_size", "db" => db_label.to_string(), "pool_kind" => cancel_kind)
            .set(f64::from(CANCEL_POOL_MAX_CONNECTIONS));
        Self {
            kind,
            pool,
            cancel_pool,
            role: role.to_string(),
        }
    }

    /// Whether the tier holds any connection. A write tier that never
    /// connected is running nothing, so there is nothing to list or cancel.
    pub(super) fn is_connected(&self) -> bool {
        self.pool.size() > 0
    }
}

fn query_pool_options(sizing: PoolSizing) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(sizing.max_connections)
        .min_connections(sizing.min_connections)
        .idle_timeout(sizing.idle_timeout)
        .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
        .after_release(reset_on_release)
}
