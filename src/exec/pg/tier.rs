//! One role's pools on a database. Every Postgres database has a read tier
//! (its `role`); one with a `write_role` also has a write tier. The tiers
//! never share a connection, so a read can never run as the write role —
//! and never share a fate: a write credential that does not resolve, or that
//! the target rejects, fails writes and leaves the read tier alone.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use metrics::gauge;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::Mutex;

use crate::config::{Database, Password, Server};

use super::super::adapter::ExecError;
use super::super::pool_sizing::{CallerSlots, PoolSizing};
use super::config::{connect_options, resolve_password, with_password};
use super::error::{Origin, log_discarded};
use super::release::{pin_lexing, reset_on_release};
use super::{CANCEL_POOL_MAX_CONNECTIONS, POOL_ACQUIRE_TIMEOUT};

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
    /// Each caller's share of `pool`; cancels are not counted.
    pub(super) callers: CallerSlots,
    /// Redacted from server messages before they reach the agent.
    pub(super) role: String,
    /// Set when the target rejected this tier's credentials: the password
    /// may have rotated, so the tier must be opened again.
    stale: AtomicBool,
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
        let opts = with_password(connect_options(server, database, &database.role), &password);
        let pool = query_pool_options(sizing)
            .connect_with(opts.clone())
            .await
            .map_err(|err| {
                let origin = Origin {
                    server: &server.name,
                    database: &database.name,
                    role: &database.role,
                    request_id: None,
                };
                log_discarded(&err, Some(&origin), "target pool open failed");
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
            callers: CallerSlots::new(sizing),
            role: role.to_string(),
            stale: AtomicBool::new(false),
        }
    }

    pub(super) fn mark_stale(&self) {
        self.stale.store(true, Ordering::Relaxed);
    }

    pub(super) fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }
}

/// The write tier of a database with a `write_role`, opened by the first
/// call that needs it: most callers of a database never write, and a write
/// password that does not resolve must fail writes, not reads. Its pools
/// connect lazily too, so a write role the target refuses is found by the
/// first write.
///
/// It is also what another replica's writes are reached through — a cancel
/// or an activity listing asks the target, not this process's pool — so a
/// replica that never wrote still opens it for those.
pub(super) struct WriteTier {
    /// Everything but the password.
    options: PgConnectOptions,
    password: Password,
    role: String,
    sizing: PoolSizing,
    db_label: String,
    /// Replaced once the target rejects its credentials, so the password
    /// reference is resolved again — rotation without touching the read tier.
    current: Mutex<Option<Arc<Tier>>>,
}

impl WriteTier {
    pub(super) fn new(
        server: &Server,
        database: &Database,
        (role, password): (&str, &Password),
        sizing: PoolSizing,
        db_label: &str,
    ) -> Self {
        Self {
            options: connect_options(server, database, role),
            // The reference (`${ENV:…}`), kept to resolve at each open.
            password: password.clone(),
            role: role.to_string(),
            sizing,
            db_label: db_label.to_string(),
            current: Mutex::new(None),
        }
    }

    /// The tier, opened now when this is its first use or the target has
    /// rejected its credentials since. A password that does not resolve is
    /// this call's error and is tried again by the next.
    pub(super) async fn get(&self) -> Result<Arc<Tier>, ExecError> {
        let mut current = self.current.lock().await;
        if let Some(tier) = current.as_ref().filter(|tier| !tier.is_stale()) {
            return Ok(Arc::clone(tier));
        }
        let password = resolve_password(&self.password).await?;
        let opts = with_password(self.options.clone(), &password);
        let pool = query_pool_options(self.sizing).connect_lazy_with(opts.clone());
        let tier = Arc::new(Tier::assemble(
            TierKind::Write,
            pool,
            opts,
            &self.role,
            self.sizing,
            &self.db_label,
        ));
        *current = Some(Arc::clone(&tier));
        Ok(tier)
    }
}

fn query_pool_options(sizing: PoolSizing) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(sizing.max_connections)
        .min_connections(sizing.min_connections)
        .idle_timeout(sizing.idle_timeout)
        .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
        .after_connect(pin_lexing)
        .after_release(reset_on_release)
}
