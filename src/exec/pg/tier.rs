//! One role's pools on a database. Every Postgres database has a read tier
//! (its `role`); one with a `write_role` also has a write tier. The tiers
//! never share a connection, so a read can never run as the write role —
//! and never share a fate: a write credential that does not resolve, or that
//! the target rejects, fails writes and leaves the read tier alone.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::Mutex;

use crate::config::{Database, Password, Server};

use super::super::adapter::ExecError;
use super::super::pool_sizing::{CallerSlots, PoolSizing};
use super::POOL_ACQUIRE_TIMEOUT;
use super::cancel_pool::cancel_pool_size;
use super::config::{connect_options, resolve_password, with_password};
use super::error::{Origin, log_discarded};
use super::pool_metrics::{self, sqlx_sample};
use super::release::{pin_lexing, reset_on_release};

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

    /// The `pool_kind` metric labels of the tier's query and cancel pools.
    fn pool_kinds(self) -> (&'static str, &'static str) {
        match self {
            Self::Read => ("query", "cancel"),
            Self::Write => ("write_query", "write_cancel"),
        }
    }
}

/// The query pool and its dedicated cancel pool (sized by
/// `PG_CANCEL_POOL_SIZE`, see [`super::cancel_pool`]), both connected as `role`: a role
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
    ) -> Result<Arc<Self>, ExecError> {
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
    ) -> Arc<Self> {
        let cancel_pool = PgPoolOptions::new()
            .max_connections(cancel_pool_size())
            .min_connections(0)
            .idle_timeout(sizing.idle_timeout)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_lazy_with(opts);
        let tier = Arc::new(Self {
            kind,
            pool,
            cancel_pool,
            callers: CallerSlots::new(sizing),
            role: role.to_string(),
            stale: AtomicBool::new(false),
        });
        let db_label = db_label.to_owned();
        pool_metrics::spawn_sampler(Arc::downgrade(&tier), move |tier: &Tier| {
            let (query_kind, cancel_kind) = tier.kind.pool_kinds();
            pool_metrics::publish(&db_label, query_kind, sqlx_sample(&tier.pool));
            pool_metrics::publish(&db_label, cancel_kind, sqlx_sample(&tier.cancel_pool));
        });
        tier
    }

    /// The `pool_kind` label of `pool`, one of this tier's two.
    pub(super) fn pool_kind(&self, pool: &PgPool) -> &'static str {
        let (query_kind, cancel_kind) = self.kind.pool_kinds();
        if std::ptr::eq(pool, &self.cancel_pool) {
            cancel_kind
        } else {
            query_kind
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
        let tier = Tier::assemble(
            TierKind::Write,
            pool,
            opts,
            &self.role,
            self.sizing,
            &self.db_label,
        );
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
