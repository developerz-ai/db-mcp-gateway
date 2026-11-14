//! `/admin/v1/*` — admin API (#52).
//!
//! Mounted only when `config_file.admin.enabled` is true; otherwise the entire
//! `/admin/*` path is 404. Spec 12 §"Admin API".
//!
//! Layer order on each route:
//!  1. `bearer_auth` (existing) — verifies the gateway-issued session JWT and
//!     injects `Identity` into request extensions.
//!  2. `require_admin_group` (this module) — confirms `Identity.groups` carries
//!     the configured admin group and stashes [`AdminActor`] for handlers.
//!     The `permissions_users` upsert is intentionally deferred to mutation
//!     handlers so it runs inside the same transaction as the audit row.
//!
//! Every write commits a `permissions_audit` row in the same transaction as
//! the data write ([`audited_tx`]). Audit failure rolls back. CLAUDE.md
//! non-negotiable #4.

mod audited_tx;
pub mod databases;
pub mod error;
pub mod grants;
pub mod middleware;
pub mod page_query;
mod payload;
pub mod users;
mod validation;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware as axum_mw;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::auth::SessionStore;
use crate::authz::PermissionsCache;
use crate::state::permissions::PermissionsRepo;

use self::databases::DatabasesState;
use self::grants::GrantsState;
use self::middleware::{AdminMiddlewareState, require_admin_group};
use self::users::UsersState;

/// Everything the admin API needs from the gateway.
#[derive(Debug, Clone)]
pub struct AdminDeps {
    /// SSO group the caller must carry.
    pub group: String,
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
    /// A committed change drops the affected cached grant sets on this
    /// replica (other replicas hear it over `NOTIFY`) — spec 12 §"Cache
    /// invalidation".
    pub cache: PermissionsCache,
    /// For `POST /admin/v1/users/:id/revoke-sessions`.
    pub sessions: SessionStore,
    /// `admin.session_max_age_secs`: older sessions get `session_too_old`
    /// (403) to bound admin-group staleness. `None` = no cap.
    pub max_session_age: Option<Duration>,
    /// Server names the gateway config declares — the only legal targets of
    /// a wildcard grant or a database registration.
    pub known_servers: Arc<[String]>,
}

/// Build the `/admin/v1/*` router. Returned router is unmounted; the caller
/// (`transport::router`) merges it into the top-level app and stacks
/// `bearer_auth` over it. Each entity family is its own `Router` with its own
/// state; they share the single `require_admin_group` layer.
pub fn router(deps: AdminDeps) -> Router {
    let AdminDeps {
        group,
        repo,
        state_db,
        cache,
        sessions,
        max_session_age,
        known_servers,
    } = deps;
    let mw_state = AdminMiddlewareState {
        admin_group: group,
        max_session_age,
    };
    let users_routes = Router::new()
        .route("/admin/v1/users", post(users::create).get(users::list))
        .route(
            "/admin/v1/users/:id",
            get(users::get_one)
                .patch(users::patch)
                .delete(users::delete),
        )
        .route(
            "/admin/v1/users/:id/revoke-sessions",
            post(users::revoke_sessions),
        )
        .with_state(UsersState {
            repo: repo.clone(),
            state_db: state_db.clone(),
            cache: cache.clone(),
            sessions,
        });
    let databases_routes = Router::new()
        .route(
            "/admin/v1/databases",
            post(databases::create).get(databases::list),
        )
        .route(
            "/admin/v1/databases/:id",
            get(databases::get_one)
                .patch(databases::patch)
                .delete(databases::delete),
        )
        .with_state(DatabasesState {
            repo: repo.clone(),
            state_db: state_db.clone(),
            cache: cache.clone(),
            known_servers: known_servers.clone(),
        });
    let grants_routes = Router::new()
        .route("/admin/v1/grants", post(grants::create).get(grants::list))
        .route(
            "/admin/v1/grants/:id",
            get(grants::get_one)
                .patch(grants::patch)
                .delete(grants::delete),
        )
        .with_state(GrantsState {
            repo,
            state_db,
            cache,
            known_servers,
        });

    Router::new()
        .merge(users_routes)
        .merge(databases_routes)
        .merge(grants_routes)
        .route_layer(axum_mw::from_fn_with_state(mw_state, require_admin_group))
}
