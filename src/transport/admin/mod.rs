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
//! the data write. Audit failure rolls back. CLAUDE.md non-negotiable #4.

pub mod databases;
pub mod error;
pub mod grants;
pub mod middleware;
pub mod users;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware as axum_mw;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::authz::PermissionsCache;
use crate::state::permissions::PermissionsRepo;

use self::databases::DatabasesState;
use self::grants::GrantsState;
use self::middleware::{AdminMiddlewareState, require_admin_group};
use self::users::UsersState;

/// Build the `/admin/v1/*` router. Returned router is unmounted; the caller
/// (`transport::router`) merges it into the top-level app and stacks
/// `bearer_auth` over it.
///
/// Each entity family is its own `Router<EntityState>` `.with_state(...)`-ed
/// to its handlers, then merged. They share the single `require_admin_group`
/// layer applied at the top.
///
/// `cache` threads through to the grants handlers so a grant change fires a
/// per-user cache invalidation post-commit — spec 12 §"Cache invalidation"
/// and #54's acceptance criterion. `None` when the gateway runs without a
/// resolver cache (YAML-only installs); invalidation then is a no-op.
///
/// `max_session_age` maps to `admin.session_max_age_secs` in YAML: sessions
/// older than this are rejected with `session_too_old` (403) to bound admin
/// group staleness. `None` = no cap (rely on `session_ttl_hours` alone).
pub fn router(
    admin_group: String,
    repo: Arc<dyn PermissionsRepo>,
    state_db: PgPool,
    cache: Option<PermissionsCache>,
    max_session_age: Option<Duration>,
) -> Router {
    let mw_state = AdminMiddlewareState {
        admin_group,
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
        .with_state(UsersState {
            repo: repo.clone(),
            state_db: state_db.clone(),
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
        });

    Router::new()
        .merge(users_routes)
        .merge(databases_routes)
        .merge(grants_routes)
        .route_layer(axum_mw::from_fn_with_state(mw_state, require_admin_group))
}
