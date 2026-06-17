//! `/admin/v1/*` — admin API (#52).
//!
//! Mounted only when `config_file.admin.enabled` is true; otherwise the entire
//! `/admin/*` path is 404. Spec 12 §"Admin API".
//!
//! Layer order on each route:
//!  1. `bearer_auth` (existing) — verifies the gateway-issued session JWT and
//!     injects `Identity` into request extensions.
//!  2. `require_admin_group` (this module) — confirms `Identity.groups` carries
//!     the configured admin group, upserts the calling admin into
//!     `permissions_users`, and stashes [`AdminActor`] for handlers.
//!
//! Every write commits a `permissions_audit` row in the same transaction as
//! the data write. Audit failure rolls back. CLAUDE.md non-negotiable #4.

pub mod databases;
pub mod error;
pub mod middleware;
pub mod users;

use std::sync::Arc;

use axum::Router;
use axum::middleware as axum_mw;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::state::permissions::PermissionsRepo;

use self::databases::DatabasesState;
use self::middleware::{AdminMiddlewareState, require_admin_group};
use self::users::UsersState;

/// Build the `/admin/v1/*` router. Returned router is unmounted; the caller
/// (`transport::router`) merges it into the top-level app and stacks
/// `bearer_auth` over it.
///
/// Each entity family is its own `Router<EntityState>` `.with_state(...)`-ed
/// to its handlers, then merged. They share the single `require_admin_group`
/// layer applied at the top.
pub fn router(admin_group: String, repo: Arc<dyn PermissionsRepo>, state_db: PgPool) -> Router {
    let mw_state = AdminMiddlewareState {
        admin_group,
        repo: repo.clone(),
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
        .with_state(DatabasesState { repo, state_db });

    Router::new()
        .merge(users_routes)
        .merge(databases_routes)
        .route_layer(axum_mw::from_fn_with_state(mw_state, require_admin_group))
}
