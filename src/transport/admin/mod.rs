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

pub mod error;
pub mod middleware;
pub mod users;

use std::sync::Arc;

use axum::Router;
use axum::middleware as axum_mw;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::state::permissions::PermissionsRepo;

use self::middleware::{AdminMiddlewareState, require_admin_group};
use self::users::UsersState;

/// Build the `/admin/v1/*` router. Returned router is unmounted; the caller
/// (`transport::router`) merges it into the top-level app and stacks
/// `bearer_auth` over it.
pub fn router(admin_group: String, repo: Arc<dyn PermissionsRepo>, state_db: PgPool) -> Router {
    let mw_state = AdminMiddlewareState {
        admin_group,
        repo: repo.clone(),
    };
    let users_state = UsersState { repo, state_db };

    Router::new()
        .route("/admin/v1/users", post(users::create).get(users::list))
        .route(
            "/admin/v1/users/:id",
            get(users::get_one)
                .patch(users::patch)
                .delete(users::delete),
        )
        .route_layer(axum_mw::from_fn_with_state(mw_state, require_admin_group))
        .with_state(users_state)
}
