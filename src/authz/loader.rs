//! DB-grant loader (#49). Projects rows from `permissions_grants` into the
//! same `config::Grant` shape the YAML loader produces, so [`super::merge`]
//! can fold both sources without caring where each grant came from.
//!
//! Spec: docs/initial-idea/12-dynamic-permissions.md §"Two sources, one
//! engine". Symmetric merge — neither source is privileged.
//!
//! Soft-deleted databases drop here, not at evaluate time. A re-created db
//! with the same `(server, db_name)` therefore does NOT silently inherit old
//! grants — those need to be re-issued through the admin API.

use crate::auth::Identity;
use crate::config::{Action, Constraints, Grant};
use crate::state::permissions::{GrantAction, GrantTarget, PermissionsRepo, RepoError};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("permissions repo query failed")]
    Repo(#[from] RepoError),
    /// `permissions_grants.constraints` JSONB didn't deserialize to the
    /// schema. Fail-closed: the request that triggered the load must Deny,
    /// because we cannot safely interpret the grant.
    #[error("grant {grant_id} has malformed constraints JSON")]
    DecodeConstraints {
        grant_id: uuid::Uuid,
        #[source]
        source: serde_json::Error,
    },
}

/// Load the live DB grants attached to `identity.user_sub`. Returns an empty
/// vec if the user has no `permissions_users` row — that's a normal state
/// for users who only have YAML grants.
pub async fn load_db_grants_for(
    repo: &dyn PermissionsRepo,
    identity: &Identity,
) -> Result<Vec<Grant>, LoadError> {
    let Some(user) = repo.get_user_by_sub(&identity.user_sub).await? else {
        return Ok(Vec::new());
    };
    let db_grants = repo.list_grants_for_user(user.id).await?;
    if db_grants.is_empty() {
        return Ok(Vec::new());
    }

    // One round-trip for all live databases, then index by id for the
    // Specific-target lookup. N+1 with get_database would be observable
    // even at a few-grants-per-user — keep this O(1) per grant.
    let databases = repo.list_databases().await?;
    let db_by_id: HashMap<_, _> = databases.iter().map(|d| (d.id, d)).collect();

    let mut out = Vec::with_capacity(db_grants.len());
    for grant in db_grants {
        let (server, database) = match &grant.target {
            GrantTarget::Specific { database_id } => {
                // Soft-deleted (or otherwise missing) db row → drop the grant.
                // Mirrors `can_see_server`'s rule that a grant pointing at
                // a non-existent database is non-applicable.
                let Some(db) = db_by_id.get(database_id) else {
                    continue;
                };
                (db.server.clone(), db.db_name.clone())
            }
            GrantTarget::Wildcard { server } => (server.clone(), "*".to_string()),
        };
        let constraints: Constraints =
            serde_json::from_value(grant.constraints).map_err(|source| {
                LoadError::DecodeConstraints {
                    grant_id: grant.id,
                    source,
                }
            })?;
        out.push(Grant {
            server,
            database,
            action: action_from_db(grant.action),
            constraints,
        });
    }
    Ok(out)
}

fn action_from_db(a: GrantAction) -> Action {
    match a {
        GrantAction::SchemaRead => Action::SchemaRead,
        GrantAction::QueryRead => Action::QueryRead,
        GrantAction::QueryWrite => Action::QueryWrite,
        GrantAction::HistoryRead => Action::HistoryRead,
    }
}
