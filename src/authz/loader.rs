//! DB-grant loader (#49). Projects the store's live grants into the same
//! `config::Grant` shape the YAML loader produces, so the merge engine can
//! fold both sources without caring where each grant came from.
//!
//! Spec: website/docs/initial-idea/12-dynamic-permissions.md §"Two sources, one
//! engine". Symmetric merge — neither source is privileged.
//!
//! One store round trip per load ([`PermissionsRepo::live_grants_for_sub`]).
//! Soft-deleted users and databases drop inside that query, so a re-created
//! `(server, db_name)` never silently inherits old grants.

use crate::config::{Action, Constraints, Grant};
use crate::state::permissions::{GrantAction, LiveGrant, PermissionsRepo, RepoError};

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

/// Load the live DB grants attached to `user_sub`. Empty when the subject has
/// no live `permissions_users` row — the normal state for YAML-only users.
pub async fn load_db_grants_for(
    repo: &dyn PermissionsRepo,
    user_sub: &str,
) -> Result<Vec<Grant>, LoadError> {
    repo.live_grants_for_sub(user_sub)
        .await?
        .into_iter()
        .map(to_config_grant)
        .collect()
}

/// Project one store row. A wildcard becomes `database: "*"`, which the
/// evaluator matches against the databases the *config* declares.
pub(super) fn to_config_grant(grant: LiveGrant) -> Result<Grant, LoadError> {
    let constraints: Constraints = serde_json::from_value(grant.constraints).map_err(|source| {
        LoadError::DecodeConstraints {
            grant_id: grant.id,
            source,
        }
    })?;
    Ok(Grant {
        server: grant.server,
        database: grant.db_name.unwrap_or_else(|| "*".to_string()),
        action: action_from_db(grant.action),
        constraints,
    })
}

fn action_from_db(a: GrantAction) -> Action {
    match a {
        GrantAction::SchemaRead => Action::SchemaRead,
        GrantAction::QueryRead => Action::QueryRead,
        GrantAction::QueryWrite => Action::QueryWrite,
        GrantAction::HistoryRead => Action::HistoryRead,
    }
}
