//! Typed error for the permissions store. Display strings never quote row
//! content: the admin layer logs only the variant type, never `%err`.

use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("permissions db query failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("row encodes unknown db_type {0:?}")]
    UnknownDbType(String),
    #[error("row encodes unknown action {0:?}")]
    UnknownAction(String),
    /// Row violates the XOR target check — should be impossible given the DB
    /// constraint, but surface it as an error rather than panicking.
    #[error("grant row violates target/wildcard XOR invariant")]
    InvalidGrantTarget {
        server: Option<String>,
        database_id: Option<Uuid>,
        wildcard: bool,
    },
    #[error("failed to encode groups JSON")]
    EncodeGroups(#[source] serde_json::Error),
    #[error("failed to decode groups JSON")]
    DecodeGroups(#[source] serde_json::Error),
}
