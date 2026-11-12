//! The DB half of a refresh-token write, shared by plain inserts and the
//! transactional mint/rotate in [`super::grants`].

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::GrantIdentity;
use crate::auth::SessionId;
use crate::state::oauth::{self as db, NewRefreshToken};

/// Size cap on stored refresh tokens. Bounds resource exhaustion from tokens
/// belonging to many users or leaked tokens stored indefinitely.
pub(super) const REFRESH_TOKENS_MAX_SIZE: usize = 100_000;

/// A token for [`store_db`]: the digest, never the raw bearer.
pub(super) struct NewDbToken<'a> {
    pub(super) token_hash: [u8; 32],
    pub(super) identity: &'a GrantIdentity,
    pub(super) issued_at: DateTime<Utc>,
    pub(super) session_id: Option<SessionId>,
}

/// DB insert, refused at the cap (`Ok(false)`) in the same statement. The cap
/// is a resource ceiling on an unauthenticated-adjacent path, not an
/// invariant. Takes a connection so the rotation can run it inside its
/// transaction.
pub(super) async fn store_db(
    conn: &mut PgConnection,
    token: &NewDbToken<'_>,
    ttl: Duration,
) -> Result<bool, sqlx::Error> {
    // `expires_at` materializes the absolute deadline so GC and the CHECK
    // constraint are plain comparisons. An out-of-range TTL yields
    // `expires_at == chain_issued_at`, which the CHECK rejects — fail closed.
    let expires_at = ChronoDuration::from_std(ttl)
        .ok()
        .and_then(|ttl| token.issued_at.checked_add_signed(ttl))
        .unwrap_or(token.issued_at);
    db::insert_refresh_token_capped(
        conn,
        &NewRefreshToken {
            token_hash: &token.token_hash,
            user_sub: &token.identity.sub,
            email: &token.identity.email,
            groups: &token.identity.groups,
            chain_issued_at: token.issued_at,
            expires_at,
            session_id: token.session_id.map(Uuid::from),
        },
        REFRESH_TOKENS_MAX_SIZE as i64,
    )
    .await
}
