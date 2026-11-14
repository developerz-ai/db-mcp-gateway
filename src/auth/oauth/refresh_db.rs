//! The DB half of refresh-token writes and revocations, shared by plain
//! inserts and the transactional mint/rotate in [`super::grants`].

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::GrantIdentity;
use crate::auth::{AuthError, SessionId, SessionStore};
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
    pub(super) chain_id: Uuid,
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
            chain_id: token.chain_id,
        },
        REFRESH_TOKENS_MAX_SIZE as i64,
    )
    .await
}

/// A client firing parallel refreshes with one token (e.g. several MCP
/// connections) replays it within moments; that is not theft, so no revoke.
const REUSE_GRACE: chrono::Duration = chrono::Duration::seconds(10);

/// A miss on a token rotated out more than [`REUSE_GRACE`] ago means it was
/// replayed — by a thief or by the client it was stolen from,
/// indistinguishably — so end its chain and the chain's live session. Returns
/// the sessions this revoked.
pub(super) async fn revoke_reused_chain(
    conn: &mut sqlx::PgConnection,
    presented_hash: &[u8],
) -> Result<Vec<SessionId>, AuthError> {
    let Some(chain_id) = db::rotated_chain(&mut *conn, presented_hash, REUSE_GRACE).await? else {
        return Ok(Vec::new());
    };
    // Waits out an in-flight rotation; the delete below then sees its token.
    db::lock_chain(&mut *conn, chain_id).await?;
    let mut revoked = Vec::new();
    for paired in db::delete_chain(&mut *conn, chain_id).await? {
        revoked.extend(revoke_paired(conn, paired.map(SessionId::from)).await?);
    }
    tracing::warn!(%chain_id, "rotated refresh token replayed; chain revoked");
    Ok(revoked)
}

/// Revoke the session paired with a consumed refresh token; returns it only if
/// this call revoked it, so counters count real revocations.
pub(super) async fn revoke_paired(
    conn: &mut sqlx::PgConnection,
    paired: Option<SessionId>,
) -> Result<Vec<SessionId>, AuthError> {
    let mut revoked = Vec::new();
    if let Some(id) = paired
        && SessionStore::revoke_in(conn, id).await?
    {
        revoked.push(id);
    }
    Ok(revoked)
}
