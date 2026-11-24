//! Redeeming a refresh token: the old pair out, a new pair in.

use std::time::Duration;

use chrono::{DateTime, Utc};

use super::grants::new_session;
use super::refresh_chain::chain_expired;
use super::refresh_db::{revoke_paired, revoke_reused_chain};
use super::refresh_tokens::RefreshBackend;
use super::{Minted, RefreshToken, RefreshTokens, hash_secret};
use crate::auth::session::is_service_subject;
use crate::auth::{AuthError, SessionStore};
use crate::state::oauth as db;

/// What redeeming a refresh token came to.
#[derive(Debug)]
pub enum Rotation {
    Rotated(Minted),
    /// Unknown, replayed or lapsed token.
    Refused,
    /// The chain's login is older than `GROUPS_MAX_AGE`. Its token is spent
    /// and its session revoked; only a fresh login re-reads the groups.
    ReloginRequired,
}

/// How long a session minted now may run on the groups read at `chain_born`:
/// `session_ttl`, cut short at `groups_max_age`. `None` once that age is
/// reached. A birth time in the future (clock step) counts as age zero.
fn session_ttl_left(
    session_ttl: Duration,
    groups_max_age: Option<Duration>,
    chain_born: DateTime<Utc>,
) -> Option<Duration> {
    let Some(max_age) = groups_max_age else {
        return Some(session_ttl);
    };
    let age = Utc::now()
        .signed_duration_since(chain_born)
        .to_std()
        .unwrap_or_default();
    let left = max_age.checked_sub(age).filter(|left| !left.is_zero())?;
    Some(session_ttl.min(left))
}

impl RefreshTokens {
    /// [`Self::rotate_within`] with no bound on the age of the chain's groups.
    pub async fn rotate(
        &self,
        sessions: &SessionStore,
        presented: &str,
        refresh_token: String,
        session_ttl: Duration,
    ) -> Result<Option<Minted>, AuthError> {
        let rotation = self
            .rotate_within(sessions, presented, refresh_token, session_ttl, None)
            .await?;
        Ok(match rotation {
            Rotation::Rotated(minted) => Some(minted),
            Rotation::Refused | Rotation::ReloginRequired => None,
        })
    }

    /// Redeem `presented`: consume it, revoke its paired session, and mint a
    /// new session + refresh token that inherit the chain's birth time. With
    /// `groups_max_age`, the new session ends no later than that age after
    /// the chain's login, and a chain already past it is ended instead. On
    /// the DB backend a replay of an already-rotated token also revokes the
    /// whole chain (RFC 9700 §4.14.2); the memory backend (tests only) does
    /// not track chains.
    pub async fn rotate_within(
        &self,
        sessions: &SessionStore,
        presented: &str,
        refresh_token: String,
        session_ttl: Duration,
        groups_max_age: Option<Duration>,
    ) -> Result<Rotation, AuthError> {
        let RefreshBackend::Db(pool) = &self.backend else {
            let Some(old) = self.take(presented).await else {
                return Ok(Rotation::Refused);
            };
            if let Some(id) = old.session_id {
                sessions.revoke(id).await?;
            }
            let Some(ttl) = session_ttl_left(session_ttl, groups_max_age, old.issued_at) else {
                return Ok(Rotation::ReloginRequired);
            };
            let minted = self
                .mint_in_memory(
                    sessions,
                    old.identity,
                    refresh_token,
                    ttl,
                    Some(old.issued_at),
                )
                .await?;
            return Ok(Rotation::Rotated(minted));
        };

        let mut tx = pool.begin().await?;
        let presented_hash = hash_secret(presented);
        // Lock before consuming, so a concurrent logout of this subject or
        // reuse-revocation of this chain sees either none or all of this
        // rotation.
        if let Some((sub, chain_id)) = db::live_chain(&mut *tx, &presented_hash).await? {
            db::lock_subject(&mut *tx, &sub).await?;
            db::lock_chain(&mut *tx, chain_id).await?;
        }
        let Some(row) = db::rotate_out_refresh_token(&mut *tx, &presented_hash).await? else {
            let revoked = revoke_reused_chain(&mut tx, &presented_hash).await?;
            tx.commit().await?;
            sessions.committed(None, &revoked).await;
            return Ok(Rotation::Refused);
        };
        let chain_id = row.chain_id;
        let old = RefreshToken::from(row);
        // A reserved-subject chain predates the IdP-login check; end it too.
        if chain_expired(old.issued_at, Utc::now(), self.ttl())
            || is_service_subject(&old.identity.sub)
        {
            // Commit the delete: a lapsed chain is dead either way.
            tx.commit().await?;
            return Ok(Rotation::Refused);
        }
        let revoked = revoke_paired(&mut tx, old.session_id).await?;
        let Some(ttl) = session_ttl_left(session_ttl, groups_max_age, old.issued_at) else {
            // The token is consumed and its session revoked: nothing of this
            // login outlives the bound.
            tx.commit().await?;
            sessions.committed(None, &revoked).await;
            tracing::info!(%chain_id, "refresh refused: login older than GROUPS_MAX_AGE");
            return Ok(Rotation::ReloginRequired);
        };
        let session = new_session(&old.identity, ttl, Some(old.issued_at));
        SessionStore::insert_in(&mut tx, &session).await?;
        self.store_paired(
            &mut tx,
            &refresh_token,
            &old.identity,
            old.issued_at,
            chain_id,
            session.id,
        )
        .await?;
        tx.commit().await?;
        sessions.committed(Some(&session), &revoked).await;
        Ok(Rotation::Rotated(Minted {
            session,
            session_ttl: ttl,
            refresh_token,
        }))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn born(ago: Duration) -> DateTime<Utc> {
        Utc::now() - ChronoDuration::from_std(ago).expect("in range")
    }

    #[test]
    fn no_bound_leaves_the_session_ttl_alone() {
        assert_eq!(
            session_ttl_left(8 * HOUR, None, born(400 * 24 * HOUR)),
            Some(8 * HOUR)
        );
    }

    #[test]
    fn a_session_never_outlives_the_groups_it_carries() {
        let left = session_ttl_left(8 * HOUR, Some(12 * HOUR), born(10 * HOUR)).expect("in bound");
        assert!(
            left <= 2 * HOUR && left > 2 * HOUR - Duration::from_secs(5),
            "{left:?}"
        );
        assert_eq!(
            session_ttl_left(8 * HOUR, Some(12 * HOUR), born(HOUR)),
            Some(8 * HOUR)
        );
    }

    #[test]
    fn at_or_past_the_bound_there_is_nothing_left() {
        assert_eq!(
            session_ttl_left(8 * HOUR, Some(12 * HOUR), born(12 * HOUR)),
            None
        );
        assert_eq!(
            session_ttl_left(8 * HOUR, Some(12 * HOUR), born(30 * HOUR)),
            None
        );
    }

    #[test]
    fn a_birth_time_in_the_future_counts_as_age_zero() {
        let future = Utc::now() + ChronoDuration::minutes(5);
        assert_eq!(session_ttl_left(8 * HOUR, Some(HOUR), future), Some(HOUR));
    }
}
