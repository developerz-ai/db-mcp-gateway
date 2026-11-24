//! A refresh grant and its paired access session, changed together.
//!
//! On the DB backend each operation is one state-DB transaction, so a failure
//! leaves the previous state intact: a failed rotation keeps the old chain
//! usable, and a rotation never leaves both the old and new session live. The
//! memory backend (tests only) runs the same steps without the transaction.

use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::refresh_db::{NewDbToken, store_db};
use super::refresh_tokens::RefreshBackend;
use super::{GrantIdentity, RefreshTokens, hash_secret};
use crate::auth::{AuthError, Session, SessionId, SessionStore};
use crate::state::oauth as db;

/// A freshly minted session and the refresh token paired with it. `Debug`
/// redacts the token.
pub struct Minted {
    pub session: Session,
    /// The lifetime `session` was minted with: the bearer's `expires_in`.
    pub session_ttl: Duration,
    pub refresh_token: String,
}

impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted")
            .field("session", &self.session)
            .field("session_ttl", &self.session_ttl)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// Why a fresh authorization got no grant handed back.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    /// Failed before any COMMIT was sent: nothing exists, a retry is safe.
    #[error(transparent)]
    NotMinted(#[from] AuthError),
    /// The grant was or may have been committed, but its tokens never reached
    /// the caller. A retry could mint a second grant for one authorization.
    #[error("grant minted or commit outcome unknown; tokens not delivered")]
    Unconfirmed,
}

impl RefreshTokens {
    /// Start a chain for a fresh authorization: a new session plus a refresh
    /// token paired with it. `refresh_token` is the caller-generated bearer.
    pub async fn mint(
        &self,
        sessions: &SessionStore,
        identity: GrantIdentity,
        refresh_token: String,
        session_ttl: Duration,
    ) -> Result<Minted, MintError> {
        let RefreshBackend::Db(pool) = &self.backend else {
            let minted = self
                .mint_in_memory(sessions, identity, refresh_token, session_ttl, None)
                .await?;
            return Ok(minted);
        };
        let session = new_session(&identity, session_ttl, None);
        let mut tx = pool.begin().await.map_err(AuthError::from)?;
        self.write_fresh_chain(&mut tx, &identity, &refresh_token, &session)
            .await?;
        // An error here does not say which way the commit went.
        tx.commit().await.map_err(|_| MintError::Unconfirmed)?;
        sessions.committed(Some(&session), &[]).await;
        Ok(Minted {
            session,
            session_ttl,
            refresh_token,
        })
    }

    /// RFC 7009 for a refresh token: end its chain and revoke the paired
    /// session. A token a rotation has already consumed still names its
    /// chain, so a revoke that loses the race to a rotation ends the pair
    /// that rotation minted. `Ok(false)` when `presented` was never a refresh
    /// token of a chain that is still live.
    pub async fn revoke(
        &self,
        sessions: &SessionStore,
        presented: &str,
    ) -> Result<bool, AuthError> {
        let RefreshBackend::Db(pool) = &self.backend else {
            let Some(old) = self.take(presented).await else {
                return Ok(false);
            };
            if let Some(id) = old.session_id {
                sessions.revoke(id).await?;
            }
            return Ok(true);
        };
        Self::revoke_in(sessions, pool.begin().await?, presented).await
    }

    /// Logout: revoke every session of `sub` and drop every refresh chain, in
    /// one transaction, after waiting out any in-flight mint or rotation for
    /// `sub`. Returns the number of sessions revoked.
    pub async fn end_all_for_sub(
        &self,
        sessions: &SessionStore,
        sub: &str,
    ) -> Result<usize, AuthError> {
        let RefreshBackend::Db(pool) = &self.backend else {
            let revoked = sessions.revoke_all_for_sub(sub).await?;
            self.purge_for_sub(sub).await;
            return Ok(revoked);
        };
        let mut tx = pool.begin().await?;
        db::lock_subject(&mut *tx, sub).await?;
        let revoked = SessionStore::revoke_all_for_sub_in(&mut tx, sub).await?;
        db::delete_refresh_tokens_for_sub(&mut *tx, sub).await?;
        tx.commit().await?;
        sessions.committed(None, &revoked).await;
        Ok(revoked.len())
    }

    /// The memory backend's mint (tests only): no transaction to lose.
    pub(super) async fn mint_in_memory(
        &self,
        sessions: &SessionStore,
        identity: GrantIdentity,
        refresh_token: String,
        session_ttl: Duration,
        chain_born: Option<DateTime<Utc>>,
    ) -> Result<Minted, AuthError> {
        let session = sessions
            .create(
                &identity.sub,
                &identity.email,
                &identity.groups,
                session_ttl,
                chain_born,
            )
            .await?;
        // The memory backend's only failure is its size cap.
        self.store(
            &refresh_token,
            identity,
            session.issued_at,
            Some(session.id),
        )
        .await
        .map_err(|_| AuthError::StoreFull)?;
        Ok(Minted {
            session,
            session_ttl,
            refresh_token,
        })
    }

    /// Everything a fresh grant writes, up to but not including its COMMIT.
    async fn write_fresh_chain(
        &self,
        tx: &mut sqlx::PgConnection,
        identity: &GrantIdentity,
        refresh_token: &str,
        session: &Session,
    ) -> Result<(), AuthError> {
        db::lock_subject(&mut *tx, &identity.sub).await?;
        SessionStore::insert_in(tx, session).await?;
        // A fresh chain is born with its session, so both clocks start together.
        let (born, chain_id) = (session.issued_at, Uuid::new_v4());
        self.store_paired(tx, refresh_token, identity, born, chain_id, session.id)
            .await
    }

    pub(super) async fn store_paired(
        &self,
        conn: &mut sqlx::PgConnection,
        refresh_token: &str,
        identity: &GrantIdentity,
        chain_born: DateTime<Utc>,
        chain_id: Uuid,
        session_id: SessionId,
    ) -> Result<(), AuthError> {
        let token = NewDbToken {
            token_hash: hash_secret(refresh_token),
            identity,
            issued_at: chain_born,
            session_id: Some(session_id),
            chain_id,
        };
        if store_db(conn, &token, self.ttl()).await? {
            Ok(())
        } else {
            Err(AuthError::StoreFull)
        }
    }
}

/// `chain_born` doubles as the session's `issued_at` so
/// `admin.session_max_age_secs` counts from the original login.
pub(super) fn new_session(
    identity: &GrantIdentity,
    ttl: Duration,
    chain_born: Option<DateTime<Utc>>,
) -> Session {
    SessionStore::prepare(
        &identity.sub,
        &identity.email,
        &identity.groups,
        ttl,
        chain_born,
    )
}
