//! [`super::PendingFlows`]' state-DB backend: the row shapes of
//! `oauth_pending_flows` / `oauth_pending_consents` (migration 0022) mapped to
//! the login types. Every failure is logged here and surfaces as
//! [`StoreError::Backend`], never with its `sqlx::Error` (the DSN rule).

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::pending_flows::{
    CONSENT_TTL, FLOW_TTL, PENDING_CONSENTS_MAX_SIZE, PENDING_CONSENTS_PER_SUBJECT,
    PENDING_FLOWS_MAX_SIZE, PendingConsent,
};
use super::{ClientName, GrantIdentity, OAuthBridge, StoreError};
use crate::state::oauth::{self as db, ConsentCaps, ConsentRow, NewConsent};

/// The `bridge` column. Its own type so the stored shape is explicit and
/// `OAuthBridge` carries no serde surface.
#[derive(Serialize, Deserialize)]
struct BridgeColumn {
    client_id: String,
    client_name: Option<String>,
    client_redirect_uri: String,
    client_state: String,
    code_challenge: String,
    resource: Option<String>,
}

fn bridge_to_json(bridge: &OAuthBridge) -> Result<serde_json::Value, StoreError> {
    serde_json::to_value(BridgeColumn {
        client_id: bridge.client_id.clone(),
        client_name: bridge
            .client_name
            .as_ref()
            .map(|name| name.as_str().to_owned()),
        client_redirect_uri: bridge.client_redirect_uri.clone(),
        client_state: bridge.client_state.clone(),
        code_challenge: bridge.code_challenge.clone(),
        resource: bridge.resource.clone(),
    })
    .map_err(|_| backend_error("encode bridge"))
}

fn bridge_from_json(value: serde_json::Value) -> Result<OAuthBridge, StoreError> {
    let column: BridgeColumn =
        serde_json::from_value(value).map_err(|_| backend_error("decode bridge"))?;
    Ok(OAuthBridge {
        client_id: column.client_id,
        // Validated at `/register`; a name that no longer parses is dropped,
        // as the client registry drops it, rather than failing the login.
        client_name: column
            .client_name
            .and_then(|name| ClientName::parse(&name).ok().flatten()),
        client_redirect_uri: column.client_redirect_uri,
        client_state: column.client_state,
        code_challenge: column.code_challenge,
        resource: column.resource,
    })
}

pub(super) async fn insert(
    pool: &PgPool,
    state_hash: &[u8; 32],
    bridge: Option<&OAuthBridge>,
) -> Result<(), StoreError> {
    let bridge = bridge.map(bridge_to_json).transpose()?;
    db::insert_flow(
        pool,
        state_hash,
        bridge.as_ref(),
        FLOW_TTL,
        PENDING_FLOWS_MAX_SIZE as i64,
    )
    .await
    .map_err(|_| backend_error("insert flow"))
}

pub(super) async fn take(
    pool: &PgPool,
    state_hash: &[u8; 32],
) -> Result<Option<Option<OAuthBridge>>, StoreError> {
    let taken = db::take_flow(pool, state_hash)
        .await
        .map_err(|_| backend_error("take flow"))?;
    match taken {
        None => Ok(None),
        Some(None) => Ok(Some(None)),
        Some(Some(bridge)) => Ok(Some(Some(bridge_from_json(bridge)?))),
    }
}

pub(super) async fn insert_consent(
    pool: &PgPool,
    consent_hash: &[u8; 32],
    consent: &PendingConsent,
) -> Result<(), StoreError> {
    let bridge = bridge_to_json(&consent.bridge)?;
    let row = NewConsent {
        consent_hash,
        csrf_hash: &consent.csrf_hash,
        user_sub: &consent.identity.sub,
        email: &consent.identity.email,
        groups: &consent.identity.groups,
        bridge: &bridge,
    };
    let caps = ConsentCaps {
        per_subject: PENDING_CONSENTS_PER_SUBJECT as i64,
        total: PENDING_CONSENTS_MAX_SIZE as i64,
    };
    let write = async {
        let mut tx = pool.begin().await?;
        db::insert_consent(&mut tx, &row, CONSENT_TTL, caps).await?;
        tx.commit().await
    };
    write.await.map_err(|_| backend_error("insert consent"))
}

pub(super) async fn take_consent(
    pool: &PgPool,
    consent_hash: &[u8; 32],
) -> Result<Option<PendingConsent>, StoreError> {
    let taken = db::take_consent(pool, consent_hash)
        .await
        .map_err(|_| backend_error("take consent"))?;
    let Some(row) = taken else {
        return Ok(None);
    };
    consent_from_row(row).map(Some)
}

fn consent_from_row(row: ConsentRow) -> Result<PendingConsent, StoreError> {
    let csrf_hash = <[u8; 32]>::try_from(row.csrf_hash.as_slice())
        .map_err(|_| backend_error("decode consent"))?;
    Ok(PendingConsent {
        identity: GrantIdentity {
            sub: row.user_sub,
            email: row.email,
            groups: row.groups.0,
        },
        bridge: bridge_from_json(row.bridge.0)?,
        csrf_hash,
    })
}

pub(super) async fn gc_expired(pool: &PgPool) -> u64 {
    db::delete_expired_login_flows(pool)
        .await
        .unwrap_or_else(|_| {
            backend_error("GC");
            0
        })
}

/// Logs the failed operation and yields [`StoreError::Backend`]. Deliberately
/// drops the error source: a `sqlx::Error` can render the DSN.
fn backend_error(operation: &'static str) -> StoreError {
    tracing::warn!(operation, "pending login state-DB call failed");
    StoreError::Backend
}
