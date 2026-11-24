//! The in-process twin of `oauth_pending_flows` / `oauth_pending_consents`
//! behind [`super::PendingFlows`]' memory backend (tests and the auth-less
//! bootstrap). Keyed by the same digests as the tables.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use super::OAuthBridge;
use super::pending_flows::{
    CONSENT_TTL, FLOW_TTL, PENDING_CONSENTS_MAX_SIZE, PENDING_CONSENTS_PER_SUBJECT,
    PENDING_FLOWS_MAX_SIZE, PendingConsent,
};

#[derive(Default)]
pub(super) struct MemoryFlows {
    pub(super) flows: Mutex<Flows>,
    pub(super) consents: Mutex<HashMap<[u8; 32], HeldConsent>>,
}

pub(super) struct HeldFlow {
    pub(super) bridge: Option<OAuthBridge>,
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) struct HeldConsent {
    pub(super) consent: PendingConsent,
    pub(super) expires_at: DateTime<Utc>,
}

#[derive(Default)]
pub(super) struct Flows {
    pub(super) by_state: HashMap<[u8; 32], HeldFlow>,
    /// Insertion order. Every flow has the same TTL, so the front is both the
    /// oldest and the first to expire. May hold states already taken; those
    /// are skipped on eviction and dropped by `gc_expired`.
    pub(super) order: VecDeque<[u8; 32]>,
}

impl Flows {
    /// Drop the oldest still-present flow, skipping taken ones. O(1) amortized.
    fn evict_oldest(&mut self) {
        while let Some(state) = self.order.pop_front() {
            if self.by_state.remove(&state).is_some() {
                return;
            }
        }
    }
}

impl MemoryFlows {
    pub(super) async fn insert(&self, state_hash: [u8; 32], bridge: Option<OAuthBridge>) {
        let mut flows = self.flows.lock().await;
        if flows.by_state.len() >= PENDING_FLOWS_MAX_SIZE
            && !flows.by_state.contains_key(&state_hash)
        {
            flows.evict_oldest();
        }
        flows.order.push_back(state_hash);
        let expires_at = Utc::now() + FLOW_TTL;
        flows
            .by_state
            .insert(state_hash, HeldFlow { bridge, expires_at });
    }

    pub(super) async fn take(&self, state_hash: &[u8; 32]) -> Option<Option<OAuthBridge>> {
        let flow = self.flows.lock().await.by_state.remove(state_hash)?;
        (flow.expires_at > Utc::now()).then_some(flow.bridge)
    }

    pub(super) async fn insert_consent(&self, consent_hash: [u8; 32], consent: PendingConsent) {
        let mut consents = self.consents.lock().await;
        let sub = consent.identity.sub.clone();
        let held = consents
            .values()
            .filter(|held| held.consent.identity.sub == sub)
            .count();
        if held >= PENDING_CONSENTS_PER_SUBJECT {
            evict_soonest(&mut consents, |held| held.consent.identity.sub == sub);
        }
        if consents.len() >= PENDING_CONSENTS_MAX_SIZE {
            let now = Utc::now();
            consents.retain(|_, held| held.expires_at > now);
        }
        if consents.len() >= PENDING_CONSENTS_MAX_SIZE {
            evict_soonest(&mut consents, |_| true);
        }
        let expires_at = Utc::now() + CONSENT_TTL;
        consents.insert(
            consent_hash,
            HeldConsent {
                consent,
                expires_at,
            },
        );
    }

    pub(super) async fn take_consent(&self, consent_hash: &[u8; 32]) -> Option<PendingConsent> {
        let held = self.consents.lock().await.remove(consent_hash)?;
        (held.expires_at > Utc::now()).then_some(held.consent)
    }

    /// Remove all expired flows and consents (compacting the flow insertion
    /// order); returns how many were removed.
    pub(super) async fn gc_expired(&self) -> u64 {
        let now = Utc::now();
        let removed_flows = {
            let mut flows = self.flows.lock().await;
            let before = flows.by_state.len();
            flows.by_state.retain(|_, flow| flow.expires_at > now);
            let removed = before - flows.by_state.len();
            let Flows { by_state, order } = &mut *flows;
            order.retain(|state| by_state.contains_key(state));
            removed
        };
        let removed_consents = {
            let mut consents = self.consents.lock().await;
            let before = consents.len();
            consents.retain(|_, held| held.expires_at > now);
            before - consents.len()
        };
        (removed_flows + removed_consents) as u64
    }
}

/// Drop the soonest-expiring consent that `eligible` admits, if any.
fn evict_soonest(
    consents: &mut HashMap<[u8; 32], HeldConsent>,
    eligible: impl Fn(&HeldConsent) -> bool,
) {
    let soonest = consents
        .iter()
        .filter(|(_, held)| eligible(held))
        .min_by_key(|(_, held)| held.expires_at)
        .map(|(id, _)| *id);
    if let Some(id) = soonest {
        consents.remove(&id);
    }
}
