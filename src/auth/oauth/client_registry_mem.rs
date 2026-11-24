//! The in-process twin of the `oauth_clients` table behind
//! [`super::ClientRegistry`]'s memory backend (tests only).

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::client_registry::{CLIENT_CAP, ClientRecord, UNAUTHORISED_CLIENT_TTL};
use crate::state::oauth::LiveClient;

#[derive(Debug, Clone)]
pub(super) struct RegisteredClient {
    pub(super) record: ClientRecord,
    pub(super) created_at: DateTime<Utc>,
    pub(super) expires_at: DateTime<Utc>,
}

impl RegisteredClient {
    pub(super) fn evictable(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now || self.expires_at <= self.created_at + UNAUTHORISED_CLIENT_TTL
    }
}

/// Memory twin of `db::insert_client_capped`.
pub(super) fn insert_mem(
    map: &mut HashMap<String, RegisteredClient>,
    client_id: String,
    record: ClientRecord,
    live: LiveClient,
) -> bool {
    let now = Utc::now();
    if map.len() >= CLIENT_CAP as usize {
        let oldest = map
            .iter()
            .filter(|(_, c)| c.evictable(now))
            .min_by_key(|(_, c)| c.created_at)
            .map(|(id, _)| id.clone());
        let Some(oldest) = oldest else {
            return false;
        };
        map.remove(&oldest);
    }
    match map.get_mut(&client_id) {
        Some(existing) if existing.expires_at > now => match live {
            LiveClient::Replace => existing.record = record,
            LiveClient::Keep => return false,
        },
        // Absent, or lapsed but not yet GC'd: (re)start as never-used.
        _ => {
            map.insert(
                client_id,
                RegisteredClient {
                    record,
                    created_at: now,
                    expires_at: now + UNAUTHORISED_CLIENT_TTL,
                },
            );
        }
    }
    true
}
