//! Dynamic-Client-Registration store for the MCP OAuth bridge.
//!
//! `POST /register` records a client's redirect-URI allowlist here under a
//! generated `client_id`; `/authorize` later matches the requested
//! `redirect_uri` against this set exactly (OAuth 2.1 redirect allowlist /
//! RFC 8252). In-memory and bounded (TTL + hard cap) because `/register` is
//! unauthenticated — see the single-replica deployment note in
//! `docs/initial-idea/04-auth-sso.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// TTL for a Dynamic-Client-Registration entry. A client registers, then walks
/// `/authorize` → `/token` right away and only re-authorizes on a full browser
/// re-login (refresh covers the common renewal), so the entry need only outlive
/// that. In-memory like every other flow store (see the single-replica
/// deployment note); a restart drops it and a spec-compliant client simply
/// re-registers on the next `invalid_client`.
const CLIENT_TTL: Duration = Duration::from_secs(24 * 3600);

/// Hard cap on registered clients. `/register` is unauthenticated (open DCR per
/// RFC 7591), so the map needs a ceiling or a flood could exhaust memory. At the
/// cap (after GC drops expired entries) a new registration is *rejected* rather
/// than evicting a live client: evicting the soonest-to-expire entry would let
/// an unauthenticated flood knock legitimate clients out of their in-flight
/// `/authorize` (`invalid_client`). Bounded memory that still self-heals as
/// TTLs lapse.
const CLIENT_CAP: usize = 10_000;

/// Bounded registry of Dynamic-Client-Registration clients: `client_id` → its
/// registered redirect URIs. `/authorize` matches the requested `redirect_uri`
/// against this set exactly, so a client can only be sent an authorization code
/// at a URI it pre-registered (OAuth 2.1 redirect allowlist / RFC 8252).
#[derive(Clone, Default, Debug)]
pub struct ClientRegistry {
    inner: Arc<Mutex<HashMap<String, RegisteredClient>>>,
}

#[derive(Debug, Clone)]
struct RegisteredClient {
    redirect_uris: Vec<String>,
    expires_at: Instant,
}

impl ClientRegistry {
    /// Record a freshly registered client's redirect URIs (validated by the
    /// caller). Drops expired entries first; if still at the cap, rejects the
    /// new registration (`false`) rather than evicting a live client — an
    /// unauthenticated `/register` must never be able to knock out a legitimate
    /// client mid-flow. Returns `true` once recorded; updating an existing
    /// `client_id` always succeeds (it doesn't grow the map).
    pub async fn insert(&self, client_id: String, redirect_uris: Vec<String>) -> bool {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        if map.len() >= CLIENT_CAP && !map.contains_key(&client_id) {
            return false;
        }
        map.insert(
            client_id,
            RegisteredClient {
                redirect_uris,
                expires_at: Instant::now() + CLIENT_TTL,
            },
        );
        true
    }

    /// The registered redirect URIs for `client_id`, if the registration is
    /// still live. `None` means "unknown client" — `/authorize` rejects it.
    pub async fn redirect_uris(&self, client_id: &str) -> Option<Vec<String>> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.get(client_id).map(|c| c.redirect_uris.clone())
    }

    fn gc(map: &mut HashMap<String, RegisteredClient>) {
        let now = Instant::now();
        map.retain(|_, c| c.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_then_lookup_roundtrips() {
        let reg = ClientRegistry::default();
        assert!(reg.insert("c1".into(), vec!["https://app/cb".into()]).await);
        assert_eq!(
            reg.redirect_uris("c1").await,
            Some(vec!["https://app/cb".into()])
        );
        assert_eq!(reg.redirect_uris("unknown").await, None);
    }

    #[tokio::test]
    async fn at_cap_rejects_new_but_updates_existing() {
        let reg = ClientRegistry::default();
        {
            let mut map = reg.inner.lock().await;
            for i in 0..CLIENT_CAP {
                map.insert(
                    format!("c{i}"),
                    RegisteredClient {
                        redirect_uris: vec!["https://app/cb".into()],
                        expires_at: Instant::now() + CLIENT_TTL,
                    },
                );
            }
        }
        // At cap: a brand-new client is refused, no live client evicted.
        assert!(
            !reg.insert("overflow".into(), vec!["https://app/cb".into()])
                .await
        );
        assert_eq!(reg.redirect_uris("overflow").await, None);
        assert!(reg.redirect_uris("c0").await.is_some());
        // Updating an already-registered client still succeeds at cap.
        assert!(
            reg.insert("c0".into(), vec!["https://app/new".into()])
                .await
        );
        assert_eq!(
            reg.redirect_uris("c0").await,
            Some(vec!["https://app/new".into()])
        );
    }
}
