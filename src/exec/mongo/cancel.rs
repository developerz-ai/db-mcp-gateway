//! Best-effort server-side cancellation for the mongo adapter (#141).
//!
//! Postgres has `pg_cancel_backend(pid)`: the pid is known before the query
//! starts and cancelling your own backend needs no extra privilege. Mongo has
//! no equivalent primitive reachable from this driver — the only route is
//! `currentOp` + `killOp`, and both come with real constraints:
//!
//! - `comment` on an arbitrary command (the only way to correlate a
//!   `currentOp` entry back to *this* request) requires MongoDB **4.4+**.
//!   The gateway's minimum supported Mongo version is 4.4 — see
//!   `config-reference.md` §Mongo.
//! - `killOp` is a cluster-admin action (`killop` on `cluster` resource, or
//!   the built-in `clusterManager` role) — NOT part of a least-privilege
//!   read-only role. Operators who want mongo cancellation must grant it
//!   explicitly on the gateway's mongo role; deployment docs call this out.
//!   Without it, `killOp` fails, the guard logs a warning, and `maxTimeMS`
//!   remains the only bound — identical to pre-#141 behavior.
//! - The lookup is inherently best-effort: `currentOp` is polled once, after
//!   the drop fires, and races the operation's own registration. A very
//!   short-lived operation may already be gone by the time we look. This is
//!   an accepted trade-off (YAGNI: don't build a polling loop for a gap this
//!   narrow) — `maxTimeMS` remains the hard backstop either way.

use mongodb::Client;
use mongodb::bson::{Bson, Document, doc};
use uuid::Uuid;

/// Stamp a unique `comment` on `cmd` and return the marker. Unconditional
/// overwrite — same rationale as the `maxTimeMS` stamp in `dispatch`: a
/// caller-supplied `comment` could otherwise collide with (or spoof) the
/// marker this module searches for in `currentOp`.
pub fn stamp_marker(cmd: &mut Document) -> String {
    let marker = Uuid::new_v4().to_string();
    cmd.insert("comment", marker.clone());
    marker
}

/// Fires `currentOp` + `killOp` from a detached task if dropped while armed —
/// the mongo analogue of `pg::CancelOnDrop`. See module docs for why this is
/// best-effort rather than a guarantee.
///
/// Disarmed on the normal path once the command has run to completion, so a
/// cleanly-finished operation is never targeted.
pub struct KillOpOnDrop {
    /// `Some` while armed: the client (to open the admin-db connection) and
    /// the marker stamped on this request's command.
    armed: Option<(Client, String)>,
}

impl KillOpOnDrop {
    pub fn armed(client: Client, marker: String) -> Self {
        Self {
            armed: Some((client, marker)),
        }
    }

    pub fn disarm(&mut self) {
        self.armed = None;
    }
}

impl Drop for KillOpOnDrop {
    fn drop(&mut self) {
        let Some((client, marker)) = self.armed.take() else {
            return;
        };
        // Detached: the parent future is being dropped, so we can't await
        // inline. Runs on a fresh task independent of the dropped future.
        tokio::spawn(async move {
            let admin = client.database("admin");
            let Some(opid) = find_opid_by_marker(&admin, &marker).await else {
                return;
            };
            if let Err(err) = admin.run_command(doc! { "killOp": 1, "op": opid }).await {
                // `killOp` commonly fails with "unauthorized" when the role
                // lacks the privilege documented in the module docs — that
                // is an expected, not exceptional, outcome for operators who
                // haven't opted in. Warn, don't error: `maxTimeMS` is still
                // the backstop.
                tracing::warn!(%err, "killOp failed during mongo cancel (missing privilege, or op already finished)");
            }
        });
    }
}

/// Look up the `opid` of the in-progress operation carrying `marker` as its
/// `command.comment`. Returns `None` on any lookup failure or if nothing
/// matched — both are expected outcomes (see module docs), not exceptions to
/// propagate.
async fn find_opid_by_marker(admin: &mongodb::Database, marker: &str) -> Option<Bson> {
    let response = admin
        .run_command(doc! {
            "currentOp": 1,
            "$ownOps": false,
            "command.comment": marker,
        })
        .await
        .inspect_err(|err| {
            tracing::warn!(%err, "currentOp lookup failed during mongo cancel");
        })
        .ok()?;
    let inprog = response.get_array("inprog").ok()?;
    let entry = inprog.first()?;
    let Bson::Document(entry_doc) = entry else {
        return None;
    };
    entry_doc.get("opid").cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_marker_inserts_comment_and_returns_it() {
        let mut cmd = doc! { "find": "users" };
        let marker = stamp_marker(&mut cmd);
        assert_eq!(cmd.get_str("comment").unwrap(), marker);
        // Sanity: markers are actually unique, not a constant placeholder.
        let mut cmd2 = doc! { "find": "users" };
        let marker2 = stamp_marker(&mut cmd2);
        assert_ne!(marker, marker2);
    }

    /// A caller-supplied `comment` must never survive the stamp — otherwise
    /// it could collide with (or be crafted to match) another request's
    /// marker and confuse the currentOp lookup.
    #[test]
    fn stamp_marker_overwrites_existing_comment() {
        let mut cmd = doc! { "find": "users", "comment": "caller-supplied" };
        let marker = stamp_marker(&mut cmd);
        assert_eq!(cmd.get_str("comment").unwrap(), marker);
        assert_ne!(marker, "caller-supplied");
    }

    /// `disarm()` must prevent the detached spawn on drop. `Client::with_options`
    /// never opens a connection until first use (same posture as `mod.rs`'s
    /// own tests), so this is safe to construct without a real mongo
    /// instance — the assertion is just that `armed` is `None` after
    /// `disarm()`, which is what `Drop::drop` checks before spawning.
    #[tokio::test]
    async fn disarm_prevents_drop_from_spawning() {
        use mongodb::options::{ClientOptions, ServerAddress};

        let options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: "localhost".to_string(),
                port: Some(27017),
            }])
            .build();
        let client = Client::with_options(options).expect("client constructs");

        let mut guard = KillOpOnDrop::armed(client, "unused-marker".to_string());
        assert!(guard.armed.is_some());
        guard.disarm();
        assert!(guard.armed.is_none());
        // Drop now runs with `armed == None` — `Drop::drop`'s `let Some(...)
        // = ... else { return }` returns immediately, no spawn.
    }
}
