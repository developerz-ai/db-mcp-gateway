//! The one shape of every admin mutation:
//! begin → lock actor → lock + mutate target → audit → notify → commit →
//! invalidate the local cache.
//!
//! Data rows, their `permissions_audit` rows and the cross-replica `NOTIFY`
//! share one transaction: an audit failure rolls the data back (CLAUDE.md
//! MUST #4) and a rolled-back write notifies no one. Local invalidation runs
//! only after commit, so a failed write never bumps a cache revision.

use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::audit::permissions::{
    self, PermissionsAuditAction, PermissionsAuditRow, PermissionsAuditTargetType,
};
use crate::authz::PermissionsCache;
use crate::state::permissions::pg::{notify, users};
use crate::state::permissions::{PermissionsChange, RepoError};

use super::error::AdminError;
use super::middleware::AdminActor;
use super::validation::{internal, store_error};

pub(super) struct AuditedTx<'a> {
    tx: Transaction<'static, Postgres>,
    actor: &'a AdminActor,
    actor_id: Option<Uuid>,
}

impl<'a> AuditedTx<'a> {
    /// Begin without touching the actor row — for a users mutation that must
    /// first learn whether its target *is* the actor.
    pub(super) async fn begin(pool: &PgPool, actor: &'a AdminActor) -> Result<Self, AdminError> {
        let tx = pool
            .begin()
            .await
            .map_err(|err| internal("begin tx", err, &actor.request_id))?;
        Ok(Self {
            tx,
            actor,
            actor_id: None,
        })
    }

    /// Begin and upsert the actor's row before anything else, so every admin
    /// write locks its actor row before its target rows — one lock order.
    pub(super) async fn begin_locked(
        pool: &PgPool,
        actor: &'a AdminActor,
    ) -> Result<Self, AdminError> {
        let mut audited = Self::begin(pool, actor).await?;
        audited.lock_actor().await?;
        Ok(audited)
    }

    pub(super) async fn lock_actor(&mut self) -> Result<(), AdminError> {
        let a = self.actor;
        let id = users::tx_upsert_actor(&mut self.tx, &a.sub, &a.email, &a.groups)
            .await
            .map_err(|err| store_error("upsert_actor", err, &a.request_id))?;
        self.actor_id = Some(id);
        Ok(())
    }

    /// The mutation targets the actor's own user row. Upserting the actor
    /// would overwrite (or resurrect) that row with the session snapshot, so
    /// the target row stands in as the actor.
    pub(super) fn actor_is(&mut self, id: Uuid) {
        self.actor_id = Some(id);
    }

    pub(super) fn tx(&mut self) -> &mut Transaction<'static, Postgres> {
        &mut self.tx
    }

    pub(super) fn request_id(&self) -> &'a str {
        &self.actor.request_id
    }

    /// Append one `permissions_audit` row inside the transaction.
    pub(super) async fn audit(
        &mut self,
        action: PermissionsAuditAction,
        target_type: PermissionsAuditTargetType,
        target_id: Uuid,
        before: Option<JsonValue>,
        after: Option<JsonValue>,
    ) -> Result<(), AdminError> {
        let request_id = self.request_id();
        // A mutation that reached here without an actor id is a handler bug;
        // refuse rather than audit an anonymous change.
        let actor_id = self
            .actor_id
            .ok_or_else(|| internal("audit without actor", (), request_id))?;
        let row = PermissionsAuditRow {
            actor_id,
            actor_email: self.actor.email.clone(),
            action,
            target_type,
            target_id,
            before,
            after,
            request_id: request_id.to_string(),
        };
        permissions::log(&mut *self.tx, &row)
            .await
            .map_err(|err| internal("audit log", err, request_id))
    }

    /// Queue the cross-replica notification (when the write can change a
    /// cached grant set), commit, then drop this replica's affected entries.
    pub(super) async fn commit(
        mut self,
        cache: &PermissionsCache,
        change: Option<PermissionsChange>,
    ) -> Result<(), AdminError> {
        let request_id = self.request_id();
        if let Some(change) = &change {
            notify::tx_notify(&mut self.tx, change)
                .await
                .map_err(|err| store_error("notify", err, request_id))?;
        }
        self.tx
            .commit()
            .await
            .map_err(|err| store_error("commit tx", RepoError::Sqlx(err), request_id))?;
        if let Some(change) = change {
            cache.spawn_apply(change);
        }
        Ok(())
    }
}
