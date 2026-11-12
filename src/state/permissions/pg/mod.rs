//! Postgres permissions store. Reads go through [`PgPermissionsRepo`] on the
//! shared state pool; writes are the `tx_*` functions in [`users`],
//! [`databases`] and [`grants`], each over the caller's open transaction so
//! the admin layer commits data, `permissions_audit` row and [`notify`]
//! together.

pub mod databases;
pub mod grants;
pub mod notify;
mod rows;
pub mod users;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    LiveGrant, Page, PermissionsDatabase, PermissionsGrant, PermissionsRepo, PermissionsUser,
    RepoError,
};

#[derive(Debug, Clone)]
pub struct PgPermissionsRepo {
    pool: PgPool,
}

impl PgPermissionsRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionsRepo for PgPermissionsRepo {
    async fn get_user(&self, id: Uuid) -> Result<Option<PermissionsUser>, RepoError> {
        users::get_user(&self.pool, id).await
    }

    async fn list_users(&self, page: Page) -> Result<Vec<PermissionsUser>, RepoError> {
        users::list_users(&self.pool, page).await
    }

    async fn get_database(&self, id: Uuid) -> Result<Option<PermissionsDatabase>, RepoError> {
        databases::get_database(&self.pool, id).await
    }

    async fn list_databases(&self, page: Page) -> Result<Vec<PermissionsDatabase>, RepoError> {
        databases::list_databases(&self.pool, page).await
    }

    async fn get_grant(&self, id: Uuid) -> Result<Option<PermissionsGrant>, RepoError> {
        grants::get_grant(&self.pool, id).await
    }

    async fn list_grants(
        &self,
        user_id: Option<Uuid>,
        database_id: Option<Uuid>,
        page: Page,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        grants::list_grants(&self.pool, user_id, database_id, page).await
    }

    async fn live_grants_for_sub(&self, user_sub: &str) -> Result<Vec<LiveGrant>, RepoError> {
        grants::live_grants_for_sub(&self.pool, user_sub).await
    }
}

#[cfg(any(test, feature = "test-support"))]
mod seed {
    use async_trait::async_trait;
    use serde_json::Value as JsonValue;
    use uuid::Uuid;

    use super::super::{
        DbType, GrantAction, GrantTarget, PermissionsDatabase, PermissionsGrant, PermissionsSeed,
        PermissionsUser, RepoError,
    };
    use super::{PgPermissionsRepo, databases, grants, users};

    /// Each fixture write is one committed transaction around the same `tx_*`
    /// function production uses — no second copy of the SQL.
    macro_rules! in_tx {
        ($pool:expr, |$tx:ident| $body:expr) => {{
            let mut $tx = $pool.begin().await?;
            let out = $body.await?;
            $tx.commit().await?;
            out
        }};
    }

    #[async_trait]
    impl PermissionsSeed for PgPermissionsRepo {
        async fn upsert_user(
            &self,
            user_sub: &str,
            user_email: &str,
            groups: &[String],
        ) -> Result<PermissionsUser, RepoError> {
            Ok(in_tx!(self.pool, |tx| users::tx_upsert_user(
                &mut tx, user_sub, user_email, groups
            )))
        }

        async fn get_user_by_sub(
            &self,
            user_sub: &str,
        ) -> Result<Option<PermissionsUser>, RepoError> {
            users::get_user_by_sub(&self.pool, user_sub).await
        }

        async fn soft_delete_user(&self, id: Uuid) -> Result<bool, RepoError> {
            Ok(in_tx!(self.pool, |tx| users::tx_soft_delete_user(
                &mut tx, id
            )))
        }

        async fn create_database(
            &self,
            server: &str,
            db_name: &str,
            db_type: DbType,
        ) -> Result<PermissionsDatabase, RepoError> {
            Ok(in_tx!(self.pool, |tx| databases::tx_create_database(
                &mut tx, server, db_name, db_type
            )))
        }

        async fn update_database(
            &self,
            id: Uuid,
            server: Option<&str>,
            db_name: Option<&str>,
            db_type: Option<DbType>,
        ) -> Result<Option<PermissionsDatabase>, RepoError> {
            Ok(in_tx!(self.pool, |tx| databases::tx_update_database(
                &mut tx, id, server, db_name, db_type
            )))
        }

        async fn soft_delete_database(&self, id: Uuid) -> Result<bool, RepoError> {
            Ok(in_tx!(self.pool, |tx| databases::tx_soft_delete_database(
                &mut tx, id
            )))
        }

        async fn create_grant(
            &self,
            user_id: Uuid,
            target: GrantTarget,
            action: GrantAction,
            constraints: JsonValue,
        ) -> Result<PermissionsGrant, RepoError> {
            let created = in_tx!(self.pool, |tx| grants::tx_create_grant(
                &mut tx,
                user_id,
                &target,
                action,
                &constraints
            ));
            created.ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))
        }

        async fn list_grants_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<PermissionsGrant>, RepoError> {
            grants::list_grants_for_user(&self.pool, user_id).await
        }

        async fn revoke_grant(&self, id: Uuid) -> Result<bool, RepoError> {
            Ok(in_tx!(self.pool, |tx| grants::tx_revoke_grant(&mut tx, id)))
        }
    }
}
