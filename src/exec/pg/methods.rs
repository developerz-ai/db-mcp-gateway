//! The [`DbAdapter`] methods: each picks a tier and the SQL to run on it.

use async_trait::async_trait;
use uuid::Uuid;

use super::super::adapter::{DbAdapter, ExecError, ExecResult};
use super::super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};
use super::super::sql_guard::Access;
use super::tier::{Tier, TierKind};
use super::{PgAdapter, catalog, explain, introspect, sample};

#[async_trait]
impl DbAdapter for PgAdapter {
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        let tier = self.tier(query.access).await?;
        self.run(&tier, &query).await
    }

    async fn describe_schema(&self, query: SchemaQuery<'_>) -> Result<ExecResult, ExecError> {
        let (sql, binds) = catalog::columns_query(query.schema, query.table);
        self.run_read(
            &sql,
            &binds,
            query.statement_timeout_ms,
            query.row_limit,
            query.request_id,
        )
        .await
    }

    async fn sample(&self, query: SampleQuery<'_>) -> Result<ExecResult, ExecError> {
        let sql = sample::sample_sql(query.schema, query.table, query.row_limit);
        self.run_read(
            &sql,
            &[],
            query.statement_timeout_ms,
            query.row_limit,
            query.request_id,
        )
        .await
    }

    async fn explain(&self, query: ExplainQuery<'_>) -> Result<ExecResult, ExecError> {
        let sql = explain::explain_sql(query.sql, query.analyze)?;
        // A write is planned under the role that would run it — `EXPLAIN`
        // checks privileges — but still in a read-only transaction.
        let tier = self.tier(query.sql.required_access()).await?;
        let exec = ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: explain::EXPLAIN_RESULT_CAP,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        };
        self.run(&tier, &exec).await
    }

    async fn table_stats(&self, query: TableStatsQuery<'_>) -> Result<ExecResult, ExecError> {
        let (sql, binds) = introspect::table_stats_query(query.schema, query.table);
        self.run_read(
            &sql,
            &binds,
            query.statement_timeout_ms,
            query.row_limit,
            query.request_id,
        )
        .await
    }

    async fn db_activity(&self, query: ActivityQuery) -> Result<ExecResult, ExecError> {
        let sql = introspect::activity_sql(TierKind::Read);
        let read = self
            .run(&self.read, &Self::activity_query(&sql, &query))
            .await?;
        if self.write.is_none() {
            return Ok(read);
        }
        let write = match self.write_tier().await {
            Ok(tier) => self.write_activity(&tier, &query).await,
            Err(err) => Err(err),
        };
        match write {
            Ok(write) => Ok(introspect::merge_activity(read, write, query.row_limit)),
            // A write tier that cannot be reached (its credentials do not
            // resolve or are refused, the target is saturated) runs nothing
            // through this gateway. The read listing stands; the failed
            // attempt is already on the log.
            Err(
                ExecError::Connection
                | ExecError::Unavailable
                | ExecError::PasswordUnresolved { .. },
            ) => Ok(read),
            Err(other) => Err(other),
        }
    }

    async fn cancel_request(&self, request_id: Uuid) -> Result<bool, ExecError> {
        // Asked of the target on both tiers, whatever this process's pools
        // hold: the statement may be another replica's.
        let read = self.cancel_on(&self.read, request_id).await;
        if read.as_ref().is_ok_and(|cancelled| *cancelled) || self.write.is_none() {
            return read;
        }
        let write = match self.write_tier().await {
            Ok(tier) => self.cancel_on(&tier, request_id).await,
            Err(err) => Err(err),
        };
        match (read, write) {
            (Ok(true), _) | (_, Ok(true)) => Ok(true),
            // "Nothing was running" needs both tiers to have said so.
            (Err(err), _) | (_, Err(err)) => Err(err),
            (Ok(false), Ok(false)) => Ok(false),
        }
    }

    fn is_stale(&self) -> bool {
        self.read.is_stale()
    }
}

impl PgAdapter {
    /// The `db_activity` statement for one tier: each role sees its own
    /// backends.
    fn activity_query<'a>(sql: &'a str, query: &ActivityQuery) -> ExecQuery<'a> {
        ExecQuery {
            sql,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: query.row_limit,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        }
    }

    /// What the write role is running, asked of the target over the write
    /// tier: the writes of every replica are there, whether or not this
    /// process ever wrote. It runs on the query pool, under the caller's
    /// share, like any statement: the cancel pool stays reserved for
    /// cancels, so a burst of listings can never hold back the cancel of a
    /// write. While writes hold every query connection the listing waits,
    /// and the read listing answers alone.
    async fn write_activity(
        &self,
        write: &Tier,
        query: &ActivityQuery,
    ) -> Result<ExecResult, ExecError> {
        let sql = introspect::activity_sql(write.kind);
        self.run(write, &Self::activity_query(&sql, query)).await
    }

    /// Signal `request_id`'s backends of `tier`'s role.
    async fn cancel_on(&self, tier: &Tier, request_id: Uuid) -> Result<bool, ExecError> {
        // Acquired here, not by the statement: a login the target refuses
        // must take the connect-phase path.
        let mut conn = self.acquire(tier, &tier.cancel_pool, request_id).await?;
        introspect::cancel_request(&mut conn, &self.origin(tier, request_id), request_id).await
    }
}
