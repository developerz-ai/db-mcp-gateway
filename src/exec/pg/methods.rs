//! The [`DbAdapter`] methods: each picks a tier and the SQL to run on it.

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use uuid::Uuid;

use super::super::adapter::{DbAdapter, ExecError, ExecResult};
use super::super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};
use super::super::sql_guard::Access;
use super::{PgAdapter, catalog, explain, introspect, sample};

#[async_trait]
impl DbAdapter for PgAdapter {
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        self.run(self.tier(query.access)?, &query).await
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
        let tier = self.tier(query.sql.required_access())?;
        let exec = ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: explain::EXPLAIN_RESULT_CAP,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        };
        self.run(tier, &exec).await
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
        let read = self.activity_on(&self.read, &query).await?;
        match self.write.as_ref().filter(|tier| tier.is_connected()) {
            Some(write) => {
                let write = self.activity_on(write, &query).await?;
                Ok(introspect::merge_activity(read, write, query.row_limit))
            }
            None => Ok(read),
        }
    }

    async fn cancel_request(&self, request_id: Uuid) -> Result<bool, ExecError> {
        let mut cancelled = false;
        for tier in self.connected_tiers() {
            cancelled |= introspect::cancel_request(tier, request_id).await?;
        }
        Ok(cancelled)
    }

    fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }
}
