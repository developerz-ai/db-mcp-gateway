//! `describe_schema` and `sample` for Mongo, built from read commands that
//! go through [`MongoAdapter::execute`] like any caller's — the rejector,
//! the `maxTimeMS` budget and the kill-on-drop guard all apply.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::super::Identifier;
use super::super::adapter::{
    DbAdapter, ExecError, ExecResult, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms,
};
use super::super::query::{ExecQuery, SampleQuery, SchemaQuery};
use super::super::sql_guard::Access;
use super::MongoAdapter;

/// Indexes listed per collection. Mongo allows 64; the cap only bounds a
/// pathological reply.
const MAX_INDEXES: u32 = 64;

impl MongoAdapter {
    /// One row per collection: `[database, collection, type, indexes]`. The
    /// whole listing — one `listCollections` plus one `listIndexes` per
    /// collection — shares a single time budget.
    pub(super) async fn describe(&self, query: SchemaQuery<'_>) -> Result<ExecResult, ExecError> {
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        match tokio::time::timeout(budget, self.describe_within(&query)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    async fn describe_within(&self, query: &SchemaQuery<'_>) -> Result<ExecResult, ExecError> {
        let started = Instant::now();
        let filter = match query.table {
            Some(name) => json!({ "name": name }),
            None => json!({}),
        };
        let command = json!({ "listCollections": 1, "nameOnly": false, "filter": filter });
        let listed = self.read(&command, query.row_limit, query).await?;

        let mut rows = Vec::with_capacity(listed.rows.len());
        for document in listed.rows.iter().filter_map(|row| row.first()) {
            let name = string_field(document, "name")?;
            let kind = string_field(document, "type")?;
            let indexes = if kind == "collection" {
                self.indexes(name, query).await?
            } else {
                Value::Array(Vec::new())
            };
            rows.push(vec![
                Value::from(self.database_name.as_str()),
                Value::from(name),
                Value::from(kind),
                indexes,
            ]);
        }
        rows.sort_by(|a, b| a[1].as_str().cmp(&b[1].as_str()));
        Ok(ExecResult {
            columns: ["database", "collection", "type", "indexes"]
                .map(String::from)
                .to_vec(),
            rows,
            truncated: listed.truncated,
            elapsed_ms: started.elapsed().as_millis() as u64,
            rows_affected: None,
        })
    }

    /// `[{name, key, unique}]` for one collection.
    async fn indexes(&self, collection: &str, query: &SchemaQuery<'_>) -> Result<Value, ExecError> {
        let command = json!({ "listIndexes": collection });
        let listed = self.read(&command, MAX_INDEXES, query).await?;
        let indexes = listed
            .rows
            .iter()
            .filter_map(|row| row.first())
            .map(|index| {
                Ok(json!({
                    "name": string_field(index, "name")?,
                    "key": index.get("key").cloned().ok_or(ExecError::Decode)?,
                    "unique": index.get("unique").and_then(Value::as_bool).unwrap_or(false),
                }))
            })
            .collect::<Result<Vec<_>, ExecError>>()?;
        Ok(Value::Array(indexes))
    }

    /// The first `row_limit` documents of the collection named `table`.
    pub(super) async fn sample_collection(
        &self,
        query: SampleQuery<'_>,
    ) -> Result<ExecResult, ExecError> {
        let command = sample_command(query.table);
        self.execute(ExecQuery {
            sql: &command,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: query.row_limit,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        })
        .await
    }

    /// One catalog command under the schema query's budget and request id.
    async fn read(
        &self,
        command: &Value,
        row_limit: u32,
        query: &SchemaQuery<'_>,
    ) -> Result<ExecResult, ExecError> {
        let command = command.to_string();
        self.execute(ExecQuery {
            sql: &command,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        })
        .await
    }
}

/// The `find` a sample runs. `sample_table` stores it as the audit row's
/// `sql`, so the record names exactly the command that read the collection.
pub fn sample_command(collection: Identifier<'_>) -> String {
    json!({ "find": collection.as_str(), "filter": {} }).to_string()
}

/// A string field the server always sends; its absence is a decode error,
/// never a fabricated value.
fn string_field<'a>(document: &'a Value, field: &str) -> Result<&'a str, ExecError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ExecError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_are_decode_errors() {
        let doc = json!({ "name": "users" });
        assert_eq!(string_field(&doc, "name").ok(), Some("users"));
        assert!(matches!(string_field(&doc, "type"), Err(ExecError::Decode)));
    }
}
