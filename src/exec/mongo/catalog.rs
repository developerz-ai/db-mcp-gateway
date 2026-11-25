//! `describe_schema` and `sample` for Mongo, built from read commands that
//! go through [`MongoAdapter::execute`] like any caller's — the rejector,
//! the `maxTimeMS` budget and the kill-on-drop guard all apply.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::super::Identifier;
use super::super::adapter::{
    DbAdapter, ExecError, ExecResult, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms,
};
use super::super::budget::ResultBudget;
use super::super::query::{ExecQuery, SampleQuery, SchemaDetail, SchemaQuery};
use super::super::rejection::RejectionKind;
use super::super::sql_guard::Access;
use super::MongoAdapter;
use super::bson_json::raw_to_json;
use super::dispatch::Render;
use super::infer::{field_list, infer_fields};
use super::rejector::is_system_collection;

/// Indexes listed per collection. Mongo allows 64; the cap only bounds a
/// pathological reply.
const MAX_INDEXES: u32 = 64;

impl MongoAdapter {
    /// One row per collection: `[database, collection, type]`, plus
    /// `indexes` at `columns` and `full`, plus `sample` (see
    /// [`infer_fields`]) at `full`. The whole listing — one
    /// `listCollections`, then per collection one `listIndexes` and the
    /// sample's `find` — shares a single time budget.
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

        // Each command is capped on its own; the assembled rows share one
        // budget too, so many wide collections cannot outgrow a response.
        let mut budget = ResultBudget::new(query.row_limit);
        let mut truncated = listed.truncated;
        let mut rows = Vec::with_capacity(listed.rows.len());
        for document in listed.rows.iter().filter_map(|row| row.first()) {
            let name = string_field(document, "name")?;
            let kind = string_field(document, "type")?;
            let Some(row) = self.describe_one(name, kind, query).await? else {
                continue;
            };
            if !budget.admit(&row) {
                truncated = true;
                break;
            }
            rows.push(row);
        }
        rows.sort_by(|a, b| a[1].as_str().cmp(&b[1].as_str()));
        let mut columns = vec!["database", "collection", "type"];
        match query.detail {
            SchemaDetail::Schemas | SchemaDetail::Names => {}
            SchemaDetail::Columns => columns.push("indexes"),
            SchemaDetail::Full => columns.extend(["indexes", "sample"]),
        }
        Ok(ExecResult {
            columns: columns.into_iter().map(String::from).collect(),
            column_types: Vec::new(),
            rows,
            truncated,
            elapsed_ms: started.elapsed().as_millis() as u64,
            rows_affected: None,
        })
    }

    /// One collection's row at `query.detail`, or `None` when `query.search`
    /// matches neither its name nor (at `full`) a sampled field.
    async fn describe_one(
        &self,
        name: &str,
        kind: &str,
        query: &SchemaQuery<'_>,
    ) -> Result<Option<Vec<Value>>, ExecError> {
        let term = query.search.map(str::to_lowercase);
        let named = term
            .as_deref()
            .is_none_or(|term| name.to_lowercase().contains(term));
        let mut row = vec![
            Value::from(self.database_name.as_str()),
            Value::from(name),
            Value::from(kind),
        ];
        let sample = match query.detail {
            SchemaDetail::Full if is_system_collection(name) => {
                Some(withheld_sample("system collection"))
            }
            SchemaDetail::Full => Some(self.sample(name, query).await?),
            _ => None,
        };
        let field_named = |sample: &Value| {
            let fields = sample["fields"].as_array().into_iter().flatten();
            term.as_deref().is_some_and(|term| {
                fields
                    .filter_map(|field| field["name"].as_str())
                    .any(|field| field.to_lowercase().contains(term))
            })
        };
        if !named && !sample.as_ref().is_some_and(field_named) {
            return Ok(None);
        }
        if matches!(query.detail, SchemaDetail::Columns | SchemaDetail::Full) {
            row.push(if kind == "collection" {
                self.indexes(name, query).await?
            } else {
                Value::Array(Vec::new())
            });
        }
        row.extend(sample);
        Ok(Some(row))
    }

    /// The inferred fields of `collection`'s sample. A collection the role
    /// may list but not read is still listed, its sample withheld: one
    /// unreadable collection never sinks the whole listing.
    async fn sample(&self, collection: &str, query: &SchemaQuery<'_>) -> Result<Value, ExecError> {
        match self.sample_field_lists(collection, query).await {
            Ok((lists, cut)) => Ok(infer_fields(&lists, cut)),
            Err(ExecError::Rejected(rejection))
                if rejection.kind() == RejectionKind::PermissionDenied =>
            {
                Ok(withheld_sample("not readable by the database role"))
            }
            Err(err) => Err(err),
        }
    }

    /// The field lists (see [`field_list`]) of up to `query.sample_limit`
    /// documents of `collection`, read by the `find` any caller could run,
    /// and whether the result budget cut them short.
    async fn sample_field_lists(
        &self,
        collection: &str,
        query: &SchemaQuery<'_>,
    ) -> Result<(Vec<Value>, bool), ExecError> {
        let command = json!({ "find": collection, "filter": {} });
        let found = self
            .read_as(&command, query.sample_limit, query, field_list)
            .await?;
        let cut = found.truncated && found.rows.len() < query.sample_limit as usize;
        let lists = found
            .rows
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect();
        Ok((lists, cut))
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
        self.read_as(command, row_limit, query, raw_to_json).await
    }

    /// [`Self::read`], each document turned into its cell by `render`.
    async fn read_as(
        &self,
        command: &Value,
        row_limit: u32,
        query: &SchemaQuery<'_>,
        render: Render,
    ) -> Result<ExecResult, ExecError> {
        let command = command.to_string();
        let query = ExecQuery {
            sql: &command,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        };
        self.run(&query, render).await
    }
}

/// The `sample` of a collection that is not read: a `system.*` one (server
/// state, not application data — see the rejector), or one the role cannot.
fn withheld_sample(why: &str) -> Value {
    json!({ "sampled": 0, "fields": [], "truncated": false, "withheld": why })
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
