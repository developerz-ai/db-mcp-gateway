//! Near-miss names for a statement that named a table or column that does
//! not exist (`42P01` / `42703`): the existing names closest to the one the
//! caller typed, so the next call can be the fix instead of a
//! `describe_schema` round trip.
//!
//! Only names the caller could already read through `describe_schema` are
//! offered: the lookup runs as the read role, inside a read-only
//! transaction, and keeps only relations and columns that role holds a
//! privilege on — the same filter `information_schema` applies. The typed
//! name is the one `redact` cut out of the caller's SQL at the parser's
//! position; it reaches the catalog query as a bound length, never as text.
//! The lookup is best-effort under its own small budget: a slow or failed
//! one answers no names, never an error.

use std::time::Duration;

use uuid::Uuid;

use super::super::adapter::{ExecError, ExecResult};
use super::super::rejection::RejectionKind;
use super::PgAdapter;
use super::redact::name_at;

/// The whole lookup — caller slot, connection, query — must fit in this.
const LOOKUP_BUDGET: Duration = Duration::from_millis(200);
const LOOKUP_TIMEOUT_MS: u32 = 200;
/// Candidates read from the catalog; the closest are picked in Rust.
const MAX_CANDIDATES: u32 = 5_000;
pub(super) const MAX_NEAR_MISSES: usize = 5;

/// Relations the read role may see, as the caller would spell them:
/// qualified unless the search path already finds them.
const RELATIONS_SQL: &str = "SELECT CASE WHEN pg_table_is_visible(c.oid) THEN quote_ident(c.relname) \
       ELSE quote_ident(n.nspname) || '.' || quote_ident(c.relname) END AS spelled, \
       c.relname::text AS name \
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') \
       AND n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' \
       AND has_schema_privilege(n.oid, 'USAGE') \
       AND has_any_column_privilege(c.oid, 'SELECT, INSERT, UPDATE, REFERENCES') \
       AND length(c.relname) BETWEEN $1::int - $2::int AND $1::int + $2::int \
     ORDER BY 1";

/// Column names of those relations, each once.
const COLUMNS_SQL: &str = "SELECT DISTINCT quote_ident(a.attname) AS spelled, a.attname::text AS name \
     FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
       JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE a.attnum > 0 AND NOT a.attisdropped \
       AND c.relkind IN ('r', 'p', 'v', 'm', 'f') \
       AND n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' \
       AND has_schema_privilege(n.oid, 'USAGE') \
       AND has_column_privilege(c.oid, a.attnum, 'SELECT, INSERT, UPDATE, REFERENCES') \
       AND length(a.attname) BETWEEN $1::int - $2::int AND $1::int + $2::int \
     ORDER BY 1";

impl PgAdapter {
    /// `result` with near misses attached when it is an undefined-object
    /// rejection of `sql`, the statement the target saw.
    pub(super) async fn with_near_misses(
        &self,
        result: Result<ExecResult, ExecError>,
        sql: &str,
        request_id: Uuid,
    ) -> Result<ExecResult, ExecError> {
        let rejection = match result {
            Err(ExecError::Rejected(rejection))
                if rejection.kind() == RejectionKind::UndefinedObject =>
            {
                rejection
            }
            other => return other,
        };
        let typed = rejection
            .position()
            .and_then(|at| name_at(rejection.sqlstate(), sql, at))
            .map(last_part);
        let Some(typed) = typed else {
            return Err(ExecError::Rejected(rejection));
        };
        let catalog = match rejection.sqlstate() {
            "42P01" => RELATIONS_SQL,
            _ => COLUMNS_SQL,
        };
        let lookup = self.candidates(catalog, &typed, request_id);
        let near = match tokio::time::timeout(LOOKUP_BUDGET, lookup).await {
            Ok(Ok(candidates)) => closest(&typed, &candidates),
            Ok(Err(_)) | Err(_) => {
                tracing::debug!(%request_id, "near-miss lookup gave up");
                Vec::new()
            }
        };
        Err(ExecError::Rejected(rejection.with_near_misses(near)))
    }

    /// `(spelled, name)` pairs from `catalog` whose length is near `typed`'s.
    async fn candidates(
        &self,
        catalog: &str,
        typed: &str,
        request_id: Uuid,
    ) -> Result<Vec<(String, String)>, ExecError> {
        let len = typed.chars().count().to_string();
        let spread = max_distance(typed).to_string();
        let found = self
            .run_read(
                catalog,
                &[&len, &spread],
                Some(LOOKUP_TIMEOUT_MS),
                MAX_CANDIDATES,
                request_id,
            )
            .await?;
        Ok(found
            .rows
            .into_iter()
            .filter_map(|row| match row.as_slice() {
                [spelled, name] => Some((spelled.as_str()?.to_owned(), name.as_str()?.to_owned())),
                _ => None,
            })
            .collect())
    }
}

/// The last dotted part of a typed name, as Postgres resolves it: a quoted
/// part keeps its case (with `""` unescaped), a bare one folds to lower case.
fn last_part(name: &str) -> String {
    let mut parts = Vec::new();
    let mut rest = name;
    while !rest.is_empty() {
        let (part, after) = match rest.strip_prefix('"') {
            Some(quoted) => split_quoted(quoted),
            None => {
                let end = rest.find('.').unwrap_or(rest.len());
                (rest[..end].to_lowercase(), &rest[end..])
            }
        };
        parts.push(part);
        rest = after.strip_prefix('.').unwrap_or(after);
    }
    parts.pop().unwrap_or_default()
}

/// A quoted part (opening quote already stripped) and the text after it.
fn split_quoted(text: &str) -> (String, &str) {
    let mut part = String::new();
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if c != '"' {
            part.push(c);
        } else if chars.next_if(|(_, next)| *next == '"').is_some() {
            part.push('"');
        } else {
            return (part, &text[at + 1..]);
        }
    }
    (part, "")
}

/// Edits allowed between a typed name and a candidate.
fn max_distance(typed: &str) -> usize {
    (typed.chars().count() / 3).max(2)
}

/// Up to [`MAX_NEAR_MISSES`] candidates within [`max_distance`] of `typed`,
/// case-insensitively, closest first.
fn closest(typed: &str, candidates: &[(String, String)]) -> Vec<String> {
    let typed = typed.to_lowercase();
    let limit = max_distance(&typed);
    let mut scored: Vec<(usize, &str)> = candidates
        .iter()
        .filter_map(|(spelled, name)| {
            let distance = edit_distance(&typed, &name.to_lowercase());
            (distance <= limit).then_some((distance, spelled.as_str()))
        })
        .collect();
    scored.sort_unstable();
    scored.dedup_by(|a, b| a.1 == b.1);
    scored
        .into_iter()
        .take(MAX_NEAR_MISSES)
        .map(|(_, spelled)| spelled.to_owned())
        .collect()
}

/// Optimal-string-alignment distance: insertions, deletions, substitutions
/// and adjacent transpositions (`usres` → `users` is one edit).
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut before: Vec<usize> = vec![0; b.len() + 1];
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut current = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            current[j] = (previous[j] + 1)
                .min(current[j - 1] + 1)
                .min(previous[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                current[j] = current[j].min(before[j - 2] + 1);
            }
        }
        before = std::mem::replace(&mut previous, current);
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transposition_is_one_edit() {
        assert_eq!(edit_distance("usres", "users"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("same", "same"), 0);
    }

    #[test]
    fn the_typed_name_is_resolved_as_postgres_would() {
        assert_eq!(last_part("Usres"), "usres");
        assert_eq!(last_part("t.Emial"), "emial");
        assert_eq!(last_part(r#""My ""T""""#), r#"My "T""#);
        assert_eq!(last_part(r#"s."Mixed.Case""#), "Mixed.Case");
    }

    #[test]
    fn closest_first_capped_and_within_distance() {
        let candidates: Vec<(String, String)> = [
            "users", "user", "orders", "usage", "uses", "abusers", "ussr", "u",
        ]
        .iter()
        .map(|name| (name.to_string(), name.to_string()))
        .collect();
        let near = closest("Usres", &candidates);
        assert_eq!(near.first().map(String::as_str), Some("users"));
        assert!(near.len() <= MAX_NEAR_MISSES);
        assert!(!near.contains(&"orders".to_string()), "{near:?}");
        assert!(!near.contains(&"u".to_string()), "{near:?}");
        // The spelling is what is offered: a mixed-case name stays quoted.
        let quoted = vec![("\"Users\"".to_string(), "Users".to_string())];
        assert_eq!(closest("users", &quoted), vec!["\"Users\"".to_string()]);
        assert!(closest("zzzzzz", &candidates).is_empty());
    }
}
