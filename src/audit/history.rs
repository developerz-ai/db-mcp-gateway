//! The `get_query_history` read model: one keyset page of a caller's own
//! `audit_calls` rows. Wire contract: `website/docs/initial-idea/03-mcp-tools.md`
//! §get_query_history.

use chrono::{DateTime, SecondsFormat, Utc};
use uuid::Uuid;

/// Bytes of `sql` a history entry carries. History is "recover context", not
/// an export of every statement verbatim; one 100 KB statement must not make
/// a page of a thousand entries a 100 MB response.
pub const HISTORY_SQL_MAX_BYTES: usize = 4096;

/// One row in the `get_query_history` response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub request_id: String,
    pub sql: Option<String>,
    /// `sql` was cut at [`HISTORY_SQL_MAX_BYTES`].
    pub sql_truncated: bool,
    pub reason: Option<String>,
    pub occurred_at: String,
    pub elapsed_ms: Option<i64>,
    pub row_count: Option<i64>,
    pub outcome: String,
}

/// Position after the last entry of a page: `(occurred_at, id)` of that row.
/// Opaque to the caller; round-trips as `<rfc3339 micros>|<uuid>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryCursor {
    pub occurred_at: DateTime<Utc>,
    pub id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("`cursor` must be a value returned as `next_cursor`")]
pub struct InvalidCursor;

impl HistoryCursor {
    pub fn encode(&self) -> String {
        // Micros: Postgres `timestamptz` precision, so the cursor compares
        // equal to the stored value instead of rounding past a row.
        format!(
            "{}|{}",
            self.occurred_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            self.id
        )
    }

    pub fn parse(raw: &str) -> Result<Self, InvalidCursor> {
        let (at, id) = raw.split_once('|').ok_or(InvalidCursor)?;
        let occurred_at = DateTime::parse_from_rfc3339(at)
            .map_err(|_| InvalidCursor)?
            .with_timezone(&Utc);
        let id = Uuid::parse_str(id).map_err(|_| InvalidCursor)?;
        Ok(Self { occurred_at, id })
    }
}

/// One validated history request. `user_sub` is the SSO-verified caller —
/// never a client-supplied field.
#[derive(Debug, Clone, Copy)]
pub struct HistoryQuery<'a> {
    pub user_sub: &'a str,
    pub server: &'a str,
    pub database: &'a str,
    pub since: Option<DateTime<Utc>>,
    pub before: Option<HistoryCursor>,
    pub limit: u32,
}

#[derive(Debug, Clone)]
pub struct HistoryPage {
    pub entries: Vec<HistoryEntry>,
    /// Set when at least one older entry exists past this page.
    pub next: Option<HistoryCursor>,
}

/// Cap `sql` at [`HISTORY_SQL_MAX_BYTES`]; the flag says whether it was cut.
pub fn cap_history_sql(sql: Option<String>) -> (Option<String>, bool) {
    match sql {
        Some(text) if text.len() > HISTORY_SQL_MAX_BYTES => (
            Some(prefix_at_char_boundary(&text, HISTORY_SQL_MAX_BYTES).to_string()),
            true,
        ),
        other => (other, false),
    }
}

/// The longest prefix of `text` that is at most `max` bytes and ends on a
/// char boundary.
pub(crate) fn prefix_at_char_boundary(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let cursor = HistoryCursor {
            occurred_at: DateTime::parse_from_rfc3339("2026-11-12T10:00:00.123456Z")
                .unwrap()
                .with_timezone(&Utc),
            id: Uuid::new_v4(),
        };
        assert_eq!(HistoryCursor::parse(&cursor.encode()), Ok(cursor));
    }

    #[test]
    fn cursor_rejects_garbage() {
        for raw in ["", "nope", "2026-11-12T10:00:00Z|not-a-uuid", "x|y"] {
            assert_eq!(HistoryCursor::parse(raw), Err(InvalidCursor), "{raw}");
        }
    }

    #[test]
    fn cap_history_sql_cuts_long_sql_on_a_char_boundary() {
        let long = "é".repeat(HISTORY_SQL_MAX_BYTES);
        let (sql, truncated) = cap_history_sql(Some(long));
        let sql = sql.unwrap();
        assert!(truncated);
        assert!(sql.len() <= HISTORY_SQL_MAX_BYTES);
        assert!(sql.chars().all(|c| c == 'é'));
    }

    #[test]
    fn cap_history_sql_leaves_short_sql_alone() {
        assert_eq!(
            cap_history_sql(Some("SELECT 1".into())),
            (Some("SELECT 1".into()), false)
        );
        assert_eq!(cap_history_sql(None), (None, false));
    }
}
