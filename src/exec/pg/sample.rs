//! `sample` SQL: `SELECT * FROM "<schema>"."<table>" LIMIT n`.

use super::super::ident::Identifier;

/// Fetches one row past `row_limit` so the row cap in `run_query_inner`
/// can see there is more and set `truncated`. `LIMIT` is a number we
/// produce, and both names are [`Identifier`]s, which cannot contain `"` —
/// so the interpolation cannot escape its quotes.
pub(super) fn sample_sql(schema: Identifier<'_>, table: Identifier<'_>, row_limit: u32) -> String {
    format!(
        "SELECT * FROM \"{schema}\".\"{table}\" LIMIT {limit}",
        schema = schema.as_str(),
        table = table.as_str(),
        limit = row_limit.saturating_add(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(s: &str) -> Identifier<'_> {
        Identifier::parse(s).expect("valid identifier")
    }

    #[test]
    fn quotes_identifiers_and_fetches_one_extra_row() {
        assert_eq!(
            sample_sql(ident("public"), ident("users"), 10),
            r#"SELECT * FROM "public"."users" LIMIT 11"#
        );
    }

    #[test]
    fn limit_saturates_instead_of_overflowing() {
        assert!(
            sample_sql(ident("s"), ident("t"), u32::MAX).ends_with(&format!("LIMIT {}", u32::MAX))
        );
    }
}
