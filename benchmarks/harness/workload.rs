//! The query shapes we measure, and the seed data they run against.
//!
//! Every shape must be expressible *identically* on both paths — through the
//! gateway and directly against the database — or the comparison measures the
//! difference between two queries instead of the difference between two paths.
//! That constraint is why these are fixed strings rather than anything
//! generated or engine-tuned.

use serde::Serialize;

/// Rows seeded into the benchmark table. Large enough that a 1000-row scan is
/// a real scan, small enough to stay in cache on both paths — we are measuring
/// gateway overhead, not the database's buffer pool.
pub const SEED_ROWS: i64 = 50_000;

/// DDL + seed, run once per benchmark session against the target database.
/// Deterministic: `generate_series` rather than random data, so two runs on
/// two machines execute over identical bytes. Derived from `SEED_ROWS` so the
/// seeded row count and the query predicates cannot disagree — one constant
/// owns the size of the table.
pub fn postgres_seed() -> String {
    format!(
        "\
DROP TABLE IF EXISTS bench_rows;
CREATE TABLE bench_rows (
    id    bigint PRIMARY KEY,
    label text   NOT NULL,
    val   bigint NOT NULL
);
INSERT INTO bench_rows (id, label, val)
SELECT g, 'label-' || g, (g * 7919) % 100000
FROM generate_series(1, {SEED_ROWS}) AS g;
CREATE INDEX bench_rows_val_idx ON bench_rows (val);
ANALYZE bench_rows;
"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// Primary-key lookup. The cheapest possible database query, which makes
    /// it the harshest test of gateway overhead: whatever the gateway costs is
    /// almost the entire measurement.
    PointLookup,
    /// 1000-row scan. Shifts the balance toward the database and toward
    /// serialization — the row-encoding cost the gateway pays that a direct
    /// driver does not.
    RangeScan,
    /// Server-side aggregate returning one row. Database does real work, the
    /// response is tiny; isolates per-request overhead from response size.
    Aggregate,
}

impl Shape {
    pub fn all() -> &'static [Shape] {
        &[Shape::PointLookup, Shape::RangeScan, Shape::Aggregate]
    }

    pub fn name(self) -> &'static str {
        match self {
            Shape::PointLookup => "point_lookup",
            Shape::RangeScan => "range_scan",
            Shape::Aggregate => "aggregate",
        }
    }

    /// One line of prose per shape, carried into the report so a reader of the
    /// published table does not have to open this file to know what ran.
    pub fn description(self) -> &'static str {
        match self {
            Shape::PointLookup => "SELECT one row by primary key",
            Shape::RangeScan => "SELECT 1000 rows over an indexed range",
            Shape::Aggregate => "COUNT + SUM aggregate over 50k rows, one row returned",
        }
    }

    /// The SQL. `iteration` varies the predicate so consecutive requests do not
    /// all hit one page — without it we would be benchmarking a cache entry.
    pub fn sql(self, iteration: u64) -> String {
        match self {
            Shape::PointLookup => {
                let id = (iteration % SEED_ROWS as u64) + 1;
                format!("SELECT id, label, val FROM bench_rows WHERE id = {id}")
            }
            Shape::RangeScan => {
                let lo = (iteration % (SEED_ROWS as u64 - 1000)) + 1;
                format!(
                    "SELECT id, label, val FROM bench_rows \
                     WHERE id >= {lo} AND id < {} ORDER BY id",
                    lo + 1000
                )
            }
            Shape::Aggregate => {
                let floor = iteration % 1000;
                format!("SELECT count(*) AS c, sum(val) AS s FROM bench_rows WHERE val > {floor}")
            }
        }
    }

    /// Row cap to send with the gateway request. Must exceed what the shape
    /// returns, or the gateway truncates and we would be comparing a truncated
    /// response against a complete one.
    pub fn limit(self) -> u32 {
        match self {
            Shape::PointLookup | Shape::Aggregate => 10,
            Shape::RangeScan => 2000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_lookup_stays_inside_the_seeded_range() {
        for i in [0u64, 1, 49_999, 50_000, 123_456] {
            let sql = Shape::PointLookup.sql(i);
            let id: i64 = sql
                .rsplit("= ")
                .next()
                .and_then(|s| s.parse().ok())
                .expect("predicate ends in the id");
            assert!(
                (1..=SEED_ROWS).contains(&id),
                "iteration {i} produced out-of-range id {id}"
            );
        }
    }

    #[test]
    fn range_scan_never_runs_past_the_seeded_rows() {
        for i in [0u64, 1, 48_999, 100_000] {
            let sql = Shape::RangeScan.sql(i);
            let hi: i64 = sql
                .split("id < ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .expect("upper bound present");
            assert!(hi <= SEED_ROWS, "iteration {i} scans past the seed: {hi}");
        }
    }

    #[test]
    fn range_scan_limit_exceeds_what_it_returns() {
        // A cap at or below the row count would silently truncate and make the
        // two paths incomparable.
        assert!(Shape::RangeScan.limit() > 1000);
    }

    #[test]
    fn seed_sql_uses_the_shared_row_count() {
        // Guards the SEED_ROWS ↔ postgres_seed() invariant. If a future edit
        // hardcodes a different number in the DDL, RangeScan would scan past
        // the seeded data and PointLookup would query missing ids.
        let sql = postgres_seed();
        assert!(
            sql.contains(&format!("generate_series(1, {SEED_ROWS})")),
            "seed SQL must derive its row count from SEED_ROWS ({SEED_ROWS}):\n{sql}"
        );
    }

    #[test]
    fn shape_names_are_unique() {
        let mut names: Vec<_> = Shape::all().iter().map(|s| s.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "shape names collide in the report");
    }
}
