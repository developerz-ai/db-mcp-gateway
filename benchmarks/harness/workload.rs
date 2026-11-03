//! The query shapes we measure, and the seed data they run against.
//!
//! Every shape must be expressible *identically* on both paths — through the
//! gateway and directly against the database — or the comparison measures the
//! difference between two queries instead of the difference between two paths.
//! That constraint is why these are fixed strings rather than anything
//! generated or engine-tuned.
//!
//! The **backend** is an axis of the workload, not a mode of the harness: a
//! shape belongs to exactly one backend, and the backend decides both the
//! query text and the row cap. Postgres shapes speak SQL; mongo shapes speak
//! mongo JSON commands — the same command document the gateway's
//! `MongoAdapter` dispatches, so the direct baseline and the gateway path run
//! byte-identical commands against byte-identical data.

use serde::Serialize;

/// Which target database a shape runs against.
///
/// Drives the query dialect, the seed, the direct client, and the target
/// `server`/`database` names the gateway path asks for. Keeping it on the
/// shape means a shape can never be run against the wrong backend by
/// accident — the compiler enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Postgres,
    Mongo,
}

impl Backend {
    pub fn all() -> &'static [Backend] {
        &[Backend::Postgres, Backend::Mongo]
    }

    pub fn name(self) -> &'static str {
        match self {
            Backend::Postgres => "postgres",
            Backend::Mongo => "mongo",
        }
    }

    /// CLI spelling — matches `--backend <postgres|mongo>`.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Some(Backend::Postgres),
            "mongo" | "mongodb" => Some(Backend::Mongo),
            _ => None,
        }
    }
}

/// Rows seeded into the benchmark table. Large enough that a 1000-row scan is
/// a real scan, small enough to stay in cache on both paths — we are measuring
/// gateway overhead, not the database's buffer pool.
pub const SEED_ROWS: i64 = 50_000;

/// Documents seeded into the mongo benchmark collection. Same reasoning as
/// [`SEED_ROWS`], and the same number so the two backends' range shapes
/// return the same number of rows — the comparison is gateway-vs-direct
/// within a backend, but equal row counts keep the two backends' overhead
/// figures comparable at a glance.
pub const MONGO_SEED_DOCS: i64 = 50_000;

/// The collection the mongo shapes read. Named, not generated, so both paths
/// address the same collection.
pub const MONGO_COLLECTION: &str = "bench_rows";

/// The field the mongo shapes filter and sort on.
///
/// `_id` — mongo's primary key, and the **only** field mongo indexes by
/// default. A filter on any other field is a collection scan, and a sort on
/// any other field adds a blocking in-memory sort on top of it: the shape
/// would then measure mongo's planner rather than the gateway's overhead.
/// The seed ([`crate::mongo`]) writes the numeric key into `_id`, so the
/// default index covers both the point find and the range find.
pub const MONGO_KEY_FIELD: &str = "_id";

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
    /// Mongo point find by `_id` — mongo's primary key, so the lookup is an
    /// index hit. The mongo analogue of [`Shape::PointLookup`].
    MongoPointFind,
    /// Mongo range find over the indexed `_id` key, 1000 documents. The
    /// index serves the range bounds and the sort, so no blocking sort runs.
    MongoRangeFind,
    /// Mongo aggregation with a `$match` and a `$group`, returning one
    /// document. The mongo analogue of [`Shape::Aggregate`].
    MongoAggregate,
}

impl Shape {
    /// Every shape, in the order they are reported.
    pub fn all() -> &'static [Shape] {
        &[
            Shape::PointLookup,
            Shape::RangeScan,
            Shape::Aggregate,
            Shape::MongoPointFind,
            Shape::MongoRangeFind,
            Shape::MongoAggregate,
        ]
    }

    /// The shapes belonging to one backend, in report order.
    pub fn for_backend(backend: Backend) -> Vec<Shape> {
        Shape::all()
            .iter()
            .copied()
            .filter(|shape| shape.backend() == backend)
            .collect()
    }

    /// Which backend this shape runs against.
    pub fn backend(self) -> Backend {
        match self {
            Shape::PointLookup | Shape::RangeScan | Shape::Aggregate => Backend::Postgres,
            Shape::MongoPointFind | Shape::MongoRangeFind | Shape::MongoAggregate => Backend::Mongo,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Shape::PointLookup => "point_lookup",
            Shape::RangeScan => "range_scan",
            Shape::Aggregate => "aggregate",
            Shape::MongoPointFind => "mongo_point_find",
            Shape::MongoRangeFind => "mongo_range_find",
            Shape::MongoAggregate => "mongo_aggregate",
        }
    }

    /// One line of prose per shape, carried into the report so a reader of
    /// the published table does not have to open this file to know what ran.
    pub fn description(self) -> &'static str {
        match self {
            Shape::PointLookup => "SELECT one row by primary key",
            Shape::RangeScan => "SELECT 1000 rows over an indexed range",
            Shape::Aggregate => "COUNT + SUM aggregate over 50k rows, one row returned",
            Shape::MongoPointFind => "mongo find by _id, one document returned",
            Shape::MongoRangeFind => "mongo find over the indexed _id range, 1000 documents",
            Shape::MongoAggregate => "mongo $match + $group aggregate, one document returned",
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
            // Mongo shapes speak JSON, not SQL. `Shape::command` is the entry
            // point for those; this arm exists only so a mistaken call on a
            // postgres-shaped path fails loudly instead of running SQL against
            // mongo.
            _ => String::new(),
        }
    }

    /// The query text sent to the gateway and to the direct baseline.
    ///
    /// For postgres this is SQL; for mongo it is the JSON command document
    /// the gateway's `MongoAdapter` parses and dispatches. **The same string
    /// goes down both paths** — that is what makes the comparison a
    /// comparison of paths rather than of queries.
    pub fn query(self, iteration: u64) -> String {
        match self.backend() {
            Backend::Postgres => self.sql(iteration),
            Backend::Mongo => self.command(iteration),
        }
    }

    /// The mongo command document for this shape.
    ///
    /// Shape mirrors the postgres shapes: a point find, a 1000-document range
    /// find, and a `$match` + `$group` aggregate. The key order matters —
    /// mongo's wire convention is "the first key is the command name", and
    /// the gateway's rejector reads the first key off the parsed JSON object.
    /// `serde_json`'s `preserve_order` feature (already enabled crate-wide)
    /// keeps insertion order, so building the text in this order is enough.
    pub fn command(self, iteration: u64) -> String {
        match self {
            Shape::MongoPointFind => {
                let id = (iteration % MONGO_SEED_DOCS as u64) + 1;
                format!(
                    r#"{{"find":"{MONGO_COLLECTION}","filter":{{"{MONGO_KEY_FIELD}":{id}}},"limit":1}}"#
                )
            }
            Shape::MongoRangeFind => {
                let lo = (iteration % (MONGO_SEED_DOCS as u64 - 1000)) + 1;
                format!(
                    r#"{{"find":"{MONGO_COLLECTION}","filter":{{"{MONGO_KEY_FIELD}":{{"$gte":{lo},"$lt":{hi}}}}},"sort":{{"{MONGO_KEY_FIELD}":1}},"limit":1000}}"#,
                    hi = lo + 1000
                )
            }
            Shape::MongoAggregate => {
                let floor = iteration % 1000;
                format!(
                    r#"{{"aggregate":"{MONGO_COLLECTION}","pipeline":[{{"$match":{{"val":{{"$gt":{floor}}}}}}},{{"$group":{{"_id":null,"c":{{"$sum":1}},"s":{{"$sum":"$val"}}}}}}],"cursor":{{}}}}"#
                )
            }
            _ => String::new(),
        }
    }

    /// Row cap to send with the gateway request. Must exceed what the shape
    /// returns, or the gateway truncates and we would be comparing a truncated
    /// response against a complete one.
    pub fn limit(self) -> u32 {
        match self {
            Shape::PointLookup | Shape::Aggregate => 10,
            Shape::RangeScan => 2000,
            Shape::MongoPointFind => 10,
            Shape::MongoRangeFind => 2000,
            Shape::MongoAggregate => 10,
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
        assert!(Shape::MongoRangeFind.limit() > 1000);
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

    /// Every shape must belong to exactly one backend, and each backend's
    /// shape list must be a partition of the whole — otherwise a shape could
    /// be silently skipped by one backend's phase and still look like a
    /// complete run.
    #[test]
    fn backend_partitions_the_shapes() {
        for backend in Backend::all() {
            let shapes = Shape::for_backend(*backend);
            assert!(!shapes.is_empty(), "{backend:?} has no shapes");
            for shape in &shapes {
                assert_eq!(shape.backend(), *backend);
            }
        }
        let covered: usize = Backend::all()
            .iter()
            .map(|b| Shape::for_backend(*b).len())
            .sum();
        assert_eq!(
            covered,
            Shape::all().len(),
            "backend lists do not partition"
        );
    }

    /// The mongo command must be a JSON object whose FIRST key is the command
    /// name — mongo's wire convention, and what the gateway's rejector reads
    /// to decide whether the command is a permitted read.
    #[test]
    fn mongo_commands_lead_with_the_command_name() {
        for shape in Shape::for_backend(Backend::Mongo) {
            for iteration in [0u64, 1, 999] {
                let cmd = shape.command(iteration);
                let parsed: serde_json::Value =
                    serde_json::from_str(&cmd).expect("mongo command must be valid JSON");
                let object = parsed
                    .as_object()
                    .expect("mongo command must be a JSON object");
                let first = object.keys().next().expect("command has fields");
                assert!(
                    ["find", "aggregate", "count", "distinct"].contains(&first.as_str()),
                    "{} produced a command named `{first}`",
                    shape.name()
                );
            }
        }
    }

    /// The mongo shapes must address the same collection the seed writes to,
    /// or the direct baseline and the gateway would read different data.
    #[test]
    fn mongo_commands_target_the_seeded_collection() {
        for shape in Shape::for_backend(Backend::Mongo) {
            let cmd = shape.command(0);
            assert!(
                cmd.contains(MONGO_COLLECTION),
                "{} addresses a different collection: {cmd}",
                shape.name()
            );
        }
    }

    /// The mongo point find and range find must stay inside the seeded
    /// document range, same invariant as the postgres shapes.
    #[test]
    fn mongo_predicates_stay_inside_the_seeded_range() {
        for i in [0u64, 1, 48_999, 100_000] {
            let cmd = Shape::MongoPointFind.command(i);
            let parsed: serde_json::Value = serde_json::from_str(&cmd).expect("valid JSON");
            let id = parsed["filter"][MONGO_KEY_FIELD]
                .as_i64()
                .expect("numeric filter");
            assert!(
                (1..=MONGO_SEED_DOCS).contains(&id),
                "iteration {i} produced out-of-range id {id}"
            );

            let cmd = Shape::MongoRangeFind.command(i);
            let parsed: serde_json::Value = serde_json::from_str(&cmd).expect("valid JSON");
            let hi = parsed["filter"][MONGO_KEY_FIELD]["$lt"]
                .as_i64()
                .expect("upper bound");
            assert!(
                hi <= MONGO_SEED_DOCS,
                "iteration {i} scans past the seed: {hi}"
            );
        }
    }

    /// The mongo shapes must filter and sort on `_id` — the only field mongo
    /// indexes by default.
    ///
    /// A filter on any other field is a collection scan over the whole
    /// collection, and a sort on any other field adds a blocking in-memory
    /// sort on top of it. The shape would then measure mongo's planner
    /// rather than the gateway's overhead, and the published "indexed range"
    /// claim would be false. This test pins the field the shapes query; the
    /// seed that makes the field indexed lives in `mongo.rs`.
    #[test]
    fn mongo_shapes_query_the_indexed_key_field() {
        let point = Shape::MongoPointFind.command(0);
        let parsed: serde_json::Value = serde_json::from_str(&point).expect("valid JSON");
        let filter = parsed["filter"].as_object().expect("filter is an object");
        assert_eq!(
            filter.keys().collect::<Vec<_>>(),
            vec![MONGO_KEY_FIELD],
            "the point find must filter on `{MONGO_KEY_FIELD}` alone: {point}"
        );

        let range = Shape::MongoRangeFind.command(0);
        let parsed: serde_json::Value = serde_json::from_str(&range).expect("valid JSON");
        let filter = parsed["filter"].as_object().expect("filter is an object");
        assert_eq!(
            filter.keys().collect::<Vec<_>>(),
            vec![MONGO_KEY_FIELD],
            "the range find must filter on `{MONGO_KEY_FIELD}` alone: {range}"
        );
        // The sort key must be the indexed field too, so the index can serve
        // the ordering and mongo does not fall back to a blocking sort.
        let sort = parsed["sort"].as_object().expect("sort is an object");
        assert_eq!(
            sort.keys().collect::<Vec<_>>(),
            vec![MONGO_KEY_FIELD],
            "the range find must sort on `{MONGO_KEY_FIELD}`: {range}"
        );
        assert_eq!(sort[MONGO_KEY_FIELD].as_i64(), Some(1));
    }

    /// `query()` is what both paths send. It must never hand a mongo shape a
    /// SQL string (or vice versa) — a mismatch there would silently compare
    /// two different queries.
    #[test]
    fn query_dispatches_on_the_backend() {
        assert_eq!(
            Shape::PointLookup.query(0),
            Shape::PointLookup.sql(0),
            "postgres shapes must send SQL"
        );
        assert_eq!(
            Shape::MongoPointFind.query(0),
            Shape::MongoPointFind.command(0),
            "mongo shapes must send the command document"
        );
    }
}
