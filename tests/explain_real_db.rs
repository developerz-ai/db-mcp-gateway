//! Real-DB test for `explain`: confirms `EXPLAIN (FORMAT JSON) SELECT ...`
//! against the live `target-db` returns a parseable plan with the structure
//! the tool's `extract_plan` expects.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{PoolRegistry, run_query};

const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 5434;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";

fn server() -> Server {
    Server {
        name: "target".to_string(),
        kind: ServerKind::Postgres,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: TARGET_PORT,
        tls: Tls::Insecure,
        databases: vec![database()],
    }
}

fn database() -> Database {
    Database {
        name: TARGET_DB.to_string(),
        role: TARGET_USER.to_string(),
        password: Password::Literal(TARGET_PASSWORD.to_string()),
        description: String::new(),
    }
}

async fn pool() -> sqlx::PgPool {
    PoolRegistry::new()
        .get_or_open(&server(), &database())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

/// The shape `explain::extract_plan` relies on: one row, one column, with
/// JSON-shaped content. Postgres returns it as a `json` column which sqlx
/// can decode directly as a Value, OR as text-with-JSON-content depending on
/// the version path; the tool's `extract_plan` handles both.
#[tokio::test]
async fn explain_returns_parseable_json_plan() {
    let p = pool().await;
    let result = run_query(&p, "EXPLAIN (FORMAT JSON) SELECT 1", None, 10)
        .await
        .expect("EXPLAIN runs");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].len(), 1);

    // The cell is either already-parsed JSON or a string containing JSON —
    // mirror `explain::extract_plan`'s tolerance.
    let cell = &result.rows[0][0];
    let plan: serde_json::Value = match cell {
        serde_json::Value::String(s) => serde_json::from_str(s).expect("plan text is JSON"),
        other => other.clone(),
    };
    assert!(
        plan.is_array(),
        "EXPLAIN (FORMAT JSON) returns an array: {plan}"
    );
    assert!(
        plan[0]["Plan"]["Node Type"].is_string(),
        "plan[0].Plan.Node Type must be a string: {plan}"
    );
}
