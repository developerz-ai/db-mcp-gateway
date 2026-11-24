//! Snapshot of the agent-facing surface: the `initialize` result and the
//! `tools/list` payload, as served over HTTP, against committed fixtures in
//! `tests/data/mcp/`. A change to a tool's name, title, description, schema
//! or annotations, or to the instructions, shows up as a fixture diff in
//! review. Regenerate with `UPDATE_MCP_FIXTURES=1 cargo test --test
//! it_offline mcp_surface::`.

use std::path::PathBuf;
use std::time::Duration;

use crate::common::gateway::{authless_state, bind, serve};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport;
use serde_json::{Value, json};

const UPDATE_ENV: &str = "UPDATE_MCP_FIXTURES";
/// Stands in for `serverInfo.version`, which moves with every release.
const VERSION_PLACEHOLDER: &str = "<crate version>";

async fn call(method: &str) -> Value {
    let (listener, addr) = bind().await;
    let config = Config {
        bind: addr,
        ..Config::default()
    };
    serve(listener, transport::test_router(&config, authless_state()));
    let body: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .post(format!("http://{addr}/mcp"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["result"].clone()
}

fn assert_matches_fixture(name: &str, actual: &Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/mcp")
        .join(name);
    let rendered = format!("{}\n", serde_json::to_string_pretty(actual).unwrap());
    if std::env::var_os(UPDATE_ENV).is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, rendered).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run with {UPDATE_ENV}=1", path.display()));
    let expected: Value = serde_json::from_str(&committed).unwrap();
    assert_eq!(
        actual,
        &expected,
        "{name} drifted from {}; if intended, rerun with {UPDATE_ENV}=1 and review the diff.\n\
         actual:\n{rendered}",
        path.display()
    );
}

#[tokio::test]
async fn initialize_matches_fixture() {
    let mut result = call("initialize").await;
    assert_eq!(
        result["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION"),
        "{result}"
    );
    result["serverInfo"]["version"] = json!(VERSION_PLACEHOLDER);
    assert_matches_fixture("initialize.json", &result);
}

#[tokio::test]
async fn tools_list_matches_fixture() {
    let result = call("tools/list").await;
    assert_matches_fixture("tools_list.json", &result);
}

/// The hints describe enforcement, so the tools that can change something
/// must never claim to be read-only.
#[tokio::test]
async fn only_pure_reads_are_annotated_read_only() {
    let result = call("tools/list").await;
    let tools = result["tools"].as_array().expect("tools array");
    for tool in tools {
        let name = tool["name"].as_str().expect("tool name");
        let hints = &tool["annotations"];
        let mutating = matches!(name, "run_query" | "explain" | "cancel_query");
        assert_eq!(hints["readOnlyHint"], !mutating, "{name}: {hints}");
        assert_eq!(hints["openWorldHint"], false, "{name}: {hints}");
        let destructive = mutating.then(|| json!(name == "run_query"));
        assert_eq!(
            hints["destructiveHint"],
            destructive.unwrap_or(Value::Null),
            "{name}: {hints}"
        );
        assert!(tool["title"].is_string(), "{name} has a title");
    }
}
