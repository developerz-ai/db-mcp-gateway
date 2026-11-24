//! Doc drift: the names the docs tell an operator or an agent to type must
//! exist in the code. Offline and fast — it reads files, never boots anything.
//!
//! - the pinned image version in the docs is `Cargo.toml`'s;
//! - every env var in the quickstart table is read by the code, and every env
//!   var the code reads is in that table;
//! - every documented HTTP route is mounted;
//! - the tool lists name exactly the advertised tools;
//! - the log contract lists every audit outcome code, and no doc uses a
//!   retired one;
//! - every metric in the catalogue is emitted;
//! - every documented MCP client URL ends in the MCP path;
//! - every gateway config under `examples/` parses.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use db_mcp_gateway::config::ConfigFile;
use regex::Regex;

/// The default `MCP_PATH`, which every client URL in the docs must carry.
const MCP_PATH: &str = "/mcp";
const QUICKSTART: &str = "website/docs/deployment/quickstart.md";
const LOGGING: &str = "website/docs/deployment/logging.md";
/// Codes that once appeared in docs but were never (or are no longer) emitted.
const RETIRED_CODES: &[&str] = &["row_limit_exceeded"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Files under `dir` (repo-relative), recursively, with one of `exts`.
fn files_under(dir: &str, exts: &[&str]) -> Vec<PathBuf> {
    fn walk(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
        for path in fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
        {
            if path.is_dir() {
                walk(&path, exts, out);
            } else if path
                .extension()
                .is_some_and(|e| exts.iter().any(|x| e == *x))
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root().join(dir), exts, &mut out);
    out
}

/// Every user-facing Markdown page: the site, the README, the examples.
fn docs() -> Vec<(String, String)> {
    let mut paths = vec![root().join("README.md")];
    paths.extend(files_under("website/docs", &["md"]));
    paths.extend(files_under("examples", &["md"]));
    let rel = |p: &Path| p.strip_prefix(root()).unwrap().display().to_string();
    paths
        .iter()
        .map(|p| (rel(p), fs::read_to_string(p).unwrap()))
        .collect()
}

/// All Rust sources under `src/`, concatenated.
fn src() -> String {
    let paths = files_under("src", &["rs"]);
    paths
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect()
}

fn captures(re: &str, text: &str) -> BTreeSet<String> {
    Regex::new(re)
        .unwrap()
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

/// Backticked names in the first cell of a Markdown table's rows, between
/// `heading` and the next heading of any level. `A` / `B` cells split.
fn first_column_names(doc: &str, heading: &str) -> BTreeSet<String> {
    let start = doc
        .find(heading)
        .unwrap_or_else(|| panic!("heading {heading:?} missing"));
    let section = &doc[start + heading.len()..];
    let section = &section[..section.find("\n#").unwrap_or(section.len())];
    let cell = Regex::new(r"`([A-Za-z0-9_]+)`").unwrap();
    section
        .lines()
        .filter(|l| l.starts_with("| `"))
        .flat_map(|l| {
            let first = l.split('|').nth(1).unwrap_or("").to_string();
            cell.captures_iter(&first)
                .map(|c| c[1].to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn pinned_image_version_is_the_crate_version() {
    let version = env!("CARGO_PKG_VERSION");
    let pin = Regex::new(r"ghcr\.io/developerz-ai/db-mcp-gateway:(\d+\.\d+\.\d+)").unwrap();
    for (rel, text) in docs() {
        for c in pin.captures_iter(&text) {
            assert_eq!(&c[1], version, "{rel} pins another image version");
        }
    }
    let install = format!("**v{version} —");
    assert!(read("README.md").contains(&install), "README install line");
}

#[test]
fn documented_env_vars_match_the_code() {
    let documented = first_column_names(
        &read(QUICKSTART),
        "### The environment variables the gateway reads",
    );
    assert!(documented.len() > 20, "env table not found: {documented:?}");
    let code = src();
    for name in &documented {
        assert!(code.contains(&format!("\"{name}\"")), "{name}: never read");
    }
    let read_by_code = captures(
        r#"(?:env::var|required|env\s*=)\(?\s*"([A-Z][A-Z0-9_]+)""#,
        &code,
    );
    let undocumented: Vec<_> = read_by_code.difference(&documented).collect();
    assert!(
        undocumented.is_empty(),
        "not in {QUICKSTART}: {undocumented:?}"
    );
}

/// A documented path with its parameter segments (`:id`, `<id>`, `{id}`, `…`)
/// normalised to `:id`.
fn normalise(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches(['.', ',', ')', ':', '`']);
    path.split('/')
        .map(|seg| {
            let param = seg.starts_with([':', '<', '{']) || seg == "…" || seg == "...";
            if param { ":id" } else { seg }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn documented_routes_are_mounted() {
    let code = src();
    let mut mounted = captures(r#"\.route\(\s*"([^"]+)""#, &code);
    mounted.extend(captures(r#"CONSENT_PATH: &str = "([^"]+)""#, &code));
    mounted.insert(MCP_PATH.to_string());
    mounted.insert(format!("/.well-known/oauth-protected-resource{MCP_PATH}"));
    assert!(
        code.contains(&format!("mcp_path: \"{MCP_PATH}\"")),
        "MCP_PATH default"
    );

    let method = Regex::new(r"\b(?:GET|POST|PATCH|DELETE|PUT)\s+(/[^\s`|]*)").unwrap();
    let gated = Regex::new(r"`(/(?:admin/v1|auth|\.well-known)/[^`\s]*)`").unwrap();
    for (rel, text) in docs() {
        let found = method
            .captures_iter(&text)
            .chain(gated.captures_iter(&text));
        for c in found {
            let path = normalise(&c[1]);
            // `/auth/…`, `/x/*`, `/x/{a,b}` and `/x[/y]` name a family of routes, not one.
            let family = c[1].ends_with('…') || c[1].contains(['*', ',', '[']);
            if path.is_empty() || path == "/" || family {
                continue;
            }
            assert!(mounted.contains(&path), "{rel}: route {path} not mounted");
        }
    }
}

#[test]
fn tool_lists_name_the_advertised_tools() {
    let tools = captures(
        r#"pub const [A-Z_]+_TOOL: &str = "([a-z_]+)";"#,
        &read("src/mcp/protocol.rs"),
    );
    assert_eq!(tools.len(), 10, "tool constants changed: {tools:?}");
    let readme = read("README.md");
    let line = readme
        .lines()
        .find(|l| l.starts_with("- **MCP tool surface**"))
        .expect("README tool line");
    let listed = captures(r"`([a-z_]+)`", line.split(". ").next().unwrap());
    assert_eq!(listed, tools, "README tool surface drifted");

    let features = read("website/docs/features.md");
    let start = features
        .find("- **Tools included:**")
        .expect("features tool list");
    let bullets = &features[start
        ..features[start..]
            .find("\n\n")
            .map_or(features.len(), |e| start + e)];
    let listed = captures(r"(?m)^\s+- `([a-z_]+)`", bullets);
    assert_eq!(listed, tools, "features.md tool list drifted");
}

#[test]
fn outcome_codes_match_the_code() {
    let codes = captures(
        r#"Self::[A-Za-z]+ => "([a-z_]+)""#,
        &read("src/audit/outcome.rs"),
    );
    assert!(codes.len() >= 16, "outcome codes not found: {codes:?}");
    let logging = read(LOGGING);
    let row = logging
        .lines()
        .find(|l| l.starts_with("| `outcome` |"))
        .expect("logging outcome row");
    for code in &codes {
        assert!(row.contains(&format!("`{code}`")), "{LOGGING} lacks {code}");
    }
    for (rel, text) in docs() {
        for retired in RETIRED_CODES {
            assert!(!text.contains(retired), "{rel} mentions {retired}");
        }
    }
}

#[test]
fn catalogued_metrics_are_emitted() {
    let metrics = first_column_names(&read(QUICKSTART), "### Metric catalogue");
    assert!(
        metrics.len() >= 10,
        "metric catalogue not found: {metrics:?}"
    );
    let code = src();
    for name in &metrics {
        assert!(
            code.contains(&format!("\"{name}\"")),
            "{name}: never emitted"
        );
    }
}

#[test]
fn documented_client_urls_end_in_the_mcp_path() {
    let patterns = [
        r"claude mcp add[^\n]*?\s(https?://\S+)",
        r#""url":\s*"(https?://[^"]+)""#,
        r"(?m)^\s+url:\s*(https?://\S+)",
        r"(?m)^\s+db-gateway\s+(https?://\S+)",
    ];
    let mut checked = 0;
    for (rel, text) in docs() {
        for re in patterns {
            for url in captures(re, &text) {
                checked += 1;
                assert!(url.ends_with(MCP_PATH), "{rel}: {url} lacks {MCP_PATH}");
            }
        }
    }
    assert!(checked >= 10, "only {checked} client URLs found");
}

#[test]
fn example_gateway_configs_parse() {
    let yamls = files_under("examples", &["yaml", "yml"]);
    let configs: Vec<&Path> = yamls
        .iter()
        .map(PathBuf::as_path)
        .filter(|p| {
            fs::read_to_string(p)
                .unwrap()
                .lines()
                .any(|l| l.starts_with("servers:"))
        })
        .collect();
    assert!(!configs.is_empty(), "no gateway config under examples/");
    for path in configs {
        if let Err(err) = ConfigFile::from_file(path) {
            panic!("{} does not parse: {err}", path.display());
        }
    }
}
