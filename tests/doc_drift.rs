//! Doc drift: the names the docs tell an operator or an agent to type must
//! exist in the code. Offline and fast — it reads files, never boots anything.
//!
//! - the pinned image version in the docs and in every example compose file
//!   (including a `${VAR:-image:tag}` default) is `Cargo.toml`'s;
//! - every env var in the quickstart table is read by the code, and every env
//!   var the code reads is in that table;
//! - every documented `METHOD /path` is mounted with that method, and every
//!   other documented gateway path is mounted;
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

/// The gateway image an `image:` value names, unwrapping a `${VAR:-default}`.
fn image_default(value: &str) -> &str {
    let value = value.trim().trim_matches(['"', '\'']);
    match value.strip_prefix("${") {
        Some(rest) => rest
            .split_once(":-")
            .map_or("", |(_, default)| default.trim_end_matches('}')),
        None => value,
    }
}

#[test]
fn example_compose_images_are_the_crate_version() {
    let version = env!("CARGO_PKG_VERSION");
    let image = Regex::new(r"(?m)^\s*image:\s*([^#\s]+)").unwrap();
    let ours = Regex::new(
        r"^(?:ghcr\.io|registry\.digitalocean\.com)/developerz-ai/db-mcp-gateway(?::(.+))?$",
    )
    .unwrap();
    let composes: Vec<PathBuf> = files_under("examples", &["yml", "yaml"])
        .into_iter()
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("docker-compose"))
        })
        .collect();
    let mut pinned = 0;
    for path in &composes {
        let text = fs::read_to_string(path).unwrap();
        for c in image.captures_iter(&text) {
            let Some(tag) = ours.captures(image_default(&c[1])) else {
                continue;
            };
            pinned += 1;
            let tag = tag.get(1).map_or("", |t| t.as_str());
            assert_eq!(
                tag,
                version,
                "{} pins the gateway image at {:?}",
                path.display(),
                &c[1]
            );
        }
    }
    assert!(pinned >= 2, "only {pinned} gateway images in {composes:?}");
}

#[test]
fn image_default_unwraps_compose_defaults() {
    assert_eq!(
        image_default("${GATEWAY_IMAGE:-ghcr.io/x:1.0.0}"),
        "ghcr.io/x:1.0.0"
    );
    assert_eq!(image_default("\"ghcr.io/x:1.0.0\""), "ghcr.io/x:1.0.0");
    assert_eq!(image_default("${GATEWAY_IMAGE}"), "");
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

/// Where a `.route(` call's path argument is an expression, what it names.
fn route_path(arg: &str, code: &str) -> String {
    if let Some(rest) = arg.strip_prefix('"') {
        return rest[..rest.find('"').expect("closing quote")].to_string();
    }
    if arg.starts_with("&path") || arg.starts_with("&normalize_path(&config.mcp_path)") {
        return MCP_PATH.to_string();
    }
    if arg.starts_with("&prm_suffixed") {
        return format!("/.well-known/oauth-protected-resource{MCP_PATH}");
    }
    if arg.starts_with("oauth::CONSENT_PATH") {
        let consent = captures(r#"CONSENT_PATH: &str = "([^"]+)""#, code);
        return consent.into_iter().next().expect("CONSENT_PATH");
    }
    panic!("doc_drift does not know the route path expression {arg:?}");
}

/// The router contract: every `(METHOD, path)` a `.route(path, get(..).post(..))`
/// mounts, read from the source.
fn mounted_routes(code: &str) -> BTreeSet<(String, String)> {
    let method = Regex::new(r"\b(get|post|patch|delete|put)\(").unwrap();
    let ends = [".route_layer(", ".layer(", ".with_state(", ".merge(", ";"];
    let mut routes = BTreeSet::new();
    for call in code.split(".route(").skip(1) {
        let call = &call[..ends
            .iter()
            .filter_map(|e| call.find(e))
            .min()
            .unwrap_or(call.len())];
        let path = route_path(call.trim_start(), code);
        for m in method.captures_iter(call) {
            routes.insert((m[1].to_uppercase(), path.clone()));
        }
    }
    routes
}

#[test]
fn documented_routes_are_mounted() {
    let code = src();
    let routes = mounted_routes(&code);
    assert!(
        routes.contains(&("DELETE".to_string(), "/admin/v1/grants/:id".to_string())),
        "router contract not read: {routes:?}"
    );
    // A path mounted for one method is not mounted for another.
    assert!(!routes.contains(&("GET".to_string(), "/token".to_string())));
    let paths: BTreeSet<String> = routes.iter().map(|(_, p)| p.clone()).collect();
    assert!(
        code.contains(&format!("mcp_path: \"{MCP_PATH}\"")),
        "MCP_PATH default"
    );

    let method = Regex::new(r"\b(GET|POST|PATCH|DELETE|PUT)\s+(/[^\s`|]*)").unwrap();
    let gated = Regex::new(r"`(/(?:admin/v1|auth|\.well-known)/[^`\s]*)`").unwrap();
    // `/auth/…`, `/x/*`, `/x/{a,b}` and `/x[/y]` name a family of routes, not one.
    let family = |raw: &str| raw.ends_with('…') || raw.contains(['*', ',', '[']);
    for (rel, text) in docs() {
        for c in method.captures_iter(&text) {
            let path = normalise(&c[2]);
            if path.is_empty() || path == "/" || family(&c[2]) {
                continue;
            }
            let route = (c[1].to_string(), path);
            assert!(
                routes.contains(&route),
                "{rel}: {} {} is not mounted with that method",
                route.0,
                route.1
            );
        }
        for c in gated.captures_iter(&text) {
            let path = normalise(&c[1]);
            if path.is_empty() || path == "/" || family(&c[1]) {
                continue;
            }
            assert!(paths.contains(&path), "{rel}: route {path} not mounted");
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
