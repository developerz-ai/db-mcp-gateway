//! Doc drift: the names the docs tell an operator or an agent to type must
//! exist in the code. Offline and fast — it reads files, never boots anything.
//!
//! - every numeric image tag in the docs (GHCR and DOCR) and in every example
//!   compose file (including a `${VAR:-image:tag}` default) is `Cargo.toml`'s;
//! - every env var in the quickstart table is read by shipped code, and every
//!   env var shipped code reads is in that table;
//! - every documented `METHOD /path` is mounted with that method, and every
//!   other documented gateway path is mounted;
//! - the tool lists name exactly the advertised tools;
//! - the log contract lists every audit outcome code, and no doc uses a
//!   retired one;
//! - every documented or shipped MCP client URL ends in the MCP path;
//! - every gateway config under `examples/` parses.
//!
//! The metric table is checked against the recorder's rendered output, not
//! source text: `src/startup/metrics/docs_tests.rs` (a binary unit test, where
//! the recorder setup lives).

// CLAUDE.md §Conventions: tests may panic; `[lints.clippy]` denies it for shipped code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use db_mcp_gateway::config::ConfigFile;
use db_mcp_gateway::mcp::protocol::TOOLS_LIST;
use regex::Regex;

/// The default `MCP_PATH`, which every client URL in the docs must carry.
const MCP_PATH: &str = "/mcp";
const QUICKSTART: &str = "website/docs/deployment/quickstart.md";
const LOGGING: &str = "website/docs/deployment/logging.md";
/// Codes that once appeared in docs but were never (or are no longer) emitted.
const RETIRED_CODES: &[&str] = &["row_limit_exceeded"];
/// Read only by the `admin` CLI to find its session file, never by the gateway.
const CLI_ONLY_ENV: &[&str] = &["HOME", "XDG_CONFIG_HOME"];

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
    shipped_files().into_iter().map(|(_, text)| text).collect()
}

/// Every `src/` file that ships, with its unit tests and comments removed: a
/// name left behind in a test, a comment or a commented-out call is not code
/// the gateway runs.
fn shipped_files() -> Vec<(PathBuf, String)> {
    files_under("src", &["rs"])
        .into_iter()
        .filter(|p| !is_test_file(p))
        .map(|p| {
            let text = shipped_text(&fs::read_to_string(&p).unwrap());
            (p, text)
        })
        .collect()
}

fn is_test_file(path: &Path) -> bool {
    let name = path.file_name().unwrap().to_string_lossy();
    name.ends_with("tests.rs") || path.components().any(|c| c.as_os_str() == "tests")
}

/// `text` up to its `#[cfg(test)] mod`, without comments.
fn shipped_text(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let test_mod = (0..lines.len()).find(|&i| {
        lines[i].trim() == "#[cfg(test)]"
            && lines[i + 1..]
                .iter()
                .find(|l| !l.trim_start().starts_with("#["))
                .is_some_and(|l| l.trim_start().starts_with("mod "))
    });
    let code: String = lines[..test_mod.unwrap_or(lines.len())]
        .iter()
        .flat_map(|l| [*l, "\n"])
        .collect();
    strip_comments(&code)
}

/// `code` with `//` and (unnested) `/* */` comments blanked; string, raw
/// string and char literals are copied whole, so a `"/*"` in one is kept.
fn strip_comments(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while let Some(c) = code[i..].chars().next() {
        let rest = &code[i..];
        if rest.starts_with("//") {
            out.push(' ');
            i = rest.find('\n').map_or(code.len(), |at| i + at);
        } else if let Some(body) = rest.strip_prefix("/*") {
            let end = body.find("*/").map_or(code.len(), |at| i + 2 + at + 2);
            // Keep the line count: a failure may report a position.
            out.extend(code[i..end].chars().filter(|&c| c == '\n'));
            out.push(' ');
            i = end;
        } else {
            let end = i + literal_len(rest).unwrap_or(c.len_utf8());
            out.push_str(&code[i..end]);
            i = end;
        }
    }
    out
}

/// Byte length of the string, raw string or char literal `rest` opens with.
fn literal_len(rest: &str) -> Option<usize> {
    if let Some(raw) = rest.strip_prefix('r') {
        let hashes = raw.len() - raw.trim_start_matches('#').len();
        let body = raw[hashes..].strip_prefix('"')?;
        let close = format!("\"{}", "#".repeat(hashes));
        return Some(
            body.find(&close)
                .map_or(rest.len(), |at| rest.len() - body.len() + at + close.len()),
        );
    }
    if let Some(body) = rest.strip_prefix('"') {
        let mut escaped = false;
        for (at, c) in body.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => return Some(1 + at + 1),
                _ => {}
            }
        }
        return Some(rest.len());
    }
    // A char literal ('x', '\''), not a lifetime ('a).
    let body = rest.strip_prefix('\'')?;
    let mut chars = body.char_indices();
    let (_, first) = chars.next()?;
    if first == '\\' {
        chars.next();
    }
    match chars.next() {
        Some((at, '\'')) => Some(1 + at + 1),
        _ => None,
    }
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

/// A gateway image pinned to a release tag in either published registry. The
/// whole tag is captured, so `2.3.1-rc1` is not read as `2.3.1`.
const PINNED_IMAGE: &str =
    r"(?:ghcr\.io|registry\.digitalocean\.com)/developerz-ai/db-mcp-gateway:(\d[0-9A-Za-z.+-]*)";

#[test]
fn pinned_image_version_is_the_crate_version() {
    let version = env!("CARGO_PKG_VERSION");
    let pin = Regex::new(PINNED_IMAGE).unwrap();
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
fn pinned_image_reads_the_whole_tag_in_both_registries() {
    let pin = Regex::new(PINNED_IMAGE).unwrap();
    let tag = |text: &str| pin.captures(text).map(|c| c[1].to_string());
    let ghcr = "ghcr.io/developerz-ai/db-mcp-gateway:2.3.1-rc1`";
    assert_eq!(tag(ghcr).as_deref(), Some("2.3.1-rc1"));
    let docr = "registry.digitalocean.com/developerz-ai/db-mcp-gateway:9.9.9 ";
    assert_eq!(tag(docr).as_deref(), Some("9.9.9"));
    assert_eq!(tag("ghcr.io/developerz-ai/db-mcp-gateway:latest"), None);
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
    let read_by_code = env_reads();
    let never_read: Vec<_> = documented.difference(&read_by_code).collect();
    assert!(
        never_read.is_empty(),
        "documented, never read: {never_read:?}"
    );
    let undocumented: Vec<_> = read_by_code
        .difference(&documented)
        .filter(|name| !CLI_ONLY_ENV.contains(&name.as_str()))
        .collect();
    assert!(
        undocumented.is_empty(),
        "not in {QUICKSTART}: {undocumented:?}"
    );
}

/// Every env var name shipped code passes to a reader: a literal argument to
/// `env::var`/`env::var_os`/`required`/`bool_flag_from_env` or clap's `env =`,
/// a same-file `const` passed to `env::var`/`env::var_os`, or a `*_VARS`
/// array the code loops over into `env::var`.
fn env_reads() -> BTreeSet<String> {
    let literal = Regex::new(
        r#"(?:env::var(?:_os)?\(|required\(|bool_flag_from_env\(|env\s*=\s*)\s*"([A-Z][A-Z0-9_]+)""#,
    )
    .unwrap();
    let constant = Regex::new(r#"const ([A-Z_]+): &str = "([A-Z][A-Z0-9_]+)""#).unwrap();
    let array = Regex::new(r"(?s)const ([A-Z_]+_VARS): \[&str; \d+\] = \[(.*?)\];").unwrap();
    let mut names = BTreeSet::new();
    for (_, text) in shipped_files() {
        names.extend(literal.captures_iter(&text).map(|c| c[1].to_string()));
        for c in constant.captures_iter(&text) {
            let passed = Regex::new(&format!(r"env::var(?:_os)?\({}\)", &c[1])).unwrap();
            if passed.is_match(&text) {
                names.insert(c[2].to_string());
            }
        }
        for c in array.captures_iter(&text) {
            let looped = format!("in {}", &c[1]);
            if text.contains(&looped) && text.contains("std::env::var(var)") {
                names.extend(captures(r#""([A-Z][A-Z0-9_]+)""#, &c[2]));
            }
        }
    }
    names
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
fn shipped_text_drops_comments_and_the_test_module() {
    let text = "let r = Router::new()\n    // .route(\"/gone\", get(gone))\n    .route(\"/kept\", get(kept));\n\
                #[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod tests;\nconst T: &str = \"TEST_ONLY\";\n";
    let shipped = shipped_text(text);
    let routes = mounted_routes(&shipped);
    assert!(routes.contains(&("GET".to_string(), "/kept".to_string())));
    assert!(
        !routes.iter().any(|(_, path)| path == "/gone"),
        "{routes:?}"
    );
    assert!(!shipped.contains("TEST_ONLY"));
}

#[test]
fn shipped_text_drops_block_comments_but_not_strings() {
    let text = "let r = Router::new()\n    /* .route(\"/inline\", get(gone)) */\n    /*\n    .route(\"/spanned\", get(gone))\n    */\n    .route(\"/kept/*rest\", get(kept)) // .route(\"/trailing\", get(gone))\n    .route(\"/also\", get(kept));\nconst Q: char = '\"';\n";
    let routes = mounted_routes(&shipped_text(text));
    let paths: BTreeSet<&str> = routes.iter().map(|(_, path)| path.as_str()).collect();
    assert_eq!(
        paths,
        BTreeSet::from(["/kept/*rest", "/also"]),
        "{routes:?}"
    );
}

#[test]
fn tool_lists_name_the_advertised_tools() {
    let tools: BTreeSet<String> = TOOLS_LIST
        .tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(tools.len() >= 10, "tools/list shrank: {tools:?}");
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
fn documented_client_urls_end_in_the_mcp_path() {
    let patterns = [
        r"claude mcp add[^\n]*?\s(https?://\S+)",
        r#""url":\s*"(https?://[^"]+)""#,
        r"(?m)^\s+url:\s*(https?://\S+)",
        r"(?m)^\s+db-gateway\s+(https?://\S+)",
    ];
    let mut checked = 0;
    for (rel, text) in docs().into_iter().chain(client_configs()) {
        for re in patterns {
            for url in captures(re, &text) {
                checked += 1;
                assert!(url.ends_with(MCP_PATH), "{rel}: {url} lacks {MCP_PATH}");
            }
        }
    }
    assert!(checked >= 10, "only {checked} client URLs found");
    let config: serde_json::Value = serde_json::from_str(&read("examples/.mcp.json"))
        .expect("example MCP config is valid JSON");
    let servers = config["mcpServers"].as_object().expect("MCP servers");
    assert!(!servers.is_empty(), "example MCP config has no servers");
    for (name, server) in servers {
        let url = server["url"].as_str().expect("server URL");
        assert!(url.ends_with(MCP_PATH), "{name}: {url} lacks {MCP_PATH}");
    }
}

/// The shipped MCP client configs (`examples/**/*.json`), each of which must
/// name at least one server URL so the check above cannot skip it.
fn client_configs() -> Vec<(String, String)> {
    let configs: Vec<(String, String)> = files_under("examples", &["json"])
        .into_iter()
        .map(|p| {
            let rel = p.strip_prefix(root()).unwrap().display().to_string();
            (rel, fs::read_to_string(&p).unwrap())
        })
        .collect();
    assert!(
        configs.iter().any(|(rel, _)| rel == "examples/.mcp.json"),
        "examples/.mcp.json not found: {configs:?}"
    );
    for (rel, text) in &configs {
        let json: serde_json::Value =
            serde_json::from_str(text).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let urls = json["mcpServers"].as_object().map_or(0, |servers| {
            servers.values().filter(|s| s["url"].is_string()).count()
        });
        assert!(urls > 0, "{rel} names no MCP server url");
    }
    configs
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
