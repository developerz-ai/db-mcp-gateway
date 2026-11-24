//! The metric catalogue (`src/startup/metrics/catalogue.rs`) against the
//! source: every catalogued series has an emit site, and every emit site
//! names a catalogued series. Docs and dashboards pin to the catalogue, so a
//! series renamed or added in code without it fails here.

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;

#[allow(dead_code)]
#[path = "../../src/startup/metrics/catalogue.rs"]
mod catalogue;

/// `counter!("name"`, `gauge!(NAME`, … — a literal or a `const` name.
const MACRO_EMIT: &str = r#"\b(?:counter|gauge|histogram)!\(\s*(?:"([a-z_]+)"|([A-Z][A-Z_]*))"#;
/// Held gauges are emitted through `held().set("name"` / `set_info("name"`.
const HELD_EMIT: &str = r#"\.set(?:_info)?\(\s*"([a-z_]+)""#;
const NAME_CONST: &str = r#"const ([A-Z][A-Z_]*): &str = "([a-z_]+)";"#;

fn sources(dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(std::fs::read_to_string(&path).expect("read source"));
        }
    }
}

/// Every series name an emit site in `src/` names.
fn emitted() -> BTreeSet<String> {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let all = files.concat();
    let consts: Vec<(String, String)> = Regex::new(NAME_CONST)
        .expect("regex")
        .captures_iter(&all)
        .map(|c| (c[1].to_owned(), c[2].to_owned()))
        .collect();
    let mut names = BTreeSet::new();
    for caps in Regex::new(MACRO_EMIT).expect("regex").captures_iter(&all) {
        if let Some(literal) = caps.get(1) {
            names.insert(literal.as_str().to_owned());
        } else if let Some(ident) = caps.get(2) {
            let ident = ident.as_str();
            let (_, value) = consts
                .iter()
                .find(|(name, _)| name == ident)
                .unwrap_or_else(|| panic!("metric name const `{ident}` not found"));
            names.insert(value.clone());
        }
    }
    for caps in Regex::new(HELD_EMIT).expect("regex").captures_iter(&all) {
        names.insert(caps[1].to_owned());
    }
    names
}

#[test]
fn every_catalogued_series_is_emitted() {
    let emitted = emitted();
    for metric in catalogue::CATALOGUE {
        assert!(
            emitted.contains(metric.name),
            "`{}` is catalogued but never emitted",
            metric.name
        );
    }
}

#[test]
fn every_emitted_series_is_catalogued() {
    for name in emitted() {
        assert!(
            catalogue::CATALOGUE.iter().any(|m| m.name == name),
            "`{name}` is emitted but missing from src/startup/metrics/catalogue.rs"
        );
    }
}

#[test]
fn no_label_names_an_identity_query_or_host() {
    const FORBIDDEN: &[&str] = &[
        "user",
        "user_sub",
        "sub",
        "email",
        "sql",
        "query",
        "request_id",
        "token",
        "host",
        "ip",
        "role",
    ];
    for metric in catalogue::CATALOGUE {
        for label in metric.labels {
            assert!(
                !FORBIDDEN.contains(label),
                "`{}` carries forbidden label `{label}`",
                metric.name
            );
        }
    }
}
