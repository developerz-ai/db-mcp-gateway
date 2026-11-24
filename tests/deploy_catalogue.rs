//! `deploy/` against the code: every series and label an alert, the dashboard
//! or the runbook names is in the metric catalogue
//! (`src/startup/metrics/catalogue.rs`), every `outcome` value is a real
//! outcome code, every alert has a runbook section, the chart and the
//! kustomize base keep the shutdown, probe and security invariants, and
//! `promtool check rules` passes when docker is available.

// CLAUDE.md §Conventions: tests may panic; `[lints.clippy]` denies it for shipped code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::Value;

#[allow(dead_code)]
#[path = "../src/startup/metrics/catalogue.rs"]
mod catalogue;

use catalogue::CATALOGUE;
use promql::check_promql;

#[path = "deploy_catalogue/manifests.rs"]
mod manifests;
#[path = "deploy_catalogue/promql.rs"]
mod promql;

const RUNBOOK_URL: &str =
    "https://github.com/developerz-ai/db-mcp-gateway/blob/main/deploy/runbook.md";
const PROMTOOL_IMAGE: &str = "prom/prometheus:v2.55.1@sha256:2659f4c2ebb718e7695cb9b25ffa7d6be64db013daba13e05c875451cf51b0d3";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn yaml(rel: &str) -> Value {
    serde_saphyr::from_str(&read(rel)).unwrap_or_else(|e| panic!("parse {rel}: {e}"))
}

fn rules() -> Vec<Value> {
    let file = yaml("deploy/prometheus/rules.yaml");
    let groups = file["groups"].as_array().expect("groups");
    groups
        .iter()
        .flat_map(|g| g["rules"].as_array().expect("rules").clone())
        .collect()
}

/// The spellings `OutcomeCode::as_str` returns.
fn outcome_codes() -> BTreeSet<String> {
    let source = read("src/audit/outcome.rs");
    let codes: BTreeSet<String> = Regex::new(r#"Self::\w+ => "([a-z_]+)","#)
        .unwrap()
        .captures_iter(&source)
        .map(|c| c[1].to_owned())
        .collect();
    assert!(
        codes.len() >= 16,
        "outcome codes not found in src/audit/outcome.rs"
    );
    codes
}

/// Every PromQL expression the dashboard runs: panel targets and variable
/// queries (`label_values(<expr>, <label>)` checked as `<expr>` by `<label>`).
fn dashboard_exprs() -> Vec<String> {
    let dashboard: Value =
        serde_json::from_str(&read("deploy/grafana/db-mcp-gateway.json")).unwrap();
    let mut exprs: Vec<String> = dashboard["panels"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["targets"].as_array().cloned().unwrap_or_default())
        .map(|t| t["expr"].as_str().expect("target expr").to_owned())
        .collect();
    let label_values = Regex::new(r"^label_values\((.+),\s*(\w+)\)$").unwrap();
    for var in dashboard["templating"]["list"].as_array().unwrap() {
        if let Some(query) = var["query"]["query"].as_str() {
            let c = label_values
                .captures(query)
                .unwrap_or_else(|| panic!("variable query `{query}`"));
            exprs.push(format!("count by ({}) ({})", &c[2], &c[1]));
        }
    }
    assert!(exprs.len() > 20, "dashboard expressions not found");
    exprs
}

/// Inline code spans in the runbook that read as PromQL.
fn runbook_exprs() -> Vec<String> {
    let promql = Regex::new(r"[{(]|\s/\s|_total$|_seconds$|_timestamp$").unwrap();
    Regex::new(r"`([^`\n]+)`")
        .unwrap()
        .captures_iter(&read("deploy/runbook.md"))
        .map(|c| c[1].to_owned())
        .filter(|span| !span.contains(['$', '<']) && !span.to_lowercase().starts_with("select "))
        .filter(|span| promql.is_match(span))
        .collect()
}

#[test]
fn every_referenced_series_and_label_is_catalogued() {
    let outcomes = outcome_codes();
    let mut exprs: Vec<String> = rules()
        .iter()
        .map(|r| r["expr"].as_str().expect("expr").to_owned())
        .collect();
    exprs.extend(dashboard_exprs());
    // A bare name in prose may be a histogram's own name.
    let (bare, promql): (Vec<String>, Vec<String>) = runbook_exprs()
        .into_iter()
        .partition(|span| Regex::new(r"^[a-z_]+$").unwrap().is_match(span));
    for name in bare {
        assert!(
            CATALOGUE.iter().any(|m| m.name == name),
            "runbook names `{name}`, not a catalogued series"
        );
    }
    assert!(promql.len() > 10, "runbook PromQL spans not found");
    exprs.extend(promql);
    let problems: Vec<String> = exprs
        .iter()
        .flat_map(|e| {
            check_promql(e, &outcomes)
                .into_iter()
                .map(move |p| format!("{p} in `{e}`"))
        })
        .collect();
    assert!(
        problems.is_empty(),
        "deploy/ drifted from the catalogue:\n{}",
        problems.join("\n")
    );
}

fn slug(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

#[test]
fn every_alert_and_outcome_has_a_runbook_section() {
    let runbook = read("deploy/runbook.md");
    let headings: BTreeSet<String> = runbook
        .lines()
        .filter_map(|l| l.strip_prefix("### "))
        .map(slug)
        .collect();
    let mut alerts = BTreeSet::new();
    for rule in rules() {
        let alert = rule["alert"].as_str().expect("alert name");
        let url = rule["annotations"]["runbook_url"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            url,
            format!("{RUNBOOK_URL}#{}", slug(alert)),
            "{alert}: runbook_url"
        );
        assert!(
            headings.contains(&slug(alert)),
            "{alert}: no `### {alert}` in deploy/runbook.md"
        );
        assert!(
            rule["labels"]["severity"].is_string(),
            "{alert}: no severity label"
        );
        alerts.insert(slug(alert));
    }
    for code in outcome_codes() {
        assert!(
            headings.contains(&code),
            "outcome `{code}`: no section in deploy/runbook.md"
        );
    }
    let alerts_section = runbook.split("## Outcome codes").next().unwrap();
    for stale in alerts_section
        .lines()
        .filter_map(|l| l.strip_prefix("### "))
        .map(slug)
    {
        assert!(
            alerts.contains(&stale),
            "runbook section `{stale}` names no alert"
        );
    }
    for anchor in Regex::new(r"\]\(#([^)]+)\)")
        .unwrap()
        .captures_iter(&runbook)
    {
        assert!(
            headings.contains(&anchor[1]),
            "runbook link #{} has no heading",
            &anchor[1]
        );
    }
}

#[test]
fn promtool_accepts_the_rules() {
    let docker_up = Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|o| o.status.success());
    if !docker_up {
        eprintln!("skipping promtool check: docker is not available");
        return;
    }
    let rules_dir = root().join("deploy/prometheus");
    let output = Command::new("docker")
        .args(["run", "--rm", "--network=none", "-v"])
        .arg(format!("{}:/rules:ro", Path::new(&rules_dir).display()))
        .args([
            "--entrypoint",
            "promtool",
            PROMTOOL_IMAGE,
            "check",
            "rules",
            "/rules/rules.yaml",
        ])
        .output()
        .expect("run docker");
    assert!(
        output.status.success(),
        "promtool check rules failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
