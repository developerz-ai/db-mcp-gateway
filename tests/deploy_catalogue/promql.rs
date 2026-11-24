//! A PromQL reader just deep enough to list the series, label names and
//! `outcome` values an expression names, checked against the catalogue.

use std::collections::BTreeSet;

use regex::Regex;

use super::catalogue::{CATALOGUE, Kind};

/// Labels Prometheus itself attaches to every scraped series.
const TARGET_LABELS: &[&str] = &[
    "job",
    "instance",
    "namespace",
    "pod",
    "service",
    "container",
    "endpoint",
];
const PROMQL_KEYWORDS: &[&str] = &["and", "or", "unless", "bool", "offset", "inf", "nan"];
const GROUPING: &[&str] = &[
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
];

/// The labels a scraped series name carries, or `None` when the catalogue
/// has no such series. A histogram is scraped as `_bucket` / `_sum` / `_count`.
fn series_labels(name: &str) -> Option<BTreeSet<&'static str>> {
    let lookup = |base: &str| CATALOGUE.iter().find(|m| m.name == base);
    if let Some(metric) = lookup(name).filter(|m| m.kind != Kind::Histogram) {
        return Some(metric.labels.iter().copied().collect());
    }
    for (suffix, extra) in [("_bucket", Some("le")), ("_sum", None), ("_count", None)] {
        let Some(base) = name.strip_suffix(suffix) else {
            continue;
        };
        if let Some(metric) = lookup(base).filter(|m| m.kind == Kind::Histogram) {
            return Some(metric.labels.iter().copied().chain(extra).collect());
        }
    }
    None
}

#[derive(Debug, PartialEq)]
enum Token<'a> {
    Ident(&'a str),
    Str(&'a str),
    Punct(char),
    Other,
}

fn tokens(expr: &str) -> Vec<Token<'_>> {
    let lexer = Regex::new(
        r#"(?x)(?P<s>"[^"]*"|'[^']*')|(?P<v>\$\{[^}]*\}|\$\w+)|(?P<n>[0-9][0-9A-Za-z.]*)|(?P<i>[A-Za-z_:][A-Za-z0-9_:]*)|(?P<p>[^\s])"#,
    )
    .unwrap();
    lexer
        .captures_iter(expr)
        .map(|c| {
            if let Some(s) = c.name("s") {
                Token::Str(&s.as_str()[1..s.as_str().len() - 1])
            } else if let Some(i) = c.name("i") {
                Token::Ident(i.as_str())
            } else if let Some(p) = c.name("p") {
                Token::Punct(p.as_str().chars().next().unwrap())
            } else {
                Token::Other
            }
        })
        .collect()
}

/// A function call or an aggregation, `sum(…)` or `sum by (…) (…)`.
fn is_call(next: Option<&Token<'_>>) -> bool {
    matches!(
        next,
        Some(Token::Punct('(') | Token::Ident("by" | "without"))
    )
}

/// Every problem with the series, labels and outcome values one PromQL
/// expression names.
pub(crate) fn check_promql(expr: &str, outcomes: &BTreeSet<String>) -> Vec<String> {
    let toks = tokens(expr);
    let mut problems = Vec::new();
    let mut known: BTreeSet<&str> = TARGET_LABELS.iter().copied().collect();
    let mut grouping = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let Token::Ident(word) = toks[i] else {
            i += 1;
            continue;
        };
        let next = toks.get(i + 1);
        if GROUPING.contains(&word) && next == Some(&Token::Punct('(')) {
            i += 2;
            while i < toks.len() && toks[i] != Token::Punct(')') {
                if let Token::Ident(label) = toks[i] {
                    grouping.push(label);
                }
                i += 1;
            }
        } else if is_call(next) || PROMQL_KEYWORDS.contains(&word) {
            i += 1;
        } else {
            let labels = series_labels(word);
            if labels.is_none() {
                problems.push(format!("`{word}` is not a catalogued series"));
            }
            let labels = labels.unwrap_or_default();
            known.extend(labels.iter().copied());
            i += 1;
            if toks.get(i) == Some(&Token::Punct('{')) {
                while i < toks.len() && toks[i] != Token::Punct('}') {
                    if let Token::Ident(label) = toks[i] {
                        if !labels.contains(label) && !TARGET_LABELS.contains(&label) {
                            problems.push(format!("`{word}` has no label `{label}`"));
                        }
                        let value = toks[i + 1..].iter().find_map(|t| match t {
                            Token::Str(v) => Some(*v),
                            _ => None,
                        });
                        if let (Some(value), "outcome") = (value, label) {
                            for code in value.split('|').filter(|c| !outcomes.contains(*c)) {
                                problems.push(format!("`{code}` is not an outcome code"));
                            }
                        }
                    }
                    i += 1;
                }
            }
        }
    }
    for label in grouping.into_iter().filter(|l| !known.contains(l)) {
        problems.push(format!(
            "grouping label `{label}` is on no series of the expression"
        ));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::check_promql;
    use crate::outcome_codes;

    #[test]
    fn the_checker_rejects_drift() {
        let outcomes = outcome_codes();
        assert!(
            check_promql(
                r#"sum by (le) (rate(audit_write_duration_seconds_bucket{job="x"}[5m]))"#,
                &outcomes
            )
            .is_empty()
        );
        assert_eq!(check_promql("rate(tool_call[5m])", &outcomes).len(), 1);
        assert_eq!(
            check_promql(r#"pool_size{database="a"}"#, &outcomes).len(),
            1
        );
        assert_eq!(
            check_promql(r#"tool_calls{outcome=~"ok|internal"}"#, &outcomes).len(),
            1
        );
        assert_eq!(
            check_promql("sum by (sink) (rate(tool_calls[5m]))", &outcomes).len(),
            1
        );
    }
}
