//! The operator's metric table (`website/docs/deployment/quickstart.md`)
//! against what the recorder renders after the boot registration, and against
//! the catalogue for the series born on their first event (histograms, pool
//! and event gauges), which `tests/it_offline/metrics_catalogue.rs` pins to
//! their emit sites.

use std::collections::{BTreeMap, BTreeSet};

use super::tests::{ONE_DB, rendered_series};
use super::*;

const QUICKSTART: &str = "website/docs/deployment/quickstart.md";
const TABLE: &str = "### Metric catalogue";

/// A series' Prometheus type and label names.
type Shape = (String, BTreeSet<String>);

/// Series name → documented shape, from every `| \`name\` | type | labels |` row.
fn documented() -> BTreeMap<String, Shape> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(QUICKSTART);
    let doc = std::fs::read_to_string(&path).expect("read the quickstart");
    let start = doc.find(TABLE).expect("metric table heading") + TABLE.len();
    let section = &doc[start..];
    let section = &section[..section.find("\n#").unwrap_or(section.len())];
    let mut table = BTreeMap::new();
    for row in section.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = row.split('|').collect();
        // The type is the cell's first word; buckets and units follow it.
        let kind = cells[2].split_whitespace().next().unwrap_or_default();
        let shape = (kind.to_owned(), label_names(cells[3]));
        for name in backticked(cells[1]) {
            assert!(
                table.insert(name.clone(), shape.clone()).is_none(),
                "`{name}` documented twice"
            );
        }
    }
    assert!(table.len() >= 20, "metric table not found: {table:?}");
    table
}

/// The label names of a Labels cell: backticked words outside its
/// parenthesised notes and before its ` — ` remark (both list values).
fn label_names(cell: &str) -> BTreeSet<String> {
    let mut depth = 0usize;
    let outside: String = cell
        .chars()
        .filter(|&c| {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                _ => return depth == 0,
            }
            false
        })
        .collect();
    backticked(outside.split('—').next().unwrap_or_default())
}

fn backticked(text: &str) -> BTreeSet<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|word| word.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
        .map(str::to_owned)
        .collect()
}

fn kind_name(kind: catalogue::Kind) -> &'static str {
    match kind {
        catalogue::Kind::Counter => "counter",
        catalogue::Kind::Gauge => "gauge",
        catalogue::Kind::Histogram => "histogram",
    }
}

/// Series name → type, from the `# TYPE` lines.
fn rendered_types(body: &str) -> BTreeMap<&str, &str> {
    body.lines()
        .filter_map(|line| line.strip_prefix("# TYPE ")?.split_once(' '))
        .collect()
}

#[test]
fn documented_metrics_match_the_recorder_output() {
    let docs = documented();
    let recorder = builder().expect("builder").build_recorder();
    let config = db_mcp_gateway::config::ConfigFile::from_yaml_str(ONE_DB).expect("config parses");
    metrics::with_local_recorder(&recorder, || {
        register_boot_series();
        preregister::register_targets(&config);
    });
    let body = recorder.handle().render();
    let types = rendered_types(&body);
    let rendered: BTreeMap<String, Shape> = rendered_series(&body)
        .into_iter()
        .map(|(name, labels)| {
            let kind = types
                .get(name.as_str())
                .unwrap_or_else(|| panic!("`{name}` has no # TYPE line"));
            let shape = ((*kind).to_owned(), labels.into_iter().collect());
            (name, shape)
        })
        .collect();

    for (name, shape) in &rendered {
        let documented = docs
            .get(name)
            .unwrap_or_else(|| panic!("`{name}` is exported but not in {QUICKSTART}"));
        assert_eq!(shape, documented, "`{name}`: exported vs documented");
    }
    for metric in catalogue::CATALOGUE {
        let documented = docs
            .get(metric.name)
            .unwrap_or_else(|| panic!("`{}` is catalogued but not documented", metric.name));
        let catalogued: Shape = (
            kind_name(metric.kind).to_owned(),
            metric.labels.iter().map(|l| (*l).to_owned()).collect(),
        );
        assert_eq!(
            &catalogued, documented,
            "`{}`: catalogued vs documented",
            metric.name
        );
        if metric.kind == catalogue::Kind::Counter {
            assert!(
                rendered.contains_key(metric.name),
                "counter `{}` is documented but not exported at boot",
                metric.name
            );
        }
    }
    for name in docs.keys() {
        assert!(
            catalogue::CATALOGUE.iter().any(|m| m.name == name),
            "`{name}` is documented but not catalogued, so nothing emits it"
        );
    }
}

#[test]
fn label_cells_drop_notes_and_values() {
    let cell = " `db` (`server/database`), `outcome`, `access` — only calls (`x`) ";
    assert_eq!(
        label_names(cell),
        BTreeSet::from(["db".to_owned(), "outcome".to_owned(), "access".to_owned()])
    );
    assert!(label_names(" — (a note with `value`) ").is_empty());
    assert_eq!(
        label_names(" `hash` (outer (`password`) more `x`) "),
        BTreeSet::from(["hash".to_owned()])
    );
}
