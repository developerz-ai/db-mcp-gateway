//! Guard for `.dz/briefs/health.md`: its signal table and its `## Rows`
//! section are one contract. A signal with no declared row is a failure the
//! `health` schedule never files; a row with no signal is a rule with nothing
//! to check. Parity is asserted in both directions — count, order and names.
//!
//! Reads a tracked file and nothing else: no state DB, no dev stack, so it
//! runs on its own (`cargo test --test brief_rows`).
//!
//! The row is derived from its signal, not from a list kept here: every
//! hyphen-separated token of a row id must appear, in order, in the slugged
//! `Signal` and `Healthy` cells of the signal in the same position. So
//! rewording a signal cell until its row no longer derives from it — or
//! swapping two rows — fails here. `EXPECTED_IDS` additionally pins the five
//! ids themselves, so a reworded id fails even when its tokens still derive.

use std::collections::BTreeSet;
use std::path::PathBuf;

const BRIEF: &str = ".dz/briefs/health.md";

/// The row ids the brief declares, in table order. One per signal.
const EXPECTED_IDS: [&str; 5] = [
    "main-green",
    "last-tag-published",
    "stamped-version-tagged",
    "github-release-published",
    "dependabot-not-stuck",
];

/// A signal row of the table, reduced to what names its row: the `Signal` and
/// `Healthy` cells. The `Command` cell is not part of a row id.
struct Signal {
    /// 1-based line of the row.
    line: usize,
    /// The two naming cells, whitespace-joined.
    naming: String,
}

struct Rows {
    /// 1-based line of the `## Rows` heading.
    heading_line: usize,
    ids: Vec<String>,
}

fn read_brief() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BRIEF);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", path.display()))
}

/// The cells of a markdown table row, or `None` for any other line.
fn table_cells(line: &str) -> Option<Vec<&str>> {
    let trimmed = line.trim();
    let inner = trimmed.strip_prefix('|')?.strip_suffix('|')?;
    Some(inner.split('|').map(str::trim).collect())
}

fn is_separator(cell: &str) -> bool {
    !cell.is_empty() && cell.chars().all(|c| c == '-' || c == ':')
}

/// The signal rows under the `| Signal | Command | Healthy |` header, in file
/// order. A malformed row panics rather than vanishing, so a broken table is
/// reported as a broken table instead of a missing signal.
fn signals(brief: &str) -> Vec<Signal> {
    let mut signals = Vec::new();
    let mut in_table = false;
    let mut separator_seen = false;
    for (index, line) in brief.lines().enumerate() {
        let line_no = index + 1;
        let Some(cells) = table_cells(line) else {
            if in_table {
                break;
            }
            continue;
        };
        if !in_table {
            if cells[0] != "Signal" {
                continue;
            }
            in_table = true;
            continue;
        }
        if !separator_seen {
            assert!(
                is_separator(cells[0]),
                "{BRIEF}:{line_no}: the signal header must be followed by a separator row"
            );
            separator_seen = true;
            continue;
        }
        assert_eq!(
            cells.len(),
            3,
            "{BRIEF}:{line_no}: a signal row needs Signal, Command and Healthy cells, found {}",
            cells.len()
        );
        assert!(
            !cells[0].is_empty() && !cells[2].is_empty(),
            "{BRIEF}:{line_no}: a signal row needs a Signal and a Healthy cell"
        );
        signals.push(Signal {
            line: line_no,
            naming: format!("{} {}", cells[0], cells[2]),
        });
    }
    assert!(
        separator_seen,
        "{BRIEF}: no `| Signal | Command | Healthy |` table found"
    );
    signals
}

/// The single `## Rows` section: its heading line and the id of every
/// ``- `<id>` — …`` item in it, in file order.
fn rows_section(brief: &str) -> Rows {
    let mut headings = 0usize;
    let mut heading_line = 0usize;
    let mut in_rows = false;
    let mut ids = Vec::new();
    for (index, line) in brief.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("## ") {
            in_rows = heading.trim() == "Rows";
            if in_rows {
                headings += 1;
                heading_line = index + 1;
            }
            continue;
        }
        if !in_rows {
            continue;
        }
        let Some(item) = trimmed.strip_prefix("- ") else {
            continue;
        };
        let Some(rest) = item.trim_start().strip_prefix('`') else {
            continue;
        };
        let Some((id, _)) = rest.split_once('`') else {
            continue;
        };
        ids.push(id.to_string());
    }
    assert_eq!(
        headings, 1,
        "{BRIEF} must carry exactly one `## Rows` section, found {headings}"
    );
    Rows { heading_line, ids }
}

/// Lowercase alphanumeric runs, so `the GitHub Release exists` and
/// `` `main` is green `` slug the same way a row id reads.
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Every token of `id` appears in `words`, in that order.
fn derives_from(id: &str, words: &[String]) -> bool {
    let mut remaining = words.iter();
    id.split('-')
        .all(|token| remaining.any(|word| word == token))
}

fn is_row_id(id: &str) -> bool {
    (1..=40).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[test]
fn every_signal_declares_exactly_one_row() {
    let brief = read_brief();
    let signals = signals(&brief);
    let rows = rows_section(&brief);

    assert_eq!(
        signals.len(),
        EXPECTED_IDS.len(),
        "{BRIEF}: the table must carry {} signals, found {} (lines {:?})",
        EXPECTED_IDS.len(),
        signals.len(),
        signals.iter().map(|signal| signal.line).collect::<Vec<_>>()
    );
    assert_eq!(
        rows.ids.len(),
        signals.len(),
        "{BRIEF}: `## Rows` must declare one row per signal ({}), found {} ({:?})",
        signals.len(),
        rows.ids.len(),
        rows.ids
    );

    let declared: BTreeSet<&String> = rows.ids.iter().collect();
    assert_eq!(
        declared.len(),
        rows.ids.len(),
        "{BRIEF}: a row id is declared twice ({:?})",
        rows.ids
    );

    // Positional pairing, so both directions hold: a signal without its row,
    // a row without its signal, or two rows swapped all fail.
    for (signal, id) in signals.iter().zip(&rows.ids) {
        assert!(
            derives_from(id, &words(&signal.naming)),
            "{BRIEF}:{}: row `{id}` does not derive from that signal's cells ({})",
            signal.line,
            signal.naming
        );
    }
}

#[test]
fn declared_row_ids_are_the_expected_five() {
    let brief = read_brief();
    let rows = rows_section(&brief);
    let declared: Vec<&str> = rows.ids.iter().map(String::as_str).collect();
    assert_eq!(
        declared,
        EXPECTED_IDS.as_slice(),
        "{BRIEF}: the declared row ids drifted from the five signals"
    );
}

#[test]
fn declared_row_ids_are_well_formed() {
    let brief = read_brief();
    for id in rows_section(&brief).ids {
        assert!(
            is_row_id(&id),
            "{BRIEF}: row id `{id}` must be lowercase letters, digits, `-` or `_`, 1-40 chars"
        );
    }
}

#[test]
fn rows_section_follows_the_filing_rules() {
    let brief = read_brief();
    let filing_rules = brief
        .lines()
        .position(|line| line.trim() == "## What to file")
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("{BRIEF}: `## What to file` must exist"));
    let rows = rows_section(&brief);
    assert!(
        rows.heading_line > filing_rules,
        "{BRIEF}: `## Rows` (line {}) must come after `## What to file` (line {filing_rules})",
        rows.heading_line
    );
}
