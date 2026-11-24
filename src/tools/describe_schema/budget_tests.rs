//! Unit tests for the statement budget a `describe_schema` call shares.

use super::*;

/// Schema discovery and the catalog read share one budget: the second read
/// gets what the first left, and none left is a timeout.
#[test]
fn the_catalog_read_gets_what_schema_discovery_left() {
    assert_eq!(remaining_budget(Some(1_000), 300).ok(), Some(700));
    assert_eq!(remaining_budget(None, 0).ok(), Some(30_000));
    assert_eq!(remaining_budget(Some(90_000), 5_000).ok(), Some(25_000));
    assert!(matches!(
        remaining_budget(Some(1_000), 1_000),
        Err(ExecError::Timeout)
    ));
    assert!(matches!(
        remaining_budget(Some(1_000), u64::MAX),
        Err(ExecError::Timeout)
    ));
}
