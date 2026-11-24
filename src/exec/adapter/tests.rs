use super::*;

#[test]
fn effective_timeout_clamps_and_defaults() {
    // No grant constraint → gateway ceiling, never unbounded.
    assert_eq!(effective_timeout_ms(None), DEFAULT_STATEMENT_TIMEOUT_MS);
    assert_eq!(effective_timeout_ms(None), 30_000);
    // A tighter grant wins (most-restrictive-wins).
    assert_eq!(effective_timeout_ms(Some(5_000)), 5_000);
    // A looser grant is clamped down to the ceiling — it can only tighten.
    assert_eq!(effective_timeout_ms(Some(60_000)), 30_000);
    assert_eq!(effective_timeout_ms(Some(3_600_000)), 30_000);
}

/// Postgres reads `statement_timeout = 0` as "no limit", so a zero grant
/// must never reach the DB as zero.
#[test]
fn effective_timeout_never_zero() {
    assert_eq!(effective_timeout_ms(Some(0)), 1);
}

proptest::proptest! {
    /// For any grant: never zero (Postgres' "no limit"), never above the
    /// grant, never above the ceiling. The upper bound is floored at 1
    /// because a zero grant still runs with the 1 ms floor.
    #[test]
    fn effective_timeout_stays_within_grant_and_ceiling(
        grant in proptest::option::of(proptest::num::u32::ANY)
    ) {
        let effective = effective_timeout_ms(grant);
        let bound = grant
            .unwrap_or(u32::MAX)
            .clamp(1, DEFAULT_STATEMENT_TIMEOUT_MS);
        proptest::prop_assert!((1..=bound).contains(&effective));
    }
}
