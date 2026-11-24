//! Date and time cells, rendered straight from Postgres' binary integers.
//!
//! Postgres holds more than `chrono` can: dates to the year 5874897,
//! timestamps to 294276, `infinity` / `-infinity`, and the time `24:00:00`.
//! The driver's `chrono` decode overflows on all of them, so nothing here
//! builds a `chrono` value. The wire integers are widened to `i64`, where no
//! step below can overflow, and spelled the way `chrono` spells the values
//! it can hold.

const MICROS_PER_SECOND: i64 = 1_000_000;
const MICROS_PER_DAY: i64 = 86_400 * MICROS_PER_SECOND;
/// Days from 1970-01-01 to Postgres' epoch, 2000-01-01.
const PG_EPOCH_DAYS: i64 = 10_957;

/// `YYYY-MM-DD`.
pub(super) fn date(wire: &[u8]) -> Option<String> {
    Some(date_text(i32::from_be_bytes(wire.try_into().ok()?)))
}

/// ISO-8601 with the `T` separator and no zone.
pub(super) fn timestamp(wire: &[u8]) -> Option<String> {
    Some(timestamp_text(
        i64::from_be_bytes(wire.try_into().ok()?),
        "",
    ))
}

/// RFC 3339 in UTC, which is how Postgres sends a `timestamptz`.
pub(super) fn timestamptz(wire: &[u8]) -> Option<String> {
    let micros = i64::from_be_bytes(wire.try_into().ok()?);
    Some(timestamp_text(micros, "+00:00"))
}

/// `HH:MM:SS[.ffffff]`.
pub(super) fn time(wire: &[u8]) -> Option<String> {
    time_text(i64::from_be_bytes(wire.try_into().ok()?))
}

/// `HH:MM:SS[.ffffff]±HH:MM`: the time of day, then the zone it was given
/// in. Postgres sends the zone as seconds *west* of UTC.
pub(super) fn timetz(wire: &[u8]) -> Option<String> {
    let (micros, west) = wire.split_first_chunk::<8>()?;
    let west = i32::from_be_bytes(west.try_into().ok()?);
    Some(format!(
        "{}{}",
        time_text(i64::from_be_bytes(*micros))?,
        offset_text(-i64::from(west))
    ))
}

/// A UTC offset in seconds east; the seconds are printed only when there
/// are any (zones before standard time had them).
fn offset_text(east: i64) -> String {
    let sign = if east < 0 { '-' } else { '+' };
    let east = east.unsigned_abs();
    let (h, m, s) = (east / 3_600, east / 60 % 60, east % 60);
    match s {
        0 => format!("{sign}{h:02}:{m:02}"),
        s => format!("{sign}{h:02}:{m:02}:{s:02}"),
    }
}

/// `days` since 2000-01-01; the two extremes are Postgres' infinities.
fn date_text(days: i32) -> String {
    match days {
        i32::MAX => "infinity".to_string(),
        i32::MIN => "-infinity".to_string(),
        days => civil(i64::from(days) + PG_EPOCH_DAYS),
    }
}

/// `micros` since 2000-01-01T00:00:00, followed by `zone`.
fn timestamp_text(micros: i64, zone: &str) -> String {
    match micros {
        i64::MAX => "infinity".to_string(),
        i64::MIN => "-infinity".to_string(),
        micros => format!(
            "{}T{}{zone}",
            civil(micros.div_euclid(MICROS_PER_DAY) + PG_EPOCH_DAYS),
            clock(micros.rem_euclid(MICROS_PER_DAY))
        ),
    }
}

/// `micros` since midnight. Postgres allows `24:00:00` itself.
fn time_text(micros: i64) -> Option<String> {
    (0..=MICROS_PER_DAY)
        .contains(&micros)
        .then(|| clock(micros))
}

/// Fractional seconds as `chrono` prints them: none, three digits or six.
fn clock(micros_of_day: i64) -> String {
    let (seconds, fraction) = (
        micros_of_day / MICROS_PER_SECOND,
        micros_of_day % MICROS_PER_SECOND,
    );
    let (h, m, s) = (seconds / 3_600, seconds / 60 % 60, seconds % 60);
    match fraction {
        0 => format!("{h:02}:{m:02}:{s:02}"),
        f if f % 1_000 == 0 => format!("{h:02}:{m:02}:{s:02}.{:03}", f / 1_000),
        f => format!("{h:02}:{m:02}:{s:02}.{f:06}"),
    }
}

/// The proleptic Gregorian date `days` after 1970-01-01, by eras of 400
/// years (146 097 days). The year is astronomical (1 BC is `0000`), four
/// digits, and signed outside `0..=9999`.
fn civil(days: i64) -> String {
    let shifted = days + 719_468; // days since 0000-03-01
    let (era, day_of_era) = (shifted.div_euclid(146_097), shifted.rem_euclid(146_097));
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = if march_month < 10 {
        march_month + 3
    } else {
        march_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    if (0..=9_999).contains(&year) {
        format!("{year:04}-{month:02}-{day:02}")
    } else {
        format!("{year:+05}-{month:02}-{day:02}")
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, NaiveDate, NaiveTime};

    use super::*;

    #[test]
    fn the_extremes_are_infinities() {
        assert_eq!(date_text(i32::MAX), "infinity");
        assert_eq!(date_text(i32::MIN), "-infinity");
        assert_eq!(timestamp_text(i64::MAX, "+00:00"), "infinity");
        assert_eq!(timestamp_text(i64::MIN, ""), "-infinity");
    }

    #[test]
    fn values_past_chrono_still_render() {
        assert_eq!(date_text(0), "2000-01-01");
        assert_eq!(date_text(i32::MAX - 1), "+5881610-07-10");
        assert_eq!(
            timestamp_text(i64::MAX - 1, ""),
            "+294277-01-09T04:00:54.775806"
        );
        assert_eq!(
            timestamp_text(i64::MIN + 1, ""),
            "-290278-12-22T19:59:05.224193"
        );
        assert_eq!(
            timestamp_text(-1, "+00:00"),
            "1999-12-31T23:59:59.999999+00:00"
        );
    }

    #[test]
    fn a_time_with_a_zone_keeps_the_zone() {
        let wire = |micros: i64, west: i32| {
            [micros.to_be_bytes().as_slice(), &west.to_be_bytes()].concat()
        };
        let noon = 12 * 3_600 * MICROS_PER_SECOND;
        assert_eq!(timetz(&wire(noon, 0)).as_deref(), Some("12:00:00+00:00"));
        assert_eq!(
            timetz(&wire(noon + 500_000, -19_800)).as_deref(),
            Some("12:00:00.500+05:30")
        );
        assert_eq!(
            timetz(&wire(MICROS_PER_DAY, 28_800)).as_deref(),
            Some("24:00:00-08:00")
        );
        assert_eq!(
            timetz(&wire(0, 1_172)).as_deref(),
            Some("00:00:00-00:19:32")
        );
        assert_eq!(timetz(&wire(noon, 0)[..11]), None);
    }

    #[test]
    fn midnight_at_the_end_of_the_day_is_a_time() {
        assert_eq!(time_text(MICROS_PER_DAY).as_deref(), Some("24:00:00"));
        assert_eq!(time_text(MICROS_PER_DAY + 1), None);
        assert_eq!(time_text(-1), None);
    }

    proptest::proptest! {
        /// Inside `chrono`'s range the output is `chrono`'s, digit for digit.
        #[test]
        fn dates_match_chrono(days in -90_000_000i32..90_000_000) {
            let epoch = NaiveDate::from_ymd_opt(2000, 1, 1).expect("valid date");
            let want = epoch + Duration::days(i64::from(days));
            proptest::prop_assert_eq!(date_text(days), want.to_string());
        }

        #[test]
        fn timestamps_match_chrono(micros in -8_000_000_000_000_000_000i64..8_000_000_000_000_000_000) {
            let epoch = DateTime::from_timestamp(946_684_800, 0).expect("valid instant");
            let want = epoch + Duration::microseconds(micros);
            proptest::prop_assert_eq!(timestamp_text(micros, "+00:00"), want.to_rfc3339());
            proptest::prop_assert_eq!(
                timestamp_text(micros, ""),
                want.naive_utc().format("%Y-%m-%dT%H:%M:%S%.f").to_string()
            );
        }

        #[test]
        fn times_match_chrono(micros in 0..MICROS_PER_DAY) {
            let want = NaiveTime::MIN + Duration::microseconds(micros);
            proptest::prop_assert_eq!(time_text(micros), Some(want.to_string()));
        }
    }
}
