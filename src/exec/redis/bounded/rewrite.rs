//! Pure argv rewrites that bound a command's reply at the source: the server
//! never builds more than `cap` (= `row_limit + 1`) elements, one past the
//! cap so `truncated` can still be detected. An argument that does not
//! parse is left alone — Redis then refuses the command itself, with no data.

/// Longest list prefix `LPOS` may scan (`MAXLEN`). `LPOS` replies with at
/// most `COUNT` positions, but without `MAXLEN` it may walk the whole list.
pub(super) const LPOS_MAX_SCAN: i64 = 100_000;

/// `[start, stop]` of an index range, bounded to `cap` elements. `len` is
/// the collection's length, needed only when an index is negative
/// ([`needs_length`]). An empty result is spelled `(1, 0)`.
pub(super) fn bounded_indices(start: i64, stop: i64, len: Option<i64>, cap: i64) -> (i64, i64) {
    let (start, stop) = match len {
        Some(len) => {
            let start = if start < 0 {
                (len + start).max(0)
            } else {
                start
            };
            let stop = if stop < 0 {
                len + stop
            } else {
                stop.min(len - 1)
            };
            (start, stop)
        }
        None => (start, stop),
    };
    if stop < start || start < 0 {
        return (1, 0);
    }
    (start, stop.min(start.saturating_add(cap - 1)))
}

/// Whether [`bounded_indices`] needs the length to resolve the range.
pub(super) fn needs_length(start: i64, stop: i64) -> bool {
    start < 0 || stop < 0
}

/// Clamp every `<option> <n>` from position `from` on to `cap`, or append
/// `<option> <cap>` when absent. `keep` says which parsed values may stay.
fn clamp_option(
    args: &[String],
    from: usize,
    option: &str,
    cap: i64,
    keep: impl Fn(i64) -> bool,
    appended: &[String],
) -> Vec<String> {
    let mut out = args.to_vec();
    let mut seen = false;
    let mut index = from;
    while index < out.len() {
        if out[index].eq_ignore_ascii_case(option) {
            seen = true;
            // `LIMIT offset count`: the count is the second value.
            let at = index
                + if option.eq_ignore_ascii_case("LIMIT") {
                    2
                } else {
                    1
                };
            if let Some(value) = out.get_mut(at)
                && let Ok(n) = value.parse::<i64>()
                && !keep(n)
            {
                *value = cap.to_string();
            }
        }
        index += 1;
    }
    if !seen {
        out.extend_from_slice(appended);
    }
    out
}

/// `… LIMIT offset count` for the score/lex range forms: a negative count
/// (Redis' "all") or one past `cap` becomes `cap`; absent, `LIMIT 0 cap`.
pub(super) fn with_limit(args: &[String], cap: i64) -> Vec<String> {
    let appended = ["LIMIT".to_string(), "0".to_string(), cap.to_string()];
    clamp_option(args, 3, "LIMIT", cap, |n| (0..=cap).contains(&n), &appended)
}

/// `XRANGE`/`XREVRANGE … COUNT n`: at most `cap` entries.
pub(super) fn with_count(args: &[String], cap: i64) -> Vec<String> {
    let appended = ["COUNT".to_string(), cap.to_string()];
    clamp_option(args, 3, "COUNT", cap, |n| (0..=cap).contains(&n), &appended)
}

/// `LPOS key element … COUNT n MAXLEN m`: `COUNT 0` means every match, so it
/// becomes `cap`; `MAXLEN` (0 = the whole list) is held to [`LPOS_MAX_SCAN`].
/// Without `COUNT`, `LPOS` answers one position and needs no cap.
pub(super) fn lpos_bounded(args: &[String], cap: i64) -> Vec<String> {
    let has_count = args.iter().skip(2).any(|a| a.eq_ignore_ascii_case("COUNT"));
    let args = if has_count {
        clamp_option(args, 2, "COUNT", cap, |n| (1..=cap).contains(&n), &[])
    } else {
        args.to_vec()
    };
    let appended = ["MAXLEN".to_string(), LPOS_MAX_SCAN.to_string()];
    clamp_option(
        &args,
        2,
        "MAXLEN",
        LPOS_MAX_SCAN,
        |n| (1..=LPOS_MAX_SCAN).contains(&n),
        &appended,
    )
}

/// `HRANDFIELD`/`SRANDMEMBER`/`ZRANDMEMBER key count`: `|count|` held to
/// `cap`, sign kept (negative = repeats allowed, so the reply is exactly
/// `|count|` long whatever the collection's size).
pub(super) fn random_count(args: &[String], cap: i64) -> Vec<String> {
    let mut out = args.to_vec();
    if let Some(value) = out.get_mut(1)
        && let Ok(count) = value.parse::<i64>()
        && count.unsigned_abs() > cap.unsigned_abs()
    {
        *value = if count < 0 { -cap } else { cap }.to_string();
    }
    out
}

/// Bytes `GETRANGE key start end` returns from a `len`-byte string — Redis'
/// own index arithmetic (`t_string.c`).
pub(super) fn getrange_len(len: i64, start: i64, end: i64) -> i64 {
    if len == 0 {
        return 0;
    }
    let start = if start < 0 {
        (len + start).max(0)
    } else {
        start
    };
    let end = if end < 0 { (len + end).max(0) } else { end }.min(len - 1);
    if start > end { 0 } else { end - start + 1 }
}

/// How many of `sizes` (in order) fit in `budget` bytes together.
pub(super) fn fitting_prefix(sizes: &[i64], budget: i64) -> usize {
    let mut total = 0_i64;
    sizes
        .iter()
        .take_while(|size| {
            total = total.saturating_add((**size).max(0));
            total <= budget
        })
        .count()
}
