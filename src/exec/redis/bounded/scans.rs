//! Whole-collection reads served by a cursor loop, and the size precheck for
//! set algebra.

use std::collections::HashSet;

use redis::aio::MultiplexedConnection;
use redis::{RedisError, Value as Reply};

use super::super::rejector::MAX_SCAN_COUNT;
use super::{BoundError, Fetched, byte_budget};

/// `HGETALL`/`HKEYS`/`HVALS`/`SMEMBERS` as an `HSCAN`/`SSCAN` loop (`COUNT`
/// [`MAX_SCAN_COUNT`]) that stops once `cap` items or the byte budget are
/// collected. The reply is laid out as the native command's would be (flat
/// field/value pairs, or one element per item), so shaping is unchanged.
/// A cursor scan may repeat an item; repeats are dropped.
pub(super) async fn collection(
    conn: &mut MultiplexedConnection,
    name: &str,
    args: &[String],
    cap: i64,
) -> Result<Fetched, RedisError> {
    let Some(key) = args.first() else {
        // Redis' own arity error, with no data.
        return redis::cmd(name)
            .arg(args)
            .query_async(conn)
            .await
            .map(Fetched::Reply);
    };
    let (scan, pairs) = if name == "SMEMBERS" {
        ("SSCAN", false)
    } else {
        ("HSCAN", true)
    };
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut out: Vec<Reply> = Vec::new();
    let mut bytes = 0_i64;
    let mut cursor = "0".to_string();
    loop {
        let (next, items): (String, Vec<Reply>) = redis::cmd(scan)
            .arg(key)
            .arg(&cursor)
            .arg("COUNT")
            .arg(MAX_SCAN_COUNT)
            .query_async(conn)
            .await?;
        let mut items = items.into_iter();
        while let Some(item) = items.next() {
            let value = if pairs { items.next() } else { None };
            if !seen.insert(identity(&item)) {
                continue;
            }
            bytes = bytes.saturating_add(size(&item) + value.as_ref().map_or(0, size));
            if bytes > byte_budget() {
                return Ok(Fetched::Partial(Reply::Array(out)));
            }
            match (name, value) {
                ("HGETALL", Some(value)) => out.extend([item, value]),
                ("HVALS", Some(value)) => out.push(value),
                _ => out.push(item),
            }
            if seen.len() >= cap {
                return Ok(Fetched::Reply(Reply::Array(out)));
            }
        }
        if next == "0" {
            return Ok(Fetched::Reply(Reply::Array(out)));
        }
        cursor = next;
    }
}

fn identity(item: &Reply) -> Vec<u8> {
    match item {
        Reply::BulkString(bytes) => bytes.clone(),
        other => format!("{other:?}").into_bytes(),
    }
}

fn size(item: &Reply) -> i64 {
    match item {
        Reply::BulkString(bytes) => i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        _ => 8,
    }
}

/// Refuse `SUNION`/`SINTER`/`SDIFF` whose result could exceed `row_limit`:
/// the `SCARD` sum (union), minimum (intersection) or first set (difference)
/// bounds the result, and Redis cannot cut these replies short.
pub(super) async fn ensure_set_algebra_fits(
    conn: &mut MultiplexedConnection,
    name: &'static str,
    keys: &[String],
    row_limit: u32,
) -> Result<(), BoundError> {
    if keys.is_empty() {
        return Ok(());
    }
    let mut pipe = redis::pipe();
    for key in keys {
        pipe.cmd("SCARD").arg(key);
    }
    let sizes: Vec<i64> = pipe.query_async(conn).await?;
    let bound = match name {
        "SUNION" => sizes.iter().fold(0_i64, |sum, n| sum.saturating_add(*n)),
        "SINTER" => sizes.iter().copied().min().unwrap_or(0),
        _ => sizes.first().copied().unwrap_or(0),
    };
    if bound > i64::from(row_limit) {
        return Err(BoundError::Refused(format!(
            "`{name}` could return up to {bound} members, past this call's row limit of \
             {row_limit}; read the sets with SSCAN, or count with SINTERCARD"
        )));
    }
    Ok(())
}
