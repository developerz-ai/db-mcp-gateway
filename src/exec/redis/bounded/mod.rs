//! Bounded reads: every allowlisted command is run so that neither the
//! server builds, nor the gateway decodes, a reply past the call's row or
//! byte budget. `shape_reply` applies the budget to rows already in memory;
//! this module keeps the reply small enough to get there.
//!
//! How each command is bounded (`cap` = `row_limit + 1`):
//!
//! - Index ranges (`LRANGE`, `ZRANGE`, `ZREVRANGE`): `stop` clamped to
//!   `start + cap - 1`; a negative index is first resolved with `LLEN` /
//!   `ZCARD` on the same connection.
//! - Score/lex ranges (`ZRANGE … BYSCORE|BYLEX`, `Z[REV]RANGEBY*`): `LIMIT`
//!   count clamped to `cap`, or `LIMIT 0 cap` appended.
//! - `XRANGE`/`XREVRANGE`: `COUNT` clamped to `cap` or appended.
//! - `LPOS`: `COUNT` (0 = all) clamped to `cap`; `MAXLEN` held to
//!   [`rewrite::LPOS_MAX_SCAN`].
//! - `HRANDFIELD`/`SRANDMEMBER`/`ZRANDMEMBER`: `|count|` clamped to `cap`.
//! - `HGETALL`/`HKEYS`/`HVALS`/`SMEMBERS`: served by an `HSCAN`/`SSCAN` loop
//!   that stops at `cap` items or [`MAX_RESULT_BYTES`].
//! - `SUNION`/`SINTER`/`SDIFF`: refused when the `SCARD` upper bound of the
//!   result exceeds `row_limit`.
//! - `GET`/`GETRANGE`/`SUBSTR`/`HGET`: `STRLEN`/`HSTRLEN` first; a value past
//!   [`MAX_RESULT_BYTES`] is not fetched (zero rows, `truncated`).
//!   `MGET`/`HMGET`: at most `cap` keys/fields, and only the prefix whose
//!   summed length fits the byte budget.
//!
//! Residual race (TOCTOU): the precheck and the read are separate commands,
//! so a key can grow between them. The gateway's client-side timeout stays
//! the backstop, and the shaping budget still cuts what does arrive.
//! Collection *elements* are not size-checked: a range of `cap` elements
//! each near Redis' 512 MiB value limit is bounded only by that timeout.

mod rewrite;
mod scans;
mod strings;
#[cfg(test)]
mod tests;

use redis::aio::MultiplexedConnection;
use redis::{RedisError, Value as Reply};

use super::super::adapter::MAX_RESULT_BYTES;
use super::rejector::Command;
use rewrite::{bounded_indices, lpos_bounded, needs_length, random_count, with_count, with_limit};

/// What a bounded read produced.
#[derive(Debug)]
pub(super) enum Fetched {
    /// The reply, already within `cap` rows; shaping applies the budget.
    Reply(Reply),
    /// Part of the reply was left out to fit the byte budget: shape it and
    /// flag the result `truncated`.
    Partial(Reply),
    /// The one value asked for exceeds the byte budget: zero rows,
    /// `truncated`.
    TooLarge,
}

/// Why a bounded read failed.
#[derive(Debug)]
pub(super) enum BoundError {
    Redis(RedisError),
    /// The command's result could exceed the row limit and cannot be cut at
    /// the source; the carried reason is agent-facing.
    Refused(String),
}

impl From<RedisError> for BoundError {
    fn from(err: RedisError) -> Self {
        Self::Redis(err)
    }
}

/// [`MAX_RESULT_BYTES`] as the `i64` Redis lengths come in.
fn byte_budget() -> i64 {
    i64::try_from(MAX_RESULT_BYTES).unwrap_or(i64::MAX)
}

/// Run `command` bounded to `row_limit`. Every await completes a full reply,
/// so after any `Err(BoundError::Redis)` that is a server error, or any
/// `Refused`, the connection is still in step.
pub(super) async fn fetch(
    conn: &mut MultiplexedConnection,
    command: &Command,
    row_limit: u32,
) -> Result<Fetched, BoundError> {
    let cap = i64::from(row_limit) + 1;
    let args = &command.args;
    let name = command.name;
    let reply = match name {
        "LRANGE" => index_range(conn, name, "LLEN", args, cap).await?,
        "ZRANGE" if is_score_or_lex(args) => send(conn, name, &with_limit(args, cap)).await?,
        "ZRANGE" | "ZREVRANGE" => index_range(conn, name, "ZCARD", args, cap).await?,
        "ZRANGEBYSCORE" | "ZREVRANGEBYSCORE" | "ZRANGEBYLEX" | "ZREVRANGEBYLEX" => {
            send(conn, name, &with_limit(args, cap)).await?
        }
        "XRANGE" | "XREVRANGE" => send(conn, name, &with_count(args, cap)).await?,
        "LPOS" => send(conn, name, &lpos_bounded(args, cap)).await?,
        "HRANDFIELD" | "SRANDMEMBER" | "ZRANDMEMBER" => {
            send(conn, name, &random_count(args, cap)).await?
        }
        "HGETALL" | "HKEYS" | "HVALS" | "SMEMBERS" => {
            return Ok(scans::collection(conn, name, args, cap).await?);
        }
        "SUNION" | "SINTER" | "SDIFF" => {
            scans::ensure_set_algebra_fits(conn, name, args, row_limit).await?;
            send(conn, name, args).await?
        }
        "GET" | "GETRANGE" | "SUBSTR" | "HGET" => return strings::single(conn, name, args).await,
        "MGET" | "HMGET" => return strings::multiple(conn, name, args, cap).await,
        _ => send(conn, name, args).await?,
    };
    Ok(Fetched::Reply(reply))
}

async fn send(
    conn: &mut MultiplexedConnection,
    name: &str,
    args: &[String],
) -> Result<Reply, RedisError> {
    redis::cmd(name).arg(args).query_async(conn).await
}

/// `ZRANGE … BYSCORE|BYLEX` ranges by value, not index.
fn is_score_or_lex(args: &[String]) -> bool {
    args.iter()
        .skip(3)
        .any(|a| a.eq_ignore_ascii_case("BYSCORE") || a.eq_ignore_ascii_case("BYLEX"))
}

/// `key start stop …` with `stop` bounded; a negative index costs one
/// `LLEN`/`ZCARD` first. Unparsable indices go to Redis as sent (it refuses).
async fn index_range(
    conn: &mut MultiplexedConnection,
    name: &str,
    length_command: &str,
    args: &[String],
    cap: i64,
) -> Result<Reply, RedisError> {
    let (Some(key), Some(Ok(start)), Some(Ok(stop))) = (
        args.first(),
        args.get(1).map(|s| s.parse::<i64>()),
        args.get(2).map(|s| s.parse::<i64>()),
    ) else {
        return send(conn, name, args).await;
    };
    let len = if needs_length(start, stop) {
        Some(
            redis::cmd(length_command)
                .arg(key)
                .query_async::<i64>(conn)
                .await?,
        )
    } else {
        None
    };
    let (start, stop) = bounded_indices(start, stop, len, cap);
    let mut bounded = args.to_vec();
    bounded[1] = start.to_string();
    bounded[2] = stop.to_string();
    send(conn, name, &bounded).await
}
