//! String-sized reads: the length is checked before the value is fetched,
//! so one value can never exceed the byte budget in gateway memory.

use redis::aio::MultiplexedConnection;
use redis::{RedisResult, Value as Reply};

use super::rewrite::{fitting_prefix, getrange_len};
use super::{BoundError, Fetched, byte_budget, send};

/// `GET key`, `GETRANGE`/`SUBSTR key start end`, `HGET key field`.
pub(super) async fn single(
    conn: &mut MultiplexedConnection,
    name: &str,
    args: &[String],
) -> Result<Fetched, BoundError> {
    let size = match (name, args) {
        ("GET", [key]) => Some(length(conn, "STRLEN", key, None).await?),
        ("HGET", [key, field]) => Some(length(conn, "HSTRLEN", key, Some(field)).await?),
        ("GETRANGE" | "SUBSTR", [key, start, end]) => {
            match (start.parse::<i64>(), end.parse::<i64>()) {
                (Ok(start), Ok(end)) => {
                    let len = length(conn, "STRLEN", key, None).await?;
                    Some(getrange_len(len, start, end))
                }
                _ => None,
            }
        }
        // Wrong arity or unparsable bounds: Redis refuses it, no data.
        _ => None,
    };
    if size.is_some_and(|size| size > byte_budget()) {
        return Ok(Fetched::TooLarge);
    }
    Ok(Fetched::Reply(send(conn, name, args).await?))
}

/// `MGET key…` / `HMGET key field…`: at most `cap` keys (fields), then only
/// the prefix whose summed length fits the byte budget. A key of another
/// type counts as empty — `MGET` answers it `nil` — and `HMGET` on a
/// non-hash surfaces Redis' own `WRONGTYPE` from the real command.
pub(super) async fn multiple(
    conn: &mut MultiplexedConnection,
    name: &str,
    args: &[String],
    cap: i64,
) -> Result<Fetched, BoundError> {
    let (hash_key, items) = match name {
        "HMGET" => match args.split_first() {
            Some((key, fields)) => (Some(key), fields),
            None => return Ok(Fetched::Reply(send(conn, name, args).await?)),
        },
        _ => (None, args),
    };
    let take = usize::try_from(cap).unwrap_or(usize::MAX).min(items.len());
    let items = &items[..take];
    let mut pipe = redis::pipe();
    pipe.ignore_errors();
    for item in items {
        match hash_key {
            Some(key) => pipe.cmd("HSTRLEN").arg(key).arg(item),
            None => pipe.cmd("STRLEN").arg(item),
        };
    }
    let sizes: Vec<RedisResult<i64>> = pipe.query_async(conn).await?;
    let sizes: Vec<i64> = sizes.into_iter().map(|size| size.unwrap_or(0)).collect();
    let fits = fitting_prefix(&sizes, byte_budget());
    if fits == 0 && !items.is_empty() {
        return Ok(Fetched::TooLarge);
    }
    let mut sent: Vec<String> = hash_key.into_iter().cloned().collect();
    sent.extend_from_slice(&items[..fits]);
    let reply: Reply = send(conn, name, &sent).await?;
    Ok(if fits < items.len() {
        Fetched::Partial(reply)
    } else {
        Fetched::Reply(reply)
    })
}

async fn length(
    conn: &mut MultiplexedConnection,
    command: &str,
    key: &str,
    field: Option<&String>,
) -> Result<i64, BoundError> {
    let mut cmd = redis::cmd(command);
    cmd.arg(key);
    if let Some(field) = field {
        cmd.arg(field);
    }
    Ok(cmd.query_async(conn).await?)
}
