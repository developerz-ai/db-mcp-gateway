//! `PG_CANCEL_POOL_SIZE`: connections in each Postgres tier's cancel pool,
//! the pool `pg_cancel_backend(pid)` runs on. It must stay separate from the
//! query pool — a cancel fired through the query pool would queue on
//! `acquire()` behind the very connections it is trying to free (N hung
//! queries + N drops with `max_connections = N` deadlocks every cancel until
//! `statement_timeout` expires). The default 2 gives a burst of disconnects
//! two round-trips in parallel; cancels are single-round and cheap.
//!
//! Process-wide and fixed at boot: read once by [`init_cancel_pool_size_from_env`]
//! before the first adapter opens.

use std::sync::OnceLock;

const DEFAULT_CANCEL_POOL_SIZE: u32 = 2;
/// Each connection is a backend slot on every target database, per tier.
const MAX_CANCEL_POOL_SIZE: u32 = 32;
const ENV: &str = "PG_CANCEL_POOL_SIZE";

static SIZE: OnceLock<u32> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
#[error("PG_CANCEL_POOL_SIZE must be an integer from 1 to {MAX_CANCEL_POOL_SIZE}, got {value:?}")]
pub struct InvalidCancelPoolSize {
    value: String,
}

/// Validate `PG_CANCEL_POOL_SIZE` (unset → the default) and fix it for the
/// process. A later call keeps the first value.
pub fn init_cancel_pool_size_from_env() -> Result<u32, InvalidCancelPoolSize> {
    let size = match std::env::var(ENV) {
        Ok(value) => parse(&value)?,
        Err(_) => DEFAULT_CANCEL_POOL_SIZE,
    };
    Ok(*SIZE.get_or_init(|| size))
}

/// The configured size; the default when boot never set one (tests).
pub(super) fn cancel_pool_size() -> u32 {
    SIZE.get().copied().unwrap_or(DEFAULT_CANCEL_POOL_SIZE)
}

fn parse(value: &str) -> Result<u32, InvalidCancelPoolSize> {
    match value.trim().parse::<u32>() {
        Ok(size) if (1..=MAX_CANCEL_POOL_SIZE).contains(&size) => Ok(size),
        _ => Err(InvalidCancelPoolSize {
            value: value.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_bounds_and_rejects_outside_them() {
        assert_eq!(parse("1").unwrap(), 1);
        assert_eq!(parse(" 32 ").unwrap(), MAX_CANCEL_POOL_SIZE);
        for bad in ["0", "33", "-1", "two", ""] {
            let err = parse(bad).unwrap_err();
            assert!(err.to_string().contains("PG_CANCEL_POOL_SIZE"), "{err}");
        }
    }
}
