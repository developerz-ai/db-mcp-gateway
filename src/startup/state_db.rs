//! State-DB bring-up at boot: retried with backoff for a bounded window, so a
//! gateway that starts alongside its database (compose, a fresh k8s namespace)
//! waits for it instead of exiting on the first refused connection.

use std::future::Future;
use std::time::Duration;

use std::str::FromStr;

use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions, PgPool};
use tokio::time::Instant;

use db_mcp_gateway::config::Config;
use db_mcp_gateway::state::{self, StateDbError};

use super::boot::boot_db_error;

const BUDGET_VAR: &str = "STATE_DB_CONNECT_TIMEOUT_SECONDS";
const DEFAULT_BUDGET: Duration = Duration::from_secs(60);
/// An hour of retrying is an outage, not a slow start.
const MAX_BUDGET_SECONDS: u64 = 3600;
const FIRST_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(8);
/// The longest one attempt waits for the state DB to answer.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// With less than this of the budget left, no further attempt is started.
const MIN_ATTEMPT: Duration = Duration::from_millis(500);

/// `STATE_DB_CONNECT_TIMEOUT_SECONDS` is not whole seconds in `0..=3600`.
#[derive(Debug, thiserror::Error)]
#[error("invalid {BUDGET_VAR} `{0}`: expected whole seconds in 0..={MAX_BUDGET_SECONDS}")]
pub(crate) struct ConnectBudgetError(String);

/// How long boot keeps retrying the state DB. `0` = one attempt, no retry.
pub(crate) fn connect_budget_from_env() -> Result<Duration, ConnectBudgetError> {
    match std::env::var(BUDGET_VAR) {
        Ok(raw) => parse_budget(&raw),
        Err(_) => Ok(DEFAULT_BUDGET),
    }
}

fn parse_budget(raw: &str) -> Result<Duration, ConnectBudgetError> {
    raw.trim()
        .parse::<u64>()
        .ok()
        .filter(|secs| *secs <= MAX_BUDGET_SECONDS)
        .map(Duration::from_secs)
        .ok_or_else(|| ConnectBudgetError(raw.to_owned()))
}

/// Connect the request pool and migrate, retrying connect failures until
/// `STATE_DB_CONNECT_TIMEOUT_SECONDS` runs out. The HTTP listener binds only
/// after this returns, so probes do not answer while it retries.
pub(crate) async fn connect_state_db(config: &Config) -> anyhow::Result<PgPool> {
    let budget = connect_budget_from_env()?;
    let state_db = retry_connect(budget, |timeout| connect_within(config, timeout))
        .await
        .map_err(|err| boot_db_error("state DB", err))?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "state DB connected, migrations applied"
    );
    Ok(state_db)
}

/// The request pool, once the state DB answers within `timeout`. Only the
/// probe is bounded: migrations then run to the end, as one cut short would
/// fail the boot it was meant to finish.
async fn connect_within(config: &Config, timeout: Duration) -> Result<PgPool, StateDbError> {
    let options =
        PgConnectOptions::from_str(&config.state_db.url).map_err(StateDbError::Connect)?;
    match tokio::time::timeout(timeout, options.connect()).await {
        Ok(Ok(probe)) => drop(probe),
        Ok(Err(err)) => return Err(StateDbError::Connect(err)),
        Err(_elapsed) => return Err(StateDbError::Connect(sqlx::Error::PoolTimedOut)),
    }
    state::connect(&config.state_db.url, config.state_db.pool_size).await
}

/// Retry `attempt` with doubling backoff while its failure may heal and the
/// budget allows another try. Each attempt is handed a timeout that ends by
/// the deadline — a zero budget gets one full attempt. A malformed URL and a
/// failed migration never heal by waiting, so they return at once.
async fn retry_connect<T, F, Fut>(budget: Duration, attempt: F) -> Result<T, StateDbError>
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = Result<T, StateDbError>>,
{
    let deadline = Instant::now() + budget;
    let mut timeout = if budget.is_zero() {
        ATTEMPT_TIMEOUT
    } else {
        ATTEMPT_TIMEOUT.min(budget)
    };
    let mut backoff = FIRST_BACKOFF;
    let mut attempt_no: u32 = 0;
    loop {
        attempt_no = attempt_no.saturating_add(1);
        let err = match attempt(timeout).await {
            Ok(value) => return Ok(value),
            Err(err) => err,
        };
        let StateDbError::Connect(source) = &err else {
            return Err(err);
        };
        let class = state::connect_error_class(source);
        let left = deadline.saturating_duration_since(Instant::now());
        if class == "configuration" || left < MIN_ATTEMPT {
            return Err(err);
        }
        let wait = backoff.min(left - MIN_ATTEMPT);
        tracing::warn!(
            attempt = attempt_no,
            error_class = %class,
            retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
            "state DB not reachable yet; retrying"
        );
        tokio::time::sleep(wait).await;
        timeout = ATTEMPT_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn connect_failure(err: sqlx::Error) -> StateDbError {
        StateDbError::Connect(err)
    }

    #[test]
    fn budget_parses_whole_seconds_and_rejects_the_rest() {
        assert_eq!(parse_budget("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_budget(" 90 ").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_budget("3600").unwrap(), Duration::from_secs(3600));
        for bad in ["", "-1", "1.5", "3601", "soon"] {
            assert!(parse_budget(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[tokio::test]
    async fn retries_until_the_database_answers() {
        let calls = AtomicU32::new(0);
        let got = retry_connect(Duration::from_secs(60), |_| async {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 | 1 => Err(connect_failure(sqlx::Error::PoolTimedOut)),
                _ => Ok("pool"),
            }
        })
        .await;
        assert_eq!(got.unwrap(), "pool");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn gives_up_once_the_budget_is_spent() {
        let calls = AtomicU32::new(0);
        let started = Instant::now();
        let got: Result<(), _> = retry_connect(Duration::from_secs(2), |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(connect_failure(sqlx::Error::PoolTimedOut))
        })
        .await;
        assert!(matches!(got, Err(StateDbError::Connect(_))));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(1500), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        // Attempts at 0, 0.5 and 1.5 s; under MIN_ATTEMPT left, no fourth.
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn no_attempt_outlives_the_budget() {
        let budget = Duration::from_secs(3);
        let started = Instant::now();
        // Slack for the deadline `retry_connect` takes a moment after this one.
        let deadline = started + budget + Duration::from_millis(50);
        let got: Result<(), _> = retry_connect(budget, |timeout| async move {
            assert!(
                Instant::now() + timeout <= deadline,
                "{timeout:?} past the budget"
            );
            // A blackholed host: the attempt takes its whole timeout.
            tokio::time::sleep(timeout).await;
            Err(connect_failure(sqlx::Error::PoolTimedOut))
        })
        .await;
        assert!(got.is_err());
        let elapsed = started.elapsed();
        assert!(elapsed < budget + Duration::from_millis(200), "{elapsed:?}");
    }

    #[tokio::test]
    async fn zero_budget_is_a_single_attempt() {
        let calls = &AtomicU32::new(0);
        let got: Result<(), _> = retry_connect(Duration::ZERO, |timeout| async move {
            assert_eq!(timeout, ATTEMPT_TIMEOUT);
            calls.fetch_add(1, Ordering::SeqCst);
            Err(connect_failure(sqlx::Error::PoolTimedOut))
        })
        .await;
        assert!(got.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_malformed_url_is_not_retried() {
        let calls = AtomicU32::new(0);
        let got: Result<(), _> = retry_connect(Duration::from_secs(60), |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(connect_failure(sqlx::Error::Configuration(
                "bad url".into(),
            )))
        })
        .await;
        assert!(got.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
