//! The connection budget: how many connections one replica may open to each
//! target server and to the state DB, at full load. Pools are lazy (min 0),
//! so this is the ceiling, not the steady state.

use db_mcp_gateway::config::{Config, ConfigFile, Database, Server, ServerKind};
use db_mcp_gateway::exec::PoolSizing;
use db_mcp_gateway::exec::pg::init_cancel_pool_size_from_env;

/// The state DB's background (pruner/GC) pool
/// (`state::BACKGROUND_POOL_SIZE`, crate-private there), and the listener's
/// `LISTEN` and ping connections (`state::permissions::pg::notify`).
const STATE_BACKGROUND_POOL: u32 = 2;
const STATE_LISTENER_POOL: u32 = 2;

/// Each Postgres tier's `pg_cancel_backend` pool, as boot sizes it
/// (`PG_CANCEL_POOL_SIZE`); the error names the variable, never its value.
pub fn cancel_pool_size() -> Result<u32, String> {
    init_cancel_pool_size_from_env()
        .map_err(|_| "invalid PG_CANCEL_POOL_SIZE: expected an integer from 1 to 32".to_string())
}

pub fn print(config: &ConfigFile, cancel: u32) {
    println!("connection budget (one replica, every pool full; multiply by replicas):");
    for server in &config.servers {
        let mut total = 0;
        for db in &server.databases {
            let Some((line, count)) = database_line(server, db, cancel) else {
                continue;
            };
            println!("  {}/{}: {line} = {count}", server.name, db.name);
            total += count;
        }
        println!(
            "  {} total: {total} — keep below the target's max_connections \
             (`db-mcp-gateway doctor` reads it)",
            server.name
        );
    }
    print_state_db();
}

/// Every pool one replica may open to `server`, at full load.
pub fn server_budget(server: &Server, cancel: u32) -> u32 {
    server
        .databases
        .iter()
        .filter_map(|db| database_line(server, db, cancel))
        .map(|(_, count)| count)
        .sum()
}

/// `None` when the merged pool sizing is invalid — already an error above.
fn database_line(server: &Server, db: &Database, cancel: u32) -> Option<(String, u32)> {
    let max = PoolSizing::resolve(server, db).ok()?.max_connections;
    let tiers = if db.write_credentials().is_some() {
        2
    } else {
        1
    };
    Some(match server.kind {
        ServerKind::Postgres => {
            let tier = format!("{max} + cancel {cancel}");
            let line = if tiers == 2 {
                format!("read {tier}, write {tier}")
            } else {
                format!("read {tier}")
            };
            (line, tiers * (max + cancel))
        }
        _ => (format!("read {max}"), max),
    })
}

fn print_state_db() {
    let full = Config::from_env()
        .ok()
        .map(|env| env.state_db.pool_size.get());
    let raw = std::env::var("STATE_DB_POOL_SIZE").ok();
    let default = Config::default().state_db.pool_size.get();
    let (pool, source) = state_pool(full, raw.as_deref(), default);
    let total = state_total(pool);
    println!(
        "  state DB: request {pool} ({source}) + background {STATE_BACKGROUND_POOL} \
         + listener {STATE_LISTENER_POOL} = {total}"
    );
}

/// Every state-DB connection: in `u64`, so an operator's `u32::MAX` request
/// pool cannot wrap to a tiny total.
fn state_total(pool: u32) -> u64 {
    u64::from(pool) + u64::from(STATE_BACKGROUND_POOL) + u64::from(STATE_LISTENER_POOL)
}

/// The request pool size and where it came from. `full` is `None` without the
/// deployment's env (e.g. TLS paths in CI); `STATE_DB_POOL_SIZE` alone is
/// then still the operator's number, and only without a usable one is the
/// built-in default the honest answer.
fn state_pool(full: Option<u32>, raw: Option<&str>, default: u32) -> (u32, &'static str) {
    if let Some(pool) = full {
        return (pool, "STATE_DB_POOL_SIZE");
    }
    match raw
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|&n| n > 0)
    {
        Some(pool) => (
            pool,
            "STATE_DB_POOL_SIZE; the rest of the environment did not load",
        ),
        None => (default, "default; the environment did not load"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: u32 = 10;

    #[test]
    fn the_pool_size_is_read_alone_when_the_rest_of_the_environment_fails() {
        assert_eq!(state_pool(None, Some("4"), DEFAULT).0, 4);
        assert_eq!(state_pool(None, None, DEFAULT).0, DEFAULT);
        assert_eq!(state_pool(None, Some("0"), DEFAULT).0, DEFAULT);
        assert_eq!(state_pool(None, Some("ten"), DEFAULT).0, DEFAULT);
        assert_eq!(state_pool(Some(7), Some("4"), DEFAULT).0, 7);
    }

    #[test]
    fn the_largest_pool_size_does_not_wrap_the_total() {
        let (pool, _) = state_pool(None, Some("4294967295"), DEFAULT);
        assert_eq!(state_total(pool), 4_294_967_299);
    }
}
