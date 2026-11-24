//! The connection budget: how many connections one replica may open to each
//! target server and to the state DB, at full load. Pools are lazy (min 0),
//! so this is the ceiling, not the steady state.

use db_mcp_gateway::config::{Config, ConfigFile, Database, Server, ServerKind};
use db_mcp_gateway::exec::PoolSizing;
use db_mcp_gateway::exec::pg::init_cancel_pool_size_from_env;

/// The state DB's background (pruner/GC) and LISTEN pools
/// (`state::{BACKGROUND,LISTENER}_POOL_SIZE`, crate-private there).
const STATE_BACKGROUND_POOL: u32 = 2;
const STATE_LISTENER_POOL: u32 = 2;

/// Each Postgres tier's `pg_cancel_backend` pool, as boot sizes it
/// (`PG_CANCEL_POOL_SIZE`); the error names the variable, never more.
pub fn cancel_pool_size() -> Result<u32, String> {
    init_cancel_pool_size_from_env().map_err(|err| err.to_string())
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
    // `from_env` fails without the deployment's env (e.g. TLS paths in CI);
    // the built-in default is then the honest answer.
    let (pool, source) = match Config::from_env() {
        Ok(env) => (env.state_db.pool_size.get(), "STATE_DB_POOL_SIZE"),
        Err(_) => (
            Config::default().state_db.pool_size.get(),
            "default; the environment did not load",
        ),
    };
    let total = pool + STATE_BACKGROUND_POOL + STATE_LISTENER_POOL;
    println!(
        "  state DB: request {pool} ({source}) + background {STATE_BACKGROUND_POOL} \
         + listener {STATE_LISTENER_POOL} = {total}"
    );
}
