//! `--check`: parse, validate and (unless `--no-secrets`) resolve a config
//! without booting, then print every error, every warning and the connection
//! budget. Exit 0 when there is no error, 1 otherwise.
//!
//! Every line is built from the schema's own field names and the config's
//! names (servers, databases, groups, env var names) — never a secret value.

mod budget;
pub(in crate::cli) mod env_names;
mod warnings;

use std::path::Path;

use db_mcp_gateway::config::ConfigFile;

pub use budget::{cancel_pool_size, server_budget};
pub use warnings::tls_warnings;

use super::{EXIT_FAILED, EXIT_OK};

pub fn run(path: &Path, no_secrets: bool) -> u8 {
    println!("config: {}", path.display());
    let config = match ConfigFile::from_file(path) {
        Ok(config) => config,
        Err(err) => {
            let errors: Vec<String> = err.into_list().iter().map(ToString::to_string).collect();
            print_lines("error", &errors);
            print_result(errors.len(), 0);
            return EXIT_FAILED;
        }
    };
    let mut errors: Vec<String> = if no_secrets {
        println!("secrets: not resolved (--no-secrets)");
        Vec::new()
    } else {
        config
            .secret_errors()
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    let env: Vec<String> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .collect();
    let warnings = warnings::collect(&config, &env);
    let cancel = budget::cancel_pool_size()
        .map_err(|err| errors.push(err))
        .ok();
    print_lines("error", &errors);
    print_lines("warning", &warnings);
    if let Some(cancel) = cancel {
        budget::print(&config, cancel);
    }
    print_result(errors.len(), warnings.len());
    if errors.is_empty() {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

fn print_lines(label: &str, lines: &[String]) {
    for line in lines {
        println!("{label}: {line}");
    }
}

fn print_result(errors: usize, warnings: usize) {
    let verdict = if errors == 0 { "valid" } else { "invalid" };
    println!("result: {verdict} ({errors} error(s), {warnings} warning(s))");
}
