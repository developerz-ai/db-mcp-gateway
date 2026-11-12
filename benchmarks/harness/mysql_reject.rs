//! MySQL query-target rejection: verified, not assumed.
//!
//! MySQL is **not** a query target in this gateway. `ServerKind::has_adapter`
//! returns `false` for `Mysql`/`Mssql` (src/config/schema.rs) and config
//! validation rejects such a server at boot (src/config/yaml.rs). So there is
//! no MySQL query performance to measure — what there *is* to measure is that
//! the rejection actually happens, through the gateway's own config loader,
//! rather than through a hand-written YAML file the harness happens to parse.
//!
//! Two things are checked, and they are different claims:
//!
//! 1. **Boot-time rejection.** The YAML — the committed
//!    `benchmarks/gateway.bench.mysql.yaml` unless the operator names
//!    another — is loaded through the gateway's own `ConfigFile::from_yaml_str`:
//!    the same parser and the same validator the binary uses at boot. A
//!    `kind: mysql` server must fail with the "no query adapter" rejection.
//! 2. **Runtime backstop.** If an undispatchable kind ever reached the exec
//!    layer (a defense-in-depth path a validated config does not take), the
//!    tool layer must map `ExecError::UnsupportedAdapter` to the stable
//!    `internal` code with a generic message — never the raw `ServerKind`,
//!    which would hint at the backend topology.
//!
//! The verdict is reported in its own section, separate from any
//! successful-query performance numbers. A "MySQL is rejected" result is not
//! a latency result and must never be read as one.

use std::path::Path;

use db_mcp_gateway::config::{ConfigFile, ConfigFileError};
use db_mcp_gateway::exec::ExecError;
use db_mcp_gateway::tools::audit_dispatch::{
    OutcomeCode, ToolErrorMessages, outcome_from_exec_error,
};
use serde::Serialize;

/// The verdict of the MySQL rejection check.
#[derive(Debug, Clone, Serialize)]
pub struct MySqlRejection {
    /// The kind that was checked. Always `mysql` today.
    pub kind: &'static str,
    /// Whether the boot-time rejection fired as expected.
    pub boot_rejected: bool,
    /// Whether the runtime backstop maps the error to the stable `internal`
    /// code without leaking the backend kind.
    pub runtime_backstop_ok: bool,
    /// The operator-facing rejection message. Carries the *schema's* words —
    /// server name and kind — never a credential or a connection string.
    pub rejection_message: Option<String>,
    /// Why the check could not be completed, if it could not. `None` means
    /// the check ran.
    pub not_run_reason: Option<String>,
}

impl MySqlRejection {
    /// A check that could not be run. Reported as such rather than as a
    /// pass — "we did not look" and "we looked and it was fine" must not
    /// look the same in the JSON.
    fn not_run(kind: &'static str, reason: String) -> Self {
        MySqlRejection {
            kind,
            boot_rejected: false,
            runtime_backstop_ok: false,
            rejection_message: None,
            not_run_reason: Some(reason),
        }
    }

    /// Whether the whole check passed.
    pub fn passed(&self) -> bool {
        self.boot_rejected && self.runtime_backstop_ok && self.not_run_reason.is_none()
    }
}

/// The YAML the check falls back to when the committed artifact cannot be
/// read.
///
/// Declares a `kind: mysql` server — the shape a real operator would write
/// and the one the gateway must refuse. The password is a literal, not a
/// secret reference: this file never reaches a live server (the rejection
/// happens before any connection is attempted) and a `${ENV:…}` reference
/// would make the check depend on the environment.
const DEFAULT_MYSQL_CONFIG: &str = r#"
servers:
  - name: legacy
    kind: mysql
    host: localhost
    port: 3306
    databases:
      - name: app
        role: app
        password: app-dev-only
"#;

/// The committed YAML that declares the `kind: mysql` target, relative to the
/// crate root.
///
/// This is the artifact the acceptance criterion names, so it is the artifact
/// the check loads — in the harness as well as in the tests. An inline
/// constant alone would let the committed file drift (say, to `kind: mongo`)
/// while every test still passed.
const COMMITTED_MYSQL_CONFIG: &str = "benchmarks/gateway.bench.mysql.yaml";

/// The path of the committed YAML, resolved against the crate root.
///
/// `CARGO_MANIFEST_DIR` is baked in at compile time, so the path does not
/// depend on the working directory the harness happens to run in.
fn committed_config_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(COMMITTED_MYSQL_CONFIG)
}

/// Verify the rejection. `config_path` is the YAML to load; `None` uses the
/// committed artifact [`COMMITTED_MYSQL_CONFIG`], falling back to
/// [`DEFAULT_MYSQL_CONFIG`] when that file cannot be read (a harness binary
/// run outside the checkout).
///
/// Never raises: a rejection check that reports "the gateway accepted
/// a MySQL target" is a *finding*, not a harness error, so it is returned as
/// a verdict rather than raised. The caller writes the verdict into the
/// report and then fails the run on it (see `main`) — the diagnostic survives
/// the non-zero exit.
pub fn verify(config_path: Option<&Path>) -> MySqlRejection {
    let raw = match config_path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) => {
                return MySqlRejection::not_run(
                    "mysql",
                    format!("could not read the supplied config file: {err}"),
                );
            }
        },
        None => match std::fs::read_to_string(committed_config_path()) {
            Ok(raw) => raw,
            Err(_) => DEFAULT_MYSQL_CONFIG.to_string(),
        },
    };

    let boot = check_boot_rejection(&raw);
    let runtime_backstop_ok = check_runtime_backstop();

    MySqlRejection {
        kind: "mysql",
        boot_rejected: boot.rejected,
        runtime_backstop_ok,
        rejection_message: boot.message,
        not_run_reason: None,
    }
}

/// Outcome of the boot-time load.
struct BootCheck {
    rejected: bool,
    message: Option<String>,
}

/// Load `raw` through the gateway's own config loader and confirm it is
/// rejected for having no query adapter.
fn check_boot_rejection(raw: &str) -> BootCheck {
    match ConfigFile::from_yaml_str(raw) {
        // Accepted. That is the failure this check exists to catch: a
        // MySQL target must not boot.
        Ok(_) => BootCheck {
            rejected: false,
            message: Some(
                "the gateway accepted a `kind: mysql` server — the boot-time rejection did not fire"
                    .to_string(),
            ),
        },
        Err(err) => {
            let message = err.to_string();
            let rejected = is_no_adapter_rejection(&err, &message);
            BootCheck {
                rejected,
                message: Some(message),
            }
        }
    }
}

/// Does this config error mean "this server kind has no query adapter"?
///
/// Matched on the *typed* variant first, then on the message text. The
/// typed check is authoritative: `ConfigFileError::Invalid` carries a
/// free-form string, and the "no query adapter" sentence is part of that
/// string rather than its own variant, so the text check is what actually
/// distinguishes this rejection from an unrelated validation failure (a
/// duplicate server name, a blank role, a superuser role).
///
/// The text must also name `Mysql` itself. A `kind: mssql` server fails with
/// the same sentence — `Mssql` has no adapter either — but this check
/// verifies the *MySQL* rejection; counting an Mssql rejection would let the
/// config drift to `kind: mssql` while the verdict still read as a verified
/// mysql rejection.
fn is_no_adapter_rejection(err: &ConfigFileError, message: &str) -> bool {
    matches!(err, ConfigFileError::Invalid(_))
        && message.contains("no query adapter")
        && message.contains("kind `Mysql`")
}

/// The runtime backstop: `ExecError::UnsupportedAdapter` must map to the
/// stable `internal` code with a generic message.
///
/// The check goes through the gateway's own `outcome_from_exec_error` — the
/// function the tool layer uses — rather than re-implementing the mapping.
/// A harness that re-implemented it would keep passing if the gateway's
/// mapping changed.
fn check_runtime_backstop() -> bool {
    let messages = ToolErrorMessages {
        timeout: "query exceeded the configured statement_timeout",
        sql_rejected: "the target DB rejected the query",
        forbidden_prefix: "query",
    };
    let outcome = outcome_from_exec_error(
        ExecError::UnsupportedAdapter(db_mcp_gateway::config::ServerKind::Mysql),
        std::time::Instant::now(),
        &messages,
    );
    if outcome.code != OutcomeCode::Internal {
        return false;
    }
    let message = outcome.error_message.unwrap_or_default().to_lowercase();
    // The backend identity must not ride along into the client-facing text.
    !message.contains("mysql") && !message.contains("mssql")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core claim: a `kind: mysql` server is refused at boot, with the
    /// "no query adapter" reason.
    ///
    /// `verify(None)` loads the committed artifact, so this test covers the
    /// file the runner script points at.
    #[test]
    fn a_mysql_target_is_rejected_at_boot() {
        let verdict = verify(None);
        assert!(
            verdict.boot_rejected,
            "mysql target was not rejected at boot: {:?}",
            verdict.rejection_message
        );
        assert!(
            verdict
                .rejection_message
                .as_deref()
                .is_some_and(|m| m.contains("no query adapter")),
            "rejection must name the missing adapter: {:?}",
            verdict.rejection_message
        );
        assert!(verdict.runtime_backstop_ok);
        assert!(verdict.passed());
    }

    /// The committed artifact must be the one that gets rejected.
    ///
    /// `verify(None)` now loads the committed file, but the runner passes it
    /// explicitly (`--mysql-rejection-config`), so that path deserves its
    /// own assertion: `benchmarks/gateway.bench.mysql.yaml` is the file the
    /// README, the runner script and the acceptance criterion all point at.
    /// If that file were edited to `kind: mongo` (or deleted, or emptied)
    /// the check must fail loudly rather than report "rejected".
    ///
    /// So: load the committed file itself, through the gateway's own
    /// `ConfigFile::from_yaml_str`, and assert the same boot-time
    /// "no query adapter" rejection.
    #[test]
    fn the_committed_mysql_config_file_is_rejected_at_boot() {
        let path = committed_config_path();
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));

        let check = check_boot_rejection(&raw);
        assert!(
            check.rejected,
            "the committed MySQL config {} was not rejected for a missing adapter: {:?}",
            path.display(),
            check.message
        );
        assert!(
            check
                .message
                .as_deref()
                .is_some_and(|m| m.contains("no query adapter")),
            "the rejection must name the missing adapter: {:?}",
            check.message
        );
    }

    /// The same claim, end to end through `verify` — the function the runner
    /// actually calls — so the committed file is covered on the path the
    /// harness uses, not only through the inner helper.
    #[test]
    fn the_committed_mysql_config_file_passes_the_full_verdict() {
        let path = committed_config_path();
        let verdict = verify(Some(&path));
        assert!(
            verdict.boot_rejected,
            "the committed MySQL config {} was not rejected at boot: {:?}",
            path.display(),
            verdict.rejection_message
        );
        assert!(verdict.not_run_reason.is_none());
        assert!(verdict.passed());
    }

    /// The default the harness runs with must be the committed artifact, not
    /// an inline copy of it.
    ///
    /// A harness that verified its own embedded YAML would keep reporting
    /// "rejected" after the committed file was edited to `kind: mongo` — the
    /// file the README and the runner script point at would no longer be the
    /// thing that was checked.
    ///
    /// The committed file declares its server as `mysql-target`; the inline
    /// fallback calls it `legacy`. So the rejection message `verify(None)`
    /// produces names which file was loaded. That is an observation of the
    /// load, not of a copy of the YAML.
    #[test]
    fn the_default_check_loads_the_committed_artifact() {
        let path = committed_config_path();
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
        assert!(
            committed.contains("kind: mysql"),
            "{} no longer declares a mysql target",
            path.display()
        );

        let verdict = verify(None);
        let message = verdict
            .rejection_message
            .as_deref()
            .expect("the default check must report why it rejected");
        assert!(
            message.contains("mysql-target"),
            "the default check did not load the committed artifact {}: {message}",
            path.display()
        );
    }

    /// The check must not be satisfied by an *unrelated* config error. A
    /// duplicate server name would also make `from_yaml_str` fail — but that
    /// is not the rejection we are verifying.
    #[test]
    fn an_unrelated_config_error_is_not_counted_as_the_adapter_rejection() {
        let yaml = "servers:\n  - name: dup\n    kind: postgres\n    host: a\n  - \
                    name: dup\n    kind: postgres\n    host: b\n";
        let check = check_boot_rejection(yaml);
        assert!(
            !check.rejected,
            "duplicate-name error is not the adapter rejection"
        );
    }

    /// The runtime backstop must map to `internal` and must not leak the
    /// backend kind into the client-facing message.
    #[test]
    fn the_runtime_backstop_maps_to_internal_without_leaking_the_kind() {
        assert!(check_runtime_backstop());
    }

    /// An Mssql target is refused at boot too — but with a different kind in
    /// the message, and this check verifies the *MySQL* rejection. Counting
    /// an Mssql rejection would let the config drift to `kind: mssql` while
    /// the verdict still read as a verified mysql rejection.
    #[test]
    fn an_mssql_rejection_does_not_satisfy_the_mysql_check() {
        let yaml = r#"
servers:
  - name: mssql-target
    kind: mssql
    host: localhost
    port: 1433
    databases:
      - name: app
        role: ro
        password: x
"#;
        let check = check_boot_rejection(yaml);
        // mssql is genuinely refused for the same missing-adapter reason —
        // the sentence is there.
        assert!(
            check
                .message
                .as_deref()
                .is_some_and(|m| m.contains("no query adapter")),
            "mssql should be refused for a missing adapter: {:?}",
            check.message
        );
        // …but it is not the mysql rejection, and must not pass this check.
        assert!(
            !check.rejected,
            "an Mssql rejection must not satisfy the mysql check: {:?}",
            check.message
        );
    }

    /// A mongo target must still boot — the check must not be satisfied by
    /// rejecting everything.
    ///
    /// The claim is asserted on the loader itself: "the rejection check did
    /// not fire" is only meaningful if the config actually loads. Checking
    /// merely `!rejected` would pass even if `from_yaml_str` refused this
    /// YAML for some unrelated reason — a validator that rejected *every*
    /// config would keep this test green while mongo was unbootable.
    #[test]
    fn a_mongo_target_still_boots() {
        let yaml = r#"
servers:
  - name: docs
    kind: mongo
    host: localhost
    databases:
      - name: app
        role: ro
        password: x
"#;
        assert!(
            ConfigFile::from_yaml_str(yaml).is_ok(),
            "mongo is a wired query target — the loader must accept this config"
        );
        // And with the load proven good, the rejection check must not claim it.
        let check = check_boot_rejection(yaml);
        assert!(!check.rejected, "mongo is a wired query target");
    }

    /// A missing config file is "not run", not "passed".
    #[test]
    fn a_missing_config_file_is_reported_as_not_run() {
        let verdict = verify(Some(Path::new("/nonexistent/bench-mysql.yaml")));
        assert!(!verdict.passed());
        assert!(
            verdict.not_run_reason.is_some(),
            "a check that could not run must say so"
        );
        assert!(!verdict.boot_rejected);
    }
}
