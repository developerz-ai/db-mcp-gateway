//! Integration tests against the real dev stack (state Postgres, target
//! Postgres, MySQL permissions store, Mongo). One binary so a library change
//! relinks one test executable, not one per file. Each module was its own
//! `tests/*.rs` binary; run one with `bin/test --test it_db <module>::`.
//!
//! Under plain `cargo test` every module shares this process, so each test
//! declares its isolation on the `world` key: `#[serial_test::serial(world)]`
//! when it has a table-wide or global side effect (reaper/pruner/GC sweeps,
//! cap seeding, global catalog counts) — it then runs alone —, else
//! `#[serial_test::parallel(world)]`. `it_offline::isolation_guard` fails a
//! test that declares neither. Nextest runs each test in its own process, so
//! there the attributes are inert.

#[path = "../common/mod.rs"]
mod common;

mod adapter_registry_concurrency;
mod admin_databases_e2e;
mod admin_grants_e2e;
mod admin_users_e2e;
mod audit_dispatch_cancellation_real_db;
mod audit_integrity_describe_schema_e2e;
mod audit_integrity_intent_e2e;
mod audit_integrity_intent_real_db;
mod audit_integrity_real_db;
mod audit_pruner_real_db;
mod audit_stream_real_db;
mod audit_two_phase_real_db;
mod auth_e2e;
mod auth_reserved_subject_real_db;
mod cancellation_real_db;
mod client_registry_real_db;
mod config_reload;
mod describe_schema_real_db;
mod exec_run_query;
mod explain_e2e;
mod explain_real_db;
mod get_query_history_real_db;
mod introspection_tools_real_db;
mod migrations_real_db;
mod mongo_cancel_killop_real_db;
mod mongo_query_real_db;
mod mongo_timeout_real_db;
mod oauth_bridge_e2e;
mod oauth_client_name;
mod oauth_consent;
mod oauth_lifecycle_real_db;
mod permissions_audit_real_db;
mod permissions_indexes_mysql;
mod permissions_repo_mysql;
mod permissions_repo_real_db;
mod permissions_resolver_real_db;
mod permissions_tx_updates_real_db;
mod refresh_tokens_real_db;
mod run_query_e2e;
mod sample_table_authz_e2e;
mod sample_table_real_db;
mod secret_refs;
mod service_account_concurrency_e2e;
mod service_tokens_e2e;
mod service_upstream_e2e;
mod session_cache_real_db;
mod sql_guard_side_effects;
mod sql_guard_unicode_escape;
mod tool_args_edge_e2e;
mod tool_dispatch_coverage;
mod transport_wave2_admin_databases;
mod two_replicas_real_db;
mod write_tier_e2e;
