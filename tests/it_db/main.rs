//! Integration tests against the real dev stack (state Postgres, target
//! Postgres, MySQL permissions store, Mongo, Redis + Dragonfly). One binary
//! so a library change relinks one test executable, not one per file. Each module was its own
//! `tests/*.rs` binary; run one with `bin/test --test it_db <module>::`.
//!
//! Under plain `cargo test` every module shares this process, so each test
//! declares its isolation on the `world` key: `#[serial_test::serial(world)]`
//! when it has a table-wide or global side effect (reaper/pruner/GC sweeps,
//! cap seeding, global catalog counts) — it then runs alone —, else
//! `#[serial_test::parallel(world)]`. `it_offline::isolation_guard` fails a
//! test that declares neither. Nextest runs each test in its own process, so
//! there the attributes are inert.

// CLAUDE.md §Conventions: tests may panic; `[lints.clippy]` denies it for shipped code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod adapter_registry_concurrency;
mod adapter_registry_open_races;
mod admin_actor_row;
mod admin_audit_calls_e2e;
mod admin_batch_e2e;
mod admin_databases_e2e;
mod admin_explain_e2e;
mod admin_export_e2e;
mod admin_grants_e2e;
mod admin_o10_support;
mod admin_users_e2e;
mod agent_walk_e2e;
mod agent_walk_support;
mod audit_dispatch_cancellation_real_db;
mod audit_dispatch_panic_real_db;
mod audit_history_digest_real_db;
mod audit_integrity_describe_schema_e2e;
mod audit_integrity_intent_e2e;
mod audit_integrity_intent_real_db;
mod audit_integrity_real_db;
mod audit_integrity_write_commit_e2e;
mod audit_pruner_real_db;
mod audit_role_split_real_db;
mod audit_rollback_admin_writes_e2e;
mod audit_stream_real_db;
mod audit_two_phase_real_db;
mod auth_e2e;
mod auth_reserved_subject_real_db;
mod blackhole_proxy;
mod boot_binary;
mod boot_network;
mod boot_pools;
mod boot_state_retry;
mod caller_share_e2e;
mod cancellation_real_db;
mod cli_admin;
mod cli_doctor;
mod cli_healthcheck;
mod client_registry_real_db;
mod config_reload;
mod describe_schema_column_privileges_real_db;
mod describe_schema_real_db;
mod describe_schema_v2_real_db;
mod discovery_e2e;
mod exec_isolation_real_db;
mod exec_run_query;
mod explain_e2e;
mod explain_real_db;
mod explain_summary_e2e;
mod get_query_history_real_db;
mod get_query_history_sha256_e2e;
mod ha_login_e2e;
mod introspection_tools_real_db;
mod limit_zero_e2e;
mod list_tools_elapsed_e2e;
mod metrics_pool_real_db;
mod migrations_real_db;
mod mongo_caller_share_real_db;
mod mongo_cancel_killop_real_db;
mod mongo_describe_denied_real_db;
mod mongo_describe_v2_real_db;
mod mongo_exec_correctness_real_db;
mod mongo_query_real_db;
mod mongo_system_collections_real_db;
mod mongo_timeout_real_db;
mod oauth_bridge_e2e;
mod oauth_client_adopt_cap_real_db;
mod oauth_client_adopt_e2e;
mod oauth_client_name;
mod oauth_client_ttl_e2e;
mod oauth_code_restore_real_db;
mod oauth_consent;
mod oauth_grant_locks_real_db;
mod oauth_grant_races_real_db;
mod oauth_lifecycle_real_db;
mod oauth_login_caps_real_db;
mod oauth_login_state_real_db;
mod oauth_refresh_bounds_e2e;
mod oauth_revoke_race_real_db;
mod params_e2e;
mod permissions_audit_real_db;
mod permissions_expires_at_real_db;
mod permissions_indexes_mysql;
mod permissions_listener_liveness_real_db;
mod permissions_listener_outage_real_db;
mod permissions_pruner_real_db;
mod permissions_repo_mysql;
mod permissions_repo_real_db;
mod permissions_resolver_real_db;
mod permissions_tx_updates_real_db;
mod pg_column_types_e2e;
mod pg_error_hints_real_db;
mod pg_error_redaction_real_db;
mod pg_result_budget_real_db;
mod pg_type_rendering_real_db;
mod pg_write_tier_real_db;
mod pool_sizing_real_db;
mod reaper_stream_real_db;
mod redis_bounded_real_db;
mod redis_bounded_values_real_db;
mod redis_idle_reconnect_real_db;
mod redis_query_real_db;
mod redis_run_query_e2e;
mod redis_timeout_real_db;
mod refresh_tokens_real_db;
mod run_query_e2e;
mod run_query_sizing_e2e;
mod sample_table_authz_e2e;
mod sample_table_columns_e2e;
mod sample_table_kind_probe_e2e;
mod sample_table_real_db;
mod secret_refs;
mod service_account_concurrency_e2e;
mod service_token_rotation_e2e;
mod service_tokens_e2e;
mod service_upstream_e2e;
mod session_cache_real_db;
mod session_max_age_e2e;
mod sql_guard_bounds_e2e;
mod sql_guard_differential;
mod sql_guard_location_e2e;
mod sql_guard_refusals_e2e;
mod sql_guard_side_effects;
mod sql_guard_unicode_escape;
mod state_probe_logs;
mod tool_args_edge_e2e;
mod tool_dispatch_coverage;
mod tool_error_codes_e2e;
mod tool_errors_body_e2e;
mod transport_wave2_admin_databases;
mod two_replicas_real_db;
mod whoami_e2e;
mod write_tier_e2e;
