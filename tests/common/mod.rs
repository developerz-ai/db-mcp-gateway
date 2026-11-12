//! Shared integration-test harness. Every `tests/*.rs` binary declares
//! `mod common;` and boots gateways, state pools and target fixtures from
//! here, so an `AppState` / `AuthConfig` field change lands in one place.
//!
//! Not security-sensitive: test-only code, never on a production path.

#![allow(dead_code)] // each test binary uses a different subset of helpers

pub mod audit;
pub mod cleanup;
pub mod env;
pub mod gateway;
pub mod idp;
pub mod mongo_target;
pub mod pg_target;
