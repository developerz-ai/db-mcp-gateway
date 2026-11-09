//! No-op stand-in for sqlx's optional SQLite driver.
//!
//! Not a default workspace member: plain `cargo build` never compiles it and
//! only `--workspace`/`--all` builds it, as an empty lib. Cargo resolves its
//! manifest either way, and that resolution is what applies the patch — see
//! `third_party/sqlx-sqlite-noop/Cargo.toml` and the root `Cargo.toml`
//! `[patch.crates-io]` entry for why it exists.
