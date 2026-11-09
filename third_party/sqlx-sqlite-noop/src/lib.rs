//! No-op stand-in for sqlx's optional SQLite driver.
//!
//! Never compiled: the `sqlite` feature is off everywhere in this workspace,
//! so cargo only ever resolves this crate's manifest, not its code. See
//! `third_party/sqlx-sqlite-noop/Cargo.toml` and the root `Cargo.toml`
//! `[patch.crates-io]` entry for why it exists.
