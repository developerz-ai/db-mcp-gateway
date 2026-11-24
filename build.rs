// `sqlx::migrate!` embeds each migration with `include_str!`, so an edited
// file rebuilds the crate, but a NEW file in the directory does not: on stable
// the macro cannot watch a directory. Without this, a fresh migration was
// silently missing from the binary until some Rust source changed.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=migrations-mysql");
}
