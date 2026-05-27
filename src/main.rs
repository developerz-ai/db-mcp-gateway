// db-mcp-gateway — entrypoint stub.
//
// Real implementation lands per docs/initial-idea/11-roadmap.md, phase 1+.
// For now this exists so `cargo check` / `cargo build` succeeds in CI.

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "db-mcp-gateway starting"
    );
    tracing::warn!("phase 0 skeleton — no behavior implemented yet");
    Ok(())
}
