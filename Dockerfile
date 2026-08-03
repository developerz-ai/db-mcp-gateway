# syntax=docker/dockerfile:1.7

# ---- chef ----
# Matches rust-toolchain.toml exactly. When the two drift, the toolchain file
# wins and rustup re-downloads inside the builder on every cache miss — bump
# both together.
#
# cargo-chef is installed from crates.io on top of the official rust image
# rather than pulled as `lukemathwalker/cargo-chef:*`, keeping the build's
# supply chain to crates.io plus the official image. Version-pinned for the
# same reason every GitHub Action is SHA-pinned.
FROM rust:1.97.1-slim-bookworm AS chef
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /src

# ---- planner ----
# Produces a dependency-only recipe. `prepare` normalises the manifest — the
# package's own version is masked — so the recipe changes when a *dependency*
# changes, and not when `version = "1.5.0"` is bumped for a release.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- builder ----
# `cook` compiles dependencies only. Because the recipe is version-masked, a
# release version bump no longer invalidates this layer. Previously every `v*`
# tag rebuilt the whole dependency graph: the dummy-main trick was fed by
# `COPY Cargo.toml`, so bumping the version busted that layer and everything
# below it.
#
# BuildKit `--mount=type=cache` is deliberately NOT used. CI caches with
# `cache-to: type=gha`, which does not persist cache mounts
# (moby/buildkit#2370, docker/build-push-action#1011), so mounts would help
# only local rebuilds while tempting us to drop the layer split that actually
# carries between CI runs. Keeping this layer *valid* is the win.
FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --locked

# ---- runtime ----
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /src/target/release/db-mcp-gateway /usr/local/bin/db-mcp-gateway
# Reference copy. The live config is mounted at /etc/gateway/config.yml.
COPY --from=builder /src/config/example.yaml /etc/gateway/example.yaml

# Canonical config path. Supplied via the --config env fallback (clap), so a
# bare `docker run -v ./config.yml:/etc/gateway/config.yml ...` boots, while
# extra CLI flags still compose and an explicit `--config <path>` overrides.
ENV DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml

EXPOSE 8443
USER nonroot

ENTRYPOINT ["/usr/local/bin/db-mcp-gateway"]
