# syntax=docker/dockerfile:1.7

# ---- build ----
# Matches rust-toolchain.toml exactly. When the two drift, the toolchain file
# wins and rustup re-downloads inside the builder on every cache miss — bump
# both together.
FROM rust:1.97-slim-bookworm AS builder
WORKDIR /src

# Cache deps separately from source. Copy only manifests first.
COPY Cargo.toml Cargo.lock* rust-toolchain.toml ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
  && cargo build --release \
  && rm -rf src target/release/db-mcp-gateway target/release/db_mcp_gateway*

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
