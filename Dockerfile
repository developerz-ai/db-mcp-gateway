# syntax=docker/dockerfile:1.7

# ---- build ----
FROM rust:1.85-slim-bookworm AS builder
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Cache deps separately from source. Copy only manifests first.
COPY Cargo.toml Cargo.lock* rust-toolchain.toml ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
  && cargo build --release \
  && rm -rf src target/release/db-mcp-gateway target/release/db_mcp_gateway*

COPY . .
RUN cargo build --release --locked
RUN strip target/release/db-mcp-gateway

# ---- runtime ----
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /src/target/release/db-mcp-gateway /usr/local/bin/db-mcp-gateway
COPY --from=builder /src/config/example.yaml /etc/db-mcp-gateway/example.yaml

EXPOSE 8443
USER nonroot

ENTRYPOINT ["/usr/local/bin/db-mcp-gateway"]
