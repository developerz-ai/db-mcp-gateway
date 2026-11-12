# syntax=docker/dockerfile:1.7

# Base images are pinned by multi-arch index digest, not just tag: a tag is
# mutable, so the same commit could build on different bases. Bump the tag and
# digest together (`docker buildx imagetools inspect <image>:<tag>`).

# ---- chef-bin ----
# The prebuilt cargo-chef release binary, verified by checksum, instead of
# `cargo install` compiling it from source on every builder-cache miss.
# Both arches are fetched because `ADD --checksum` takes a literal; the
# build's own arch is picked by TARGETARCH. busybox only unpacks the .tar.xz
# (the rust slim image ships no xz).
FROM busybox:1.37.0-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478 AS chef-bin
ARG TARGETARCH
ADD --checksum=sha256:ff390181459f53c787a496c4ee9a52d8c9c7975ab8d02c8dbd1a0fa1626171f4 \
    https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.77/cargo-chef-x86_64-unknown-linux-gnu.tar.xz \
    /dl/amd64.tar.xz
ADD --checksum=sha256:64cd1b405894f587a461a0dd0f60127330b1ebd204fd46b1a36fb0ff6da157e0 \
    https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.77/cargo-chef-aarch64-unknown-linux-gnu.tar.xz \
    /dl/arm64.tar.xz
RUN tar -xJf "/dl/${TARGETARCH}.tar.xz" -C /dl --strip-components=1

# ---- chef ----
# Matches rust-toolchain.toml exactly. When the two drift, the toolchain file
# wins and rustup re-downloads inside the builder on every cache miss — bump
# both together.
FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS chef
COPY --from=chef-bin /dl/cargo-chef /usr/local/cargo/bin/cargo-chef
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
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
WORKDIR /app

COPY --from=builder /src/target/release/db-mcp-gateway /usr/local/bin/db-mcp-gateway
# Reference copy. The live config is mounted at /etc/gateway/config.yml.
COPY --from=builder /src/config/example.yaml /etc/gateway/example.yaml

# Canonical config path. Supplied via the --config env fallback (clap), so a
# bare `docker run -v ./config.yml:/etc/gateway/config.yml ...` boots, while
# extra CLI flags still compose and an explicit `--config <path>` overrides.
ENV DB_MCP_GATEWAY_CONFIG=/etc/gateway/config.yml
# The binary's own default is loopback (safe for a dev `cargo run`); in a
# container loopback is unreachable, so the image listens on all interfaces.
# METRICS_BIND keeps its loopback default: set `0.0.0.0:9090` to scrape, and
# fence that port to the Prometheus namespace.
ENV GATEWAY_BIND=0.0.0.0:8443

EXPOSE 8443
USER nonroot

ENTRYPOINT ["/usr/local/bin/db-mcp-gateway"]
