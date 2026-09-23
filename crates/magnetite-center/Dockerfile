# syntax=docker/dockerfile:1
#
# Magnetite Center — the vCenter-like control plane, as a standalone container.
# Unlike the main server this is a lightweight headless binary (no Leptos/WASM):
# it serves its own embedded dashboard + JSON API and needs only env-var config.
#
# Build (context MUST be the repo root so the whole workspace compiles):
#   DOCKER_BUILDKIT=1 docker build -f crates/magnetite-center/Dockerfile -t magnetite-center:latest .
#   # Podman:
#   podman build -f crates/magnetite-center/Dockerfile -t magnetite-center:latest .
#
# Run (single node, embedded DB in a volume):
#   docker run --rm -p 5555:5555 -e CENTER_ADMIN_TOKEN=$(openssl rand -hex 32) \
#     -v magnetite-center-data:/app/data magnetite-center:latest
#
# BuildKit cache mounts keep the multi-GB build cache OUT of the image layers
# (reclaim with `docker builder prune`).

# ---- build stage ----------------------------------------------------------
FROM rust:1-bookworm AS builder

# RocksDB (via surrealdb) needs a C/C++ toolchain + libclang for bindgen.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build only the center binary; copy it out of the cache mount into a real layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/src/target,id=magnetite-target \
    cargo build --release -p magnetite-center \
    && mkdir -p /out \
    && cp target/release/magnetite-center /out/magnetite-center

# ---- test stage -----------------------------------------------------------
# Built by CI (`docker build --target test`) to run the checks, reusing the
# builder's compiled dependencies via the SAME cache mounts (id=cargo-registry /
# id=magnetite-target) so nothing is recompiled from scratch. Scoped to the center
# package (the runtime image builds only `-p magnetite-center`, not the whole
# monorepo — the main server body has its own pipeline). Requires the `rustfmt` +
# `clippy` components — pinned in rust-toolchain.toml so a fixed toolchain (which
# rustup fetches minimally) still carries them.
FROM builder AS test

RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/src/target,id=magnetite-target \
    cargo fmt -p magnetite-center -- --check \
    && cargo clippy -p magnetite-center --all-targets -- -D warnings \
    && cargo test -p magnetite-center

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates for outbound TLS to managed servers; curl for the healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/magnetite-center /app/magnetite-center

# Run as a non-root user (uid/gid 10001). Own /app (binary + data dir) so the
# embedded RocksDB store is writable when run with a plain volume; under Kubernetes
# the Deployment's `fsGroup: 10001` makes the mounted PVC group-writable too.
RUN groupadd -g 10001 magnetite \
    && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin magnetite \
    && mkdir -p /app/data \
    && chown -R 10001:10001 /app

# Bind on all interfaces inside the container and keep the embedded DB on the
# persisted volume. CENTER_ADMIN_TOKEN is REQUIRED and must be supplied at run
# time (never baked into the image). For HA, set CENTER_DB_URL to a shared
# SurrealDB instead and run several replicas.
ENV CENTER_LISTEN=0.0.0.0:5555 \
    CENTER_DB_PATH=/app/data/center \
    CENTER_POLL_SECS=30 \
    CENTER_LEASE_SECS=15

VOLUME ["/app/data"]
EXPOSE 5555

# Drop to the non-root user for the running process.
USER 10001:10001

# Container healthcheck = liveness: hit /healthz (no dependencies). Readiness
# (/readyz, which probes the datastore) is evaluated by Kubernetes, not here.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5555/healthz || exit 1

ENTRYPOINT ["/app/magnetite-center"]
