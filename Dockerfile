# syntax=docker/dockerfile:1
#
# Magnetite - integrated infrastructure platform.
# Multi-stage build: compile the single server binary + WASM/CSS site bundle
# with cargo-leptos, then ship a slim runtime image.
#
#   DOCKER_BUILDKIT=1 docker build -t magnetite:latest .
#   docker run --rm -p 4000:4000 -v magnetite-data:/app/data magnetite:latest
#
# Disk footprint: this uses BuildKit **cache mounts** for the cargo registry and
# the Rust `target/` dir, so the multi-GB build cache is kept in BuildKit's
# prunable cache and is NEVER baked into image layers. Only the compiled binary
# and site bundle end up in the final (slim) image. Reclaim the build cache with
# `docker builder prune` (see PACKAGING.md). If you would rather not compile in a
# container at all, use `Dockerfile.prebuilt` with `scripts/package.*`.
#
# BuildKit is required (default in modern Docker; enable with DOCKER_BUILDKIT=1).

# ---- build stage ----------------------------------------------------------
FROM rust:1-bookworm AS builder

# RocksDB (via surrealdb) needs a C/C++ toolchain + libclang for bindgen; curl +
# ca-certificates are needed to fetch the prebuilt cargo-leptos below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev build-essential pkg-config libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

# cargo-leptos: fetch the verified prebuilt gnu binary rather than `cargo install
# --locked`, which fails on a newer cargo (it rejects an old dependency crate's
# manifest). The sha256 pins the exact release. (See docs/CICD-GITLAB.md §前提1.)
RUN curl -sSL -o /tmp/cl.tar.gz https://github.com/leptos-rs/cargo-leptos/releases/download/v0.3.7/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz \
    && echo "fda80f4845e92d0e8f5ec13cf1a46982ba7a518ae01182e7e4201312944bc05d  /tmp/cl.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/cl.tar.gz -C /tmp \
    && install -m0755 /tmp/cargo-leptos-x86_64-unknown-linux-gnu/cargo-leptos /usr/local/cargo/bin/cargo-leptos \
    && rm -rf /tmp/cl.tar.gz /tmp/cargo-leptos-x86_64-unknown-linux-gnu \
    && cargo leptos --version

WORKDIR /src
COPY . .

# Build with cache mounts, then copy the two artifacts OUT of the cache mount
# into a real layer (/out) — cache-mount contents are not persisted in the
# image, so the runtime stage copies from /out, not from target/. The cache ids
# are versioned (…-v2) so a stale pre-fix cache is not reused.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-v2 \
    --mount=type=cache,target=/src/target,id=magnetite-target-v2 \
    cargo leptos build --release \
    && mkdir -p /out \
    && cp target/release/magnetite-server /out/magnetite-server \
    && cp -r target/site /out/site

# ---- test stage -----------------------------------------------------------
# Built by CI (`docker build --target test`) to run the checks over the WHOLE
# workspace (this is the platform body, not one crate), reusing the builder's
# compiled dependencies via the SAME cache mounts (the `…-v2` ids, distinct from the
# center Dockerfile's `cargo-registry`/`magnetite-target` so the shared runner's
# BuildKit cache is not fought over). Requires the rustfmt + clippy components —
# pinned in rust-toolchain.toml so a fixed toolchain (fetched minimally) carries them.
FROM builder AS test
ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-v2 \
    --mount=type=cache,target=/src/target,id=magnetite-target-v2 \
    cargo fmt --all -- --check \
    && cargo clippy --workspace --all-targets -- -D warnings \
    && cargo test --workspace

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/magnetite-server /app/magnetite-server
COPY --from=builder /out/site /app/site
COPY --from=builder /src/magnetite.toml /app/magnetite.toml

# The binary serves the front-end from LEPTOS_SITE_ROOT and stores the embedded
# database next to the config file (/app/data).
ENV LEPTOS_SITE_ROOT=/app/site
VOLUME ["/app/data"]
EXPOSE 4000

# ENTRYPOINT is the binary; CMD is the (overridable) config path argument.
ENTRYPOINT ["/app/magnetite-server"]
CMD ["magnetite.toml"]
