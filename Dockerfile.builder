# Builder toolchain image for the two-phase workflow (docker-compose.build.yml).
# It contains ONLY the Rust toolchain + cargo-leptos — no source code. The source
# tree, the Rust `target/`, the cargo registry and the `dist/` output are all
# bind-mounted from the host at run time, so:
#   * the multi-GB build cache lives on the HOST disk (./.docker-cache/*), not in
#     the engine's virtual disk, and you can inspect or delete it directly;
#   * the produced binary is a Linux ELF written to ./dist on the host.
#
# Build this image once:  docker compose -f docker-compose.build.yml build
FROM rust:1-bookworm

# RocksDB (via surrealdb) needs a C/C++ toolchain + libclang for bindgen.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
RUN cargo install cargo-leptos --locked

WORKDIR /src
# The actual build command is provided by docker-compose.build.yml (it runs
# scripts/docker-build.sh from the bind-mounted source).
CMD ["bash", "scripts/docker-build.sh"]
