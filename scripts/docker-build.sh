#!/usr/bin/env bash
# Runs INSIDE the builder container (docker-compose.build.yml). The source tree
# is bind-mounted at /src (CWD); target/, the cargo registry and ./dist are also
# host bind-mounts, so the build cache stays on the host and the produced Linux
# binary is written to ./dist/magnetite for the runtime phase to consume.
set -euo pipefail

echo "==> cargo leptos build --release"
cargo leptos build --release

OUT=/dist/magnetite
echo "==> Assembling $OUT"
mkdir -p "$OUT"
cp target/release/magnetite-server "$OUT/magnetite-server"
# Strip debug symbols to shrink the committed/runtime binary (~214MB -> ~130MB).
strip "$OUT/magnetite-server" 2>/dev/null || true
rm -rf "$OUT/site"
cp -r target/site "$OUT/site"
# Runtime config binds 0.0.0.0 (container-friendly).
cp deploy/magnetite.container.toml "$OUT/magnetite.toml"
chmod +x "$OUT/magnetite-server"

echo "==> Done. Linux binary + site + config in ./dist/magnetite"
ls -la "$OUT"
