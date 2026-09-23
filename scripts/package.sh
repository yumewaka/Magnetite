#!/usr/bin/env bash
# Build Magnetite into a self-contained, runnable distribution folder.
#
# Drives `cargo leptos build --release` (single binary + WASM/CSS site bundle),
# then assembles dist/magnetite with the binary, compiled site/ assets, config
# and launchers. See PACKAGING.md for details.
#
# Usage: scripts/package.sh [--out DIR] [--zip] [--skip-build]
set -euo pipefail

OUT_DIR="dist/magnetite"
DO_ZIP=0
SKIP_BUILD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2 ;;
    --zip) DO_ZIP=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "'$1' not found. $2" >&2; exit 1; }; }

echo "==> Checking prerequisites"
need cargo "Install from https://rustup.rs"
need cargo-leptos "cargo install cargo-leptos"
if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
  echo "    Adding wasm32-unknown-unknown target"
  rustup target add wasm32-unknown-unknown
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  echo "==> cargo leptos build --release (this takes a while)"
  cargo leptos build --release
fi

BIN="target/release/magnetite-server"
SITE="target/site"
[ -f "$BIN" ] || { echo "Server binary not found at $BIN" >&2; exit 1; }
[ -d "$SITE" ] || { echo "Site bundle not found at $SITE" >&2; exit 1; }

echo "==> Assembling $OUT_DIR"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp "$BIN" "$OUT_DIR/magnetite-server"
cp -r "$SITE" "$OUT_DIR/site"
cp magnetite.toml "$OUT_DIR/magnetite.toml"

cat > "$OUT_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export LEPTOS_SITE_ROOT="./site"
exec ./magnetite-server magnetite.toml
EOF

cat > "$OUT_DIR/README.txt" <<'EOF'
Magnetite - integrated infrastructure platform
==============================================

Run:  ./run.sh   (then open the [server] address, default http://127.0.0.1:4000)

The first launch creates ./data (embedded database) and prompts for first-admin
setup. Configure magnetite.toml before production use:
  * [server] host = "0.0.0.0" to serve on the LAN.
  * [domains.<d>.server] to enable embedded DNS/DHCP/LDAP/Mail/Proxy servers
    (privileged ports 53/67/25/389/443 need elevated privileges).
  * [sso] optional OIDC; remove for local accounts only.
Keep magnetite-server, site/ and magnetite.toml together; back up ./data.
EOF

chmod +x "$OUT_DIR/magnetite-server" "$OUT_DIR/run.sh"

echo "==> Done: $OUT_DIR"
ls -la "$OUT_DIR"

if [ "$DO_ZIP" -eq 1 ]; then
  ZIP="${OUT_DIR}.zip"
  rm -f "$ZIP"
  echo "==> Zipping -> $ZIP"
  (cd "$(dirname "$OUT_DIR")" && zip -qr "$(basename "$ZIP")" "$(basename "$OUT_DIR")")
  echo "==> Wrote $ZIP"
fi
