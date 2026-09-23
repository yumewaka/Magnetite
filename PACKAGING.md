# Packaging Magnetite for real-world use

Magnetite ships as **one server binary plus a compiled front-end bundle**. The
binary (`magnetite-server`) opens a single embedded database, serves the Leptos
web UI + server functions, and — when enabled in config — runs the embedded
DNS/DHCP/LDAP/Mail/Proxy/Watch/SSO servers in-process. There is no external
database, application server, or Node runtime to deploy.

A runnable deployment is just four things kept together:

```
magnetite-server(.exe)   the single binary (SSR server + embedded services)
site/                    compiled front-end assets (WASM/JS bundle, CSS, favicon)
magnetite.toml           configuration
data/                    the embedded database (created on first run)
```

---

## 1. Prerequisites

| Tool | Install | Why |
|------|---------|-----|
| Rust (stable) | <https://rustup.rs> | compiler |
| `wasm32-unknown-unknown` target | `rustup target add wasm32-unknown-unknown` | hydration bundle |
| `cargo-leptos` | `cargo install cargo-leptos --locked` | builds binary + WASM + CSS together |
| C/C++ toolchain (Linux) | `clang libclang-dev build-essential pkg-config libssl-dev` | RocksDB (SurrealDB) bindgen |

On Windows the MSVC toolchain (Visual Studio Build Tools) covers the native
dependency; `clang` is not required.

---

## 2. Build & package (bare metal)

The build is driven entirely by `cargo leptos`, configured under
`[[workspace.metadata.leptos]]` in the root `Cargo.toml` (binary = the
`magnetite-server` package, hydration lib = `magnetite-app`, styles from
`crates/magnetite-app/style/main.scss`, output to `target/site`).

One-shot packaging scripts wrap the whole flow and assemble a portable folder:

```powershell
# Windows
pwsh ./scripts/package.ps1 -Zip
```
```bash
# Linux / macOS / Git-Bash
./scripts/package.sh --zip
```

This runs `cargo leptos build --release` and produces `dist/magnetite/`:

```
dist/magnetite/
  magnetite-server(.exe)
  site/                  (pkg/magnetite.js, pkg/magnetite_bg.wasm, pkg/magnetite.css, …)
  magnetite.toml
  run.ps1 / run.sh       launchers (set LEPTOS_SITE_ROOT=./site, then run)
  README.txt
```

Copy that folder to the target host and run `run.ps1` / `run.sh`.

### Doing it manually

```bash
cargo leptos build --release
#  -> target/release/magnetite-server        (binary)
#  -> target/site/                            (front-end bundle, incl. pkg/)

# Run it (LEPTOS_SITE_ROOT points the binary at the bundle; defaults to
# target/site for in-tree `cargo leptos serve`):
LEPTOS_SITE_ROOT=target/site ./target/release/magnetite-server magnetite.toml
```

> The binary resolves `data/` **relative to the config file's directory**, so
> keep `magnetite.toml` beside the binary and the database follows it.

---

## 3. Docker / Compose / Kubernetes

For **Docker Compose, Podman Compose, and Kubernetes** deployments, see
[deploy/README.md](deploy/README.md) — they share the container image below plus
`deploy/magnetite.container.toml` (bound to `0.0.0.0`) and a persistent `data/`
volume. Quick reference: `docker compose up -d --build`,
`podman compose up -d --build`, or `kubectl apply -k deploy/k8s`.

### Plain `docker run`

```bash
docker build -t magnetite:latest .

# Web UI only (mount the container config, which binds 0.0.0.0):
docker run --rm -p 4000:4000 \
    -v magnetite-data:/app/data \
    -v "$PWD/deploy/magnetite.container.toml:/app/magnetite.toml:ro" \
    magnetite:latest
```

The image's built-in `magnetite.toml` binds `127.0.0.1`, so the mount above
uses `deploy/magnetite.container.toml` (bound to `0.0.0.0`) to make the published
port reachable. To also run the embedded protocol servers, enable their
`[domains.<d>.server]` blocks and publish the ports, e.g.
`-p 53:53/udp -p 53:53/tcp -p 25:25`.

`/app/data` is a volume, so the embedded database persists across container
restarts.

### Disk footprint & build cache

The **final image is slim** (multi-stage: the runtime stage is
`debian-bookworm-slim` + the binary + `site/`, ~tens of MB). The multi-GB Rust
build cache is *not* in the image. But **where the build cache lives during the
build** matters — Rust's `target/` and the cargo registry can be many GB, and on
Windows/macOS the engine stores them in a VM/WSL2 virtual disk that grows and
does not auto-shrink. Two ways to keep that under control:

1. **`Dockerfile` (build in container, BuildKit cache mounts)** — the default.
   `target/` and the cargo registry are BuildKit **cache mounts**, so they never
   become image layers; only the compiled artifacts are copied into the image.
   Reclaim the cache explicitly:
   ```bash
   docker builder prune            # drop BuildKit build cache (incl. target/)
   docker image prune              # drop dangling builder-stage layers
   ```
   Requires BuildKit (`DOCKER_BUILDKIT=1`, default in modern Docker; Podman
   supports the cache-mount syntax too).

2. **`Dockerfile.prebuilt` (no compilation in the container)** — build the dist
   on the host with `scripts/package.sh` (Linux/WSL, so the binary is a Linux
   ELF), then package it. **Nothing is compiled in the container, so no Rust
   cache ever touches the engine's storage.**
   ```bash
   ./scripts/package.sh
   docker build -f Dockerfile.prebuilt -t magnetite:latest .
   ```

**Shrinking the engine's virtual disk (Windows/macOS).** Pruning frees space
*inside* the VM but the vdisk file itself stays large until compacted:

- *Docker Desktop*: Settings → Resources → "Clean / Purge data", or
  `wsl --shutdown` then compact the `docker-desktop-data` vhdx with
  `Optimize-VHD` (Hyper-V) / `diskpart`.
- *Podman*: `podman system prune -a --volumes`, then
  `podman machine stop && podman machine rm` / recreate, or compact the machine
  image. On Linux there is no VM — pruning reclaims space directly.

---

## 4. Production configuration (`magnetite.toml`)

- **`[server]`** — `host`/`port`/`base_url`. Set `host = "0.0.0.0"` to serve
  beyond localhost. `base_url` must be the externally reachable URL (it is used
  for SSO redirects and the embedded OIDC issuer).
- **`[domains.<d>.server]`** — uncomment to run an embedded protocol server.
  Binding the standard ports (**DNS 53, DHCP 67, SMTP 25, LDAP 389, HTTPS 443**)
  requires elevated privileges:
  - Linux: run as root, or grant the binary
    `sudo setcap 'cap_net_bind_service=+ep' magnetite-server`.
  - Windows: run the service as an account allowed to bind those ports.
  Use high ports (e.g. `127.0.0.1:5353`) for local testing without privileges.
- **TLS** — LDAP StartTLS, SMTP STARTTLS/implicit TLS, and the reverse proxy's
  HTTPS listener present certificates by name from the in-app certificate store
  (Proxy → Certificates / the domain's `tls_cert_name`). For the **web UI**
  itself, terminate HTTPS at a reverse proxy (nginx/Caddy/Traefik) in front of
  `:4000`.
- **`[sso]`** — optional OIDC single sign-on. Remove the whole section to run
  with local accounts only. Secrets here stay server-side (the config file is
  never sent to clients).

---

## 5. Running as a service

**systemd** (`/etc/systemd/system/magnetite.service`):

```ini
[Unit]
Description=Magnetite
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/magnetite
Environment=LEPTOS_SITE_ROOT=/opt/magnetite/site
ExecStart=/opt/magnetite/magnetite-server /opt/magnetite/magnetite.toml
Restart=on-failure
# For privileged embedded-server ports without running as root:
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

**Windows** — register with NSSM or `sc.exe`, setting the working directory to
the deployment folder and `LEPTOS_SITE_ROOT` to its `site\` subfolder.

---

## 6. Operating notes

- **Backup = copy `data/`.** It holds every domain's config plus accounts,
  sessions, audit log, and operational logs. Stop the server (or snapshot) for a
  consistent copy.
- **Upgrades** — replace `magnetite-server` and `site/` together (they are built
  as a matched pair); keep `data/` and `magnetite.toml`.
- **First run** creates `data/` and walks you through first-admin setup.
- **Private keys never leave the server** — DKIM keys, TLS certificate keys, the
  DNSSEC signing key, and SSO secrets are stored in `data/` and are never
  projected to browser clients.
