# Deploying Magnetite

Magnetite is a **single stateful process** on an embedded RocksDB store: run
exactly **one** instance per data volume. It does not scale horizontally. State
lives in a persistent `data/` volume (the embedded database).

There are two workflows:

- **Two-phase (recommended)** — build the Linux artifacts once, then run them
  from Docker Compose, Podman Compose, or Kubernetes. The Rust build cache is
  bind-mounted to the **host** (`./.docker-cache`), so it never bloats the
  engine's virtual disk and you can delete it directly.
- **All-in-one** — `docker compose up -d --build` (root `docker-compose.yml`)
  builds and runs in one step; simplest for a quick try. See
  [../PACKAGING.md](../PACKAGING.md) §3 for its build-cache behaviour.

---

## Phase 1 — build the Linux artifacts

```bash
# Builds inside a container; cache -> ./.docker-cache, output -> ./dist
docker compose -f docker-compose.build.yml run --rm --build builder
# Podman: build the image first, then run
#   podman compose -f docker-compose.build.yml build
#   podman compose -f docker-compose.build.yml run --rm builder
```

Produces `./dist/magnetite/` = `magnetite-server` (Linux ELF) + `site/` +
`magnetite.toml` (the `0.0.0.0` container config). Reclaim the build cache any
time by deleting `./.docker-cache`.

> On Linux the container runs as root, so files under `./.docker-cache` and
> `./dist` are root-owned (use `sudo rm -rf ./.docker-cache` to clean, or add
> `user: "${UID}:${GID}"` to the build service). On Windows/macOS this is a
> non-issue.

---

## Phase 2 — run

### Docker Compose / Podman Compose

```bash
docker compose -f docker-compose.runtime.yml up -d --build
# or
podman compose -f docker-compose.runtime.yml up -d --build
```

`Dockerfile.prebuilt` only **copies** `./dist/magnetite` into a slim image — no
compilation, no Rust cache in the engine. Open <http://localhost:4000>. The
`magnetite-data` volume persists the database.

To run the embedded protocol servers, enable their `[domains.<d>.server]` blocks
in `deploy/magnetite.container.toml`, re-run Phase 1, then uncomment the matching
`ports:` in `docker-compose.runtime.yml`.

### Kubernetes

```bash
# 1. Phase 1 above produced ./dist. Package + push the runtime image:
docker build -f Dockerfile.prebuilt -t <registry>/magnetite:0.1.0 .
docker push <registry>/magnetite:0.1.0

# 2. Point the manifests at that image (deploy/k8s/kustomization.yaml -> images:)
#    then apply:
kubectl apply -k deploy/k8s

# 3. Reach the UI:
kubectl port-forward svc/magnetite 4000:80        # quick check
#   or configure deploy/k8s/ingress.yaml with your host + TLS.
```

Baked into the manifests:

- **1 replica, `Recreate` strategy** — never two pods on one volume.
- **PVC `magnetite-data` (RWO, 5Gi)** at `/app/data` — set `storageClassName` in
  `pvc.yaml` if the cluster has no default.
- **Config via generated ConfigMap** from `magnetite.container.toml` — editing it
  rolls the pod (the generated name carries a content hash).
- **Readiness/liveness** probe `GET /` on port 4000.

Embedded protocol servers (DNS, DHCP, SMTP, …) need their own Services (e.g. a
`LoadBalancer` with UDP/TCP 53) — add them for the ports you enable; they are
intentionally not in the default manifests.

---

## CI/CD (GitLab) and rollback

`.gitlab-ci.yml` runs one pipeline for the whole monorepo but ships **two
deployables**, split by `rules:changes`:

- **Server** (this platform body) → built as `$CI_REGISTRY_IMAGE:<sha>`, deployed
  to the two Podman Quadlet nodes **`10.69.134.30` (mag1)** and **`10.69.134.31`
  (mag2)**. `build:server` + `test:server` run automatically; `deploy:mag1` /
  `deploy:mag2` are **manual** and per-node, so the two hosts roll one at a time.
- **Center** (control plane) → `$CI_REGISTRY_IMAGE/center:<sha>`, auto-deployed to
  Kubernetes (namespace `magnetite`). See [center/README.md](center/README.md).

Every image is pinned to its commit SHA — there is no `:latest`. A deploy job
SSHes to the node (the job container installs `openssh-client` and the CI-only
key from the `MAG_SSH_KEY` File variable, pinning the host key via
`ssh-keyscan`), `podman pull`s the new image, **backs up the current unit**
(`/etc/containers/systemd/magnetite.container` → `.bak-<datetime>`), rewrites only
the `Image=` line, `daemon-reload` + `restart`s, then polls **`/readyz`** for up to
five minutes and fails the job if it never turns green.

> The gate is `/readyz`, not `/healthz`. `/healthz` is liveness only — it returns
> `200` the instant the HTTP stack answers, doing no I/O, so it would pass before
> the database opened or a served domain bound. `/readyz` returns `200` only once
> the DB answers and **no served domain is in `Error`**, so a half-up rollout fails
> the job instead of being reported as a success.

### Rollback — server (mag1 / mag2)

Two independent ways back. **Neither touches data** — the `magnetite-data` volume
and any host config under `/etc/magnetite/` are never modified by a deploy or a
rollback; only the container image changes.

**A. From CI (preferred — same path as forward, image pinned by SHA).**
In GitLab, open the pipeline of the **last-known-good commit** (CI/CD →
Pipelines → pick the older green commit), and press **`deploy:mag1`** and/or
**`deploy:mag2`** there. Because the image tag is the commit SHA, that job pulls
the exact older image and swaps it in. Roll one node, confirm `/healthz`, then the
other. Prefer this when the CI runner still reaches the node.

**B. On the host (fastest, no CI needed — uses the unit backup).**
Each deploy left a timestamped backup beside the unit. SSH to the node and restore
the most recent one:

```bash
ssh root@10.69.134.30        # or .31 for mag2
cd /etc/containers/systemd
ls -t magnetite.container.bak-*      # newest first — the pre-deploy state
cp -a "$(ls -t magnetite.container.bak-* | head -1)" magnetite.container
systemctl daemon-reload
systemctl restart magnetite.service
# confirm it is READY (DB up + no domain in error) before walking away:
for i in $(seq 1 60); do curl -fsS http://127.0.0.1:4000/readyz && break; sleep 5; done
```

The `Image=` line in the restored backup points at the previously-running image, so
no pull is needed if it is still in Podman's local store (it normally is). Use B
when CI is unavailable or the runner cannot reach the node.

> One node at a time. mag1 and mag2 share the domain but run independent stores;
> roll and verify one, then the other, so the service stays up throughout.

---

## Rancher Desktop notes (verified 2026-07-15)

The two-phase flow was validated on Rancher Desktop (dockerd/moby backend). A few
environment quirks and their fixes:

- If both Rancher Desktop **and** a Podman machine are installed, the Windows
  `docker` default context may talk to Podman. Target Rancher's dockerd directly
  from its WSL distro: `wsl -d rancher-desktop -- docker …` (the project is at
  `/mnt/<drive>/…`). `docker compose` may be absent there — use plain
  `docker build` + `docker run` with the same mounts as the compose files.
- The `credsStore` credential helper can time out and block image pulls. Bypass
  it for public images with an empty config:
  `mkdir -p /tmp/emptycfg && echo '{}' >/tmp/emptycfg/config.json` then prefix
  commands with `DOCKER_CONFIG=/tmp/emptycfg`.
- If BuildKit can't fetch the `docker/dockerfile:1` frontend (registry DNS
  timeouts), `Dockerfile.builder` / `Dockerfile.prebuilt` deliberately omit the
  `# syntax=` line (built-in frontend, no external pull); pre-pull base images
  with `docker pull` and add `--network=host` to `docker build` for reliable
  apt/cargo DNS during the build.

## Notes

- **`base_url`** in the config must be the externally reachable URL (SSO
  redirects + embedded OIDC issuer) when behind a proxy/Ingress.
- **Backup** = snapshot the `data/` volume / `magnetite-data`.
- **TLS for the web UI** is terminated at the proxy/Ingress; Magnetite serves
  plain HTTP on 4000. Protocol-level TLS (LDAP StartTLS, SMTP STARTTLS, proxy
  HTTPS) uses certificates from the in-app certificate store.
- **Private keys never leave the server** (DKIM/TLS/DNSSEC/SSO secrets live only
  in `data/`).
