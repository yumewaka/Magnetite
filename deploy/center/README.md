# Deploying Magnetite Center

Standalone deployment configs for the control plane (`magnetite-center`) — a
lightweight headless binary that serves its own dashboard + JSON API on `:5555`.
Its only required setting is `CENTER_ADMIN_TOKEN`. See the crate
[README](../../crates/magnetite-center/README.md) for the full env-var reference.

The image is built from [`crates/magnetite-center/Dockerfile`](../../crates/magnetite-center/Dockerfile);
the **build context is the repo root** (the whole workspace compiles), so always
pass `-f crates/magnetite-center/Dockerfile .` from the root.

## Docker / Podman

```sh
# build (from the repo root)
DOCKER_BUILDKIT=1 docker build -f crates/magnetite-center/Dockerfile -t magnetite-center:latest .
#   Podman:  podman build -f crates/magnetite-center/Dockerfile -t magnetite-center:latest .

# run — single container, embedded DB in a named volume
docker run --rm -p 5555:5555 \
  -e CENTER_ADMIN_TOKEN=$(openssl rand -hex 32) \
  -v magnetite-center-data:/app/data \
  magnetite-center:latest
```

Or with Compose (works with `docker compose` and `podman-compose`):

```sh
cd deploy/center
CENTER_ADMIN_TOKEN=$(openssl rand -hex 32) docker compose up -d
```

The dashboard is then at <http://localhost:5555/> — paste the token to connect.

## Kubernetes

```sh
# 1. build + push to a registry your cluster can pull from
docker build -f crates/magnetite-center/Dockerfile -t <registry>/magnetite-center:0.1.0 .
docker push <registry>/magnetite-center:0.1.0
#    then set the image in deploy/center/k8s/kustomization.yaml (images:)

# 2. create the namespace + admin-token Secret (once). The Secret is deliberately
#    NOT a kustomize resource (a re-apply would overwrite the live token); see
#    k8s/secret.example.yaml.
kubectl create namespace magnetite-center
kubectl -n magnetite-center create secret generic magnetite-center-admin \
  --from-literal=token=$(openssl rand -hex 32)

# 3. apply (idempotently (re)creates the namespace and the rest)
kubectl apply -k deploy/center/k8s
```

Single replica with a `Recreate` strategy + a `ReadWriteOnce` PVC, because the
embedded RocksDB store is single-writer. The pod runs **non-root** (uid 10001;
`fsGroup` makes the PVC writable — on an existing volume this triggers a one-time
recursive `chown`, so back it up first). Two probes: **liveness** `/healthz`
(depends on nothing — restarting never fixes a bad datastore) and **readiness**
`/readyz` (probes the datastore; `503` drains the pod without restarting it). Roll
out an image that serves `/readyz` before pointing readiness at it.

## High availability

The single-node configs above are a SPOF. For HA, run **several** center
instances against **one shared SurrealDB** (`CENTER_DB_URL`): they elect a single
leader through a lease in that store, and only the leader runs the failover loop
(a standby takes over within one `CENTER_LEASE_SECS`). Give each instance a
stable `CENTER_ID`. A commented multi-instance sketch is in
[`docker-compose.yml`](docker-compose.yml), and an HA note is at the bottom of
[`k8s/deployment.yaml`](k8s/deployment.yaml). The SurrealDB server version must
match the `surrealdb` crate the binary was built against.
