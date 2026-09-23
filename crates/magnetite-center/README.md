# magnetite-center

A vCenter-like control plane for a fleet of Magnetite servers. It runs as its own
headless binary, keeps a small datastore of clusters and registered servers, polls each
server's `/mgmt/*` agent API for health, and exposes a JSON HTTP API for inventory and
status plus a self-contained Web dashboard at `/`.

## Dashboard

Open `http://<CENTER_LISTEN>/` in a browser. It's a single embedded page (no build step,
no framework) that talks to the JSON API below. Paste the `CENTER_ADMIN_TOKEN` once — it's
kept only in that browser's session storage — then manage clusters, register servers, and
watch the live fleet: per-server reachability, per-domain health chips (role-aware), and
last-seen. It auto-refreshes every 10s.

## Running

Configuration is environment-only:

| Variable             | Default            | Meaning                                  |
| -------------------- | ------------------ | ---------------------------------------- |
| `CENTER_ADMIN_TOKEN` | — (**required**)   | Bearer token guarding every API route    |
| `CENTER_DB_PATH`     | `./center-data`    | Datastore directory (embedded RocksDB)   |
| `CENTER_DB_URL`      | — (optional)       | Shared SurrealDB URL for HA (e.g. `ws://dbhost:8000`); overrides `CENTER_DB_PATH` |
| `CENTER_LISTEN`      | `127.0.0.1:5555`   | API bind address                         |
| `CENTER_POLL_SECS`   | `30`               | Seconds between health polls             |
| `CENTER_ID`          | random uuid        | Stable instance id (for HA leadership)   |
| `CENTER_LEASE_SECS`  | `15`               | Leader-lease TTL (for HA)                |

```sh
CENTER_ADMIN_TOKEN=$(openssl rand -hex 32) cargo run -p magnetite-center
```

### High availability (P5)

Run several center instances against **one shared** `CENTER_DB_URL` (a networked
SurrealDB). They elect a single leader via a lease in that store; **only the leader** runs
the failover loop (so the orchestrator stays single — no double-promote), and a standby
takes over within one `CENTER_LEASE_SECS` if the leader stops renewing. Give each instance
a distinct `CENTER_ID`. Manual control (promote/demote, policy edits) works from any
instance since they share the store. `/status` reports a `center` block
(`{id, is_leader, leader}`) and the dashboard shows a リーダー / スタンバイ badge. A single
embedded-DB instance is always its own leader, so single-node setups need no change.

```sh
# two centers behind one shared SurrealDB
CENTER_ADMIN_TOKEN=$TOK CENTER_DB_URL=ws://db:8000 CENTER_ID=c1 CENTER_LISTEN=0.0.0.0:5555 magnetite-center
CENTER_ADMIN_TOKEN=$TOK CENTER_DB_URL=ws://db:8000 CENTER_ID=c2 CENTER_LISTEN=0.0.0.0:5555 magnetite-center
```

Each managed Magnetite server must have its `[mgmt]` agent API enabled (see the server's
`magnetite.toml`): `enabled = true` and a shared `token`. That `token` is the value you
pass when registering the server below.

## API

Every route except `/healthz` requires `Authorization: Bearer <CENTER_ADMIN_TOKEN>`.

| Method   | Path            | Body / notes                                          |
| -------- | --------------- | ----------------------------------------------------- |
| `GET`    | `/healthz`      | Unauthenticated liveness probe                        |
| `GET`    | `/clusters`     | List clusters                                         |
| `POST`   | `/clusters`     | `{ "name": "..." }` → create a cluster                |
| `GET`    | `/servers`      | List registered servers with last polled health       |
| `POST`   | `/servers`      | `{ "name", "base_url", "token", "cluster"? }`         |
| `DELETE` | `/servers/{id}` | Deregister a server by its id                         |
| `POST`   | `/servers/{id}/promote` | Promote (pause replication pull → act as primary); optional `{"domain":"proxy"}`, else all managed domains |
| `POST`   | `/servers/{id}/demote`  | Demote (resume pull → track primary again); same body |
| `POST`   | `/servers/{id}/intent`  | Set failover role `{"intent":"primary"\|"standby"\|"unset"}` |
| `POST`   | `/servers/{id}/dns-target` | Set the client-routable IP `{"ip":"10.0.0.5"}` this server's DNS record points at when active |
| `POST`   | `/clusters/{id}/failover-policy` | Arm auto-failover `{"auto_failover":true,"failure_threshold":3}` |
| `POST`   | `/clusters/{id}/dns-policy` | Set the steered record `{"zone":"example.com","name":"app.example.com","ttl":30}` |
| `GET`    | `/events`       | Recent failover + DNS audit events (newest first)     |
| `GET`    | `/status`       | Clusters + servers + recent events in one snapshot    |

### Automatic failover (P3)

Per cluster, set one server's `intent` to `primary` and one or more to `standby`, then
arm `auto_failover` with a `failure_threshold` N. The center (single arbiter) watches the
active primary; after N consecutive missed health polls it promotes a healthy standby,
**fences** the old primary (so that when it returns it is demoted to a secondary rather
than becoming a second primary), and records the new active primary. A reachable server
acting as primary that is not the recorded active primary is demoted (split-brain guard).
Failback is **not** automatic — after a failover the standby stays primary until an
operator moves it back. Every automatic action is written to the event log. Fencing here
is demote-on-return + refuse-double-primary, not power-level STONITH (the center has no
power control); pair it with the DNS repointing / network isolation your environment
provides for hard fencing.

### DNS repointing on failover (P4)

Failover also moves **client traffic**. Give a cluster a DNS-failover policy — the service
record to steer (`dns-policy`: zone apex + record FQDN + TTL) — and give each server a
`dns-target` (the client-routable IP it should be reached at when it is the active
primary). When a server becomes the active primary (auto-failover or a whole-node manual
promote), the center posts `/mgmt/dns` to every node in the cluster, upserting the A/AAAA
record to the new active server's IP. The record is served live (no restart) and its zone
serial is bumped so DNS secondaries transfer it; clients follow after the TTL expires — so
keep the TTL low (e.g. 30–60s). Steering is a no-op when the policy or target is unset, or
when the record already holds the target IP. This uses whatever DNS zone the operator has
already provisioned on the Magnetite nodes; a node that does not serve the zone simply
reports `changed:false`.

Promote/demote are forwarded to the target server's `/mgmt/promote` · `/mgmt/demote`
(server-to-server, using the stored per-server mgmt token) and the server's status +
JSON response are relayed back. Only a domain configured as a *secondary* on that node
is runtime-flippable; promoting a standalone/primary domain is rejected there (409). This
is a **manual failover** for the config-replication domains (mail/dhcp/proxy/sso) — AD
FSMO and DNS zone master/slave roles keep their own separate mechanisms.

`base_url` is the managed server's root (e.g. `https://dc1.example.com:4000`); the center
appends `/mgmt/health` and `/mgmt/identity` when polling. The per-server `token` is stored
for polling but never returned by any read route.

### Example

```sh
TOK=$CENTER_ADMIN_TOKEN
# create a cluster
CID=$(curl -s -XPOST localhost:5555/clusters -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{"name":"prod"}' | jq -r .id)
# register a server into it
curl -s -XPOST localhost:5555/servers -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"dc1\",\"base_url\":\"https://dc1.example.com:4000\",\"token\":\"<mgmt-token>\",\"cluster\":\"$CID\"}"
# read fleet status
curl -s localhost:5555/status -H "authorization: Bearer $TOK" | jq
```
