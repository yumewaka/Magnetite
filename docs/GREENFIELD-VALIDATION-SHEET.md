# magnetite Greenfield (Sole-IdP, 2-Node) Validation Sheet

**Goal:** stand up magnetite as a brand-new, **standalone** AD domain on **two** nodes,
prove it holds up as the *sole* identity provider for a small fleet, then cut the few
endpoints over — while keeping the old Samba domain as a **powered-off fallback** until
the soak passes. No Samba interaction, no DRS-from-Samba, no FSMO transfer. GPO is not
used, so GPO checks are omitted.

> **How to use:** work top-down. Each check has a **pass condition** and a **command**.
> Record PASS/FAIL + who/when in the result column. A FAIL on a **prerequisite** or a
> **P1** item blocks go-live. Keep Samba recoverable until §6 passes.

---

## Prerequisites — fix before go-live (blockers)

These are not "tests"; they are conditions that must be true before magnetite is your
*only* IdP.

| # | Blocker | Why it matters | Status |
|---|---------|----------------|--------|
| **PRE-1** | **Set strong krbtgt + service secrets.** The keys are env-configurable: `KRBTGT_SECRET`, `CIFS_SECRET`, `HOST_SECRET`, `KADMIN_SECRET`, `DNS_SECRET` (plus `MACHINE_PASSWORD`). Unset ⇒ built-in PoC defaults + a startup warning. **Set `PRODUCTION=1`** and the daemon now **hard-fails at startup** if any of the six is unset or still at its PoC default (no more relying on spotting a warning). | The krbtgt key is the **root of your domain's Kerberos trust**. Left at the public default, anyone who reads the source can **forge golden tickets = full domain compromise**. | **MUST DO** — set all six to strong random values, the **identical** value on every DC, and run with `PRODUCTION=1`. Startup succeeds only when all six are overridden. |
| **PRE-2** | **No backup/restore** exists (see §1). | Two nodes protect against a node dying, **not** against corruption / bad writes / operator error / bugs — which replicate to both. | **MUST BUILD** (§1). |
| **PRE-3** | **Both nodes must run identical secrets + config.** | A magnetite domain is "one domain" only because both nodes derive the **same** krbtgt/service keys. Different secrets on the two nodes = a **split domain** (a TGT from node 1 is rejected by node 2). | Deploy the same secret set / build to both nodes; verify in §3-C. |

---

## Section A — Two-node setup & config correctness

Two nodes, one realm. Assign FSMO to node 1; give each node a **distinct** RID range; have
each node pull from the other.

**Node 1 (primary) env**
```
REALM=<REALM>  DC_NAME=MAG1  DC_IPV4=<mag1-ip>
MAGNETITE_DB_PATH=/var/lib/magnetite/db
NODE_INDEX=0                         # disjoint RID base
NODE_DSA_ID=mag1
FSMO_OWNERS=schema=mag1,naming=mag1,rid=mag1,pdc=mag1,infra=mag1
REPL_PEERS=<mag2-drs-host:port>=ldap/<mag2-fqdn>
REPL_KDC=<mag2-kdc:88> REPL_REALM=<REALM> REPL_USER=Administrator REPL_PASS=<pw>
REPL_NC=<domain-DN> REPL_INTERVAL_SECS=120
MACHINE_PASSWORD=<strong>  AD_FUNCTIONAL_LEVEL=7
# PRE-1 — strong secrets, IDENTICAL on both nodes:
KRBTGT_SECRET=<strong>  CIFS_SECRET=<strong>  HOST_SECRET=<strong>
KADMIN_SECRET=<strong>  DNS_SECRET=<strong>
PRODUCTION=1                         # hard-fail startup if any secret is a default
# The PoC demo users (alice/bob, known passwords) are NOT auto-seeded unless
# SEED_POC_USERS=1 — leave it UNSET in production so no known-credential account exists.
```
**Node 2 (secondary) env** — same, except:
```
DC_NAME=MAG2  DC_IPV4=<mag2-ip>  NODE_INDEX=1  NODE_DSA_ID=mag2
REPL_PEERS=<mag1-drs-host:port>=ldap/<mag1-fqdn>
REPL_KDC=<mag1-kdc:88>
```

| ID | Verify | Pass condition | Command |
|----|--------|----------------|---------|
| A-1 | RID ranges are disjoint | `NODE_INDEX` differs (0 / 1); a new object on each node gets a **non-overlapping** RID | Create a user on each node, compare `objectSid` RID (LDAP search / web UI) |
| A-2 | FSMO owned by exactly one node | All 7 role objects' `fSMORoleOwner` name MAG1's nTDSDSA | `ldapsearch -x -H ldap://<mag1> -b '<domain-DN>' '(fSMORoleOwner=*)' fSMORoleOwner` |
| A-3 | Both nodes serve LDAP/KDC/SMB | Every listener is up on both | `nc -vz <node> 88 389 445 464` (+ CLDAP/UDP) |
| A-4 | DNS has **both** DCs' locator records | `_ldap._tcp.dc._msdcs.<domain>` SRV lists MAG1 **and** MAG2; A records resolve | `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>` |

---

## §1 — Backup & restore  ·  **Priority 1**

The only protection against the failure class two nodes do **not** cover. Do not go live
without a rehearsed restore.

| ID | Verify | Pass condition | Command / method |
|----|--------|----------------|------------------|
| 1-A | A backup can be taken | A complete export of the directory exists off-box | Embedded RocksDB is single-writer, so back up **one node at a time** (the other keeps serving): stop node → `surreal export --conn rocksdb:///var/lib/magnetite/db --ns magnetite --db main /backup/mag-$(date +%F).surql` → start node. (Or stop + copy the DB dir.) Copy the export **off both nodes.** |
| 1-B | The backup restores | Import into a **fresh** instance yields the same object counts | `surreal import --conn rocksdb:///tmp/restore --ns magnetite --db main /backup/mag-YYYY-MM-DD.surql`; compare user/group/computer counts to the live directory |
| 1-C | The restore is *usable* | A test domain user can authenticate against the **restored** copy | Point a throwaway KDC at the restored store; `kinit <user>` succeeds |
| 1-D | Backups are scheduled + retained | A cron/timer runs 1-A daily, keeps N days, off-box | Inspect the scheduler; confirm yesterday's export exists off both nodes |

**Pass §1:** a scheduled backup exists **and** a restore has been proven to boot + authenticate. Else **do not go live.**

---

## §2 — Machine-account password rotation (~30-day landmine)

Windows rotates each computer's account password (~every 30 days). If magnetite mishandles
it, **every endpoint silently loses the domain trust ~30 days after join.** Force it now —
don't wait 30 days.

| ID | Verify | Pass condition | Command (on the Windows client, as admin) |
|----|--------|----------------|-------------------------------------------|
| 2-A | Secure channel healthy at join | Trust is intact | `Test-ComputerSecureChannel -Verbose` → **True** |
| 2-B | Forced rotation succeeds | The machine changes its own password and stays trusted | `Reset-ComputerMachinePassword -Server <mag1-fqdn>` (or `nltest /sc_change_pwd:<domain>`) → reboot → `Test-ComputerSecureChannel` → **True**; interactive logon still works |
| 2-C | Rotation replicated to node 2 | The new machine password is accepted by **MAG2** too | Point the client at MAG2 (stop MAG1 or DNS) → logon succeeds after 2-B |

**Pass §2:** a forced rotation leaves the machine trusted and able to log on via **either** node.

---

## §3 — Two-node replication, cross-DC Kerberos & failover

The core of the 2-node promise. magnetite↔magnetite convergence is **test-proven but not
production-soaked** — validate it live.

| ID | Verify | Pass condition | Command |
|----|--------|----------------|---------|
| 3-A | Change on node 1 → node 2 | A user created on MAG1 appears on MAG2 within `REPL_INTERVAL_SECS` | Create a user on MAG1; `ldapsearch -H ldap://<mag2> …(sAMAccountName=<u>)` |
| 3-B | Change on node 2 → node 1 | Same, reverse direction | Create on MAG2; search MAG1 |
| 3-C | **Cross-DC Kerberos** | A TGT from MAG1 is accepted by a service verified on MAG2 (proves shared krbtgt/keys — PRE-3) | `kinit` against MAG1, then access an SMB share on MAG2; `klist` shows the ticket; access succeeds |
| 3-D | Client failover | With MAG1 **down**, a domain user still logs on (via MAG2) | Stop MAG1 → lock/logon on the client → succeeds; `nltest /dsgetdc:<domain>` finds MAG2 |
| 3-E | Password-change convergence | A password changed on one node works on the other after the interval | Change a user's password (see §4), then authenticate against the other node |

**Pass §3:** bidirectional convergence, cross-DC Kerberos, and single-node-down logon all work.

---

## §4 — Day-2 operations

The operations that follow "day 0" and eventually bite every deployment.

| ID | Verify | Pass condition | Command |
|----|--------|----------------|---------|
| 4-A | User self-service password change | User changes their own password and re-authenticates | Windows: Ctrl+Alt+Del → Change password. Linux: `kpasswd <user>` |
| 4-B | Forced change at next logon | "User must change password at next logon" is honored | Set the flag; next logon prompts + completes |
| 4-C | Kerberos ticket renewal | Next-day unlock / re-access works after TGT lifetime | `klist` before/after; unlock the session the next day and access a resource |
| 4-D | Time sync from the DC | Client↔DC skew < 5 min (Kerberos breaks past that) | `w32tm /query /status`; `w32tm /stripchart /computer:<mag1> /samples:3` |
| 4-E | Group SIDs in the token | Group-based share ACLs allow/deny correctly | `whoami /groups` on the client shows the right group SIDs; test an allowed and a denied share |
| 4-F | Account lockout (if used) | N bad passwords locks; unlock works | Attempt bad logons to the threshold; verify lock + admin unlock |

**Pass §4:** password lifecycle, ticket renewal, time, and group-based access all work.

---

## §5 — DNS

You are managing DNS manually (kether-as-source-of-truth mindset), so the bar is: name
resolution works and clients don't depend on dynamic registration.

| ID | Verify | Pass condition | Command |
|----|--------|----------------|---------|
| 5-A | DC + host resolution | Clients resolve both DCs' A/SRV; hosts resolve each other | `nslookup <mag1-fqdn>`; `nslookup -type=SRV _kerberos._tcp.<domain>` |
| 5-B | Dynamic registration acceptable | Either magnetite accepts the client's secure dynamic update, **or** the client's record is managed manually and resolution still works | Check whether the client's A record exists after join; if not, add it manually and confirm resolution |

---

## §6 — Soak, fallback & the decommission gate

| ID | Verify | Pass condition |
|----|--------|----------------|
| 6-A | Soak crosses the 30-day boundary | The fleet runs on magnetite for a soak that includes a **real (or forced) machine-password rotation cycle** with no trust breaks |
| 6-B | Durability across restarts/crashes | Reboot each node (and pull power on one) — directory survives, logon continues on the peer, restarted node re-converges |
| 6-C | **Samba kept as fallback** | Old Samba DC(s) are **powered off but data-intact and restorable** for the whole soak — a documented "roll back to Samba" path exists |
| 6-D | Decommission gate | **Only after** §1–§5 pass **and** the soak (6-A/6-B) is clean: retire Samba. Not before. |

---

## Sign-off

| Gate | Result | Verified by | Date |
|------|--------|-------------|------|
| PRE-1 secrets configurable + strong | | | |
| PRE-2 / §1 backup + restore rehearsed | | | |
| Section A — 2-node config correct | | | |
| §2 — machine-password rotation | | | |
| §3 — replication + cross-DC Kerberos + failover | | | |
| §4 — day-2 operations | | | |
| §5 — DNS | | | |
| §6 — soak + fallback (decommission gate) | | | |

Decommissioning Samba is authorized **only** when every row above is PASS. Until then, Samba
stays powered off but recoverable.

---

### Honest notes

- The hardest unknown — **does a real Windows client join + interactively log on** — is
  already **proven** (prior throwaway-client test). This sheet validates the parts a
  30-minute test cannot: **time-based failures, day-2 operations, 2-node behaviour, and
  recovery.**
- magnetite is far less battle-tested than Samba. The two things that most often turn a
  "works in the demo" DC into an outage are **(§2) the 30-day machine-password rotation**
  and **(§1) the absence of a tested backup**. Treat both as non-negotiable.
- **PRE-1** — the krbtgt/service secrets are now env-configurable (a9cb2a3); the remaining work is
  operational: **set them to strong random values, identical on every DC**, and verify no PoC-default
  warning appears at startup. Left at the defaults, the domain's Kerberos root key is public.
