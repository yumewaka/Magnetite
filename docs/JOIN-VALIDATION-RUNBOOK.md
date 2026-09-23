# magnetite — Production Additive-Join **Validation** Runbook

**Goal:** register magnetite in the *production* Samba AD domain as an **additive,
validation-only replica** so its real daemon binary can be exercised against the
live domain — **without** decommissioning Samba, without taking any FSMO/RID role,
and without exposing magnetite to production clients.

> ## ⚠️ Read this first — honest risk statement
>
> This procedure **writes into your production directory** (magnetite's
> `nTDSDSA` / `server` / `computer` / `nTDSConnection` objects, and DNS records)
> and starts magnetite replicating from your live DCs. magnetite's **full daemon
> binary has never run against real Samba**, and a real client join / logon / GPO /
> DNS path has **not** been proven. This is therefore a **high-risk change on a
> tier-0 system**.
>
> A **throwaway restored clone** of the domain is materially safer and is the
> recommended venue (see `MIGRATION.md` Appendix D). You have chosen to validate
> against production; this runbook makes that **as safe as it can be**, but the
> residual risk is real. Do **not** run it without: a verified full backup, a
> rehearsed rollback, an approved change window, and the network isolation in
> Phase 2. If any Go/No-Go gate fails, **abort and roll back** (Section R).

---

## Roles & sign-off

| Role | Responsibility |
|------|----------------|
| Change owner | Owns this change record; holds the abort decision |
| AD admin (Samba) | Runs all `samba-tool` steps; owns backup + rollback |
| Network admin | Implements + verifies the Phase 2 firewall isolation |
| magnetite operator | Runs the magnetite binary + replication config |
| Observer | Watches Samba health throughout; independent abort trigger |

Migration/decommission is **out of scope**. This runbook ends with magnetite as an
isolated shadow replica, or fully rolled back. Nothing here transfers a role,
demotes a DC, or moves authoritative DNS.

---

## Safety model (what makes this "safe-ish")

Four controls, all mandatory:

1. **Network isolation (Phase 2)** — production clients and the Samba DCs are
   firewalled *out* of magnetite's service ports. magnetite pulls *from* Samba but
   nothing pulls *from* magnetite. This is the primary control: it decouples "magnetite
   is a registered DC object" from "anything actually uses magnetite."
2. **No roles** — join with `ROLES=` (empty) and `RID_POOL=0`. magnetite takes no
   FSMO role and requests no RID pool. All roles stay on Samba.
3. **No client discovery** — magnetite's DC-locator DNS records (SRV/A) are removed
   immediately after the join so DC discovery never returns magnetite (belt to the
   firewall's braces).
4. **Inbound-only replication** — magnetite replicates *in* from Samba; no reverse
   replication agreement is created, and the firewall blocks Samba→magnetite DRS.

---

## Phase 0 — Build & isolated smoke test (do NOT skip)

Prove the binary works **before** it touches production.

- [ ] Build the **release** binary on the target host and resolve the SurrealDB
      toolchain (needs clang/cmake for RocksDB):
      `cargo build --release -p magnetite-addc` (and the LDAP/DNS servers you will run).
- [ ] Run it in **full isolation** (no network path to production) in database mode
      (`MAGNETITE_DB_PATH=/var/lib/magnetite/db`), confirm every listener binds and the
      process stays healthy (KDC 88, LDAP 389, SMB 445, RPC/DRS, CLDAP, kpasswd, EPM, SNTP).
- [ ] Replace **all** PoC secrets with production-grade secrets — set
      `MACHINE_PASSWORD` (else the daemon logs a warning and uses the built-in default),
      and the service keys / `Passw0rd!23`-class values. **Gate:** no default/PoC
      credential remains.
- [ ] Confirm the daemon **exits cleanly on SIGTERM** (systemd stop) rather than being
      SIGKILLed — verify the shutdown line appears in the log.

**Go/No-Go 0:** the release binary runs healthy in isolation with real secrets, and stops cleanly. If not, **stop.**

---

## Phase 1 — Pre-flight & backup (on Samba)

- [ ] **Full backup** of the domain and a **rehearsed restore** on a separate host:
      `samba-tool domain backup offline --targetdir=/backup/predate` (or `online`).
      **Do not proceed until a restore has actually been test-booted.**
- [ ] Record current state (for rollback + comparison):
  - `samba-tool fsmo show` → all 5 (+2 DNS) roles and their owners
  - `samba-tool drs showrepl` on every DC → clean, no failures
  - `samba-tool dbcheck --cross-ncs` → **clean** (fix issues before joining)
  - Domain SID, object/principal counts, the DCs' names/GUIDs/IPs
- [ ] **Domain-health prerequisites (fix in the production domain first — independent of
      magnetite):**
  - `drs showrepl` / `dbcheck --cross-ncs` **clean on every DC**. A DomainDnsZones (or any
    NC) that has not converged between DCs is a **hard stop** — do not add a new DC to a
    domain whose existing DCs are not replicating cleanly.
  - The `636` TLS certificates on the source DC(s) are **valid, not expired** (see Phase 3
    TLS pre-check). Regenerate them first if needed.
- [ ] Approved **change window**, off-peak, with comms to stakeholders and a named
      abort authority present.
- [ ] Confirm **no existing `CN=MAGNETITE`** object (computer / server) in the directory.

**Go/No-Go 1:** verified restore + clean `dbcheck`/`showrepl` on all DCs + valid source-DC certs + approved window. Else **stop.**

---

## Phase 2 — Network isolation (on the network / firewall) — **the critical control**

Implement and **verify** before the join. magnetite gets one management path in, and an
egress path to Samba; nothing else reaches it.

| Direction | Ports | Policy |
|-----------|-------|--------|
| Production clients → magnetite | 88, 135, 389, 445, 464, 636, 3268/3269, DRS/EPM, 53 | **BLOCK** |
| Samba DCs → magnetite | DRS/RPC (135 + dynamic), 389, 445 | **BLOCK** |
| magnetite → Samba DCs | 389/636, 88, 464, **135 + the RPC dynamic range 49152–49154** (DRSUAPI/SAMR/Netlogon) | **ALLOW** (needed to join + pull) |
| Validation admin host → magnetite | as needed | **ALLOW** |

- [ ] Apply the rules. **Verify from a real client subnet** that magnetite's 88/389/445
      are unreachable, and **from a Samba DC** that magnetite's DRS/LDAP are unreachable.
- [ ] Confirm magnetite **can** reach Samba's LDAP(S)/KDC/DRS.

**Go/No-Go 2:** clients + Samba proven **unable** to reach magnetite's service ports; magnetite proven able to reach Samba. Else **stop.**

---

## Phase 3 — Join as a role-less replica (from the magnetite host)

Use `promote_dc` (or the equivalent daemon path) with **no roles**, **no RID request**,
and **`SKIP_DNS=1`** (never write locator DNS — you manage this DC's DNS out of band).
Prefer **StartTLS/LDAPS** — production Samba requires strong auth (`ldap server require
strong auth`), so a plaintext simple bind will (correctly) be refused.

> **TLS pre-check (learned the hard way):** verify the Samba DCs' `636` certificates are
> **valid, not expired** *before* relying on `TLS_CA`. If you pass `TLS_CA`, rustls rejects
> an expired cert and the join fails; if you omit it, the transport encrypts but does **not**
> authenticate the server (the admin password is exposed to a MITM). `TLS_CA` now **fails
> the run** on an unreadable path rather than silently downgrading. If the domain certs are
> expired, regenerate them first.

```
TARGET=<samba-ldap-host:port> \
BIND_DN='Administrator@REALM' BIND_PW='<privileged-pw>' \
REALM=<REALM> KDC=<samba-kdc:88> DRS=<samba-drs-host:dynamic-port> SPN='ldap/<samba-fqdn>' \
DC_NAME=MAGNETITE IP=<magnetite-ip> \
ROLES= RID_POOL=0 SKIP_DNS=1 \
STARTTLS=1 TLS_CA=/path/to/domain-ca.pem \
  cargo run --release -p magnetite-addc --example promote_dc
```

- [ ] The echoed `[promote] SAFETY roles=[] request_rid_pool=false skip_dns=true transport=…`
      line shows **no roles, no RID pool, DNS skipped, and the intended TLS mode** — confirm
      before it writes anything.
- [ ] `DRS=` is the source DC's **current** DRSUAPI endpoint. It is a *dynamic* RPC port
      (magnetite has no Endpoint-Mapper client), so resolve it with `ept_map` / pin Samba's
      RPC ports in `smb.conf`. If Samba restarts and the port moves, replication stalls.
- [ ] For a clean rollback+rejoin, pass a **fresh** `INVOCATION_ID=<32 hex>` (and/or a new
      `DC_NAME`) so a tombstoned DC's identity is never reused.
- [ ] Record the created object DNs (computer / server / nTDSDSA / nTDSConnection) — you
      need them for rollback.
- [ ] On Samba: `samba-tool drs showrepl` and `dbcheck --cross-ncs` again → still clean.
      **Any new dbcheck error → abort + roll back (Section R).**

> The `nTDSConnection` created here is magnetite's **inbound** agreement (magnetite pulls
> from Samba). Do **not** create any connection under a Samba DC that names magnetite as
> `fromServer` — that would make Samba pull *from* magnetite.

**Go/No-Go 3:** join objects present, `dbcheck` still clean, roles unchanged (`fsmo show` = Samba). Else **roll back.**

---

## Phase 4 — Confirm no client discovery

With `SKIP_DNS=1` the join writes **no** DC-locator records, so there is no discovery
window to close — just confirm. (If a join was ever run *without* `SKIP_DNS`, delete the
records as below.)

- [ ] Confirm from a client resolver that DC discovery returns **only** Samba DCs
      (`nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>` names no magnetite record).
- [ ] Fallback (only if DNS was written): delete magnetite's `A`/`CNAME` and the
      `_ldap._tcp` / `_kerberos._tcp` / `_gc._tcp` **SRV** records (all sites + `_msdcs`):
      `samba-tool dns delete <dns-host> <zone> <name> <type> <data> -U Administrator`
- [ ] Verify from a client resolver that DC discovery for the domain returns **only**
      Samba DCs (`nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>`).

**Go/No-Go 4:** no locator record resolves to magnetite. (Firewall remains the primary guard.)

---

## Phase 5 — Inbound-only replication (on the magnetite host)

Run the daemon in database mode, pulling from Samba on an interval. **No** FSMO owner
override, **no** RID node index that would let it mint SIDs into the domain.

```
REALM=<REALM> DC_NAME=MAGNETITE DC_IPV4=<magnetite-ip> \
MAGNETITE_DB_PATH=/var/lib/magnetite/db \
REPL_DRS=<samba-drs-addr> REPL_KDC=<samba-kdc:88> REPL_REALM=<REALM> \
REPL_USER=<repl-account> REPL_PASS='<pw>' REPL_SPN='ldap/<samba-fqdn>' \
REPL_NC='<domain-DN>' REPL_INTERVAL_SECS=300 \
  ./magnetite-addc
```

- [ ] Watch magnetite logs: replication cycles complete, object/secret counts climb toward
      Samba's, then settle (deltas → 0). Compare counts to Phase 1.
- [ ] On **Samba**: `samba-tool drs showrepl` shows **no inbound agreement from magnetite**
      and no new failures. magnetite must appear only as a peer magnetite pulls *from*.
- [ ] Multiple pull cycles: no USN rollback, no replication storm, Samba CPU/repl latency normal.

**Go/No-Go 5:** magnetite converges read-only; Samba health unchanged; no reverse replication. Else **roll back.**

---

## Phase 6 — Validation (from the isolated admin host only)

Exercise magnetite's serving **without any production client**. Use a **throwaway** test
machine/account on the isolated segment, pointed explicitly at magnetite.

- [ ] LDAP: bind + search magnetite (StartTLS/SASL); compare a sample of users/groups/OUs
      and `fSMORoleOwner` against Samba.
- [ ] Kerberos: `kinit` a test principal against magnetite's KDC; `kvno` a service ticket.
- [ ] SMB/SYSVOL: read a GPO's `GPT.INI` / `Registry.pol` over SMB from magnetite.
- [ ] DNS: query magnetite's resolver for domain records.
- [ ] (Optional, throwaway only) join a **disposable** test client to magnetite explicitly
      and attempt logon + GPO apply. **Never** point a production client at magnetite.

Record every result against the Go/No-Go sheet. Discrepancies are **findings**, not
pass-with-caveats.

**Go/No-Go 6:** every validation item passes against magnetite in isolation. Findings feed the eventual clone/migration decision — **not** a production cut-over.

---

## Phase 7 — Soak & monitor

- [ ] Leave the shadow replica running for the agreed soak (days, not hours), pulling deltas.
- [ ] Continuously on Samba: `drs showrepl` (clean), `dbcheck --cross-ncs` (clean),
      event/replication logs, RID pool + FSMO unchanged.
- [ ] Re-verify the Phase 2 firewall periodically (a config drift that exposes magnetite is
      the top failure mode).

Any Samba-side regression at any point → **roll back** and treat as a finding.

---

## Section R — Rollback / abort (rehearse before Phase 3)

Run this on **any** failed gate, any Samba-side error, or on the abort authority's call.
magnetite is only ever *additive* here, so rollback = remove magnetite and clean up.

1. **Stop** the magnetite daemon (replication halts immediately).
2. **Remove the DC metadata** from Samba (the supported path):
   `samba-tool domain demote --remove-other-dead-server=MAGNETITE -U Administrator`
   (or `ntdsutil` metadata cleanup). This removes the `nTDSDSA` / `server` /
   `nTDSConnection` / `computer` references.
3. **Delete leftover objects** by the DNs recorded in Phase 3 if any remain
   (computer/server/nTDSDSA/connection under the Config/Domain NC).
4. **Delete magnetite's DNS records** (A/CNAME/SRV, all sites + `_msdcs`) if any remain.
5. `samba-tool dbcheck --cross-ncs --fix --yes` and `drs showrepl` on every DC →
   confirm **clean** with magnetite fully gone.
6. If cleanup is not provably clean, **restore from the Phase 1 backup** onto the affected
   DC. This is why the verified restore is a hard prerequisite.

> Note: deleting join objects can leave **tombstones**; re-joining later must use fresh
> object GUIDs (a known magnetite behaviour). Prefer the `demote --remove-other-dead-server`
> path over raw `ldbdel`.

---

## Residual risks (acknowledge on the change record)

Even with every control above:

- The join **wrote to production**; a malformed object or a mid-join failure can affect
  Samba replication/`dbcheck` (mitigated by backup + rollback, not eliminated).
- A **firewall misconfiguration or drift** would expose an unproven DC to clients.
- magnetite's **outbound/serving code is unproven against real Samba**; keeping it firewalled
  and role-less contains but does not remove that risk.
- This validates the binary against production data; it does **not** make magnetite
  ready to replace Samba. A **clone-based full rehearsal** (join → soak → FSMO → demote,
  with real clients) is still required before any decommissioning decision.

---

## Sign-off

| Gate | Result (pass/fail) | Verified by | Time |
|------|--------------------|-------------|------|
| Go/No-Go 0 — isolated binary | | | |
| Go/No-Go 1 — backup + clean dbcheck | | | |
| Go/No-Go 2 — network isolation | | | |
| Go/No-Go 3 — role-less join, dbcheck clean | | | |
| Go/No-Go 4 — no client discovery | | | |
| Go/No-Go 5 — inbound-only convergence | | | |
| Go/No-Go 6 — validation in isolation | | | |

Proceeding past a failed gate is not authorized. Decommissioning Samba is **not**
authorized by this runbook under any outcome.
