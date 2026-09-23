# magnetite AD DC Migration Runbook

Replacing the production Samba domain controllers **kether** (`10.69.134.30`) and
**binar** (`10.69.134.31`) with **magnetite** (`10.69.134.20`), an in-process
self-built AD DC (`magnetite-addc`).

> **Golden rule:** kether and binar stay **running and authoritative** until every
> phase below is verified. magnetite is added as an additional replica DC first;
> the old DCs are demoted **only** after magnetite has proven it holds every role
> and both replication directions converge. Every phase has a **Verify** gate and a
> **Rollback**. Do not advance past a failed gate.

---

## 0. Topology & roles

| Host | IP | Role now | Role after |
|------|-----|----------|-----------|
| kether | `10.69.134.30` | Samba AD DC (likely FSMO holder) | demoted / decommissioned |
| binar | `10.69.134.31` | Samba AD DC (replica) | demoted / decommissioned |
| magnetite | `10.69.134.20` | — | primary AD DC (`magnetite-addc`) |

Discover the live domain facts before touching anything (fill these in — the rest of
the runbook references them):

```bash
# Against kether. Record the values.
samba-tool domain info 10.69.134.30
ldbsearch -H ldap://kether -b '' -s base defaultNamingContext configurationNamingContext \
  schemaNamingContext rootDomainNamingContext dnsHostName
# Domain SID (needed for magnetite's DOMAIN_SID):
ldbsearch -H ldap://kether -b '<defaultNamingContext>' -s base objectSid
# Current FSMO holders:
samba-tool fsmo show
```

Fill in and keep next to this runbook:

| Fact | Value |
|------|-------|
| Realm (Kerberos) | `EXAMPLE.COM` → **`<REALM>`** |
| Domain NC (base DN) | `DC=example,DC=com` → **`<DOMAIN_NC>`** |
| Config NC | `CN=Configuration,<DOMAIN_NC>` |
| Schema NC | `CN=Schema,CN=Configuration,<DOMAIN_NC>` |
| Domain SID | `S-1-5-21-a-b-c` → sub-auths **`<DOMAIN_SID>`** (space-separated: `21 a b c`) |
| FSMO holder(s) | e.g. all five on kether |
| kether NTDS DSA GUID | from `samba-tool` / DRS |

---

## 1. Capability status (what is proven vs. what needs production validation)

This drives the risk decisions below. **PROVEN** = validated live against a real
Samba 4.17 AD DC in the lab harness (`magtest.local`). **LAB-ONLY / UNVALIDATED** =
built and unit-tested but not yet exercised against *your* production domain.

| Capability | Status | Notes |
|------------|--------|-------|
| DC join (computer + server + nTDSDSA + serverReference + nTDSConnection + DNS) | **PROVEN** | `promote_dc`, DRS `DsAddEntry`; created magnetite's nTDSDSA in Samba's Config NC |
| Inbound DRS pull (Domain + Config + Schema NCs, Kerberos-sealed) | **PROVEN** | 100s of objects; multi-fragment reassembly; per-attr metadata + conflict resolution |
| Inbound secret recovery (NT hash + AES256/AES128 Kerberos keys) | **PROVEN** | byte-match Samba's own store/keytab |
| Inbound groups + memberships | **PROVEN** | 38 groups w/ members; served over SAMR/LSA |
| Outbound DRS serve — **objects + groups + memberships** (Samba pulls **from** magnetite) | **PROVEN** | real Samba `drs_Replicate` creates the `user`/`group` objects **and** applies `member` links; fixed the group class governsID (was `groupOfNames`→now AD `group`) |
| Outbound secret (`unicodePwd`) round-trip | **PROVEN** | stored NT hash byte-identical to `MD4(pw)` |
| Outbound delta / idempotency (honours `pUpToDateVecDest`) | **PROVEN (protocol)** | 0 objects when dest current; needs configured `repsFrom` for full e2e |
| Per-attribute conflict resolution (secret converges on its own stamp) | **PROVEN** | a newer local password is not clobbered by a newer *name* change |
| **FSMO discovery over LDAP** (`samba-tool fsmo show`) | **PROVEN** | reports magnetite as holder of all **7** roles (5 core + DomainDnsZones/ForestDnsZones), zero errors |
| FSMO role transfer (DRS extended ops, all 5 roles) | **PROVEN** | `FSMO_REQ_ROLE` / `RID_REQ_ROLE` |
| **RID master serves pools** (`EXOP_FSMO_RID_ALLOC`, durable) | **PROVEN** | grants disjoint pools from one persistent counter shared with local mint |
| **RID pool acquisition** (magnetite `rIDSet` + real pool from Samba's RID master) | **PROVEN** | magnetite `DsAddEntry`s its rIDSet, requests, Samba writes `rIDAllocationPool` (e.g. 5100-5599). `rIDSetReferences` link is systemOnly → set via relax/system (Samba doesn't register the relax control over network LDAP) |
| **Client Kerberos GSS-SPNEGO SASL bind** | **PROVEN** | `SASL-BIND-INTEROP-OK` vs real Samba — one-round bind (non-DCE AP-REQ + two-mech negTokenInit) |
| LDAPS (implicit TLS) + StartTLS + cert validation + critical LDAP controls | **PROVEN / LAB** | StartTLS + cert-validation proven; LDAPS shares the same TLS path (Samba :636 unmapped in harness); relax control reaches Samba critical |
| KCC ring topology (static + health-driven dynamic self-heal) + dead-node SRV withdrawal | **LAB** | unit-tested; single-DC serving proven; multi-magnetite mesh not run live |
| Per-node disjoint RID ranges (multi-master RID safety) | **LAB** | `NODE_INDEX`; unit-tested |
| Kerberos (AS/TGS/PAC/S4U), SMB3 SYSVOL/GPO, SAMR/LSA/Netlogon | **PROVEN** | MIT + Samba + impacket interop |
| Periodic bidirectional replication agent in the daemon | **PROVEN (lab)** | `spawn_replication_thread`, `REPL_*` env; multi-upstream (`REPL_PEERS`) + computed topology (`REPL_TOPOLOGY`) |
| Full `magnetite-addc` binary e2e outbound | **UNVALIDATED** | build image lacks clang/cmake for SurrealDB; serving code is identical to the proven rig |
| DNS authoritative serving to real BIND/nsd | **LAB-ONLY** | zone/AXFR/IXFR/TSIG built; real-resolver interop untested |

> **⚠ Before production:** stand up a **throwaway staging clone** of the domain
> (restore kether's backup into an isolated network) and run Phases 1–11 end to end
> there first. The PoC default credentials (`Passw0rd!23`) and secrets **must** be
> replaced with real ones.

---

## 2. Prerequisites / pre-flight

- [ ] **Full backups** of kether and binar (`samba-tool domain backup offline`), plus a
      known-good system-state snapshot. Verify the backup restores in the lab.
- [ ] Change window agreed; stakeholders notified; rollback owner identified.
- [ ] `10.69.134.20` reachable from kether/binar and vice-versa on: 88 (KDC), 135
      (EPM), 389/636 (LDAP/LDAPS), 445 (SMB), 464 (kpasswd), 3268 (GC, if used), 123
      (NTP), and the dynamic DRS port magnetite advertises.
- [ ] **Time sync**: magnetite within 5 min of the domain (Kerberos skew). magnetite
      serves SNTP on :123; point it at the same source as kether initially.
- [ ] DNS: you can edit the AD DNS zone (SRV/A records) on kether, and you have the
      TTLs noted (to plan cut-over timing).
- [ ] magnetite host: `magnetite-addc` binary built for the host OS, a persistent
      data directory for `magnetite-db`, and the config below staged.
- [ ] An `Administrator`-equivalent domain credential for the join / replication.

**Tooling note.** Two helpers are referenced below; today they ship as `magnetite-addc`
examples — build them into standalone binaries for production, or run in place:

| Alias used below | Actual invocation |
|------------------|-------------------|
| `magnetite-addc-promote_dc` | `cargo run --release -p magnetite-addc --example promote_dc` |
| `magnetite-addc-samba_replicate_to_db` | `cargo run --release -p magnetite-addc --example samba_replicate_to_db` |
| `magnetite-addc-rid_set_acquire` | `cargo run --release -p magnetite-addc --example rid_set_acquire` (Phase 8 rIDSet + pool) |
| outbound rig (Samba pulls from magnetite) | `cargo run --release -p magnetite-rpc --example outbound_drs_server` + `scripts/interop/drs_pull_from_magnetite.py` |
| Kerberos SASL bind check | `cargo run --release -p magnetite-ldap --example sasl_bind` |

`magnetite-addc` itself is the long-running daemon (`cargo build --release -p
magnetite-addc`, then run the binary).

---

## 3. Phase 1 — Provision magnetite (isolated, not yet joined)

Bring `magnetite-addc` up in **database mode** so its directory and RID pool persist
across restarts, but do **not** point clients at it yet.

```bash
# On 10.69.134.20. Persist state under /var/lib/magnetite.
export REALM='<REALM>'                       # e.g. EXAMPLE.COM
export DC_NAME='MAGNETITE'
export DC_IPV4='10.69.134.20'
export MAGNETITE_DB_PATH='/var/lib/magnetite/db'
# The target domain's real SID (space-separated sub-authorities after S-1-5):
export DOMAIN_SID='<DOMAIN_SID>'             # e.g. 21 2171852460 1012688135 3873131180

magnetite-addc
```

The daemon prints its listeners (KDC/SMB/RPC/DRSUAPI/EPM/LDAP/CLDAP/kpasswd/SNTP) and
`directory sourced from magnetite-db`. It also mints a **persistent DSA invocation
ID** (its replication identity) stored in the DB.

**Verify**

```bash
# From the magnetite host:
kinit Administrator@<REALM>                  # (once joined; skip here)
ldapsearch -x -H ldap://10.69.134.20:389 -b '' -s base            # RootDSE answers
# DSA invocation id is stable across restarts (record it):
#   grep it from the DB or the promote output in Phase 2.
```

**Rollback:** stop the daemon; delete `/var/lib/magnetite/db`. Nothing in the domain
changed yet.

---

## 4. Phase 2 — Join magnetite as a replica DC

Create magnetite's DC identity objects **in the live domain** (via kether) using the
promotion orchestrator. This writes: `computer` account, `server`, `serverReference`,
`nTDSDSA` (via DRS `DsAddEntry`), `nTDSConnection`, and DNS `A`/`CNAME`/`SRV` records.

> Use **StartTLS** (`STARTTLS=1`) so the machine-secret write is encrypted. Samba must
> allow the strong bind (default). Point `TARGET`/`KDC`/`DRS`/`SPN` at **kether**.

```bash
export TARGET='10.69.134.30:389'             # kether LDAP
export STARTTLS=1
export BIND_DN='Administrator@<REALM>'
export BIND_PW='<admin-password>'
export REALM='<REALM>'
export KDC='10.69.134.30:88'
export DRS='10.69.134.30:135'                # EPM resolves the DRS port
export SPN='ldap/kether.<dns-domain>'
export DC_NAME='MAGNETITE'
export IP='10.69.134.20'
export ROLES=''                              # transfer FSMO later (Phase 7), not now
export RID_POOL=0                            # request the pool in Phase 8

magnetite-addc-promote_dc                     # (the promote_dc orchestrator)
```

It prints the created DNs: `computer`, `server`, `nTDSDSA`, `nTDSConnection`, and the
DNS record count. Samba auto-sets `primaryGroupID=516` (Domain Controllers) on the
computer account — recognising magnetite as a DC.

**Verify (on kether)**

```bash
samba-tool computer list | grep -i magnetite
ldbsearch -H ldap://kether -b '<DOMAIN_NC>' '(cn=MAGNETITE)' primaryGroupID
# nTDSDSA + server + connection exist in the Config NC:
ldbsearch -H ldap://kether -b 'CN=Configuration,<DOMAIN_NC>' '(cn=MAGNETITE)' objectClass
samba-tool drs showrepl 10.69.134.30 | sed -n '1,40p'   # magnetite appears as a partner
# DNS:
host -t A magnetite.<dns-domain> 10.69.134.30
```

**Rollback:** delete the objects magnetite created (leaf-first) and its DNS records:

```bash
samba-tool computer delete MAGNETITE                     # removes the computer account
ldbdel -H ldap://kether 'CN=NTDS Settings,CN=MAGNETITE,CN=Servers,CN=<site>,CN=Sites,CN=Configuration,<DOMAIN_NC>'
ldbdel -H ldap://kether 'CN=MAGNETITE,CN=Servers,CN=<site>,CN=Sites,CN=Configuration,<DOMAIN_NC>'
samba-tool dns delete kether <dns-domain> magnetite A 10.69.134.20 -U Administrator
```

---

## 5. Phase 3 — Initial inbound replication (pull all NCs into magnetite)

magnetite pulls the **Domain, Config, and Schema** NCs from kether over
Kerberos-sealed DRSUAPI and applies them (objects, groups+memberships, and secrets:
NT hash + AES256 Kerberos keys) into `magnetite-db`.

The daemon does this continuously when the `REPL_*` env is set (Phase 6). For the
**initial full seed**, either restart the daemon with `REPL_*` set, or run the
one-shot seeder:

```bash
# One-shot full seed (Domain NC shown; repeat per NC or let the agent sweep):
export KDC='10.69.134.30:88'
export DRS='10.69.134.30:135'
export SPN='ldap/kether.<dns-domain>'
export USERK='Administrator'
export PASS='<admin-password>'
# writes into MAGNETITE_DB_PATH
magnetite-addc-samba_replicate_to_db
```

**Verify**

```bash
# Object / principal counts on magnetite match kether's (allow small in-flight delta):
samba-tool user list -H ldap://10.69.134.20:389 | wc -l
samba-tool group list -H ldap://10.69.134.20:389 | wc -l
# A known user's secret replicated (its NT hash / AES key is present):
#   compare `samba-tool user getpassword --attributes=unicodePwd` style checks,
#   or authenticate a test account against magnetite's KDC:
kinit -S krbtgt/<REALM> testuser@<REALM>       # via 10.69.134.20 as KDC
```

**Rollback:** stop the daemon; wipe `magnetite-db`; re-seed. The source (kether) is
read-only in this phase, so nothing upstream is affected.

---

## 6. Phase 4 — Continuous bidirectional replication

Run the daemon with the inbound agent enabled so magnetite stays converged with
kether, and confirm kether can pull **from** magnetite (outbound).

```bash
# magnetite-addc daemon, database mode, inbound agent on:
export REALM='<REALM>'
export DC_NAME='MAGNETITE'
export DC_IPV4='10.69.134.20'
export MAGNETITE_DB_PATH='/var/lib/magnetite/db'
export DOMAIN_SID='<DOMAIN_SID>'
# Inbound: pull from kether every 5 min
export REPL_DRS='10.69.134.30:135'
export REPL_KDC='10.69.134.30:88'
export REPL_REALM='<REALM>'
export REPL_USER='Administrator'
export REPL_PASS='<admin-password>'          # dev/PoC; prefer REPL_KEYTAB in production
# Production: a keytab for REPL_USER (no cleartext password in the environment):
#   samba-tool domain exportkeytab /etc/magnetite/repl.keytab --principal=Administrator
# export REPL_KEYTAB='/etc/magnetite/repl.keytab'   # loads the AES256 key from the keytab
export REPL_SPN='ldap/kether.<dns-domain>'
export REPL_NC='<DOMAIN_NC>'
# Seed the read-only Config + Schema partitions ONCE into the LDAP tree (paged in
# full, projected as generic objects). ';'-separated NC DNs:
export REPL_EXTRA_NCS='CN=Configuration,<DOMAIN_NC>;CN=Schema,CN=Configuration,<DOMAIN_NC>'
export REPL_INTERVAL_SECS=300
# Outbound: the DRS acceptor key kether/binar hold for magnetite's machine account.
# Recover it once (DCSync MAGNETITE$ from kether) and pin it so peers' tickets verify:
export DRS_KEY='<magnetite$-aes256-key-hex>'

magnetite-addc
```

**Verify — inbound** (magnetite tracks kether):

```bash
# Make a change on kether, confirm it appears on magnetite within the interval:
samba-tool user create repltest-in --random-password -H ldap://kether
sleep 320
samba-tool user list -H ldap://10.69.134.20:389 | grep repltest-in   # present
```

**Verify — outbound** (kether pulls from magnetite):

```bash
# Trigger a pull FROM magnetite on kether:
samba-tool drs replicate kether magnetite.<dns-domain> <DOMAIN_NC> -U Administrator
# A user originated on magnetite appears on kether:
samba-tool user create repltest-out --random-password -H ldap://10.69.134.20:389
samba-tool drs replicate kether magnetite.<dns-domain> <DOMAIN_NC> -U Administrator
samba-tool user list -H ldap://kether | grep repltest-out            # present
```

> **Idempotency note:** re-running the pull must report **0 changes** once converged
> (magnetite honours `pUpToDateVecDest`). If a pull re-sends everything, kether is not
> persisting a `repsFrom`/UTDV cursor for magnetite — confirm the `nTDSConnection`
> from Phase 2 exists and the KCC has run (`samba-tool drs kcc kether`).

**Rollback:** unset the `REPL_*` env and stop the outbound pulls. Delete the two
`repltest-*` accounts. Replication is additive; no destructive change to kether.

---

## 7. Phase 5 — Soak

Leave both DCs and magnetite running, replicating, for a **soak period** (recommend ≥
24–72h across at least one full business cycle). Watch for:

- [ ] No replication errors/backlog in either direction (`samba-tool drs showrepl`).
- [ ] Logons succeed against magnetite as KDC (point a test client at `10.69.134.20`).
- [ ] SYSVOL/GPO readable from magnetite over SMB (`smbclient //10.69.134.20/sysvol`).
- [ ] Password changes on either DC propagate to the other.
- [ ] Time stays in skew; DNS answers from magnetite match kether.

Do not proceed while any item is red.

---

## 8. Phase 6 — Move authoritative DNS & client discovery to magnetite

Add magnetite's SRV/A records so clients can *discover* it, but keep kether/binar in
DNS too (parallel operation). Only after clients are happily using magnetite do you
remove the old DCs' records.

```bash
# Ensure magnetite's _ldap/_kerberos/_gc SRV + A records exist (Phase 2 created A).
samba-tool dns query kether <dns-domain> @ SRV | grep -i magnetite
# Optionally lower TTLs a day ahead to speed the eventual cut-over.
```

**Verify:** a fresh client `nltest /dsgetdc:<REALM>` (or `realm discover`) can return
magnetite; Kerberos logons via magnetite succeed.

**Rollback:** remove magnetite's SRV records; clients fall back to kether/binar.

---

## 9. Phase 7 — Transfer FSMO roles to magnetite

Move the five roles **one at a time**, verifying after each. magnetite requests each
role from the current holder via DRS extended ops (`FSMO_REQ_ROLE` / `FSMO_RID_REQ_ROLE`
/ `FSMO_REQ_PDC`). Transfer order (least → most disruptive): infrastructure → schema →
naming → rid → pdc.

```bash
export TARGET='10.69.134.30:389'; export STARTTLS=1
export BIND_DN='Administrator@<REALM>'; export BIND_PW='<admin-password>'
export REALM='<REALM>'; export KDC='10.69.134.30:88'; export DRS='10.69.134.30:135'
export SPN='ldap/kether.<dns-domain>'; export DC_NAME='MAGNETITE'; export IP='10.69.134.20'

# One role at a time — re-run per role, verifying between:
ROLES=infrastructure magnetite-addc-promote_dc
samba-tool fsmo show                                   # infrastructure → MAGNETITE
ROLES=schema         magnetite-addc-promote_dc && samba-tool fsmo show
ROLES=naming         magnetite-addc-promote_dc && samba-tool fsmo show
ROLES=rid            magnetite-addc-promote_dc && samba-tool fsmo show
ROLES=pdc            magnetite-addc-promote_dc && samba-tool fsmo show
```

**Verify:** `samba-tool fsmo show` reports **MAGNETITE** for each transferred role, on
**both** kether and magnetite (the change replicated). PDC-role move last: confirm time
service and password-change routing still work.

**Rollback:** transfer the role back to kether (`samba-tool fsmo transfer --role=<role>
-H ldap://kether`, or magnetite's reverse transfer). Roles are single-valued and
seizable, so a botched transfer is recoverable while kether is still up.

---

## 10. Phase 8 — RID master & RID pool

With magnetite as RID master (from Phase 7), confirm it can hand out a RID pool and that
new-object creation works domain-wide.

magnetite must have a `rIDSet` object referenced from its machine account before the RID
master can grant it a pool (proven live — `rid_set_acquire` example). The `rIDSet` is a
`systemOnly` class (created via DRS `DsAddEntry`), and the `rIDSetReferences` link is a
`systemOnly` attribute — Samba does **not** register the LDAP relax control over the
network, so provision that link as the system does in dcpromo:

```bash
export RID_POOL=1
ROLES=rid magnetite-addc-promote_dc          # request/confirm a RID pool
# If magnetite's rIDSet/rIDSetReferences are not yet present, provision the link on the
# CURRENT RID master (relax control, as dcpromo does), then request the pool:
#   ldbmodify -H .../sam.ldb --controls=relax:0 <<'EOF'
#   dn: CN=MAGNETITE,OU=Domain Controllers,<domain-dn>
#   changetype: modify
#   add: rIDSetReferences
#   rIDSetReferences: CN=RID Set,CN=MAGNETITE,OU=Domain Controllers,<domain-dn>
#   EOF
# Create an object and confirm its RID comes from magnetite's pool:
samba-tool user create ridtest --random-password -H ldap://10.69.134.20:389
ldbsearch -H ldap://10.69.134.20:389 '(cn=ridtest)' objectSid
```

**Verify:** magnetite's `rIDSet.rIDAllocationPool` holds a real range from the RID master
(lab: `5100-5599`); the new SID's RID is inside magnetite's allocated pool; no RID
collision warnings on either DC.

**Rollback:** transfer RID master back to kether.

---

## 11. Phase 9 — Demote the old DCs (kether, then binar) — one at a time

Only now, and only if **every** gate above is green. Demote **binar first** (the
non-FSMO replica), verify the domain is healthy on magnetite alone + kether, then demote
kether.

```bash
# On binar:
samba-tool domain demote --server=magnetite.<dns-domain> -U Administrator
# Verify domain health with binar gone:
samba-tool drs showrepl 10.69.134.20
samba-tool dbcheck --cross-ncs -H ldap://10.69.134.20:389
# Soak briefly, then on kether:
samba-tool domain demote --server=magnetite.<dns-domain> -U Administrator
```

After each demote: remove that host's DNS `A`/SRV records and its `server`/`nTDSDSA`
objects if the demote didn't (check `samba-tool drs showrepl` for stale partners).

**Verify (magnetite standalone):**

```bash
samba-tool fsmo show -H ldap://10.69.134.20:389        # all 5 = MAGNETITE
samba-tool dbcheck --cross-ncs -H ldap://10.69.134.20:389   # 0 errors
# Real client: domain-join / logon / GPO apply against magnetite only.
```

**Rollback:** demotion is the point of no easy return. Because you demoted **binar
first**, if magnetite misbehaves you still have **kether** fully authoritative — re-add
binar from backup or promote it back, and demote magnetite instead. Do **not** demote
kether until magnetite has run the domain solo (with binar gone) through a soak.

---

## 12. Phase 10 — Post-migration validation

- [ ] `samba-tool dbcheck --cross-ncs` clean on magnetite.
- [ ] All 5 FSMO roles on magnetite; RID pool healthy.
- [ ] Kerberos logon, NTLM fallback, password change, GPO apply, SYSVOL, DNS — all
      exercised by a real client against `10.69.134.20`.
- [ ] Backups now target magnetite; monitoring/alerting repointed.
- [ ] kether/binar powered off but **retained** (not wiped) for a defined grace period.

---

## Appendix A — `magnetite-addc` environment reference

| Var | Purpose |
|-----|---------|
| `REALM` | Kerberos realm (e.g. `EXAMPLE.COM`) |
| `DC_NAME` | this DC's label (default `magnetite`) |
| `DC_IPV4` | IP the Endpoint Mapper advertises in RPC towers |
| `MAGNETITE_DB_PATH` | embedded SurrealDB path (database mode) |
| `MAGNETITE_DB_URL` | shared networked SurrealDB (`ws://…`) — takes precedence, for multi-DC (Tier B; make it HA — Appendix E) |
| `DOMAIN_SID` | target domain SID sub-authorities (space/dash separated) for outbound objects |
| `DRS_KEY` | AES256 (hex) the domain holds for magnetite's machine account — DRS acceptor key |
| `REPL_DRS`/`REPL_KDC`/`REPL_REALM`/`REPL_USER`/`REPL_PASS`/`REPL_SPN`/`REPL_NC`/`REPL_INTERVAL_SECS` | inbound replication agent (pull from a single upstream) |
| `REPL_PEERS` | multi-upstream inbound: comma list of `drs_addr=spn` (pull from several DCs, e.g. both old DCs during migration) |
| `REPL_SYSVOL_URL` + `REPL_SYSVOL_SECRET` | self-contained SYSVOL (Group Policy) pull: fetch a peer's `/repl/sysvol` feed straight into this DC's store (served over SMB by the live re-serve). `REPL_SYSVOL_INTERVAL_SECS` (default 60) paces it |
| `REPL_TOPOLOGY` + `NODE_DSA_ID` | computed KCC ring: the whole DC set as `id@host:port=spn`, each node self-selects its ring partners (deploy the same env to every node) |
| `REPL_RECONCILE_SECS` | with `REPL_TOPOLOGY`, run the dynamic KCC manager (reroute around dead peers, re-seed on recovery) instead of static agents |
| `NODE_INDEX` | Tier C: distinct per node → disjoint RID range (`rid_pool_base`) so object SIDs never collide across independent magnetite DCs |
| `FSMO_OWNERS` | multi-DC FSMO ownership: comma `role=owner_dsa` (keys `schema`/`naming`/`rid`/`pdc`/`infra`); unset roles default to this node |
| `KDC_ADDR`/`SMB_ADDR`/`RPC_ADDR`/`DRS_ADDR`/`EPM_ADDR`/`LDAP_ADDR`/`CLDAP_ADDR`/`KPASSWD_ADDR`/`SNTP_ADDR` | listen-socket overrides |

Join orchestrator (`promote_dc`): `TARGET BIND_DN BIND_PW REALM KDC DRS SPN DC_NAME IP
ROLES RID_POOL STARTTLS TLS_CA`. `ROLES` ∈ {`schema`,`naming`/`domainnaming`,`pdc`,
`rid`,`infrastructure`}, comma-separated.

## Appendix B — Known limitations / risk register

- **Production transport:** the join/secret path is proven over **StartTLS**, and the
  **client Kerberos GSS-SPNEGO SASL bind is now proven live against real Samba**
  (`SASL-BIND-INTEROP-OK`, one-round bind) — magnetite can authenticate LDAP with
  Kerberos instead of a cleartext simple bind. LDAPS (implicit TLS) is implemented and
  shares the proven StartTLS TLS path; critical LDAP controls (relax etc.) are sendable.
  Still test against your **exact** Samba/Windows versions in staging. A full Windows
  `net ads join` was previously blocked by a **Samba client** crash (not magnetite);
  re-test that path on your target build.
- **RID pool acquisition:** magnetite obtaining a real RID pool from the domain's RID
  master is **proven** (magnetite creates its `rIDSet` via DRS `DsAddEntry`, requests
  `EXOP_FSMO_RID_ALLOC`, Samba writes the granted pool). The `rIDSetReferences` link on
  the machine account is a `systemOnly` attribute; Samba does **not** register the LDAP
  relax control over the network, so provision that link with `ldbmodify --controls=relax`
  (a system/DRS operation, as in a real dcpromo) — see Phase 8.
- **Daemon binary e2e:** the outbound DRS serving in `magnetite-addc` is byte-identical
  to the standalone rig proven live, but the full daemon binary has not itself been run
  against Samba (the build image lacks clang/cmake for the SurrealDB dependency). Build
  and smoke-test the actual binary before production.
- **Outbound idempotency** is proven at the protocol level (magnetite returns 0 objects
  when the destination is current); the end-to-end "no re-send" behaviour depends on the
  peer maintaining a `repsFrom`/UTDV cursor for magnetite (Phase 2 `nTDSConnection` +
  KCC). Confirm during Phase 4.
- **DNS** authoritative serving is built (zones/AXFR/IXFR/TSIG) but real BIND/nsd resolver
  interop is untested — validate name resolution thoroughly in Phases 6–9.
- **Credentials:** replace all PoC secrets (`Passw0rd!23`, fixed service secrets) before
  any production use. Set the six domain secrets (`KRBTGT_SECRET`, `CIFS_SECRET`,
  `HOST_SECRET`, `KADMIN_SECRET`, `DNS_SECRET`, `MACHINE_PASSWORD`) to strong random
  values, identical on every DC, and run with **`PRODUCTION=1`** — the daemon then
  hard-fails at startup if any is unset or still at its PoC default. The PoC demo users
  (alice/bob) are NOT auto-seeded unless `SEED_POC_USERS=1`, so leave it unset.
- **Schema/version parity:** validate magnetite against the **exact** functional level
  and schema version of your production domain in staging first.
- **Shared-database SPOF (Tier B):** when several magnetite front-ends share one networked
  SurrealDB via `MAGNETITE_DB_URL`, that database is a single point of failure — losing it
  takes down every DC that points at it. Make the store itself highly available (or run
  Tier C, per-node stores with magnetite's own replication) before relying on Tier B in
  production. See **Appendix E**.

## Appendix C — Emergency rollback (any phase before kether is demoted)

1. Stop `magnetite-addc`.
2. Transfer any FSMO roles magnetite holds back to kether:
   `samba-tool fsmo seize --role=all -H ldap://kether -U Administrator` (seize if
   magnetite is unreachable).
3. Remove magnetite's DNS SRV/A records so clients stop discovering it.
4. Delete magnetite's `computer`/`server`/`nTDSDSA`/`nTDSConnection` objects (Phase 2
   rollback commands).
5. Run `samba-tool dbcheck --cross-ncs` on kether; confirm clean.

Because magnetite is only ever *additive* until Phase 9, and binar is demoted before
kether, a fully authoritative Samba DC exists at every step until the final cut-over.

---

## Appendix D — Lab rehearsal log (Samba harness `magtest.local`)

The phases below were rehearsed against the lab harness — a real Samba 4 AD DC
(`samba-dc`, `magtest.local`, DC1) standing in for kether — with magnetite's
identity (`MAGNETITE$` machine account + `nTDSDSA` GUID `c0ad5139…` + server +
`nTDSConnection` + DNS A/CNAME) already provisioned in Samba. Reproduce with the
noted example; each carries a live `*-INTEROP-OK` marker in the commit history.

| Phase / capability | Harness command | Result |
|---|---|---|
| Ph.2 join objects | `promote_dc` (DsAddEntry nTDSDSA/server/computer/connection/DNS) | objects exist in Samba's Config NC |
| Ph.3 inbound pull + secrets | `samba_replicate_to_db` (Kerberos-sealed DRS) | 100s of objects; NT hash + AES256 keys byte-match Samba |
| Ph.3 inbound groups | replication agent | 38 groups + memberships applied |
| Ph.4 outbound (Samba pulls) | `outbound_drs_server` (container @172.17.0.3) + `scripts/interop/drs_pull_from_magnetite.py` | Samba `drs_Replicate`: "Replicated 3 objects (2 linked attributes)" — 2 users + **group with 2 members** created as AD `group` |
| Ph.6/9 FSMO discovery | `magnetite-ldap --example fsmo_server` + `samba-tool fsmo show -H ldap://…` | all **7** roles report magnetite; multi-DC via `FSMO_OWNERS` shows the peer holder |
| Ph.8 RID pool acquisition | `magnetite-addc --example rid_set_acquire` (+ `ldbmodify --controls=relax` for the systemOnly `rIDSetReferences`) | Samba's RID master wrote `rIDAllocationPool: 5100-5599` to magnetite's rIDSet |
| Ph.8 RID request (client) | `samba_request_rid_pool` | Samba grants a 500-RID pool per call (watermark advances 4100→4600→…) |
| Transport: Kerberos SASL bind | `magnetite-ldap --example sasl_bind` | `SASL-BIND-INTEROP-OK` — one-round GSS-SPNEGO bind |

**Harness reproduction notes** (see the crate memories for detail):
- `samba-tool drs replicate` (plain) needs a `repsFrom` agreement (WERR_FILE_NOT_FOUND);
  `--local` does a source LDAP lookup the minimal outbound rig doesn't serve — use the
  `drs_Replicate` script (`scripts/interop/drs_pull_from_magnetite.py`) which binds the
  source directly.
- Deterministic object GUIDs (`00000<rid-hex>-1111-…`) + `ldbdel` leave **tombstones** →
  re-adding the same GUID fails "Operations error"; use fresh RIDs for clean re-runs.
- The outbound rig runs in a **container on the docker bridge** at magnetite's registered
  A-record IP (`172.17.0.3`) so Samba can reach it; Samba `:636` is unmapped, so LDAPS
  shares the StartTLS-proven TLS path rather than a separate live test.
- Ground-truth for the SASL bind came from `tcpdump -i any tcp port 389` + `tshark` of a
  working `ldbsearch -H ldap://dc1 -k yes` (Samba's own GSS-SPNEGO client).

**What a production staging clone still adds** (not reproducible in the container harness):
the full `magnetite-addc` daemon binary end-to-end (SurrealDB build), a real Windows
`net ads join` / logon / GPO apply, DNS resolution by real clients, and the demote
(Phase 9) of a live replica — run these on a throwaway restore of your domain first.

---

## Appendix E — Database high availability (Tier B shared store)

magnetite offers **two independent redundancy models**; pick one deliberately.

| | **Tier B — shared store** | **Tier C — independent copies** |
|---|---|---|
| Storage | one networked SurrealDB, every DC via `MAGNETITE_DB_URL=ws://…` | per-node embedded store, `MAGNETITE_DB_PATH` |
| Consistency | strong (single source of truth) | eventual (magnetite's own DRS/feed replication + conflict resolution) |
| Failure domain | **the database is a SPOF** unless *it* is made HA (this appendix) | no shared component; a node loss is local |
| Front-ends | stateless; add/remove freely | each node is self-contained |
| Best when | you want one authoritative copy and can run an HA datastore | you want no shared component / geo-distribution |

All magnetite front-ends open namespace `magnetite`, database `main`, and run
`init_schema` (idempotent `IF NOT EXISTS`) on startup, so concurrent boots against a
shared store are safe. The gap is that a *single* `surreal start` server is one process
on one host. Close it one of three ways.

### Option 1 — Distributed SurrealDB (recommended for Tier B HA)

Run SurrealDB over a **distributed KV backend** (TiKV or FoundationDB) instead of the
embedded engine. The KV layer replicates the data (Raft); the SurrealDB servers become
stateless compute you can scale and lose individually.

1. Stand up a **TiKV cluster**: ≥3 PD (placement driver) + ≥3 TiKV nodes across
   fault domains (Raft needs a majority to keep writing, so 3 tolerates 1 loss).
2. Run **≥2 SurrealDB server nodes**, each pointing at the same cluster:
   ```
   surreal start --user <root> --pass <secret> tikv://<pd1>:2379,<pd2>:2379,<pd3>:2379
   ```
3. Put a **VIP / L4 load balancer** in front of the SurrealDB nodes (health-check the
   `/health` endpoint; pool port 8000).
4. Point every magnetite DC at the VIP: `MAGNETITE_DB_URL=ws://<vip>:8000`.

Now a SurrealDB node or a TiKV node can fail without an outage. This is the only option
that survives a node loss with **no failover gap** for writes.

### Option 2 — Active/passive single node (simpler, has a failover gap)

Keep one embedded-engine SurrealDB (`rocksdb://` / `surrealkv://`) but make the *host*
recoverable:

- Put the data directory on **replicated block storage** (DRBD, or your SAN/cloud disk
  with synchronous replication).
- Manage a **VIP + the `surreal start` process** with a cluster resource manager
  (Pacemaker/Corosync, or keepalived + a small supervisor). On primary failure the VIP
  and the process move to the standby, which opens the same replicated volume.
- magnetite reconnects to the same `MAGNETITE_DB_URL=ws://<vip>:8000` after the VIP moves.

Simpler to operate, but writes pause for the failover window (seconds to tens of seconds),
and split-brain protection is on you (fence the old primary).

### Option 3 — Don't share a database (use Tier C)

If you'd rather not operate an HA datastore, give each DC its own `MAGNETITE_DB_PATH`
and let magnetite replicate between them — DRS for the directory (`REPL_TOPOLOGY` /
`REPL_PEERS`, Phases 3–4), plus the mail/DHCP/SYSVOL feed-pull agents. There is then no
shared component to make HA, at the cost of eventual consistency and app-level conflict
resolution. This is the same multi-master design the migration itself rides on.

> **magnetite needs no special build for Option 1/2.** It talks to the SurrealDB
> server(s) over `ws://` (the `protocol-ws` feature it already ships); the distributed
> or embedded storage backend lives *in the `surreal start` server*, not in magnetite.
> The magnetite binary's own `kv-rocksdb` feature is only for the Tier C embedded path.

### Operational notes (all options)

- **Client reconnect:** magnetite opens the handle once at startup (`any::connect`); the
  SurrealDB v3 `ws` client reconnects automatically after a transient drop. Still front
  the servers with a VIP/LB so the client can reach a *surviving* node when one dies (a
  reconnect to a dead host does not help), and treat a total DB outage as a DC restart.
- **Back up regardless of tier:** `surreal export` (or a TiKV/volume snapshot) on a
  schedule; a replicated store protects against a node loss, not against a bad write or an
  operator mistake. Rehearse `surreal import` restore timing.
- **Secrets:** the SurrealDB root credentials and the `ws://` transport must not cross an
  untrusted network in clear — terminate TLS at the LB (`wss://`) or keep the DB network
  private.
- **Capacity:** the distributed backends add latency per query vs. embedded RocksDB;
  size the SurrealDB/TiKV nodes and validate DC login/replication latency in staging.
