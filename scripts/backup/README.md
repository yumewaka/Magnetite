# magnetite directory backup

Templates to back up and restore a magnetite DC's directory store. This is
**mandatory** before running magnetite as a sole IdP: two nodes protect against a node
dying, but **not** against corruption, a bad write, an operator mistake, or a bug —
those replicate to both nodes. **Redundancy is not a backup.** (Validation sheet §1.)

| File | Purpose |
|------|---------|
| `magnetite-backup.sh`  | Cold, consistent backup of one node's store (stop → copy → start). |
| `magnetite-restore.sh` | Restore a store from an archive (disaster recovery). |
| `magnetite-backup.service` / `.timer` | Sample systemd units to schedule the backup. |

## Why stop-and-copy

magnetite embeds a **single-writer RocksDB** store. A *hot* file copy can capture a torn
(inconsistent) state, and `surreal export` also needs exclusive access to the embedded
store. The reliable, version-agnostic method is: **stop the node briefly, copy the store
while nothing writes, start it again.** For a small directory the stop is seconds, and in a
two-node domain the **peer keeps serving** — so schedule the two nodes at **different**
times (below).

> **Alternative — networked SurrealDB.** If you run magnetite against a networked SurrealDB
> (`MAGNETITE_DB_URL=ws://…`) instead of an embedded path, you can export **live** without
> stopping:
> `surreal export --conn ws://<host>:8000 --user <root> --pass <pw> --ns magnetite --db main out.surql`
> and restore with `surreal import …`. The scripts here target the **embedded** store.

## Setup

1. Install the scripts and make them executable:
   ```
   install -m 0755 magnetite-backup.sh magnetite-restore.sh /usr/local/sbin/
   ```
2. Edit `magnetite-backup.service` for your paths, and **set an off-box destination** —
   a backup that lives only on the node it came from will not survive that node dying:
   ```
   Environment=MAGNETITE_BACKUP_OFFBOX=user@backup-host:/srv/magnetite    # or /mnt/nfs/magnetite
   ```
3. Install the units and enable the timer **with a different time on each node** so both
   DCs are never stopped at once:
   ```
   # on MAG1:  OnCalendar=*-*-* 02:15:00
   # on MAG2:  OnCalendar=*-*-* 03:15:00
   cp magnetite-backup.service magnetite-backup.timer /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now magnetite-backup.timer
   ```
   (cron equivalent, staggered: `15 2 * * *` on MAG1, `15 3 * * *` on MAG2.)

Run once by hand and check the log (`/var/log/magnetite-backup.log`) before trusting the
schedule: `systemctl start magnetite-backup.service`.

## Restore — disaster recovery only

`magnetite-restore.sh <archive.tar.gz>` verifies the checksum, stops the node, moves the
current store aside (reversible), extracts the archive, and restarts. **When to use which
path:**

- **One node lost, the peer is healthy** → **do not restore an old backup into it.** Rebuild
  that node **fresh** (empty store, a fresh `INVOCATION_ID` / DC name) and let it
  re-replicate from the healthy peer. Restoring a stale copy into a live domain risks a
  **USN rollback** (a serious AD replication hazard).
- **Both nodes lost, or a bad write/corruption reached both** → **this is what restore is
  for.** Restore the latest good archive onto **one** node to bootstrap the domain, verify
  it, then rebuild the second node fresh replicating from the restored one.

## Validation-sheet §1 mapping

- **1-A** backup can be taken → `magnetite-backup.sh` (one node at a time, off-box).
- **1-B** the backup restores → `magnetite-restore.sh` into a throwaway host; compare object counts.
- **1-C** the restore is usable → `kinit` a test user against the restored node.
- **1-D** scheduled + retained → the systemd timer + `MAGNETITE_BACKUP_RETENTION_DAYS`, off-box.

**Rehearse a restore before go-live.** "Backups exist" is worthless until a restore has been
proven to boot and authenticate.
