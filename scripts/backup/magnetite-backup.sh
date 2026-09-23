#!/usr/bin/env bash
#
# magnetite-backup.sh — cold, consistent backup of ONE magnetite DC's directory store.
#
# magnetite embeds a single-writer RocksDB store, so a *hot* file copy can capture a torn
# (inconsistent) state. The safe, version-agnostic method is: stop the node briefly, copy
# the store while nothing is writing, start it again. In a two-node domain the PEER keeps
# serving during the short stop — so schedule the two nodes at DIFFERENT times (see README).
#
# This protects against the failure class redundancy does NOT: corruption, a bad write, an
# operator mistake, or a bug — all of which replicate to both nodes. Redundancy ≠ backup.
#
# Configure via env (or edit the defaults). Run as root (needs systemctl + the store path).
#   MAGNETITE_SERVICE            systemd unit to stop/start        (default: magnetite-addc)
#   MAGNETITE_DB_PATH            the embedded RocksDB directory     (default: /var/lib/magnetite/db)
#   MAGNETITE_BACKUP_DIR         where archives are written         (default: /var/backups/magnetite)
#   MAGNETITE_BACKUP_OFFBOX      off-box destination (rsync target) (REQUIRED for real safety; e.g.
#                               user@backup:/srv/magnetite  or  /mnt/nfs/magnetite)
#   MAGNETITE_BACKUP_RETENTION_DAYS  local retention                (default: 14)
#   MAGNETITE_NODE_NAME         label in the archive name          (default: hostname -s)
#   MAGNETITE_BACKUP_LOG        log file                           (default: /var/log/magnetite-backup.log)
#
# Exit non-zero on any failure so a systemd timer / cron can alert.

set -euo pipefail

SERVICE="${MAGNETITE_SERVICE:-magnetite-addc}"
DB_PATH="${MAGNETITE_DB_PATH:-/var/lib/magnetite/db}"
BACKUP_DIR="${MAGNETITE_BACKUP_DIR:-/var/backups/magnetite}"
OFFBOX_DEST="${MAGNETITE_BACKUP_OFFBOX:-}"
RETENTION_DAYS="${MAGNETITE_BACKUP_RETENTION_DAYS:-14}"
NODE_NAME="${MAGNETITE_NODE_NAME:-$(hostname -s)}"
LOG="${MAGNETITE_BACKUP_LOG:-/var/log/magnetite-backup.log}"

log()  { printf '%s [%s] %s\n' "$(date -Is)" "$NODE_NAME" "$*" | tee -a "$LOG" >&2; }
fail() { log "ERROR: $*"; exit 1; }

# If we die between stop and start, still bring the node back — never leave a DC down.
node_was_stopped=0
cleanup() {
  if [ "$node_was_stopped" = 1 ]; then
    log "cleanup: restarting $SERVICE after an error"
    systemctl start "$SERVICE" || log "WARN: could not restart $SERVICE — CHECK THIS DC NOW"
  fi
}
trap cleanup EXIT

wait_state() { # wait_state active|inactive <seconds>
  local want="$1" secs="$2" i
  for ((i=0; i<secs; i++)); do
    if [ "$want" = active ]; then systemctl is-active --quiet "$SERVICE" && return 0
    else systemctl is-active --quiet "$SERVICE" || return 0; fi
    sleep 1
  done
  return 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -d "$DB_PATH" ]    || fail "MAGNETITE_DB_PATH '$DB_PATH' not found (embedded store only; networked SurrealDB → use surreal export, see README)"
mkdir -p "$BACKUP_DIR"

ts="$(date +%Y%m%d-%H%M%S)"
archive="$BACKUP_DIR/magnetite-$NODE_NAME-$ts.tar.gz"

# 1. Stop the node (SIGTERM is graceful → RocksDB flushes). The peer keeps serving.
log "stopping $SERVICE for a consistent copy"
systemctl stop "$SERVICE" || fail "could not stop $SERVICE"
node_was_stopped=1
wait_state inactive 30 || fail "$SERVICE still active after 30s — aborting to avoid a torn copy"

# 2. Archive the store while nothing writes to it.
log "archiving $DB_PATH -> $archive"
tar -czf "$archive.partial" -C "$(dirname "$DB_PATH")" "$(basename "$DB_PATH")" || fail "tar failed"
mv "$archive.partial" "$archive"

# 3. Start the node again as soon as possible, and confirm it is healthy.
log "starting $SERVICE"
systemctl start "$SERVICE" || fail "FAILED TO RESTART $SERVICE — THIS DC IS DOWN"
node_was_stopped=0
wait_state active 30 || fail "$SERVICE did not become active within 30s after restart"

# 4. Checksum for integrity + a restore-time verify.
( cd "$BACKUP_DIR" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256" )
log "backup written: $archive ($(du -h "$archive" | cut -f1))"

# 5. Copy off-box — this is the part that actually protects you from losing the host.
if [ -n "$OFFBOX_DEST" ]; then
  log "copying off-box -> $OFFBOX_DEST"
  rsync -a "$archive" "$archive.sha256" "$OFFBOX_DEST/" \
    || log "WARN: off-box copy to $OFFBOX_DEST failed — the backup is only on this node"
else
  log "WARN: MAGNETITE_BACKUP_OFFBOX not set — the backup lives only on this node (NOT disaster-safe)"
fi

# 6. Prune local archives older than the retention window.
find "$BACKUP_DIR" -maxdepth 1 -type f -name "magnetite-$NODE_NAME-*.tar.gz*" \
  -mtime +"$RETENTION_DAYS" -print -delete \
  | while read -r f; do log "pruned $f"; done || true

log "backup complete"
