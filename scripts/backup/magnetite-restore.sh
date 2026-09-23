#!/usr/bin/env bash
#
# magnetite-restore.sh — restore a magnetite DC's directory store from a backup archive.
#
#   magnetite-restore.sh <archive.tar.gz>
#
# READ THIS FIRST — restore is DISASTER recovery, not the normal repair path:
#
#   * ONE node lost, the peer is healthy  → do NOT restore an old backup into it. Rebuild the
#     node FRESH (empty store, fresh INVOCATION_ID / DC name) and let it re-replicate from the
#     healthy peer. Restoring a stale copy into a live domain risks a USN rollback (a serious
#     AD replication hazard).
#   * BOTH nodes lost, or corruption/bad-write replicated to both  → THIS is when you restore:
#     restore the latest good archive onto ONE node to bootstrap the domain, verify it, then
#     rebuild the second node fresh replicating from the restored one.
#
# Run as root on the target node. The current store is moved aside (never deleted), so a bad
# restore is reversible.

set -euo pipefail

SERVICE="${MAGNETITE_SERVICE:-magnetite-addc}"
DB_PATH="${MAGNETITE_DB_PATH:-/var/lib/magnetite/db}"
archive="${1:-}"

log()  { printf '%s %s\n' "$(date -Is)" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -n "$archive" ]    || fail "usage: magnetite-restore.sh <archive.tar.gz>"
[ -f "$archive" ]    || fail "archive '$archive' not found"

# Verify the checksum if it is alongside the archive.
if [ -f "$archive.sha256" ]; then
  log "verifying checksum"
  ( cd "$(dirname "$archive")" && sha256sum -c "$(basename "$archive").sha256" ) \
    || fail "checksum mismatch — refusing to restore a corrupt archive"
else
  log "WARN: no $archive.sha256 alongside — cannot verify integrity"
fi

# Confirm the archive really contains the store directory before we touch anything.
# (Read the listing into a variable and match with [[ ]] — avoids a `| grep -q` pipeline,
#  which can trip `pipefail` when grep closes the pipe early via SIGPIPE.)
base="$(basename "$DB_PATH")"
listing="$(tar -tzf "$archive")" || fail "cannot read archive '$archive'"
[[ $'\n'"$listing"$'\n' == *$'\n'"$base/"* ]] \
  || fail "archive does not contain a '$base/' directory — wrong archive?"

log "stopping $SERVICE"
systemctl stop "$SERVICE" || fail "could not stop $SERVICE"
for _ in $(seq 1 30); do systemctl is-active --quiet "$SERVICE" || break; sleep 1; done
systemctl is-active --quiet "$SERVICE" && fail "$SERVICE still active — aborting"

# Move the current store aside (reversible), then extract.
if [ -e "$DB_PATH" ]; then
  aside="$DB_PATH.pre-restore.$(date +%Y%m%d-%H%M%S)"
  log "moving current store aside -> $aside"
  mv "$DB_PATH" "$aside"
fi
log "extracting $archive -> $(dirname "$DB_PATH")"
mkdir -p "$(dirname "$DB_PATH")"
tar -xzf "$archive" -C "$(dirname "$DB_PATH")" || fail "extract failed"
[ -d "$DB_PATH" ] || fail "extracted archive did not produce $DB_PATH"

log "starting $SERVICE"
systemctl start "$SERVICE" || fail "FAILED TO START $SERVICE after restore"
for _ in $(seq 1 30); do systemctl is-active --quiet "$SERVICE" && break; sleep 1; done
systemctl is-active --quiet "$SERVICE" || fail "$SERVICE did not come back healthy"

log "restore complete."
log "VERIFY NOW: kinit a test user against this node; compare LDAP object counts to expectations."
log "The previous store is preserved at ${aside:-<none>} — remove it once the restore is confirmed good."
