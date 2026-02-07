#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Oracle Linux 9 + Splunk Backup
# -----------------------------

# Edit these if your environment differs
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_USER="${SPLUNK_USER:-splunk}"

# Standard backup location on OL9
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/splunk}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

# If you want to include indexed data (can be VERY large), set to 1
INCLUDE_INDEXES="${INCLUDE_INDEXES:-0}"

# -----------------------------
TS="$(date +%F_%H%M%S)"
HOST="$(hostname -s 2>/dev/null || hostname)"
DEST_DIR="${BACKUP_ROOT}/${HOST}"
ARCHIVE="${DEST_DIR}/splunk_backup_${HOST}_${TS}.tar.gz"
LOG_TAG="splunk-backup"

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$(date -Is)] $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }; }

need_cmd tar
need_cmd gzip
need_cmd logger
need_cmd find
need_cmd install
need_cmd id

if [[ ! -d "$SPLUNK_HOME" ]]; then
  echo "SPLUNK_HOME not found: $SPLUNK_HOME" >&2
  exit 1
fi

# Create backup directory with tight perms
install -d -m 0700 -o root -g root "$DEST_DIR"

log "Starting backup. SPLUNK_HOME=$SPLUNK_HOME ARCHIVE=$ARCHIVE INCLUDE_INDEXES=$INCLUDE_INDEXES"

# Optional: KV store backup (best-effort)
KV_BACKUP_DIR=""
if [[ -x "${SPLUNK_HOME}/bin/splunk" ]] && id "$SPLUNK_USER" >/dev/null 2>&1; then
  KV_BACKUP_DIR="${DEST_DIR}/kvstore_${TS}"
  install -d -m 0700 -o root -g root "$KV_BACKUP_DIR"

  if sudo -n -u "$SPLUNK_USER" "${SPLUNK_HOME}/bin/splunk" help backup kvstore >/dev/null 2>&1; then
    log "Attempting KV store backup into $KV_BACKUP_DIR"
    if sudo -n -u "$SPLUNK_USER" "${SPLUNK_HOME}/bin/splunk" backup kvstore \
        -archiveName "kvstore_${TS}" -backupDir "$KV_BACKUP_DIR" >/dev/null 2>&1; then
      log "KV store backup succeeded."
    else
      log "KV store backup failed (continuing)."
      rm -rf "$KV_BACKUP_DIR" || true
      KV_BACKUP_DIR=""
    fi
  else
    rm -rf "$KV_BACKUP_DIR" || true
    KV_BACKUP_DIR=""
  fi
fi

# What to back up (high-value recovery items)
INCLUDE_PATHS=(
  "etc"                 # configs, apps, auth, inputs, outputs, deployment configs
  "var/run/splunk"       # small runtime state
)

# Exclude noisy/large by default
TAR_EXCLUDES=(
  "--exclude=${SPLUNK_HOME}/var/cache"
  "--exclude=${SPLUNK_HOME}/var/log"
  "--exclude=${SPLUNK_HOME}/var/spool"
  "--exclude=${SPLUNK_HOME}/var/tmp"
)

# Indexes are in var/lib/splunk by default
if [[ "$INCLUDE_INDEXES" != "1" ]]; then
  TAR_EXCLUDES+=("--exclude=${SPLUNK_HOME}/var/lib/splunk")
else
  INCLUDE_PATHS+=("var/lib/splunk")
fi

# Include KV backup output if created
EXTRA_INCLUDE=()
if [[ -n "$KV_BACKUP_DIR" ]]; then
  EXTRA_INCLUDE+=("$KV_BACKUP_DIR")
fi

# Create archive
tar -czf "$ARCHIVE" \
  "${TAR_EXCLUDES[@]}" \
  -C "$SPLUNK_HOME" \
  "${INCLUDE_PATHS[@]}" \
  "${EXTRA_INCLUDE[@]}" 2>/dev/null

chmod 0600 "$ARCHIVE"
chown root:root "$ARCHIVE"

# Retention cleanup
find "$DEST_DIR" -type f -name "splunk_backup_${HOST}_*.tar.gz" -mtime "+$RETENTION_DAYS" -print -delete >/dev/null 2>&1 || true

log "Backup complete: $ARCHIVE"
echo "Backup created: $ARCHIVE"
