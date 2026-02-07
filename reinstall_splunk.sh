#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Reinstall Splunk systemd service
# Oracle Linux 9
# -----------------------------

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_USER="${SPLUNK_USER:-splunk}"
SERVICE_NAME="splunk"

log() {
  echo "[$(date -Is)] $*"
}

# Sanity checks
if [[ ! -x "${SPLUNK_HOME}/bin/splunk" ]]; then
  echo "ERROR: splunk binary not found at ${SPLUNK_HOME}/bin/splunk"
  exit 1
fi

if ! id "$SPLUNK_USER" >/dev/null 2>&1; then
  echo "ERROR: splunk user '$SPLUNK_USER' does not exist"
  exit 1
fi

log "Stopping Splunk (if running)"
sudo -u "$SPLUNK_USER" "${SPLUNK_HOME}/bin/splunk" stop || true

log "Disabling existing systemd service (if present)"
systemctl disable splunk.service 2>/dev/null || true

log "Removing old systemd unit file (if present)"
rm -f /etc/systemd/system/splunk.service
rm -f /usr/lib/systemd/system/splunk.service

log "Recreating systemd service using Splunk"
"${SPLUNK_HOME}/bin/splunk" enable boot-start \
  -user "$SPLUNK_USER" \
  --accept-license --answer-yes --no-prompt

log "Reloading systemd"
systemctl daemon-reexec
systemctl daemon-reload

log "Starting Splunk service"
systemctl start splunk.service

log "Checking Splunk service status"
systemctl status splunk.service --no-pager

log "Splunk service reinstall complete"
