#!/usr/bin/env bash
# ccdc_startup_hardening.sh
# CCDC-friendly startup hardening for a Splunk Linux box (single-host backups, no snapshots/remote).
# Designed to be RUN AS ROOT at boot via systemd, but safe to run manually as sysadmin with sudo.

set -Eeuo pipefail

############################
# Config (edit as needed)
############################
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"

# Where to store local backups (two locations to survive easy wipe attempts)
BKP_PRIMARY="${BKP_PRIMARY:-/var/backups/.ccdc_hidden}"
BKP_SECONDARY="${BKP_SECONDARY:-/usr/local/lib/.cache/.systemd-helper}"

# What to back up (keep small + scoring-relevant)
BACKUP_PATHS=(
  "${SPLUNK_HOME}/etc"
  "/etc"
  "/var/spool/cron"
  "/etc/systemd/system"
  "/root"
  "/home"
)

# Ports you expect to be open (tune to your environment)
# Common Splunk: 8000 (web), 8089 (mgmt), 9997 (forwarders), 514 (syslog)
APPROVED_LISTEN_PORTS_REGEX="${APPROVED_LISTEN_PORTS_REGEX:-^(8000|8089|9997|514)$}"

# Containment mode:
# 0 = observe-only (recommended default)
# 1 = mild containment (stop clearly suspicious containers)
# 2 = aggressive containment (also disables unknown systemd units matching obvious bad patterns)
CONTAIN="${CONTAIN:-0}"

# Simple "bad smell" patterns (expand cautiously)
SUS_PROC_REGEX="${SUS_PROC_REGEX:-/dev/shm|/tmp|base64|curl |wget |socat|nc |ncat|bash -i|/dev/tcp|python -c|perl -e|ruby -e}"

LOG_DIR="${LOG_DIR:-/var/log}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/ccdc_startup_hardening.log}"

TS="$(date +%F_%H%M%S)"
HOST="$(hostname -f 2>/dev/null || hostname)"
RUN_DIR="/root/quarantine/${TS}"
MANIFEST="${RUN_DIR}/manifest.txt"

############################
# Helpers
############################
need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Please run as root (or: sudo -E $0) so checks and backups are complete." >&2
    exit 1
  fi
}

log() {
  local msg="[$(date -Is)] $*"
  echo "$msg" | tee -a "$LOG_FILE" >/dev/null
  logger -t ccdc-hardening "$msg" 2>/dev/null || true
}

section() {
  log "==================== $* ===================="
}

run() {
  local name="$1"; shift
  log "RUN: $name"
  {
    echo "---- $name ----"
    "$@"
    echo
  } >>"$LOG_FILE" 2>&1 || log "WARN: $name failed"
}

safe_mkdir() {
  mkdir -p "$1"
  chmod 700 "$1" || true
}

hash_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f"
  else
    echo "NOHASH $f"
  fi
}

############################
# Main
############################
need_root
umask 077

safe_mkdir "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE" || true

safe_mkdir "$RUN_DIR"
touch "$MANIFEST"
chmod 600 "$MANIFEST" || true

log "Start hardening run on ${HOST} as UID=${EUID}. CONTAIN=${CONTAIN}"
log "Tip: Operate day-to-day as 'sysadmin' and use sudo for root tasks; avoid staying in a root shell."

section "BOOT BASELINE (capture evidence first)"
run "system_basics" bash -c 'uname -a; uptime; who -b; date -Is'
run "who_w_last" bash -c 'who -a || true; w || true; last -a | head -n 30 || true'
run "recent_journal" bash -c 'journalctl -b --no-pager -n 300 || true'
run "recent_sshd" bash -c 'journalctl -b _SYSTEMD_UNIT=sshd.service --no-pager -n 200 || true'

section "NETWORK TRIAGE (reverse shells / active access)"
run "listeners_ss" bash -c 'ss -tulpn || true'
run "established_ss" bash -c 'ss -tpn state established || true'
run "dns_routes" bash -c 'resolvectl status 2>/dev/null || cat /etc/resolv.conf; ip route || true'
run "open_ports_suspects" bash -c \
  "ss -tulpnH 2>/dev/null | awk '{print \$5\" \"\$7}' | sed 's/.*://;s/\"//g' | \
   awk '{print \$1}' | sort -n | uniq -c | sort -nr | head -n 30 || true"

# Highlight non-approved listeners (does NOT kill anything)
section "NON-APPROVED LISTENERS (review these first)"
run "non_approved_listeners" bash -c \
  "ss -tulpnH 2>/dev/null | awk '{print \$5\" \"\$7\" \"\$1\" \"\$4}' | \
   sed -E 's/.*:([0-9]+) .*/\\1 &/' | \
   awk '{port=\$1; \$1=\"\"; sub(/^ /,\"\"); if (port !~ /${APPROVED_LISTEN_PORTS_REGEX}/) print \"PORT=\"port\" | \"\$0; }' || true"

section "PROCESS TRIAGE (quick wins)"
run "ps_suspects" bash -c "ps auxfww | egrep -i \"${SUS_PROC_REGEX}\" || true"
run "ps_top_cpu" bash -c 'ps auxfww --sort=-%cpu | head -n 40'
run "ps_top_mem" bash -c 'ps auxfww --sort=-%mem | head -n 40'

section "SYSTEMD PERSISTENCE (services + timers)"
run "systemd_running" bash -c 'systemctl --no-pager --type=service --state=running || true'
run "systemd_timers" bash -c 'systemctl list-timers --all --no-pager || true'
run "systemd_local_units" bash -c 'find /etc/systemd/system -maxdepth 2 -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) -print 2>/dev/null || true'
run "systemd_sus_grep" bash -c \
  'grep -RIn --color=never -E "(curl|wget|base64|/dev/tcp|bash -i|nc |ncat|socat|python -c|perl -e)" /etc/systemd/system 2>/dev/null || true'

section "CRON / AT PERSISTENCE"
run "root_crontab" bash -c 'crontab -l -u root || true'
run "user_crons" bash -c 'ls -la /var/spool/cron 2>/dev/null || true'
run "etc_cron_dirs" bash -c 'ls -la /etc/cron* 2>/dev/null || true'
run "cron_sus_grep" bash -c \
  'grep -RIn --color=never -E "(curl|wget|bash -i|nc |ncat|/dev/tcp|python -c|perl -e|socat|base64|chmod \+x)" /etc/cron* /var/spool/cron 2>/dev/null || true'
run "at_jobs" bash -c 'command -v atq >/dev/null && atq || true'

section "CONTAINERS (C2 containers: docker/podman)"
run "podman_ps" bash -c 'command -v podman >/dev/null && podman ps -a --no-trunc || true'
run "podman_images" bash -c 'command -v podman >/dev/null && podman images || true'
run "docker_ps" bash -c 'command -v docker >/dev/null && docker ps -a --no-trunc || true'
run "docker_images" bash -c 'command -v docker >/dev/null && docker images || true'

# Mild containment: stop containers that look obviously malicious by name/image/cmdline patterns
if [[ "$CONTAIN" -ge 1 ]]; then
  section "CONTAINMENT: containers (mild)"
  # Podman
  if command -v podman >/dev/null 2>&1; then
    while read -r cid name image cmd; do
      [[ -z "${cid:-}" ]] && continue
      if echo "$name $image $cmd" | egrep -qi "(c2|beacon|meterpreter|reverse|shell|kali|empire|sliver|cobalt|msf|netcat|ncat|socat)"; then
        log "Contain: stopping suspicious podman container: $cid $name $image"
        podman stop "$cid" >>"$LOG_FILE" 2>&1 || true
      fi
    done < <(podman ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Command}}' 2>/dev/null || true)
  fi
  # Docker
  if command -v docker >/dev/null 2>&1; then
    while read -r cid name image cmd; do
      [[ -z "${cid:-}" ]] && continue
      if echo "$name $image $cmd" | egrep -qi "(c2|beacon|meterpreter|reverse|shell|kali|empire|sliver|cobalt|msf|netcat|ncat|socat)"; then
        log "Contain: stopping suspicious docker container: $cid $name $image"
        docker stop "$cid" >>"$LOG_FILE" 2>&1 || true
      fi
    done < <(docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Command}}' 2>/dev/null || true)
  fi
else
  section "CONTAINMENT: disabled (observe-only)"
  log "Set CONTAIN=1 (mild) or CONTAIN=2 (aggressive) via systemd Environment=CONTAIN=1"
fi

section "PROMPT / PROFILE PERSISTENCE (avoid root interactive shells)"
run "env_prompt_vars" bash -c 'printenv | egrep -i "PROMPT_COMMAND|BASH_ENV|ENV=" || true'
run "grep_prompt_system" bash -c 'grep -RIn --color=never -E "PROMPT_COMMAND|BASH_ENV|/dev/tcp|curl|wget|base64" /etc/profile /etc/profile.d /etc/bashrc /etc/bash* 2>/dev/null || true'
run "grep_prompt_users" bash -c 'grep -RIn --color=never -E "PROMPT_COMMAND|BASH_ENV|/dev/tcp|curl|wget|base64" /home/*/.*bash* /root/.*bash* 2>/dev/null || true'

section "ROOTKIT / INTEGRITY QUICK CHECKS (last)"
run "lsmod" bash -c 'lsmod | head -n 200 || true'
run "dmesg_tail" bash -c 'dmesg -T | tail -n 120 || true'
run "rpm_verify_sample" bash -c 'command -v rpm >/dev/null && rpm -Va --nomtime --nosize --nodigest 2>/dev/null | head -n 200 || true'

########################################
# LOCAL BACKUPS (single-box strategy)
########################################
section "BACKUPS (single-box: two locations + hashes + immutability best-effort)"

safe_mkdir "$BKP_PRIMARY"
safe_mkdir "$BKP_SECONDARY"

# Build tar includes list (skip missing paths cleanly)
INCLUDES=()
for p in "${BACKUP_PATHS[@]}"; do
  if [[ -e "$p" ]]; then
    INCLUDES+=("$p")
  else
    log "Backup skip (missing): $p"
  fi
done

BACKUP_NAME="${HOST}_ccdc_backup_${TS}.tar.gz"
TMP_TAR="${RUN_DIR}/${BACKUP_NAME}"

# Create tarball in RUN_DIR first (then copy into both backup dirs)
if [[ "${#INCLUDES[@]}" -gt 0 ]]; then
  log "Creating backup tarball: ${TMP_TAR}"
  # Use -P to preserve absolute paths; OK for restore (tar -xzf ... -C /)
  tar -czPf "$TMP_TAR" "${INCLUDES[@]}" >>"$LOG_FILE" 2>&1 || log "WARN: tar creation had errors"
else
  log "WARN: No includes exist; skipping tar creation."
fi

# Hash + manifest
if [[ -f "$TMP_TAR" ]]; then
  log "Hashing backup tarball"
  hash_file "$TMP_TAR" | tee -a "$MANIFEST" >>"$LOG_FILE" 2>&1

  log "Copying backup to primary + secondary"
  cp -f "$TMP_TAR" "${BKP_PRIMARY}/${BACKUP_NAME}"
  cp -f "$TMP_TAR" "${BKP_SECONDARY}/${BACKUP_NAME}"

  # Keep a symlink to "latest" in each location
  ln -sfn "${BKP_PRIMARY}/${BACKUP_NAME}" "${BKP_PRIMARY}/LATEST.tar.gz"
  ln -sfn "${BKP_SECONDARY}/${BACKUP_NAME}" "${BKP_SECONDARY}/LATEST.tar.gz"

  # Best-effort: make dirs immutable so casual tampering fails (root can still undo, but it’s noisy)
  if command -v chattr >/dev/null 2>&1; then
    log "Applying best-effort immutability"
    chattr +i "$BKP_PRIMARY" 2>>"$LOG_FILE" || true
    chattr +i "$BKP_SECONDARY" 2>>"$LOG_FILE" || true
    chattr +a "$LOG_FILE" 2>>"$LOG_FILE" || true
    # Record attributes so you can detect removal later
    lsattr -d "$BKP_PRIMARY" "$BKP_SECONDARY" >>"$LOG_FILE" 2>&1 || true
  else
    log "chattr not available; skipping immutability"
  fi

  # Rotate old backups (keep last 10 in each location)
  log "Rotating backups (keep last 10)"
  ls -1t "${BKP_PRIMARY}"/*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
  ls -1t "${BKP_SECONDARY}"/*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
else
  log "WARN: No tarball produced; no backups copied."
fi

section "RESTORE QUICK COMMANDS (for you, not auto-run)"
log "To restore Splunk etc only (safer):  tar -xzPf ${BKP_PRIMARY}/LATEST.tar.gz ${SPLUNK_HOME}/etc"
log "To restore everything (risky):      tar -xzPf ${BKP_PRIMARY}/LATEST.tar.gz -C /"
log "Reminder: operate as sysadmin; use sudo for root tasks; avoid staying logged in as root."

log "DONE. Evidence/quarantine dir: ${RUN_DIR}"
exit 0