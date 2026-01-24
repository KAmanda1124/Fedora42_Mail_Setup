#!/bin/bash
# detect_nonstandard_cron.sh
# Flags suspicious AND "non-standard" cron/timer persistence indicators.

set -u

SUSPICIOUS=false
NONSTANDARD=false
TMP_REPORT="$(mktemp)"
trap 'rm -f "$TMP_REPORT"' EXIT

echo "Checking cron jobs & timers for suspicious / non-standard persistence..."
echo "-----------------------------------------------------------"

# High-signal suspicious patterns
SUSP_PATTERN='(curl[^|]*\|\s*(bash|sh))|(wget[^|]*\|\s*(bash|sh))|(\bbase64\b.*(-d|--decode))|(/dev/tcp/)|(\bnc\b.*\s-e\s)|(\bsocat\b)|(\bpython\b.*-c)|(\bperl\b.*-e)|(\bphp\b.*-r)|(\bnohup\b)|(\bmkfifo\b)|(/tmp/)|(/dev/shm/)|(/var/tmp/)|(\.ssh/authorized_keys)|(\bchattr\b.*\+i)|(\bLD_PRELOAD\b)|(\biptables\b)|(\b(crontab|at)\b)'

# Paths that are commonly "non-standard" for system cron execution
# (Often writable, user-controlled, or staging areas)
NONSTD_PATHS='(/tmp/|/dev/shm/|/var/tmp/|/run/user/|/home/|/mnt/|/media/|/srv/|/opt/[^/]+/tmp|/root/[^/]+/tmp)'

# Helper: report lines with labels
report() {
  local level="$1"   # INFO/WARN/SUSP/NONSTD
  local msg="$2"
  echo "[$level] $msg" | tee -a "$TMP_REPORT"
}

# Check file metadata for "non-standard" perms/ownership
check_file_meta() {
  local f="$1"
  [[ -e "$f" ]] || return 0

  # Use stat; portable-ish format
  local meta owner group mode
  meta="$(stat -c '%U %G %a %n' "$f" 2>/dev/null || true)"
  [[ -n "$meta" ]] || return 0

  owner="$(echo "$meta" | awk '{print $1}')"
  group="$(echo "$meta" | awk '{print $2}')"
  mode="$(echo "$meta" | awk '{print $3}')"

  # World-writable (others write bit)
  # mode is like 644 / 777; last digit >=2 means writable by others.
  local last_digit="${mode: -1}"
  if [[ "$last_digit" =~ [2367] ]]; then
    report "NONSTD" "World-writable cron file: $meta"
    NONSTANDARD=true
  fi

  # For system cron locations, expect root ownership
  if [[ "$f" == /etc/cron* || "$f" == /etc/crontab || "$f" == /etc/anacrontab || "$f" == /var/spool/cron* ]]; then
    if [[ "$owner" != "root" ]]; then
      report "NONSTD" "Non-root ownership for system cron file: $meta"
      NONSTANDARD=true
    fi
  fi
}

# Scan file content for suspicious patterns and non-standard execution paths
scan_file_content() {
  local f="$1"
  local label="$2"
  [[ -r "$f" ]] || return 0

  # Suspicious patterns
  local susp
  susp="$(grep -Ein "$SUSP_PATTERN" "$f" 2>/dev/null | tail -n 120 || true)"
  if [[ -n "$susp" ]]; then
    report "SUSP" "Suspicious entries in $label: $f"
    echo "$susp" | tee -a "$TMP_REPORT"
    report "INFO" ""
    SUSPICIOUS=true
  fi

  # Non-standard execution paths (even if not matching the high-signal pattern)
  local nonstd
  nonstd="$(grep -Ein "$NONSTD_PATHS" "$f" 2>/dev/null | tail -n 120 || true)"
  if [[ -n "$nonstd" ]]; then
    report "NONSTD" "Cron references non-standard/writable paths in $label: $f"
    echo "$nonstd" | tee -a "$TMP_REPORT"
    report "INFO" ""
    NONSTANDARD=true
  fi
}

# Scan a string (e.g., crontab -l output)
scan_text() {
  local label="$1"
  local content="$2"

  if echo "$content" | grep -Ein "$SUSP_PATTERN" >/dev/null 2>&1; then
    report "SUSP" "Suspicious entries in $label:"
    echo "$content" | grep -Ein "$SUSP_PATTERN" | tail -n 120 | tee -a "$TMP_REPORT"
    report "INFO" ""
    SUSPICIOUS=true
  fi

  if echo "$content" | grep -Ein "$NONSTD_PATHS" >/dev/null 2>&1; then
    report "NONSTD" "Non-standard/writable path usage in $label:"
    echo "$content" | grep -Ein "$NONSTD_PATHS" | tail -n 120 | tee -a "$TMP_REPORT"
    report "INFO" ""
    NONSTANDARD=true
  fi
}

# Check for very high frequency cron schedules (every minute / */1)
flag_high_frequency() {
  local label="$1"
  local content="$2"
  local freq
  freq="$(echo "$content" | grep -Ein '(^|\s)(\*\s+\*\s+\*\s+\*\s+\*)|(\*/1\s)' | tail -n 120 || true)"
  if [[ -n "$freq" ]]; then
    report "NONSTD" "High-frequency schedule (every minute) found in $label:"
    echo "$freq" | tee -a "$TMP_REPORT"
    report "INFO" ""
    NONSTANDARD=true
  fi
}

# 1) System-wide crontab + cron directories
echo "[*] Scanning system cron files..."
for f in /etc/crontab /etc/anacrontab; do
  if [[ -e "$f" ]]; then
    check_file_meta "$f"
    scan_file_content "$f" "system cron"
  fi
done

for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d "$d" ]]; then
    while IFS= read -r -d '' f; do
      check_file_meta "$f"
      scan_file_content "$f" "$d"

      # Non-standard: scripts in cron.* should generally be executable (especially daily/hourly)
      if [[ "$d" =~ /etc/cron\.(daily|hourly|weekly|monthly) ]]; then
        if [[ ! -x "$f" ]]; then
          report "NONSTD" "Non-executable script in $d: $f (unexpected for cron.* directories)"
          NONSTANDARD=true
        fi
      fi
    done < <(find "$d" -maxdepth 1 -type f -print0 2>/dev/null || true)
  fi
done

# 2) Per-user crontabs
echo "[*] Scanning per-user crontabs (best-effort)..."
if command -v crontab >/dev/null 2>&1; then
  CUR_USER_CRON="$(crontab -l 2>/dev/null || true)"
  if [[ -n "$CUR_USER_CRON" ]]; then
    scan_text "current user crontab" "$CUR_USER_CRON"
    flag_high_frequency "current user crontab" "$CUR_USER_CRON"
  fi

  ROOT_CRON="$(crontab -u root -l 2>/dev/null || true)"
  if [[ -n "$ROOT_CRON" ]]; then
    scan_text "root crontab" "$ROOT_CRON"
    flag_high_frequency "root crontab" "$ROOT_CRON"
  fi
else
  report "WARN" "crontab command not found; skipping crontab -l checks."
fi

# Cron spools (varies by distro)
for spool in /var/spool/cron /var/spool/cron/crontabs; do
  if [[ -d "$spool" ]]; then
    while IFS= read -r -d '' f; do
      check_file_meta "$f"
      scan_file_content "$f" "cron spool ($spool)"
    done < <(find "$spool" -type f -print0 2>/dev/null || true)
  fi
done

# 3) Systemd timers (non-standard often = custom units in /etc/systemd/system or user units)
echo "[*] Checking systemd timers..."
if command -v systemctl >/dev/null 2>&1; then
  TIMERS="$(systemctl list-timers --all 2>/dev/null || true)"
  if [[ -n "$TIMERS" ]]; then
    # Flag suspicious timer names (heuristic)
    if echo "$TIMERS" | grep -Eiq "(payload|agent|backdoor|miner|update.*\.timer|sync.*\.timer|\.cache|tmp|shm|run)"; then
      report "NONSTD" "Systemd timer list includes potentially suspicious keywords:"
      echo "$TIMERS" | grep -Ei "(payload|agent|backdoor|miner|update.*\.timer|sync.*\.timer|\.cache|tmp|shm|run)" | tee -a "$TMP_REPORT"
      report "INFO" ""
      NONSTANDARD=true
    fi
  fi

  # Look for custom timer/service unit files (often persistence lives here)
  for unitdir in /etc/systemd/system /usr/local/lib/systemd/system; do
    if [[ -d "$unitdir" ]]; then
      # Any timers here are inherently more "non-standard" than vendor units in /usr/lib/systemd/system
      while IFS= read -r -d '' u; do
        check_file_meta "$u"
        # Scan unit content for suspicious patterns/paths
        scan_file_content "$u" "custom systemd unit"
        NONSTANDARD=true
        report "NONSTD" "Custom unit present (non-vendor location): $u"
      done < <(find "$unitdir" -maxdepth 1 -type f \( -name "*.timer" -o -name "*.service" \) -print0 2>/dev/null || true)
    fi
  done
else
  report "WARN" "systemctl not found; skipping systemd timer checks."
fi

echo "-----------------------------------------------------------"
if [[ "$SUSPICIOUS" == true || "$NONSTANDARD" == true ]]; then
  echo "Timey-wimey stuff... you might want to look at that"
  echo ""
  echo "Findings:"
  cat "$TMP_REPORT"
else
  echo "No suspicious or clearly non-standard cron/timer indicators found."
fi
