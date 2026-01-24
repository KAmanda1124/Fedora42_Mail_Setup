#!/bin/bash
# Scans shell history files and (optionally) system logs for suspicious command patterns.

set -u

SUSPICIOUS=false
TMP_REPORT="$(mktemp)"
trap 'rm -f "$TMP_REPORT"' EXIT

echo "Checking for suspicious prompt/command activity..."
echo "---------------------------------------------------"

# Patterns commonly seen in compromises
PATTERN='(curl[^|]*\|\s*(bash|sh))|(wget[^|]*\|\s*(bash|sh))|(/dev/tcp/)|(\bnc\b.*\s-e\s)|(\bsocat\b)|(\bpython\b.*-c)|(\bperl\b.*-e)|(\bphp\b.*-r)|(\bbase64\b.*(-d|--decode))|(\bchmod\b.*\+x)|(\bchattr\b.*\+i)|(\bsetcap\b)|(\buseradd\b|\badduser\b)|(\busermod\b)|(\bpasswd\b)|(\bcrontab\b)|(/etc/cron)|(\bsystemctl\b.*(enable|start))|(\bnohup\b)|(\bmkfifo\b)|(\biptables\b)|(\bssh\b.*-R\s)|(\bssh\b.*-D\s)|(\bauthorize(d)?_keys\b)|(\bscp\b|\brsync\b)|(\bnmap\b)|(\bnetcat\b)|(\btcpdump\b)|(\bstrings\b)|(\bld_preload\b)|(\bexport\b.*LD_)'

# Helper: scan a file for patterns, print matching lines with context
scan_file() {
  local f="$1"
  local label="$2"

  [[ -r "$f" ]] || return 0

  local matches
  matches="$(grep -Ein "$PATTERN" "$f" 2>/dev/null | tail -n 50 || true)"
  if [[ -n "$matches" ]]; then
    echo "[!] Suspicious-looking entries in $label: $f" | tee -a "$TMP_REPORT"
    echo "$matches" | tee -a "$TMP_REPORT"
    echo "" | tee -a "$TMP_REPORT"
    SUSPICIOUS=true
  fi
}

# 1) Scan common shell history locations for current user + root (if readable)
declare -a HISTORY_FILES=()

# Current user
[[ -n "${HOME:-}" ]] && HISTORY_FILES+=(
  "$HOME/.bash_history"
  "$HOME/.zsh_history"
  "$HOME/.sh_history"
  "$HOME/.ash_history"
  "$HOME/.local/share/fish/fish_history"
)

# Root (may require sudo to read)
HISTORY_FILES+=(
  "/root/.bash_history"
  "/root/.zsh_history"
  "/root/.sh_history"
  "/root/.local/share/fish/fish_history"
)

echo "[*] Scanning shell history files..."
for f in "${HISTORY_FILES[@]}"; do
  scan_file "$f" "history"
done

# 2) Scan other users' history files (best-effort)
echo "[*] Scanning other users' history files (best-effort)..."
if [[ -d /home ]]; then
  while IFS= read -r -d '' f; do
    scan_file "$f" "user history"
  done < <(find /home -maxdepth 2 -type f \( -name ".bash_history" -o -name ".zsh_history" -o -name ".sh_history" -o -name "fish_history" \) -print0 2>/dev/null || true)
fi

# 3) Optional: scan recent sudo/ssh activity from journal (if available)
echo "[*] Scanning recent sudo/ssh events from journald (last 48h)..."
if command -v journalctl >/dev/null 2>&1; then
  # You may need sudo for full visibility; still works partially without it
  JMATCH="$(journalctl --since "48 hours ago" 2>/dev/null | grep -Ein "(sudo:|sshd\[|COMMAND=)" | grep -Ein "$PATTERN" | tail -n 50 || true)"
  if [[ -n "$JMATCH" ]]; then
    echo "[!] Suspicious-looking sudo/ssh log entries (last 48h):" | tee -a "$TMP_REPORT"
    echo "$JMATCH" | tee -a "$TMP_REPORT"
    echo "" | tee -a "$TMP_REPORT"
    SUSPICIOUS=true
  fi
else
  echo "[-] journalctl not found; skipping journald scan."
fi

# Summary / message
echo "---------------------------------------------------"
if [[ "$SUSPICIOUS" == true ]]; then
  echo "You may want to look into this..."
  echo ""
  echo "Top hits (saved in-memory for this run):"
  cat "$TMP_REPORT"
else
  echo "No obvious suspicious command patterns found in scanned sources."
fi
