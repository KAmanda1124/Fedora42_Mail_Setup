#!/bin/bash
# detect_rootkit_indicators.sh
# Purpose: Best-effort rootkit indicator checks (read-only).
# Output: Lists suspicious findings with reasons.
# Note: This does NOT prove a rootkit. It highlights leads to investigate.

set -u

ALERT=false
REPORT="$(mktemp)"
trap 'rm -f "$REPORT"' EXIT

add_finding() {
  local category="$1"
  local reason="$2"
  local detail="${3:-}"
  ALERT=true
  echo "CATEGORY: $category" >> "$REPORT"
  echo "REASON:   $reason" >> "$REPORT"
  if [[ -n "$detail" ]]; then
    echo "DETAIL:   $detail" >> "$REPORT"
  fi
  echo "----" >> "$REPORT"
}

echo "Rootkit indicator scan starting..."
echo "Host:   $(hostname 2>/dev/null || echo unknown)"
echo "Kernel: $(uname -a 2>/dev/null || echo unknown)"
echo

# 1) Kernel taint / secure boot / lockdown indicators (context, not always malicious)
if [[ -r /proc/sys/kernel/tainted ]]; then
  taint="$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "")"
  if [[ -n "$taint" && "$taint" != "0" ]]; then
    add_finding "KERNEL_TAINT" "Kernel is tainted (non-zero). Can indicate unsigned/out-of-tree modules or other abnormal conditions." "tainted=$taint"
  fi
fi

# 2) Suspicious kernel module names (heuristic)
if command -v lsmod >/dev/null 2>&1; then
  mods="$(lsmod 2>/dev/null || true)"
  sus_mods="$(echo "$mods" | awk 'NR>1{print $1}' | grep -Eis '(^|_)(rootkit|rkit|hide|stealth|keylog|sniff|backdoor|reptile|diamorphine)($|_)' || true)"
  if [[ -n "$sus_mods" ]]; then
    add_finding "KERNEL_MODULE_NAME" "Loaded kernel module name matches suspicious keywords (heuristic)." "$sus_mods"
  fi
else
  add_finding "TOOLING" "lsmod not found; cannot list kernel modules." "Install kmod tools or ensure PATH includes lsmod."
fi

# 3) Module load path anomalies (modules not under /lib/modules/<kernel>/)
if command -v lsmod >/dev/null 2>&1 && command -v modinfo >/dev/null 2>&1; then
  while read -r mod; do
    [[ -z "$mod" ]] && continue
    path="$(modinfo -n "$mod" 2>/dev/null || true)"
    if [[ -n "$path" && "$path" != /lib/modules/* ]]; then
      add_finding "KERNEL_MODULE_PATH" "Module file path is non-standard (not under /lib/modules). Investigate origin and signing." "$mod -> $path"
    fi
  done < <(lsmod 2>/dev/null | awk 'NR>1{print $1}')
fi

# 4) Hidden process heuristic: /proc PID directories vs `ps` count delta
proc_count="$(ls -1 /proc 2>/dev/null | grep -E '^[0-9]+$' | wc -l | awk '{print $1}')"
ps_count_raw="$(ps -e 2>/dev/null | wc -l | awk '{print $1}')"
ps_count=$ps_count_raw
if [[ "$ps_count" -gt 0 ]]; then ps_count=$((ps_count - 1)); fi

# Large deltas can occur, but very large persistent gaps can be suspicious
delta=$((proc_count - ps_count))
if [[ "$delta" -gt 75 ]]; then
  add_finding "PROCESS_MISMATCH" "Large mismatch between /proc PID dirs and ps output. Could indicate hidden processes or very short-lived process churn." "/proc=$proc_count ps=$ps_count delta=$delta"
fi

# 5) Check critical binaries for dangerous permissions and path oddities
critical_bins=(
  /bin/ps /usr/bin/ps
  /bin/ls /usr/bin/ls
  /usr/bin/grep
  /usr/bin/find
  /usr/bin/ss /bin/ss
  /usr/bin/netstat /bin/netstat
  /usr/bin/top /bin/top
  /usr/bin/ssh
  /usr/sbin/sshd
)

for b in "${critical_bins[@]}"; do
  if [[ -e "$b" ]]; then
    meta="$(stat -c '%a %U %G %n' "$b" 2>/dev/null || true)"
    mode="$(echo "$meta" | awk '{print $1}')"
    owner="$(echo "$meta" | awk '{print $2}')"
    # World-writable critical binaries are highly suspicious
    last="${mode: -1}"
    if [[ "$last" =~ [2367] ]]; then
      add_finding "BINARY_PERMS" "Critical binary is writable by 'others' (world-writable). This is highly abnormal." "$meta"
    fi
    # Non-root owned critical binaries are suspicious on most systems
    if [[ "$owner" != "root" ]]; then
      add_finding "BINARY_OWNERSHIP" "Critical binary not owned by root. This is abnormal on most systems." "$meta"
    fi
  fi
done

# 6) Check for LD_PRELOAD style persistence
# /etc/ld.so.preload is a common userland hooking technique
if [[ -e /etc/ld.so.preload ]]; then
  if [[ -s /etc/ld.so.preload ]]; then
    content="$(cat /etc/ld.so.preload 2>/dev/null | sed 's/[[:space:]]\+$//' || true)"
    add_finding "LD_PRELOAD" "/etc/ld.so.preload exists and is non-empty. This is often used for userland hooking." "$content"
  else
    add_finding "LD_PRELOAD" "/etc/ld.so.preload exists (empty). Presence alone can be non-standard depending on environment." "File exists but is empty."
  fi
fi

# 7) RPM verification (Fedora/RHEL-like) for tampered packages/binaries
# Only runs if rpm is present. This can be slow.
if command -v rpm >/dev/null 2>&1; then
  # Focus on high-value packages first; expand if you want broader coverage
  pkgs=(bash coreutils procps-ng util-linux openssh-server openssh-clients iproute grep findutils systemd)
  for p in "${pkgs[@]}"; do
    if rpm -q "$p" >/dev/null 2>&1; then
      out="$(rpm -V "$p" 2>/dev/null || true)"
      # rpm -V prints lines when verification fails
      if [[ -n "$out" ]]; then
        add_finding "RPM_VERIFY" "Package verification reports changes. Could be updates, local modifications, or tampering. Review each file listed." "package=$p\n$out"
      fi
    fi
  done
fi

# 8) Check for common userland rootkit artifacts (heuristic file names)
# These are not definitive, but worth flagging.
artifact_paths=(
  /dev/.udev
  /dev/.initramfs
  /dev/.rc
  /usr/bin/.../.
  /lib/.hidden
  /usr/local/bin/.*
)

for ap in "${artifact_paths[@]}"; do
  # Use globbing carefully
  for p in $ap; do
    if [[ -e "$p" ]]; then
      add_finding "ARTIFACT" "Potentially suspicious hidden/odd artifact path exists (heuristic)." "$p"
    fi
  done
done

# 9) Kernel messages for module/load anomalies (best-effort)
if command -v dmesg >/dev/null 2>&1; then
  dm="$(dmesg 2>/dev/null | tail -n 300 | grep -Ei '(taint|module verification failed|signature|Lockdown|denied|BPF|kprobe|ftrace)' || true)"
  if [[ -n "$dm" ]]; then
    add_finding "DMESG_HINTS" "Recent kernel messages include keywords that can be relevant to tampering/modules (not always malicious)." "$dm"
  fi
fi

echo "Scan complete."
echo

if [[ "$ALERT" == true ]]; then
  echo "UH OH something doesn't look right"
  echo
  echo "Suspiciousness list (what was flagged and why):"
  cat "$REPORT"
else
  echo "No strong rootkit indicators were flagged by these heuristics."
  echo "This is not a guarantee of a clean system; it only means nothing matched these checks."
fi
