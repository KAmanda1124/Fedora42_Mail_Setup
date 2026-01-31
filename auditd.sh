!# /bin/bash

#!/usr/bin/env bash
# auditd_setup.sh
# Purpose: Install/enable auditd and apply a practical Blue Team ruleset
# Usage: sudo bash auditd_setup.sh
# Notes:
#  - This creates /etc/audit/rules.d/99-blue-team.rules and loads it.
#  - Reboot or `augenrules --load` ensures persistence.

set -euo pipefail

RULE_FILE="/etc/audit/rules.d/99-blue-team.rules"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Run as root (use sudo)."
    exit 1
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  else
    echo "unknown"
  fi
}

install_auditd() {
  local mgr
  mgr="$(detect_pkg_mgr)"

  echo "[*] Installing auditd (package manager: $mgr)..."
  case "$mgr" in
    apt)
      apt-get update -y
      apt-get install -y auditd audispd-plugins
      ;;
    dnf)
      dnf install -y audit audit-libs
      ;;
    yum)
      yum install -y audit audit-libs
      ;;
    zypper)
      zypper --non-interactive install audit
      ;;
    *)
      echo "[!] Unknown package manager. Install auditd manually, then re-run."
      exit 1
      ;;
  esac
}

enable_auditd() {
  echo "[*] Enabling and starting auditd..."
  systemctl enable --now auditd || true
  systemctl restart auditd || true
}

write_rules() {
  echo "[*] Writing rules to: $RULE_FILE"
  install -d -m 0750 /etc/audit/rules.d

  cat > "$RULE_FILE" <<'EOF'
## 99-blue-team.rules
## Practical auditd ruleset for Blue Team / IR
## Loaded via augenrules (preferred on modern distros)

## Reset existing rules (safe when you control the box)
-D

## Increase buffer to reduce event loss under load
-b 8192

## Log what can be audited (not required but helps)
--backlog_wait_time 60000

## Fail mode:
## 0=silent, 1=printk, 2=panic (2 is risky in competitions)
-f 1

############################################
# EXECUTION LOGGING (who ran what)
############################################
# Log execve (commands) for both 64-bit and 32-bit
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

############################################
# IDENTITY / PRIVILEGE CHANGES
############################################
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/gshadow -p wa -k identity

# sudoers changes
-w /etc/sudoers   -p wa -k sudo_changes
-w /etc/sudoers.d -p wa -k sudo_changes

############################################
# SSH & ACCESS CONTROL
############################################
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /root/.ssh/authorized_keys -p wa -k ssh_keys
-w /home/ -p wa -k home_changes

############################################
# PERSISTENCE LOCATIONS (cron/systemd/startup)
############################################
-w /etc/crontab    -p wa -k cron
-w /etc/cron.d     -p wa -k cron
-w /etc/cron.daily -p wa -k cron
-w /etc/cron.hourly -p wa -k cron
-w /etc/cron.weekly -p wa -k cron
-w /etc/cron.monthly -p wa -k cron

-w /etc/systemd/system -p wa -k systemd
-w /lib/systemd/system -p wa -k systemd
-w /usr/lib/systemd/system -p wa -k systemd

# Common startup hooks (may not exist on all distros)
-w /etc/rc.local -p wa -k startup
-w /etc/profile  -p wa -k shell_profile
-w /etc/profile.d/ -p wa -k shell_profile
-w /etc/bash.bashrc -p wa -k shell_profile

############################################
# CRITICAL CONFIG CHANGES
############################################
-w /etc/hosts      -p wa -k net_config
-w /etc/resolv.conf -p wa -k net_config
-w /etc/nsswitch.conf -p wa -k net_config
-w /etc/hostname   -p wa -k net_config
-w /etc/issue      -p wa -k banner

############################################
# KERNEL MODULE / LOW-LEVEL TAMPERING
############################################
-w /sbin/insmod  -p x -k kernel_modules
-w /sbin/rmmod   -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k kernel_modules

############################################
# Make rules immutable until reboot (optional)
# Uncomment if you want to prevent tampering.
# WARNING: You must reboot to change rules after enabling this.
# -e 2
EOF

  chmod 0640 "$RULE_FILE"
}

load_rules() {
  echo "[*] Loading audit rules..."
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
  else
    # Fallback
    auditctl -R "$RULE_FILE"
  fi

  echo "[*] Verifying auditd status and rules..."
  systemctl is-active --quiet auditd && echo "[+] auditd is active" || echo "[!] auditd not active"
  auditctl -s || true
}

print_how_to_use() {
  cat <<'EOF'

[+] Done. Useful commands:

  # Where logs live:
  /var/log/audit/audit.log

  # Search by key:
  ausearch -k exec_log
  ausearch -k cron
  ausearch -k systemd
  ausearch -k identity
  ausearch -k sudo_changes
  ausearch -k ssh_keys

  # Summaries:
  aureport -x --summary        # executed programs summary
  aureport -au --summary       # auth summary

Tips:
- If you uncomment "-e 2" (immutable), you MUST reboot to change audit rules.
- To reduce noise later, you can narrow execve logging to only interactive users.
EOF
}

main() {
  need_root
  install_auditd
  enable_auditd
  write_rules
  load_rules
  print_how_to_use
}

main "$@"
