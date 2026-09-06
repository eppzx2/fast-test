#!/bin/bash
# ============================================================
# Simulate: wget Masquerading as httpd (triggers Wazuh rules
# 100220 -> 100221)
# ============================================================
# Copies the wget binary to /tmp/httpd (so the process name/comm
# becomes "httpd") and executes it with wget-style arguments.
#
# IMPORTANT: this script must run ON THE TARGET HOST itself (the
# machine whose Wazuh Agent + auditd are being tested).
#
# REQUIREMENT: run setup_prereqs.sh first so auditd watches execve
# and the Wazuh agent collects /var/log/audit/audit.log.
# ============================================================

set -Eeuo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
AUDIT_LOCATION='<location>/var/log/audit/audit.log</location>'

WGET_BIN="$(command -v wget || true)"
if [ -z "$WGET_BIN" ]; then
    echo "ERROR: wget is not installed on this host." >&2
    exit 1
fi

if ! systemctl is-active --quiet auditd 2>/dev/null; then
    echo "ERROR: auditd is not running. Run setup_prereqs.sh on this target first." >&2
    exit 1
fi

# ossec.conf is commonly root:wazuh 0640. The simulator normally runs as an
# unprivileged target user, so a direct grep can return "permission denied" and
# falsely claim that setup_prereqs.sh did not add audit.log collection. Only
# enforce this preflight when the current user can actually read the file. The
# setup script itself runs as root and is the authoritative configuration step.
if [ ! -f "$OSSEC_CONF" ]; then
    echo "ERROR: Wazuh agent config was not found at $OSSEC_CONF." >&2
    echo "Run setup_prereqs.sh on this target first." >&2
    exit 1
elif [ -r "$OSSEC_CONF" ]; then
    if ! grep -Fq "$AUDIT_LOCATION" "$OSSEC_CONF"; then
        echo "ERROR: Wazuh agent is not configured to collect /var/log/audit/audit.log." >&2
        echo "Run setup_prereqs.sh on this target first." >&2
        exit 1
    fi
    echo "[OK] Wazuh audit.log collection is present in agent config"
else
    echo "[WARN] $OSSEC_CONF is not readable by the current user; skipping the read-only config preflight."
    echo "       setup_prereqs.sh already validates/adds audit.log collection as root."
fi

# Confirm the kernel audit rule itself is active. auditctl -l generally needs
# root, so use it when readable via sudo without making the simulation depend on
# an interactive sudo prompt. setup_prereqs.sh already performs the strict check.
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    if ! sudo -n auditctl -l 2>/dev/null | grep -q 'audit-wazuh-c'; then
        echo "ERROR: auditd execve rule (key=audit-wazuh-c) is not active." >&2
        echo "Run sudo ./setup_prereqs.sh on this target first." >&2
        exit 1
    fi
fi

FAKE_HTTPD="/tmp/httpd"
OUTPUT_FILE="/tmp/httpd_sim_output.tmp"
trap 'rm -f "$OUTPUT_FILE" "$FAKE_HTTPD"' EXIT

echo "==> Copying $WGET_BIN to $FAKE_HTTPD (masquerading as httpd)"
cp "$WGET_BIN" "$FAKE_HTTPD"
chmod +x "$FAKE_HTTPD"

echo "==> Executing $FAKE_HTTPD with wget-style arguments"
# Use loopback instead of an Internet dependency. Port 9 is normally closed;
# connection success is irrelevant because auditd records execve before wget
# attempts the network connection. The URL and -O argument give rule 100221
# deterministic wget-style command-line evidence.
"$FAKE_HTTPD" -T 2 -t 1 -O "$OUTPUT_FILE" \
    "http://127.0.0.1:9/fast-lolbin-test" >/dev/null 2>&1 || true

# Give auditd/logcollector a moment to flush the execution record.
sleep 1

echo "[OK] Masquerading process executed locally."
echo "Expected Wazuh chain: 80792 -> 100220 -> 100221."
