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

WGET_BIN="$(command -v wget || true)"
if [ -z "$WGET_BIN" ]; then
    echo "ERROR: wget is not installed on this host." >&2
    exit 1
fi

if ! systemctl is-active --quiet auditd 2>/dev/null; then
    echo "ERROR: auditd is not running. Run setup_prereqs.sh on this target first." >&2
    exit 1
fi

if [ ! -f /var/ossec/etc/ossec.conf ] || \
   ! grep -Fq '<location>/var/log/audit/audit.log</location>' /var/ossec/etc/ossec.conf; then
    echo "ERROR: Wazuh agent is not configured to collect /var/log/audit/audit.log." >&2
    echo "Run setup_prereqs.sh on this target first." >&2
    exit 1
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
